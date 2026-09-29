"""The packaging facts that are permanent once a version is published.

PyPI will not let a version's metadata be amended, only superseded. So a
missing field is not a bug you fix — it is a bug you ship, under a version
number nobody can reuse. This file is the pre-publish checklist, run on every
commit instead of remembered at release time.

Every assertion here corresponds to something that was actually wrong when the
notary was first built for publication: it had no `readme`, so its PyPI page
would have rendered blank, and no license, classifiers, keywords or URLs.
`twine check` warned about the description and passed the package anyway.
"""

import tomllib
from pathlib import Path

import pytest

NOTARY = Path(__file__).resolve().parents[1]
REPO = NOTARY.parent


@pytest.fixture(scope="module")
def project():
    return tomllib.loads((NOTARY / "pyproject.toml").read_text())["project"]


def test_the_pypi_page_will_not_be_blank(project):
    """`readme` is what becomes the project page. Without it PyPI shows nothing
    at all — which is what this package was one `git tag` away from doing."""
    assert project.get("readme") == "README.md"
    readme = NOTARY / project["readme"]
    assert readme.is_file(), f"{readme} is declared but missing from the sdist"
    # Not a stub. A one-line readme renders as an empty page in practice.
    assert len(readme.read_text()) > 2000


def test_the_license_is_declared_where_installers_look(project):
    classifiers = project.get("classifiers", [])
    assert any(c.startswith("License ::") for c in classifiers), classifiers


def test_the_license_text_ships_inside_the_distribution():
    """A license at the repo root is not in a distribution built from this
    subdirectory, and `pip download lethe-notary` gets the distribution."""
    assert (NOTARY / "LICENSE").is_file()


def test_the_notary_license_has_not_drifted_from_the_repo_license():
    """It is a copy, because a build backend cannot reach outside its own
    project directory for a license file. A copy with nothing watching it is a
    copy that goes stale: relicense the repo and this package keeps shipping
    the old terms, silently, in every wheel.
    """
    assert (NOTARY / "LICENSE").read_bytes() == (REPO / "LICENSE").read_bytes(), (
        "notary/LICENSE differs from the repo LICENSE. It is a copy of it; "
        "update both or the published package ships the wrong terms."
    )


def test_someone_can_find_the_source_from_the_pypi_page(project):
    urls = project.get("urls", {})
    assert "Repository" in urls, urls
    assert urls["Repository"].startswith("https://github.com/"), urls


def test_the_changelog_describes_the_version_about_to_be_published(project):
    """`lethe-notary` publishes no GitHub Release, so this file is the only
    record of what a version contains. The release workflow refuses a tag with
    no matching section — but that refusal arrives after the tag is pushed,
    which is the wrong time to learn about it. This fails on the commit that
    bumps the version instead, when the fix is still free.
    """
    changelog = NOTARY / "CHANGELOG.md"
    heading = f"## [{project['version']}]"
    lines = changelog.read_text().splitlines()
    sections = [line for line in lines if line.startswith("## ")]
    assert any(s == heading or s.startswith(heading + " ") for s in sections), (
        f"notary/CHANGELOG.md has no {heading!r} section; it has {sections}"
    )

    # A heading with nothing under it passes the existence check and is the
    # same failure: a published version whose contents nobody can read.
    at = next(i for i, line in enumerate(lines)
              if line == heading or line.startswith(heading + " "))
    rest = lines[at + 1:]
    stop = next((i for i, line in enumerate(rest) if line.startswith("## ")),
                len(rest))
    assert any(line.strip() for line in rest[:stop]), (
        f"notary/CHANGELOG.md's {heading!r} section is empty"
    )


def test_the_changelog_is_the_notarys_own_and_not_the_repos():
    """The two files are one `cp` apart and the failure is silent: a notary
    release would announce lethe-delete's changes, which is the drift the split
    exists to prevent. Pinned on the heading, which is what a reader sees.
    """
    first = (NOTARY / "CHANGELOG.md").read_text().splitlines()[0]
    assert "lethe-notary" in first, first
    assert first != (REPO / "CHANGELOG.md").read_text().splitlines()[0]


def test_the_changelog_is_reachable_from_the_pypi_page(project):
    """Without a GitHub Release there is no other link to it."""
    assert "Changelog" in project.get("urls", {}), project.get("urls")


def test_the_version_is_a_plain_release_number(project):
    """A tag drives the publish and must equal this exactly, so a local
    version, a dev suffix or a stray `v` here is a release that cannot happen.
    """
    version = project["version"]
    assert version.replace(".", "").isdigit(), version
    assert len(version.split(".")) == 3, version


def test_declaring_a_test_only_dependency_as_a_runtime_one_would_be_caught(project):
    """PyJWT exists to cross-check `cdp_auth` against a reference
    implementation. It must never become a runtime requirement: the whole point
    of hand-rolling that JWS was to add no supply chain to the paid path.
    """
    runtime = " ".join(project["dependencies"]).lower()
    assert "jwt" not in runtime, project["dependencies"]
    assert any("pyjwt" in d.lower()
               for d in project["optional-dependencies"]["dev"])
