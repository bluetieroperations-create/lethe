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
