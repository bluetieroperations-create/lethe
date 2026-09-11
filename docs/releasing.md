# Releasing

A release is one act: pushing a `v*` tag. `.github/workflows/release.yml` turns
that into a GitHub Release and a PyPI upload, and refuses to do either if the
tag disagrees with what the repo says it is.

## Cutting one

1. Bump `lethe/version.py` (and `notary/pyproject.toml` if the notary changed).
2. Rename the CHANGELOG's `## [Unreleased]` heading to `## [X.Y.Z] — <date>`.
3. Merge that to `main`.
4. Tag the **merge commit** and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z" <merge-commit-sha>
   git tag --list vX.Y.Z                                    # must print the tag
   git push origin refs/tags/vX.Y.Z:refs/tags/vX.Y.Z
   git ls-remote --tags origin vX.Y.Z                       # must print two lines
   ```

   **Check both times.** A tag push can fail in two quiet ways, and v0.7.1 hit
   one of each before it landed. The tag can never have been created — a
   `git tag` line that scrolled past in a multi-command paste leaves nothing to
   push, and `git push` then reports success for the branch it did push. And a
   push whose tag ref is filtered on the way out can print
   `Everything up-to-date` while sending nothing. Neither prints an error, so
   the local `git tag --list` and the remote `git ls-remote` are what tell you.
   The explicit refspec is just being unambiguous about what is being pushed;
   it is not itself a guarantee the ref arrived.

The workflow then checks that the tag matches `lethe/version.py`, extracts the
notes from the CHANGELOG (failing if that section is missing, empty, or still
marked unreleased), publishes the GitHub Release, and only then uploads to
PyPI — the GitHub Release can be redone, a PyPI version can never be
re-uploaded, so the irreversible step goes last.

## Retrying a failed PyPI publish

The GitHub Release and the PyPI upload are separate jobs, and only the second
one can fail on its own. When it does, the Release already exists, so re-running
the workflow is not an option — `gh release create` refuses a release that is
already there.

Run the workflow by hand instead, against the tag that failed:

**Actions → Release → Run workflow**, and enter the tag (`v0.7.2`).

That skips the Release job entirely and runs only the PyPI publish, checked out
at that tag. No new version number is needed, and the existing Release is left
alone.

The tag-vs-`version.py` gate lives in the Release job, which this path skips, so
the publish job carries three of its own: the input must look like a release tag
(`vN…`), the checkout must actually be sitting on that tag's commit, and the
built artifacts must carry that tag's version. Together they keep the hand-run
path as safe as the automatic one.

## PyPI, one-time setup

Uploads use **Trusted Publishing**: GitHub proves the workflow's identity over
OIDC and PyPI mints a token good for that one upload. There is no API token in
the repo, in Actions secrets, or anywhere else to leak or rotate.

At <https://pypi.org/manage/project/lethe-delete/settings/publishing/>, add a
GitHub publisher:

| field | value |
|---|---|
| Owner | `bluetieroperations-create` |
| Repository | `lethe` |
| Workflow name | `release.yml` |
| Environment | *leave blank* |

Leave Environment blank unless you also add `environment:` to the `pypi` job —
PyPI matches on it when set, and a mismatch fails every publish.

If it does not match, the publish step prints **PyPI's own response body**,
which names the claim that failed, and fails before `twine upload` — nothing
half-publishes.

The trap worth knowing in advance: **Workflow name is the filename**,
`release.yml`. Entering `Release` — the name at the top of the workflow, and the
name shown in the Actions tab — produces a publisher that never matches, and a
422 on every publish. v0.7.2's first attempt failed exactly here.

## Why this exists

The repo reached 0.7.1 while `pip install lethe-delete` still served **0.2.0**,
published in July. That version's `[mcp]` extra declares an unpinned
`mcp>=1.9`, so pip resolved mcp 2.x, and `lethe/mcp.py` at 0.2.0 does
`from mcp.server.fastmcp import FastMCP` — a module 2.x renamed. The documented
MCP install was broken for every user for the entire time it was being fixed in
the repo. It also made `pip install ./notary` unsatisfiable, since the notary
requires `lethe-delete>=0.7` and no such version was public.

Tagging without publishing is the same drift the Release workflow was written
to stop, one layer down. Hence: same tag, same run, both artifacts.
