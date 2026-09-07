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
   git push origin refs/tags/vX.Y.Z:refs/tags/vX.Y.Z
   ```

   The explicit refspec is deliberate: a plain `git push origin vX.Y.Z` can
   print `Everything up-to-date` and silently drop the ref when the push is
   filtered, which is how v0.7.1 appeared to be tagged for half an hour
   without being tagged at all.

The workflow then checks that the tag matches `lethe/version.py`, extracts the
notes from the CHANGELOG (failing if that section is missing, empty, or still
marked unreleased), publishes the GitHub Release, and only then uploads to
PyPI — the GitHub Release can be redone, a PyPI version can never be
re-uploaded, so the irreversible step goes last.

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

If it is not configured, the publish step says so by name rather than dying on
a 403.

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
