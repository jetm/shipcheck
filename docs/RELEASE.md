# Release Process

shipcheck releases are one-shot from a clean main: bump the version with `bump-my-version`, push the resulting commit and tag, and let `.github/workflows/publish.yml` build the wheel, publish to PyPI via OIDC, and create the GitHub release. Everything else is automation around that single command.

This document is the source of truth for the ceremony. The recurring failure mode it exists to prevent is hand-editing CHANGELOG.md before the bump - that path skips the entire automation chain and forces a manual tag ceremony.

## When to release

- **Triage signal**: open issues or in-flight changes are either fixed or stable, the `## [Unreleased]` block in CHANGELOG.md has user-visible entries, and the pilot gate (per `docs/pilot.md` and the pilot-0001 conventions) is satisfied for any new check IDs that landed since the last tag.
- **Cadence**: roughly monthly, or whenever an external user (issue or PR) needs a fix shipped.

Patch releases follow the same flow as minor and major releases. There is no separate "hotfix" path; ship forward.

## During development

Add entries ONLY under `## [Unreleased]` in CHANGELOG.md. Use the Keep-a-Changelog subsections: `### Added`, `### Changed`, `### Fixed`, `### Removed`.

Each `### Added` or `### Changed` entry that touches a registered check ID must have a matching `Pilot:` reference in the README Roadmap section, per `docs/pilot.md`. PR reviewers enforce this in the comment thread; no CI step blocks on it today.

Do **not** manually create a `## [<version>]` header. `bump-my-version` does that automatically at release time. The recurring v0.0.5 mistake was renaming `## [Unreleased]` to `## [0.0.5]` by hand before bumping; that single edit is what disconnects the rest of the automation.

## Release ceremony

Run every command from the shipcheck repo root.

```bash
# 1. Make sure working tree is clean and main is up to date.
git status
git fetch origin && git rebase origin/main   # if any divergence

# 2. Verify CHANGELOG.md has the entries you want to ship under
#    ## [Unreleased]. Visual review is enough; no manual rename.

# 3. Bump version (one command, picks up Unreleased entries):
uv run bump-my-version bump patch    # or `minor` or `major`

# 4. Push main and the new tag:
git push origin main
git push origin v<new>
```

The `bump-my-version bump <level>` invocation does five things in one shot:

- Bumps `version = "..."` in `pyproject.toml`.
- Bumps `__version__ = "..."` in `src/shipcheck/__init__.py`.
- Bumps `current_version = "..."` inside `pyproject.toml`'s own `[tool.bumpversion]` block.
- Inserts `## [<new>] - <today>` immediately below `## [Unreleased]` in CHANGELOG.md so the existing Unreleased entries roll under the new version header.
- Auto-commits with the message `Bump version: <old> → <new>` and tags `v<new>`.

After the tag push, `.github/workflows/publish.yml` triggers. The workflow:

1. Builds the wheel with `uv build`.
2. Publishes to PyPI via OIDC trusted publishing (no API token).
3. Extracts the relevant `## [<version>]` section from CHANGELOG.md using a state-flag awk walker (commit `f345840` on 2026-04-29 replaced an earlier broken `awk /start/,/end/` range pattern that emitted empty notes).
4. Calls `gh release create --notes-file release-notes.md --verify-tag` to publish the GitHub release with the extracted section as its body.

If the workflow run is green, the release is done. Watch the run once for each release - silent failures in the publish step land as a missing wheel on PyPI, and the cheapest detection is the workflow log.

## What can go wrong

Each subsection lists the symptom, the cause, and the fix.

### `bump-my-version` reports `current_version` mismatch

Symptom: `uv run bump-my-version bump patch` exits with `current version "X.Y.Z" does not match expected "A.B.C"`.

Cause: one of the configured files drifted out of sync with `[tool.bumpversion].current_version`. Usually this is `src/shipcheck/__init__.py` getting hand-edited in the middle of a feature change.

Fix: align the offending file's version string with `current_version` and re-run. Do not edit `current_version` itself unless every other file already matches it.

### Pre-commit hook modifies `uv.lock` during the bump-my-version commit

Symptom: bump-my-version's auto-commit fails because the `uv-lock` pre-commit hook updated `uv.lock` (the `version` field in `pyproject.toml` changed, so the lock changed too).

Cause: the lock hook is correctly catching a real `pyproject.toml` change. Nothing is broken; the commit just needs the updated lock staged.

Fix: stage `uv.lock` and re-run `uv run bump-my-version bump <level>`. The bump only re-applies the version-string edits to files where the value already matches the target, so it will not double-bump.

### PyPI rejects the upload as a duplicate

Symptom: the workflow fails at the "Publish to PyPI" step with a 400 or 409 from PyPI.

Cause: the wheel was built with a version that already exists on PyPI. Almost always means `pyproject.toml` `version` was not bumped - someone tagged the previous commit instead of the bump commit.

Fix: revert or delete the bad tag locally and on origin, run `bump-my-version` properly, push the new tag.

### GitHub release body is empty

Symptom: the release exists at `github.com/jetm/shipcheck/releases/tag/v<X>` but its body is blank.

Cause: either CHANGELOG.md doesn't have a `## [<version>]` header that matches the tag (e.g. tag is `v0.0.5-rc1` but the header is `## [0.0.5]`), or the awk extraction silently produced empty output. The latter was the bug fixed in commit `f345840` on 2026-04-29.

Fix: backfill manually with `gh release edit v<X> --notes-file <path>` after assembling the section by hand. For the bug class itself, verify `.github/workflows/publish.yml` uses the state-flag awk walker, not the broken `/start/,/end/` range pattern.

### Manual `## [<version>]` header in CHANGELOG.md before bumping

Symptom: `uv run bump-my-version bump <level>` inserts a SECOND `## [<new>]` header below the manually-added one, producing a duplicate.

Cause: the bump-my-version search/replace targets the literal string `## [Unreleased]` and inserts a new version header below it. Manually pre-renaming Unreleased to a version is what caused the v0.0.5 mistake - the rename removed the `## [Unreleased]` anchor, the bump fell back to inserting nothing useful, and the rest of the ceremony had to be done by hand.

Fix: before bumping, the only `## [<X.Y.Z>]` headers in CHANGELOG.md should be PRIOR releases. The block being released is in `## [Unreleased]`. If you accidentally renamed it manually, revert that rename (entries go back under Unreleased) before running bump-my-version.

## OIDC trusted publishing

shipcheck publishes to PyPI without an API token. The configuration lives on PyPI's side: the project trusts GitHub Actions runs from `jetm/shipcheck` on the `main` branch and any tag matching `v*` to mint short-lived OIDC tokens. The workflow grants `id-token: write` permission so the runner can request the token. There is no `PYPI_API_TOKEN` secret to manage.

If trusted publishing breaks (for example, the PyPI account changes hands), reconfigure the trusted publisher under PyPI project settings - shipcheck does not keep that wiring in repo.

## Roll-forward, not roll-back

Releases are append-only. If a `v0.0.X` has a bug, ship `v0.0.X+1` with the fix rather than yanking. PyPI lets you yank a release for security reasons, but routine bugs should ride forward.

If a release is fundamentally broken (for example, the wheel does not import), yank it via `https://pypi.org/manage/project/shipcheck/release/<X>/` and ship the next patch immediately so users running `uv tool install shipcheck` do not pin the bad version.
