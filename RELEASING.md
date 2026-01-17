# Releasing shipcheck

## Prerequisites

- Clean working tree (`git status` shows no changes)
- All tests pass (`uv run pytest`)
- Lint clean (`uv run ruff check src/ tests/`)
- On `main` branch
- PyPI trusted publisher configured for `jetm/shipcheck` with workflow `publish.yml`

## Release Process

### 1. Update CHANGELOG.md

Add entries under `## [Unreleased]` describing what changed. Use Keep a Changelog format:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description
```

Commit the changelog update before bumping.

### 2. Bump version

`bump-my-version` handles everything atomically: updates `pyproject.toml`,
`src/shipcheck/__init__.py`, and `CHANGELOG.md`, then commits and tags.

```bash
# Patch release (0.0.2 -> 0.0.3)
uv run bump-my-version bump patch

# Minor release (0.0.x -> 0.1.0)
uv run bump-my-version bump minor

# Major release (0.x.y -> 1.0.0)
uv run bump-my-version bump major
```

This creates a commit "Bump version: X.Y.Z -> A.B.C" and a `vA.B.C` tag.

The CHANGELOG `## [Unreleased]` header is preserved, and a new dated
version header is inserted below it.

### 3. Push

```bash
git push origin main --follow-tags
```

This pushes the commit and the tag. The tag triggers the `publish.yml`
GitHub Actions workflow which builds and publishes to PyPI automatically.

### 4. Verify

- Check GitHub Actions: publish workflow should pass
- Check PyPI: `pip install shipcheck==A.B.C` should work
- Check CLI: `shipcheck --help` should show the new version

## Versioning Policy

- **0.0.x**: Alpha releases during Phase 1 development
- **0.1.0**: First public release (after blog post and announcement)
- **0.x.y**: Pre-1.0 releases, minor bumps for new checks/features
- **1.0.0**: Stable release with full CRA check coverage

## What NOT to do

- Do not create tags manually (`git tag vX.Y.Z`) - use bump-my-version
- Do not edit version strings in files manually - bump-my-version handles all three locations
- Do not push tags separately from commits - use `--follow-tags`
