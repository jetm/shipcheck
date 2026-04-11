# Fixture provenance

This fixture is a minimized slice of a real Yocto build, committed for
regression tests so shipcheck exercises real bitbake output paths in CI
without running a full pilot.

## Source

- poky commit: `cb2dcb4963e5fbe449f1bcb019eae883ddecc8ec`
- poky branch: `scarthgap` (LTS)
- build target: `core-image-minimal`
- machine: `qemux86-64`
- distro: `poky`
- extraction date: `2026-04-20`

## Regenerate

```bash
uv run scripts/extract_pilot_fixture.py --build-dir <path-to-populated-build>
```

Refresh when poky Scarthgap point-releases shift file layouts (new
per-arch subdir names, renamed SPDX fields, relocated cve-summary.json),
or when shipcheck's discovery logic changes. See `docs/pilot.md` for
the full regeneration workflow.
