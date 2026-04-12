#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Extract a minimal real-layout shipcheck fixture from a live bitbake build."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

PREFERRED_RECIPES = ("tzdata", "openssl", "glibc", "busybox", "libxml2-native")
DEFAULT_ALLOWLIST = "openssl,glibc,curl,busybox,linux-yocto,bash"
KAS_YML_RELATIVE = "pilots/0001-poky-scarthgap-min/kas.yml"
PROVENANCE_UNKNOWN_SHA = "unknown - kas.yml not found"


def _die(msg: str) -> None:
    print(f"extract_pilot_fixture: {msg}", file=sys.stderr)
    sys.exit(1)


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _select_spdx(spdx_root: Path) -> list[Path]:
    all_paths = spdx_root.rglob("recipe-*.spdx.json")
    # Filter out sstate hash copies and by-namespace alternates; only keep the
    # canonical per-arch layout at tmp/deploy/spdx/<ver>/<arch>/recipes/.
    filtered = [p for p in all_paths if "by-hash" not in p.parts and "by-namespace" not in p.parts]
    candidates = sorted(filtered)
    if not candidates:
        return []
    picks: list[Path] = []
    seen: set[Path] = set()
    for name in PREFERRED_RECIPES:
        prefix = f"recipe-{name}"
        for path in candidates:
            if path in seen:
                continue
            base = path.name[: -len(".spdx.json")]
            if base == prefix or base.startswith(f"{prefix}-") or base.startswith(f"{prefix}."):
                picks.append(path)
                seen.add(path)
                break
    if not picks:
        picks = list(candidates[:3])
    return picks


def _copy_spdx(build_dir: Path, out: Path) -> int:
    spdx_root = build_dir / "tmp" / "deploy" / "spdx"
    picks = _select_spdx(spdx_root)
    for src in picks:
        rel = src.relative_to(build_dir)
        _copy(src, out / rel)
    return len(picks)


def _copy_newest_license_manifest(build_dir: Path, out: Path) -> bool:
    licenses_root = build_dir / "tmp" / "deploy" / "licenses"
    if not licenses_root.exists():
        return False
    manifests = sorted(licenses_root.rglob("license.manifest"))
    if not manifests:
        return False
    newest = max(manifests, key=lambda p: p.stat().st_mtime)
    rel = newest.relative_to(build_dir)
    _copy(newest, out / rel)
    return True


def _copy_image_artifacts(build_dir: Path, out: Path) -> None:
    images_root = build_dir / "tmp" / "deploy" / "images"
    if not images_root.exists():
        return
    for machine_dir in sorted(p for p in images_root.iterdir() if p.is_dir()):
        for manifest in sorted(machine_dir.glob("*.manifest")):
            if manifest.is_symlink():
                continue
            rel = manifest.relative_to(build_dir)
            _copy(manifest, out / rel)


def _issue_status_priority(issue: object) -> int:
    """Return sort priority by status: 0=Unpatched, 1=Ignored, 2=otherwise."""
    if not isinstance(issue, dict):
        return 2
    status = issue.get("status")
    if status == "Unpatched":
        return 0
    if status == "Ignored":
        return 1
    return 2


def _truncate_issues(package: dict) -> dict:
    issues = package.get("issue")
    if not isinstance(issues, list):
        return package
    ordered = sorted(
        issues,
        key=lambda item: (
            _issue_status_priority(item),
            item.get("id", "") if isinstance(item, dict) else "",
        ),
    )
    package["issue"] = ordered[:3]
    return package


def _rewrite_cve_summary(build_dir: Path, out: Path, allowlist: set[str]) -> bool:
    src = build_dir / "tmp" / "log" / "cve" / "cve-summary.json"
    if not src.exists():
        return False
    with src.open() as fh:
        data = json.load(fh)
    packages = data.get("package", [])
    kept = [p for p in packages if p.get("name") in allowlist]
    data["package"] = [_truncate_issues(p) for p in kept]
    dst = out / "tmp" / "log" / "cve" / "cve-summary.json"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return True


def _read_poky_commit_from_kas(kas_path: Path) -> str:
    """Return the first commit SHA found under a ``poky:`` entry in kas.yml.

    Uses a small line scanner so the extractor stays dependency-free. Looks
    for a ``poky:`` top-level repo key followed, within the same indented
    block, by a ``commit: <sha>`` line. Returns the SHA or the unknown
    placeholder if the file is absent, unreadable, or lacks the entry.
    """
    try:
        lines = kas_path.read_text().splitlines()
    except OSError:
        return PROVENANCE_UNKNOWN_SHA

    in_poky = False
    poky_indent = -1
    for raw in lines:
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(stripped)
        if not in_poky:
            if stripped.startswith("poky:"):
                in_poky = True
                poky_indent = indent
            continue
        # Leaving the poky block when we return to poky_indent or shallower.
        if indent <= poky_indent:
            in_poky = False
            continue
        if stripped.startswith("commit:"):
            value = stripped.split(":", 1)[1].strip()
            # Strip inline comments and quotes.
            if "#" in value:
                value = value.split("#", 1)[0].strip()
            value = value.strip("'\"")
            if value:
                return value
    return PROVENANCE_UNKNOWN_SHA


def _default_provenance(commit_sha: str, today: str) -> str:
    """Render the default PROVENANCE.md body used when none is preserved."""
    return (
        "# Fixture provenance\n"
        "\n"
        "This fixture is a minimized slice of a real Yocto build, committed for\n"
        "regression tests so shipcheck exercises real bitbake output paths in CI\n"
        "without running a full pilot.\n"
        "\n"
        "## Source\n"
        "\n"
        f"- poky commit: `{commit_sha}`\n"
        "- poky branch: `scarthgap` (LTS)\n"
        "- build target: `core-image-minimal`\n"
        "- machine: `qemux86-64`\n"
        "- distro: `poky`\n"
        f"- extraction date: `{today}`\n"
        "\n"
        "## Regenerate\n"
        "\n"
        "```bash\n"
        "uv run scripts/extract_pilot_fixture.py --build-dir <path-to-populated-build>\n"
        "```\n"
        "\n"
        "Refresh when poky Scarthgap point-releases shift file layouts (new\n"
        "per-arch subdir names, renamed SPDX fields, relocated cve-summary.json),\n"
        "or when shipcheck's discovery logic changes. See `docs/pilot.md` for\n"
        "the full regeneration workflow.\n"
    )


def _generate_default_provenance(script_dir: Path) -> str:
    kas_path = script_dir.parent / KAS_YML_RELATIVE
    commit_sha = _read_poky_commit_from_kas(kas_path)
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    return _default_provenance(commit_sha, today)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("./build"))
    parser.add_argument("--out", type=Path, default=Path("tests/fixtures/pilot_real/build"))
    parser.add_argument("--cve-allowlist", default=DEFAULT_ALLOWLIST)
    args = parser.parse_args()

    build_dir: Path = args.build_dir
    out: Path = args.out

    if not build_dir.exists():
        _die(f"--build-dir {build_dir} does not exist")
    spdx_root = build_dir / "tmp" / "deploy" / "spdx"
    if not spdx_root.exists():
        _die(f"missing subtree: tmp/deploy/spdx (looked in {build_dir})")

    local_conf = build_dir / "conf" / "local.conf"
    if not local_conf.exists():
        _die(f"missing subtree: conf/local.conf (looked in {build_dir})")

    allowlist = {s.strip() for s in args.cve_allowlist.split(",") if s.strip()}

    # Capture any existing PROVENANCE.md so the extractor can preserve it
    # verbatim across a wipe-and-regenerate cycle.
    provenance_path = out / "PROVENANCE.md"
    preserved_provenance: str | None = None
    if provenance_path.is_file():
        preserved_provenance = provenance_path.read_text()

    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)

    _copy(local_conf, out / "conf" / "local.conf")

    spdx_count = _copy_spdx(build_dir, out)
    if spdx_count == 0:
        _die("no recipe-*.spdx.json files found under tmp/deploy/spdx/")

    _copy_newest_license_manifest(build_dir, out)
    _copy_image_artifacts(build_dir, out)
    _rewrite_cve_summary(build_dir, out, allowlist)

    if preserved_provenance is not None:
        provenance_path.write_text(preserved_provenance)
    else:
        script_dir = Path(__file__).resolve().parent
        provenance_path.write_text(_generate_default_provenance(script_dir))


if __name__ == "__main__":
    main()
