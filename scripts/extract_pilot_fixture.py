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
from pathlib import Path

PREFERRED_RECIPES = ("tzdata", "openssl", "glibc", "busybox", "libxml2-native")
DEFAULT_ALLOWLIST = "openssl,glibc,curl,busybox,linux-yocto,bash"


def _die(msg: str) -> None:
    print(f"extract_pilot_fixture: {msg}", file=sys.stderr)
    sys.exit(1)


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _select_spdx(spdx_root: Path) -> list[Path]:
    candidates = sorted(spdx_root.rglob("recipe-*.spdx.json"))
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


def _truncate_issues(package: dict) -> dict:
    issues = package.get("issue")
    if not isinstance(issues, list):
        return package
    ordered = sorted(issues, key=lambda item: item.get("id", "") if isinstance(item, dict) else "")
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

    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)

    _copy(local_conf, out / "conf" / "local.conf")

    spdx_count = _copy_spdx(build_dir, out)
    if spdx_count == 0:
        _die("no recipe-*.spdx.json files found under tmp/deploy/spdx/")

    _copy_newest_license_manifest(build_dir, out)
    _copy_image_artifacts(build_dir, out)
    _rewrite_cve_summary(build_dir, out, allowlist)


if __name__ == "__main__":
    main()
