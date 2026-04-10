"""Unit tests for scripts/extract_pilot_fixture.py.

The extractor is a PEP 723 script, not a package module. We invoke it via
subprocess so its sys.exit() calls don't terminate the test process, and so
we exercise the real CLI surface (argparse, stderr, exit code).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "extract_pilot_fixture.py"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Invoke the extractor script with the given CLI args."""
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _make_minimal_build_dir(root: Path) -> Path:
    """Construct a synthetic bitbake-like build directory under root."""
    build = root / "build"

    # conf/local.conf
    conf = build / "conf"
    conf.mkdir(parents=True)
    (conf / "local.conf").write_text('MACHINE ?= "qemux86-64"\n')

    # One recipe SPDX document at 2.2/<arch>/recipes/recipe-foo.spdx.json
    spdx_dir = build / "tmp" / "deploy" / "spdx" / "2.2" / "x86_64" / "recipes"
    spdx_dir.mkdir(parents=True)
    (spdx_dir / "recipe-foo.spdx.json").write_text(
        json.dumps({"spdxVersion": "SPDX-2.2", "name": "recipe-foo"}, indent=2) + "\n"
    )

    # One per-arch license.manifest
    lic_dir = build / "tmp" / "deploy" / "licenses" / "qemux86_64" / "image-x"
    lic_dir.mkdir(parents=True)
    (lic_dir / "license.manifest").write_text("PACKAGE NAME: foo\nLICENSE: MIT\n\n")

    # One image manifest
    img_dir = build / "tmp" / "deploy" / "images" / "qemux86-64"
    img_dir.mkdir(parents=True)
    (img_dir / "img.manifest").write_text("foo qemux86_64 1.0\n")

    # CVE summary with both allowlisted and non-allowlisted packages.
    # openssl has 5 issues so the truncation-to-3 behaviour is exercised.
    cve_dir = build / "tmp" / "log" / "cve"
    cve_dir.mkdir(parents=True)
    cve_data = {
        "version": "1",
        "package": [
            {
                "name": "openssl",
                "layer": "meta",
                "version": "3.0.0",
                "issue": [
                    {"id": "CVE-2024-0005", "status": "Patched"},
                    {"id": "CVE-2024-0001", "status": "Patched"},
                    {"id": "CVE-2024-0003", "status": "Unpatched"},
                    {"id": "CVE-2024-0002", "status": "Ignored"},
                    {"id": "CVE-2024-0004", "status": "Patched"},
                ],
            },
            {"name": "zlib", "layer": "meta", "version": "1.2.13", "issue": []},
            {
                "name": "glibc",
                "layer": "meta",
                "version": "2.39",
                "issue": [
                    {"id": "CVE-2023-0002", "status": "Patched"},
                    {"id": "CVE-2023-0001", "status": "Patched"},
                    {"id": "CVE-2023-0003", "status": "Unpatched"},
                    {"id": "CVE-2023-0004", "status": "Ignored"},
                ],
            },
            {"name": "some-random-pkg", "layer": "meta", "version": "0.1", "issue": []},
        ],
    }
    (cve_dir / "cve-summary.json").write_text(json.dumps(cve_data, indent=2) + "\n")

    return build


@pytest.mark.unit
def test_missing_build_dir_exits_nonzero_and_names_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    result = _run(["--build-dir", str(missing), "--out", str(tmp_path / "out")])

    assert result.returncode != 0
    assert str(missing) in result.stderr


@pytest.mark.unit
def test_missing_spdx_subtree_exits_nonzero_and_names_subtree(tmp_path: Path) -> None:
    build = tmp_path / "build"
    # Create build dir but NO tmp/deploy/spdx/ subtree.
    (build / "conf").mkdir(parents=True)
    (build / "conf" / "local.conf").write_text('MACHINE ?= "qemux86-64"\n')

    result = _run(["--build-dir", str(build), "--out", str(tmp_path / "out")])

    assert result.returncode != 0
    assert "tmp/deploy/spdx" in result.stderr


@pytest.mark.unit
def test_extracts_expected_tree_and_filters_cve_allowlist(tmp_path: Path) -> None:
    build = _make_minimal_build_dir(tmp_path)
    out = tmp_path / "out"

    result = _run(["--build-dir", str(build), "--out", str(out)])

    assert result.returncode == 0, (
        f"extractor failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    # Expected out tree: conf/local.conf, SPDX document, license manifest,
    # image manifest, rewritten cve-summary.json.
    assert (out / "conf" / "local.conf").is_file()
    assert (
        out / "tmp" / "deploy" / "spdx" / "2.2" / "x86_64" / "recipes" / "recipe-foo.spdx.json"
    ).is_file()
    assert (
        out / "tmp" / "deploy" / "licenses" / "qemux86_64" / "image-x" / "license.manifest"
    ).is_file()
    assert (out / "tmp" / "deploy" / "images" / "qemux86-64" / "img.manifest").is_file()

    cve_out = out / "tmp" / "log" / "cve" / "cve-summary.json"
    assert cve_out.is_file()

    data = json.loads(cve_out.read_text())
    names = {pkg["name"] for pkg in data["package"]}
    # openssl and glibc are in the default allowlist, the others are not.
    assert names == {"openssl", "glibc"}
    assert "zlib" not in names
    assert "some-random-pkg" not in names


@pytest.mark.unit
def test_extraction_is_byte_identical_across_runs(tmp_path: Path) -> None:
    build = _make_minimal_build_dir(tmp_path)
    out_a = tmp_path / "out_a"
    out_b = tmp_path / "out_b"

    first = _run(["--build-dir", str(build), "--out", str(out_a)])
    second = _run(["--build-dir", str(build), "--out", str(out_b)])

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr

    files_a = sorted(p.relative_to(out_a) for p in out_a.rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(out_b) for p in out_b.rglob("*") if p.is_file())
    assert files_a == files_b, "file sets differ between runs"

    for rel in files_a:
        bytes_a = (out_a / rel).read_bytes()
        bytes_b = (out_b / rel).read_bytes()
        assert bytes_a == bytes_b, f"byte mismatch for {rel}"


@pytest.mark.unit
def test_issue_arrays_are_truncated_to_three(tmp_path: Path) -> None:
    build = _make_minimal_build_dir(tmp_path)
    out = tmp_path / "out"

    result = _run(["--build-dir", str(build), "--out", str(out)])

    assert result.returncode == 0, result.stderr

    data = json.loads((out / "tmp" / "log" / "cve" / "cve-summary.json").read_text())
    for package in data["package"]:
        assert len(package["issue"]) <= 3, (
            f"package {package.get('name')!r} retained {len(package['issue'])} issues"
        )

    # openssl had 5 issues in the fixture - verify deterministic sort-by-id
    # keeps the three lowest-id entries.
    by_name = {pkg["name"]: pkg for pkg in data["package"]}
    openssl_ids = [issue["id"] for issue in by_name["openssl"]["issue"]]
    assert openssl_ids == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
