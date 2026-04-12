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

    # openssl had 5 issues with mixed statuses (3 Patched, 1 Unpatched, 1 Ignored).
    # The truncation sort key is (status_priority, id) where
    # Unpatched=0, Ignored=1, Patched/other=2. Under that key the 3 kept entries
    # must include the Unpatched and Ignored ones, not only Patched.
    by_name = {pkg["name"]: pkg for pkg in data["package"]}
    openssl_issues = by_name["openssl"]["issue"]
    openssl_statuses = [issue["status"] for issue in openssl_issues]
    assert "Unpatched" in openssl_statuses, (
        f"Unpatched issue was dropped from kept 3: {openssl_issues!r}"
    )
    assert "Ignored" in openssl_statuses, (
        f"Ignored issue was dropped from kept 3: {openssl_issues!r}"
    )
    # Ordering within the kept 3 stays by (status_priority, id):
    # Unpatched CVE-2024-0003 first, Ignored CVE-2024-0002 second,
    # lowest-id Patched CVE-2024-0001 third.
    openssl_ids = [issue["id"] for issue in openssl_issues]
    assert openssl_ids == ["CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0001"]


@pytest.mark.unit
def test_by_hash_spdx_paths_are_excluded(tmp_path: Path) -> None:
    """sstate SPDX copies under by-hash/ must not leak into the fixture.

    bitbake also stages recipe-*.spdx.json files under
    tmp/deploy/spdx/<ver>/by-hash/<sstate-hash>/ (and similarly under
    by-namespace/). Those are sstate-reuse copies of the canonical
    per-arch artifacts - selecting them would poison the fixture with
    paths that shipcheck never sees in a real image build.
    """
    build = tmp_path / "build"

    # conf/local.conf
    conf = build / "conf"
    conf.mkdir(parents=True)
    (conf / "local.conf").write_text('MACHINE ?= "qemux86-64"\n')

    spdx_base = build / "tmp" / "deploy" / "spdx" / "2.2"

    # Canonical per-arch layout.
    canonical = spdx_base / "x86_64" / "recipes"
    canonical.mkdir(parents=True)
    (canonical / "recipe-foo.spdx.json").write_text(
        json.dumps({"spdxVersion": "SPDX-2.2", "name": "recipe-foo"}, indent=2) + "\n"
    )

    # sstate by-hash copy. Use a filesystem-safe directory name (no colons).
    by_hash = spdx_base / "by-hash" / "some-hash-dir"
    by_hash.mkdir(parents=True)
    (by_hash / "recipe-foo.spdx.json").write_text(
        json.dumps({"spdxVersion": "SPDX-2.2", "name": "recipe-foo-by-hash"}, indent=2) + "\n"
    )

    out = tmp_path / "out"
    result = _run(["--build-dir", str(build), "--out", str(out)])

    assert result.returncode == 0, (
        f"extractor failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    out_spdx_files = [p for p in out.rglob("recipe-*.spdx.json") if p.is_file()]
    assert out_spdx_files, "extractor produced no SPDX files"

    # Canonical path present, by-hash path absent.
    assert (
        out / "tmp" / "deploy" / "spdx" / "2.2" / "x86_64" / "recipes" / "recipe-foo.spdx.json"
    ).is_file()
    for path in out_spdx_files:
        assert "by-hash" not in path.parts, f"by-hash leaked into fixture: {path}"
        assert "by-namespace" not in path.parts, f"by-namespace leaked into fixture: {path}"


@pytest.mark.unit
def test_provenance_is_preserved_on_rerun(tmp_path: Path) -> None:
    """A pre-existing PROVENANCE.md must survive a wipe-and-regenerate cycle.

    The extractor deletes the --out tree before repopulating it. Any
    hand-maintained provenance note at <out>/PROVENANCE.md must be
    round-tripped verbatim so fixture refreshes do not clobber the
    human-authored record of where the fixture came from.
    """
    build = _make_minimal_build_dir(tmp_path)
    out = tmp_path / "out"

    first = _run(["--build-dir", str(build), "--out", str(out)])
    assert first.returncode == 0, first.stderr

    prov_path = out / "PROVENANCE.md"
    assert prov_path.is_file(), "first run must create PROVENANCE.md"

    marker = "# MARKER-preserve-me-42\n"
    original = prov_path.read_text()
    prov_path.write_text(original + marker)

    second = _run(["--build-dir", str(build), "--out", str(out)])
    assert second.returncode == 0, second.stderr

    after = prov_path.read_text()
    assert marker in after, "marker line was dropped across regeneration"
    assert after == original + marker, "PROVENANCE.md was rewritten instead of preserved verbatim"


@pytest.mark.unit
def test_provenance_is_created_when_missing(tmp_path: Path) -> None:
    """A fresh --out with no PROVENANCE.md must get a default one.

    The default body should reference the poky commit SHA read from
    pilots/0001-poky-scarthgap-min/kas.yml when that file is reachable,
    or the documented placeholder when it is not.
    """
    build = _make_minimal_build_dir(tmp_path)
    out = tmp_path / "fresh-out"
    assert not out.exists()

    result = _run(["--build-dir", str(build), "--out", str(out)])
    assert result.returncode == 0, result.stderr

    prov_path = out / "PROVENANCE.md"
    assert prov_path.is_file()
    body = prov_path.read_text()

    kas_path = PROJECT_ROOT / "pilots" / "0001-poky-scarthgap-min" / "kas.yml"
    if kas_path.is_file():
        assert "cb2dcb4963e" in body, (
            "default provenance should embed the poky commit SHA from kas.yml"
        )
    else:
        assert "unknown - kas.yml not found" in body

    # Sanity: the regenerated body is non-trivial and mentions the fixture.
    assert "poky" in body.lower()
