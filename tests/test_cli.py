"""Tests for the shipcheck CLI check command."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shipcheck.cli import app

runner = CliRunner()

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def build_dir_with_spdx(tmp_path: Path) -> Path:
    """Create a minimal build dir with a valid SPDX 2.3 file."""
    spdx_dir = tmp_path / "tmp" / "deploy" / "spdx"
    spdx_dir.mkdir(parents=True)
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2026-01-01T00:00:00Z",
            "creators": ["Tool: shipcheck-test"],
        },
        "packages": [
            {
                "name": "test-pkg",
                "versionInfo": "1.0",
                "supplier": "Organization: TestCorp",
                "licenseDeclared": "Apache-2.0",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "abc123"}],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package",
                "relationshipType": "DESCRIBES",
            }
        ],
    }
    (spdx_dir / "image.spdx.json").write_text(json.dumps(spdx_doc))
    return tmp_path


@pytest.fixture()
def build_dir_empty(tmp_path: Path) -> Path:
    """Create a build dir with no check outputs (SPDX dir missing, no CVE output)."""
    tmp_path.mkdir(exist_ok=True)
    return tmp_path


class TestCheckCommand:
    """Tests for `shipcheck check`."""

    def test_check_produces_terminal_output(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0
        assert "Readiness score" in result.output

    def test_check_writes_markdown_by_default(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.md"
        assert report_path.exists(), f"Expected {report_path} to be written"

    def test_check_writes_html_report(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "html"]
        )
        assert result.exit_code == 0
        report_path = tmp_path / "shipcheck-report.html"
        assert report_path.exists()
        content = report_path.read_text()
        assert "<html" in content

    def test_check_filters_checks(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--checks", "sbom-generation"]
        )
        assert result.exit_code == 0
        assert "SBOM" in result.output

    def test_check_filters_secure_boot(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--checks", "secure-boot"]
        )
        assert result.exit_code == 0
        assert "Secure Boot" in result.output

    def test_check_filters_image_signing(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--checks", "image-signing"]
        )
        assert result.exit_code == 0
        assert "Image Signing" in result.output

    def test_check_loads_config_file(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".shipcheck.yaml"
        config_file.write_text(f"build_dir: {build_dir_with_spdx}\nreport:\n  format: json\n")
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0

    def test_check_cli_overrides_config(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".shipcheck.yaml"
        config_file.write_text(f"build_dir: {build_dir_with_spdx}\nreport:\n  format: json\n")
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "html"]
        )
        assert result.exit_code == 0
        assert (tmp_path / "shipcheck-report.html").exists()


class TestJsonStdout:
    """Tests for `shipcheck check --format json` emitting to stdout.

    Task 1.1 of devspec change ``v01-pilot-fixes``. When `--format json` is
    used without `--out`, the JSON payload goes to stdout (so `> scan.json`
    captures it cleanly), no Rich terminal report is rendered, and no
    ``shipcheck-report.json`` is silently written in cwd. Covers spec
    ``config-and-cli`` scenarios "JSON format goes to stdout" and
    "JSON format with shell redirection".

    Note: ``mix_stderr=False`` is no longer a ``CliRunner`` constructor
    kwarg in Click 8.2+ (removed upstream); the default runner already
    exposes ``result.stdout`` and ``result.stderr`` as separate streams,
    which is the behaviour the task requested.
    """

    def test_json_stdout_emits_parseable_payload(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--format json` without `--out` writes well-formed JSON to stdout."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"]
        )
        assert result.exit_code == 0, result.output

        data = json.loads(result.stdout)
        assert "readiness_score" in data
        assert "score" in data["readiness_score"]

    def test_json_stdout_suppresses_rich_terminal_report(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--format json` without `--out` must not render the Rich terminal report.

        The terminal renderer emits a "Readiness score" header; its absence
        confirms the JSON short-circuit skipped ``terminal.render()``. Parsing
        ``result.stdout`` as JSON is the stronger check (any stray terminal
        bytes would break ``json.loads``), but the explicit absence assertion
        documents the intent.
        """
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"]
        )
        assert result.exit_code == 0, result.output

        # stdout must be pure JSON - no Rich header, no table borders.
        json.loads(result.stdout)
        assert "Readiness score" not in result.stdout

    def test_json_stdout_does_not_write_report_file(
        self, build_dir_with_spdx: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--format json` without `--out` must not write ``shipcheck-report.json`` in cwd."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_with_spdx), "--format", "json"]
        )
        assert result.exit_code == 0, result.output
        assert not (tmp_path / "shipcheck-report.json").exists(), (
            "--format json without --out must emit to stdout only; "
            "silent file write in cwd breaks shell redirection contract"
        )


class TestFailOn:
    """Tests for --fail-on exit code gating."""

    def test_no_fail_on_exits_zero_with_findings(self, build_dir_empty: Path) -> None:
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_empty)])
        assert result.exit_code == 0

    def test_fail_on_critical_exits_one_when_critical_findings(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "critical"]
        )
        assert result.exit_code == 1

    def test_fail_on_critical_exits_zero_when_no_critical(self, build_dir_with_spdx: Path) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir_with_spdx),
                "--checks",
                "sbom-generation",
                "--fail-on",
                "critical",
            ],
        )
        # With valid SPDX, SBOM check should not have critical findings
        assert result.exit_code == 0

    def test_fail_on_low_exits_one_when_any_finding(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "low"]
        )
        assert result.exit_code == 1

    def test_fail_on_high_exits_one_when_critical_exists(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--fail-on", "high"]
        )
        assert result.exit_code == 1


class TestEvidenceFormat:
    """Tests for `shipcheck check --format evidence`."""

    def test_evidence_format_exits_zero(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--format", "evidence"]
        )
        assert result.exit_code == 0, result.output

    def test_evidence_format_emits_heading(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--format", "evidence"]
        )
        assert result.exit_code == 0, result.output
        assert "CRA Evidence Report" in result.output

    def test_evidence_format_emits_per_requirement_section(self, build_dir_empty: Path) -> None:
        # An empty build dir triggers failing findings from secure-boot and
        # image-signing, both of which carry cra_mapping ["I.P1.d", "I.P1.f"],
        # so the evidence pivot must surface at least one of those headings.
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--format", "evidence"]
        )
        assert result.exit_code == 0, result.output
        assert "I.P1.d" in result.output or "I.P1.f" in result.output

    def test_evidence_format_emits_gaps_section(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--format", "evidence"]
        )
        assert result.exit_code == 0, result.output
        assert "Gaps" in result.output


class TestCheckErrors:
    """Tests for error handling in check command."""

    def test_missing_build_dir_arg_without_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check"])
        assert result.exit_code != 0

    def test_invalid_format(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--format", "xml"]
        )
        assert result.exit_code != 0

    def test_unknown_check_id(self, build_dir_empty: Path) -> None:
        result = runner.invoke(
            app, ["check", "--build-dir", str(build_dir_empty), "--checks", "nonexistent"]
        )
        assert result.exit_code != 0


class TestInitCommand:
    """Tests for `shipcheck init`."""

    def test_init_creates_config_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        config_path = tmp_path / ".shipcheck.yaml"
        assert config_path.exists(), "Expected .shipcheck.yaml to be created"

    def test_init_scaffold_contains_all_config_sections(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "build_dir" in content
        assert "framework" in content
        assert "checks" in content
        assert "sbom" in content
        assert "cve" in content
        assert "report" in content

    def test_init_scaffold_is_commented(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        comment_lines = [line for line in content.splitlines() if line.startswith("#")]
        assert len(comment_lines) >= 5, "Scaffold should contain explanatory comments"

    def test_init_refuses_overwrite(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / ".shipcheck.yaml"
        existing.write_text("build_dir: ./build\n")
        original_content = existing.read_text()

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "already exists" in result.output
        assert existing.read_text() == original_content, "File content should not be modified"

    def test_init_prints_success_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"])
        assert ".shipcheck.yaml" in result.output

    def test_init_scaffold_contains_sbom_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "required_fields" in content
        assert "supplier" in content
        assert "checksum" in content

    def test_init_scaffold_contains_cve_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "suppress" in content

    def test_init_scaffold_contains_report_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "format" in content
        assert "output" in content
        assert "fail_on" in content

    def test_init_scaffold_contains_secure_boot_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "secure_boot" in content
        assert "known_test_keys" in content

    def test_init_scaffold_contains_image_signing_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "image_signing" in content
        assert "expect_fit" in content
        assert "expect_verity" in content

    def test_init_scaffold_checks_list_includes_new_check_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "secure-boot" in content
        assert "image-signing" in content

    def test_init_scaffold_lists_all_v03_check_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The scaffold's checks list must enumerate every registered check.

        Otherwise users initialising a fresh project miss out on
        license-audit, yocto-cve-check, and vuln-reporting because the
        scaffold predates them.
        """
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        for check_id in (
            "sbom-generation",
            "cve-tracking",
            "secure-boot",
            "image-signing",
            "license-audit",
            "yocto-cve-check",
            "vuln-reporting",
        ):
            assert check_id in content, f"scaffold missing check id {check_id!r}"

    def test_init_scaffold_contains_v03_config_sections(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All per-check config sections + product_config_path + history must be templated."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        for section in (
            "product_config_path",
            "license_audit",
            "yocto_cve",
            "history",
            "vuln_reporting",
        ):
            assert section in content, f"scaffold missing config section {section!r}"

    def test_init_scaffold_contains_v03_usage_examples(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Comment header should advertise the v0.3 CLI surface."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["init"])
        content = (tmp_path / ".shipcheck.yaml").read_text()
        assert "--format evidence" in content
        assert "--out" in content
        assert "shipcheck dossier" in content
        assert "shipcheck docs" in content
        assert "shipcheck doc declaration" in content


class TestBuildCheckConfig:
    """Tests for `_build_check_config()` mapping new check IDs."""

    def test_build_check_config_includes_secure_boot(self) -> None:
        from shipcheck.cli import _build_check_config
        from shipcheck.config import ShipcheckConfig

        config = ShipcheckConfig()
        result = _build_check_config(config)
        assert "secure-boot" in result

    def test_build_check_config_includes_image_signing(self) -> None:
        from shipcheck.cli import _build_check_config
        from shipcheck.config import ShipcheckConfig

        config = ShipcheckConfig()
        result = _build_check_config(config)
        assert "image-signing" in result

    def test_build_check_config_preserves_existing_checks(self) -> None:
        from shipcheck.cli import _build_check_config
        from shipcheck.config import ShipcheckConfig

        config = ShipcheckConfig()
        result = _build_check_config(config)
        assert "sbom-generation" in result
        assert "cve-tracking" in result


# ---------------------------------------------------------------------------
# Dossier multi-file emit (--out DIR) — task 10.3 (RED until 10.4 lands)
# ---------------------------------------------------------------------------


def _build_dossier_build_dir(tmp_path: Path) -> Path:
    """Create a minimal realistic build dir for --out dossier tests.

    Mirrors the layout used by `test_integration._setup_evidence_build_dir`
    so every evidence input is discoverable:
      - tmp/deploy/licenses/core-image-test/license.manifest (mixed licenses)
      - tmp/deploy/spdx/core-image-test.spdx.json (valid SPDX 2.3)
      - tmp/deploy/images/core-image-test/core-image-test-qemux86-64.spdx.json
      - tmp/log/cve/cve-summary.json (yocto cve-check summary)
      - product.yaml (complete product fixture)
    """
    build_dir = tmp_path / "build"
    build_dir.mkdir()

    licenses_src = FIXTURES_DIR / "licenses" / "core-image-minimal" / "license.manifest"
    sbom_src = FIXTURES_DIR / "sbom" / "valid-spdx-2.3.json"
    cve_src = FIXTURES_DIR / "yocto_cve" / "cve-summary-scarthgap.json"
    product_src = FIXTURES_DIR / "product" / "complete.yaml"

    for src in (licenses_src, sbom_src, cve_src, product_src):
        if not src.exists():
            pytest.skip(f"required fixture missing: {src}")

    licenses_dir = build_dir / "tmp" / "deploy" / "licenses" / "core-image-test"
    licenses_dir.mkdir(parents=True)
    shutil.copy(licenses_src, licenses_dir / "license.manifest")

    images_dir = build_dir / "tmp" / "deploy" / "images" / "core-image-test"
    images_dir.mkdir(parents=True)
    shutil.copy(
        sbom_src,
        images_dir / "core-image-test-qemux86-64.spdx.json",
    )
    spdx_dir = build_dir / "tmp" / "deploy" / "spdx"
    spdx_dir.mkdir(parents=True)
    shutil.copy(sbom_src, spdx_dir / "core-image-test.spdx.json")

    cve_dir = build_dir / "tmp" / "log" / "cve"
    cve_dir.mkdir(parents=True)
    shutil.copy(cve_src, cve_dir / "cve-summary.json")

    shutil.copy(product_src, build_dir / "product.yaml")

    return build_dir


def _write_dossier_config(build_dir: Path, *, include_product: bool = False) -> Path:
    """Write a minimal `.shipcheck.yaml` for the dossier tests.

    When ``include_product`` is true, ``product_config_path`` is set to the
    build dir's product.yaml so the CLI can discover product-identity data.
    Called after ``monkeypatch.chdir(tmp_path)`` so the config lands in cwd.
    """
    config_path = Path(".shipcheck.yaml")
    lines = [
        "history:",
        "  enabled: false",
    ]
    if include_product:
        lines.append(f"product_config_path: {build_dir}/product.yaml")
    config_path.write_text("\n".join(lines) + "\n")
    return config_path


class TestDossierOut:
    """Tests for `shipcheck check --format evidence --out DIR` dossier emit.

    These tests are RED until task 10.4 adds the `--out` Typer option to the
    `check` command. Today they fail at runtime with `No such option: --out`.
    """

    def test_dossier_out_creates_core_artifacts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(a) --out DIR writes at minimum evidence-report.md, cve-report.md, scan.json."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_dossier_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
                "--checks",
                "sbom-generation,cve-tracking,secure-boot,image-signing,yocto-cve-check",
            ],
        )

        assert result.exit_code == 0, result.output
        assert dossier_dir.is_dir(), f"expected dossier dir at {dossier_dir}"
        assert (dossier_dir / "evidence-report.md").exists()
        assert (dossier_dir / "cve-report.md").exists()
        assert (dossier_dir / "scan.json").exists()

    def test_dossier_out_writes_license_audit_when_enabled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(b) With `license-audit` enabled, also writes license-audit.md."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_dossier_config(build_dir)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
                "--checks",
                "sbom-generation,cve-tracking,license-audit",
            ],
        )

        assert result.exit_code == 0, result.output
        assert (dossier_dir / "license-audit.md").exists()

    def test_dossier_out_writes_product_paperwork_when_product_config_supplied(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(c) --product-config → technical-documentation.md + declaration-of-conformity.md."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_dossier_config(build_dir, include_product=True)
        dossier_dir = tmp_path / "dossier"

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
                "--product-config",
                str(build_dir / "product.yaml"),
            ],
        )

        assert result.exit_code == 0, result.output
        assert (dossier_dir / "technical-documentation.md").exists()
        assert (dossier_dir / "declaration-of-conformity.md").exists()

    def test_dossier_out_errors_when_path_is_a_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(d) --out points at an existing FILE → non-zero exit with clear error."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_dossier_config(build_dir)
        existing_file = tmp_path / "not-a-dir"
        existing_file.write_text("occupied\n")

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(existing_file),
            ],
        )

        assert result.exit_code != 0, result.output
        assert "not a directory" in result.output.lower()

    def test_dossier_out_creates_nonexistent_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(e) --out at a path that doesn't exist → create it and emit artifacts."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        _write_dossier_config(build_dir)
        dossier_dir = tmp_path / "deep" / "nested" / "dossier"
        assert not dossier_dir.exists()

        result = runner.invoke(
            app,
            [
                "check",
                "--build-dir",
                str(build_dir),
                "--format",
                "evidence",
                "--out",
                str(dossier_dir),
                "--checks",
                "sbom-generation,cve-tracking",
            ],
        )

        assert result.exit_code == 0, result.output
        assert dossier_dir.is_dir(), (
            f"expected shipcheck to create missing dossier path at {dossier_dir}"
        )
        assert (dossier_dir / "evidence-report.md").exists()


# ---------------------------------------------------------------------------
# Dossier subcommand (`shipcheck dossier`) — task 10.5
# ---------------------------------------------------------------------------


def _make_synthetic_report(
    *,
    timestamp: str = "2026-02-15T10:00:00Z",
    build_dir: str = "/srv/yocto/product-a",
    cve_findings: int = 1,
    license_findings: int = 0,
) -> object:
    """Build a minimal ReportData the history store can persist.

    Mirrors the seeder used by ``tests/test_history/test_dossier.py`` so the
    dossier CLI test exercises the same persistence contract without pulling
    in the full registry pipeline.
    """
    from shipcheck.models import CheckResult, CheckStatus, Finding, ReportData

    cve_check = CheckResult(
        check_id="cve-tracking",
        check_name="CVE tracking",
        status=CheckStatus.WARN if cve_findings else CheckStatus.PASS,
        score=50 - cve_findings,
        max_score=50,
        findings=[
            Finding(
                message=f"CVE-2026-{1000 + i} affecting openssl",
                severity="medium",
                cra_mapping=["I.P2.2", "I.P2.3"],
            )
            for i in range(cve_findings)
        ],
        summary=f"{cve_findings} unresolved CVEs",
        cra_mapping=["I.P2.2", "I.P2.3"],
    )
    license_check = CheckResult(
        check_id="license-audit",
        check_name="License audit",
        status=CheckStatus.WARN if license_findings else CheckStatus.PASS,
        score=50 - license_findings,
        max_score=50,
        findings=[
            Finding(
                message=f"unknown-license-package-{i}",
                severity="low",
                cra_mapping=["I.P2.1", "VII.2.b"],
            )
            for i in range(license_findings)
        ],
        summary=f"{license_findings} unknown licences",
        cra_mapping=["I.P2.1", "VII.2.b"],
    )
    return ReportData(
        checks=[cve_check, license_check],
        total_score=cve_check.score + license_check.score,
        max_total_score=100,
        framework="CRA",
        framework_version="2024/2847",
        bsi_tr_version="TR-03183-2 v2.1.0",
        build_dir=build_dir,
        timestamp=timestamp,
        shipcheck_version="0.3.0",
    )


class TestDossierCmd:
    """Tests for the `shipcheck dossier` subcommand (task 10.5)."""

    def test_dossier_cmd_empty_store_exits_zero_with_marker(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty history store exits 0 and surfaces 'no scans recorded'."""
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / ".shipcheck.yaml"
        config_path.write_text("history:\n  path: .shipcheck/history.db\n")

        result = runner.invoke(app, ["dossier"])

        assert result.exit_code == 0, result.output
        assert "no scans recorded" in result.output.lower()

    def test_dossier_cmd_with_seeded_store_renders_header(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A store seeded with one synthetic scan produces the dossier header."""
        from shipcheck.history.store import HistoryStore

        monkeypatch.chdir(tmp_path)
        history_path = tmp_path / ".shipcheck" / "history.db"
        config_path = tmp_path / ".shipcheck.yaml"
        config_path.write_text(f"history:\n  path: {history_path}\n")

        store = HistoryStore(history_path)
        store.persist(_make_synthetic_report())

        result = runner.invoke(app, ["dossier"])

        assert result.exit_code == 0, result.output
        assert "Compliance Dossier" in result.output

    def test_dossier_cmd_honors_history_disabled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`history.enabled: false` prints the disabled notice and exits 0."""
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / ".shipcheck.yaml"
        config_path.write_text("history:\n  enabled: false\n")

        result = runner.invoke(app, ["dossier"])

        assert result.exit_code == 0, result.output
        assert "history persistence disabled" in result.output.lower()

    def test_dossier_cmd_writes_to_out_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`--out FILE` writes the rendered dossier to disk instead of stdout."""
        from shipcheck.history.store import HistoryStore

        monkeypatch.chdir(tmp_path)
        history_path = tmp_path / ".shipcheck" / "history.db"
        config_path = tmp_path / ".shipcheck.yaml"
        config_path.write_text(f"history:\n  path: {history_path}\n")

        store = HistoryStore(history_path)
        store.persist(_make_synthetic_report())

        out_file = tmp_path / "dossier.md"
        result = runner.invoke(app, ["dossier", "--out", str(out_file)])

        assert result.exit_code == 0, result.output
        assert out_file.exists()
        assert "Compliance Dossier" in out_file.read_text()

    def test_dossier_cmd_honors_since_filter(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`--since DATE` filters out older scans; unmatched → 'no scans recorded'."""
        from shipcheck.history.store import HistoryStore

        monkeypatch.chdir(tmp_path)
        history_path = tmp_path / ".shipcheck" / "history.db"
        config_path = tmp_path / ".shipcheck.yaml"
        config_path.write_text(f"history:\n  path: {history_path}\n")

        store = HistoryStore(history_path)
        store.persist(_make_synthetic_report(timestamp="2026-01-01T00:00:00Z"))

        result = runner.invoke(app, ["dossier", "--since", "2027-01-01"])

        assert result.exit_code == 0, result.output
        assert "no scans recorded" in result.output.lower()


# ---------------------------------------------------------------------------
# docs subcommand (`shipcheck docs`) - task 10.6
# ---------------------------------------------------------------------------


class TestDocsCmd:
    """Tests for the `shipcheck docs` subcommand (task 10.6).

    The `docs` subcommand runs the enabled checks against ``--build-dir`` to
    build a ``ReportData`` (reusing the same code path as ``shipcheck check``),
    loads ``--product-config``, then calls ``generate_annex_vii`` to write the
    Annex VII technical documentation draft to ``--out``.
    """

    def test_docs_cmd_writes_annex_vii_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`docs` exits 0, writes the file, and emits a DRAFT banner."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        product_yaml = FIXTURES_DIR / "product" / "complete.yaml"
        out_path = tmp_path / "tech.md"

        result = runner.invoke(
            app,
            [
                "docs",
                "--build-dir",
                str(build_dir),
                "--product-config",
                str(product_yaml),
                "--out",
                str(out_path),
            ],
        )

        assert result.exit_code == 0, result.output
        assert out_path.exists(), f"expected {out_path} to be written"
        content = out_path.read_text()
        # The generator injects a "DRAFT - FOR MANUFACTURER REVIEW" banner at
        # the top of the file; first few lines must include the DRAFT marker.
        head = "\n".join(content.splitlines()[:5])
        assert "DRAFT" in head, f"expected DRAFT banner near top, got:\n{head}"

    def test_docs_cmd_missing_product_config_errors(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing `--product-config` file exits non-zero with descriptive error."""
        build_dir = _build_dossier_build_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        missing_product = tmp_path / "does-not-exist.yaml"
        out_path = tmp_path / "tech.md"

        result = runner.invoke(
            app,
            [
                "docs",
                "--build-dir",
                str(build_dir),
                "--product-config",
                str(missing_product),
                "--out",
                str(out_path),
            ],
        )

        assert result.exit_code != 0, result.output
        assert not out_path.exists(), "expected no output file on error"
        # Error message must name the missing file so users can act on it.
        assert "product" in result.output.lower() or str(missing_product) in result.output


# ---------------------------------------------------------------------------
# doc declaration subcommand (`shipcheck doc declaration`) - task 10.7
# ---------------------------------------------------------------------------


# The eight Annex V section titles mandated by Regulation (EU) 2024/2847.
# Mirrors the contract asserted in tests/test_docs_generator/test_declaration.py
# so the CLI-level test and the generator-level test stay in lock-step.
_ANNEX_V_FIELDS: tuple[str, ...] = (
    "product identification",
    "manufacturer identification",
    "sole-responsibility statement",
    "object of declaration",
    "conformity statement",
    "harmonised standards",
    "notified body",
    "additional information",
)

# The fixed Annex VI one-sentence declaration. The generator substitutes
# [manufacturer] and [type] from product.yaml, so the CLI test asserts on
# the invariant prefix/suffix segments of the sentence.
_ANNEX_VI_PREFIX = "Hereby,"
_ANNEX_VI_SUFFIX = "is in compliance with Regulation (EU) 2024/2847"


class TestDocDeclarationCmd:
    """Tests for the `shipcheck doc declaration` nested subcommand (task 10.7)."""

    def test_doc_declaration_writes_annex_v_full_form(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Full form: exits 0, writes file with all 8 Annex V section markers."""
        monkeypatch.chdir(tmp_path)
        product_yaml = FIXTURES_DIR / "product" / "complete.yaml"
        out_path = tmp_path / "dec.md"

        result = runner.invoke(
            app,
            [
                "doc",
                "declaration",
                "--product-config",
                str(product_yaml),
                "--out",
                str(out_path),
            ],
        )

        assert result.exit_code == 0, result.output
        assert out_path.exists(), f"expected {out_path} to be written"
        content = out_path.read_text().lower()
        for field in _ANNEX_V_FIELDS:
            assert field in content, f"expected Annex V section '{field}' in output"

    def test_doc_declaration_simplified_emits_annex_vi_sentence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simplified form: exits 0, output contains the fixed Annex VI sentence."""
        monkeypatch.chdir(tmp_path)
        product_yaml = FIXTURES_DIR / "product" / "complete.yaml"
        out_path = tmp_path / "dec.md"

        result = runner.invoke(
            app,
            [
                "doc",
                "declaration",
                "--product-config",
                str(product_yaml),
                "--out",
                str(out_path),
                "--simplified",
            ],
        )

        assert result.exit_code == 0, result.output
        assert out_path.exists(), f"expected {out_path} to be written"
        content = out_path.read_text()
        assert _ANNEX_VI_PREFIX in content, f"expected '{_ANNEX_VI_PREFIX}' in simplified output"
        assert _ANNEX_VI_SUFFIX in content, f"expected '{_ANNEX_VI_SUFFIX}' in simplified output"


class TestHistoryPersist:
    """Tests for `shipcheck check` persisting scan rows to the history store.

    Task 10.8 of devspec change ``shipcheck-v03-cra-evidence``. Every
    successful scan writes one row to ``.shipcheck/history.db`` so
    ``shipcheck dossier`` can prove sustained compliance activity per
    CRA Annex I Part II §3. Tests use ``-k history_persist`` selection.
    """

    def test_history_persist_writes_row_after_check(
        self,
        build_dir_with_spdx: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After `shipcheck check`, a scan row exists in .shipcheck/history.db."""
        import sqlite3

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0, result.output

        db_path = tmp_path / ".shipcheck" / "history.db"
        assert db_path.exists(), f"expected history DB at {db_path}"

        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM scans")
            (row_count,) = cursor.fetchone()
        finally:
            conn.close()

        assert row_count == 1, f"expected exactly one scan row, got {row_count}"

    def test_history_persist_disabled_does_not_create_db(
        self,
        build_dir_with_spdx: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With `history.enabled: false`, no DB file is created."""
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / ".shipcheck.yaml"
        config_path.write_text("history:\n  enabled: false\n")

        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])
        assert result.exit_code == 0, result.output

        db_path = tmp_path / ".shipcheck" / "history.db"
        assert not db_path.exists(), (
            f"expected no history DB when history.enabled=false, found {db_path}"
        )


# ---------------------------------------------------------------------------
# CRA mapping validation in `check` pipeline — task 10.9
# ---------------------------------------------------------------------------


class TestCraValidation:
    """Tests for `shipcheck check` invoking `validate_cra_mappings(report)`.

    Task 10.9 of devspec change ``shipcheck-v03-cra-evidence``. An invalid
    CRA mapping ID emitted by any check must cause the command to exit
    non-zero with a dedicated error exit code (distinct from ``--fail-on``'s
    exit code 1) so operators can tell the two failure modes apart.
    Tests use ``-k cra_validation`` selection.
    """

    def test_cra_validation_rejects_invalid_mapping_id(
        self,
        build_dir_with_spdx: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A check emitting `cra_mapping=["BOGUS.X.1"]` → non-zero exit,
        error message names the invalid ID.
        """
        from shipcheck.checks.registry import CheckRegistry
        from shipcheck.models import (
            BaseCheck,
            CheckResult,
            CheckStatus,
            Finding,
        )

        class _BogusCheck(BaseCheck):
            id = "bogus-mapping"
            name = "Bogus Mapping"
            framework = ["CRA"]
            severity = "low"

            def run(self, build_dir, config):  # type: ignore[override]
                return CheckResult(
                    check_id=self.id,
                    check_name=self.name,
                    status=CheckStatus.WARN,
                    score=0,
                    max_score=1,
                    findings=[
                        Finding(
                            message="synthetic bogus finding",
                            severity="low",
                            cra_mapping=["BOGUS.X.1"],
                        )
                    ],
                    summary="bogus",
                )

        def _stub_registry() -> CheckRegistry:
            registry = CheckRegistry()
            registry.register(_BogusCheck())
            return registry

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("shipcheck.cli.get_default_registry", _stub_registry)

        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])

        assert result.exit_code != 0, result.output
        # Validation failure must NOT collide with --fail-on exit code (1).
        assert result.exit_code != 1, (
            f"expected distinct exit code from --fail-on's 1, got {result.exit_code}"
        )
        combined = result.output + (result.stderr if result.stderr_bytes else "")
        assert "BOGUS.X.1" in combined, (
            f"expected invalid ID 'BOGUS.X.1' in output, got:\n{combined}"
        )

    def test_cra_validation_silent_on_valid_mappings(
        self,
        build_dir_with_spdx: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Normal `check` run with valid mappings: no validation error printed,
        exits 0 (no --fail-on threshold set).
        """
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["check", "--build-dir", str(build_dir_with_spdx)])

        assert result.exit_code == 0, result.output
        assert "unknown CRA requirement id" not in result.output
