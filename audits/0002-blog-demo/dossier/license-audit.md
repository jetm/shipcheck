# shipcheck Compliance Report

**Version:** 0.0.3
**Build directory:** tests/fixtures/pilot_real/build
**Timestamp:** 2026-04-24T20:31:38.915962+00:00
**Framework:** CRA (2024/2847)
**BSI TR:** TR-03183-2 v2.1.0

## Check Results

### License Audit

| Field | Value |
|-------|-------|
| Status | **WARN** |
| Score | 25/50 |
| Summary | 37 package(s) in core-image-minimal-qemux86-64.rootfs-20260417211226/license.manifest; permissive: 9; weak-copyleft: 2; strong-copyleft: 21; unknown: 5 |

#### Findings

- **[medium]** Unknown licence for package 'busybox': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'busybox-hwclock': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'busybox-syslog': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'busybox-udhcpc': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'liblzma': 'PD' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.## Readiness Score

**106/350**
