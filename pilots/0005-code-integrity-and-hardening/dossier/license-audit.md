# shipcheck Compliance Report

**Version:** 0.0.4
**Build directory:** pilots/0005-code-integrity-and-hardening/build
**Timestamp:** 2026-04-29T22:51:06.365412+00:00
**Framework:** CRA (2024/2847)
**BSI TR:** TR-03183-2 v2.1.0

## Check Results

### License Audit

| Field | Value |
|-------|-------|
| Status | **WARN** |
| Score | 15/50 |
| Summary | 38 package(s) in core-image-minimal-qemuarm64.rootfs-20260429222712/license.manifest; permissive: 10; weak-copyleft: 3; strong-copyleft: 18; unknown: 7 |

#### Findings

- **[medium]** Unknown licence for package 'busybox': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'busybox-hwclock': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'busybox-syslog': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'busybox-udhcpc': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'ima-evm-utils': 'GPL-2.0-with-OpenSSL-exception' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'liblzma': 'PD' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.- **[medium]** Unknown licence for package 'util-linux-blkid': 'GPL-1.0-or-later & GPL-2.0-or-later & LGPL-2.1-or-later & BSD-2-Clause & BSD-3-Clause & BSD-4-Clause & MIT' not in canonical category map  - Remediation: Add the licence ID to `src/shipcheck/checks/license_categories.yaml` under the correct category, or correct the package's LICENSE field.## Readiness Score

**35/250**
