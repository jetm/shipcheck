# Annex VII - Technical Documentation

> **DRAFT - FOR MANUFACTURER REVIEW**
>
> This document is an auto-generated draft produced by shipcheck from scan
> evidence and the supplied `product.yaml`. It is **not** a finished
> technical file. The manufacturer is responsible for reviewing every
> section, filling in any `[TO BE FILLED BY MANUFACTURER: <field>]`
> placeholders, and obtaining legal and engineering sign-off before the
> document is filed as the Annex VII technical documentation required by
> Regulation (EU) 2024/2847.

**Product:** VENDOR
**Type:** VENDOR
**Version:** VENDOR
**Manufacturer:** VENDOR
**Generated:** 2026-04-24T20:31:38.915962+00:00
**Shipcheck version:** 0.0.3
**Regulation:** CRA 2024/2847

---

## Item 1 - General product description

> a general description of the product with digital elements, including:
(a) its intended purpose;
(b) versions of software affecting compliance with essential cybersecurity requirements;
(c) where the product with digital elements is a hardware product, photographs or illustrations showing external features, marking and internal layout;
(d) user information and instructions as set out in Annex II;

**Product name:** VENDOR

**Product type:** VENDOR

**Product version:** VENDOR

**Intended purpose:** [TO BE FILLED BY MANUFACTURER: intended purpose and
essential functionalities of the product]

**Manufacturer:**

- Name: VENDOR
- Address: VENDOR
- Contact: VENDOR

**Photographs, drawings, schematics:** [TO BE FILLED BY MANUFACTURER:
photographs, drawings or schematics illustrating the product]

---

## Item 2 - Design, development, production and vulnerability handling

> a description of the design, development and production of the product with digital elements and vulnerability handling processes, including:
(a) necessary information on the design and development of the product with digital elements, including, where applicable, drawings and schemes and a description of the system architecture explaining how software components build on or feed into each other and integrate into the overall processing;
(b) necessary information and specifications of the vulnerability handling processes put in place by the manufacturer, including the software bill of materials, the coordinated vulnerability disclosure policy, evidence of the provision of a contact address for the reporting of the vulnerabilities and a description of the technical solutions chosen for the secure distribution of updates;
(c) necessary information and specifications of the production and monitoring processes of the product with digital elements and the validation of those processes;

### Software Bill of Materials (SBOM)

The following SBOM-related evidence was collected during the most recent
shipcheck scan. Findings are drawn from checks whose `cra_mapping`
includes `I.P2.1` (Annex I Part II §1 SBOM requirement) or `VII.2`
(Annex VII §2 design, development and vulnerability handling).

| check | finding title | severity | cra_mapping | timestamp |
|-------|---------------|----------|-------------|-----------|
| license-audit | Unknown licence for package 'busybox': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map | medium | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| license-audit | Unknown licence for package 'busybox-hwclock': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map | medium | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| license-audit | Unknown licence for package 'busybox-syslog': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map | medium | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| license-audit | Unknown licence for package 'busybox-udhcpc': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map | medium | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| license-audit | Unknown licence for package 'liblzma': 'PD' not in canonical category map | medium | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata': missing or invalid checksum | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata-source-1': missing or invalid licenseDeclared | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata-source-1': missing or invalid supplier | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata-source-1': missing or invalid versionInfo | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata-source-2': missing or invalid licenseDeclared | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata-source-2': missing or invalid supplier | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |
| sbom-generation | Package 'tzdata-source-2': missing or invalid versionInfo | low | I.P2.1, VII.2 | 2026-04-24T20:31:38.915962+00:00 |

### Vulnerability handling processes

[TO BE FILLED BY MANUFACTURER: describe the vulnerability handling
processes used during the design, development and production phases,
including the coordinated vulnerability disclosure policy and the
contact address below.]

- **CVD policy URL:** VENDOR
- **CVD contact:** VENDOR
- **Update distribution mechanism:** VENDOR

---

## Item 3 - Cybersecurity risk assessment

> an assessment of the cybersecurity risks against which the product with digital elements is designed, developed, produced, delivered and maintained pursuant to Article 13, including how the essential cybersecurity requirements set out in Part I of Annex I are applicable;

The cybersecurity risk assessment maps every Annex I Part I essential
requirement to the evidence collected by shipcheck. Requirements with no
mapped finding must be addressed in the manufacturer narrative below.

### I.P1.a - No known exploitable vulnerabilities

> be made available on the market without known exploitable vulnerabilities;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.b - Secure by default configuration

> be made available on the market with a secure by default configuration, unless otherwise agreed between manufacturer and business user in relation to a tailor-made product with digital elements, including the possibility to reset the product to its original state;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.c - Security updates

> ensure that vulnerabilities can be addressed through security updates, including, where applicable, through automatic security updates that are installed within an appropriate timeframe enabled as a default setting, with a clear and easy-to-use opt-out mechanism, through the notification of available updates to users, and the option to temporarily postpone them;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.d - Protection from unauthorised access

> ensure protection from unauthorised access by appropriate control mechanisms, including but not limited to authentication, identity or access management systems, and report on possible unauthorised access;

Mapped findings:

- **[medium]** (secure-boot) No Secure Boot signing class found in IMAGE_CLASSES

### I.P1.e - Confidentiality of data

> protect the confidentiality of stored, transmitted or otherwise processed data, personal or other, such as by encrypting relevant data at rest or in transit by state of the art mechanisms, and by using other technical means;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.f - Integrity of data

> protect the integrity of stored, transmitted or otherwise processed data, personal or other, commands, programs and configuration against any manipulation or modification not authorised by the user, and report on corruptions;

Mapped findings:

- **[medium]** (image-signing) No FIT image files (.itb, .fit) found in deploy directory
- **[medium]** (image-signing) No dm-verity configuration or hash files found
- **[medium]** (secure-boot) No Secure Boot signing class found in IMAGE_CLASSES

### I.P1.g - Data minimisation

> process only data, personal or other, that are adequate, relevant and limited to what is necessary in relation to the intended purpose of the product with digital elements (data minimisation);

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.h - Availability of essential functions

> protect the availability of essential and basic functions, also after an incident, including through resilience and mitigation measures against denial-of-service attacks;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.i - Minimise impact on other devices/networks

> minimise the negative impact by the products themselves or connected devices on the availability of services provided by other devices or networks;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.j - Limit attack surfaces

> be designed, developed and produced to limit attack surfaces, including external interfaces;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.k - Reduce incident impact

> be designed, developed and produced to reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques;

Mapped findings:

- **[medium]** (image-signing) No dm-verity configuration or hash files found

### I.P1.l - Security logging and monitoring

> provide security related information by recording and monitoring relevant internal activity, including the access to or modification of data, services or functions, with an opt-out mechanism for the user;

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_

### I.P1.m - Secure data and settings removal

> provide the possibility for users to securely and easily remove on a permanent basis all data and settings and, where such data can be transferred to other products or systems, ensure that this is done in a secure manner.

_N/A - no mapped findings. [TO BE FILLED BY MANUFACTURER: describe how
this requirement is addressed for VENDOR.]_


---

## Item 4 - Support period determination

> relevant information that was taken into account to determine the support period pursuant to Article 13(8) of the product with digital elements;

**Declared support period end date:** VENDOR

**Rationale:** [TO BE FILLED BY MANUFACTURER: relevant information taken
into account to determine the support period pursuant to Article 13(8),
including expected product lifetime, user expectations, nature of the
digital elements, and any applicable legal or regulatory constraints.]

---

## Item 5 - Harmonised standards and specifications applied

> a list of the harmonised standards applied in full or in part the references of which have been published in the Official Journal of the European Union, common specifications as set out in Article 27 of this Regulation or European cybersecurity certification schemes adopted pursuant to Regulation (EU) 2019/881 pursuant to Article 27(8) of this Regulation, and, where those harmonised standards, common specifications or European cybersecurity certification schemes have not been applied, descriptions of the solutions adopted to meet the essential cybersecurity requirements set out in Parts I and II of Annex I, including a list of other relevant technical specifications applied. In the event of partly applied harmonised standards, common specifications or European cybersecurity certification schemes, the technical documentation shall specify the parts which have been applied;

_N/A - harmonised standards under Regulation (EU) 2024/2847 are pending
publication (EU Commission mandate M/596). [TO BE FILLED BY
MANUFACTURER: list applicable harmonised standards, common
specifications or cybersecurity certification schemes applied once
published.]_

---

## Item 6 - Conformity test reports

> reports of the tests carried out to verify the conformity of the product with digital elements and of the vulnerability handling processes with the applicable essential cybersecurity requirements as set out in Parts I and II of Annex I;

The following shipcheck checks were executed against the build directory
and contribute evidence of conformity testing:

| Check | Status | Score | Findings | CRA mapping |
|-------|--------|-------|----------|-------------|
| CVE Tracking (cve-tracking) | fail | 23/50 | 5 | I.P2.2, I.P2.3 |
| Image Signing (image-signing) | warn | 0/50 | 2 | I.P1.f |
| License Audit (license-audit) | warn | 25/50 | 5 | I.P2.1, VII.2 |
| SBOM Generation (sbom-generation) | warn | 20/50 | 7 | I.P2.1, VII.2 |
| Secure Boot (secure-boot) | warn | 5/50 | 1 | I.P1.d, I.P1.f |
| Vulnerability Reporting (vuln-reporting) | fail | 10/50 | 4 | I.P2.5, II.2, II.7, I.P2.7 |
| Yocto CVE Check (yocto-cve-check) | fail | 23/50 | 0 | I.P2.2, I.P2.3 |

[TO BE FILLED BY MANUFACTURER: include reports of any additional tests
performed outside shipcheck, such as penetration testing, static
analysis, fuzzing, or third-party audits.]

---

## Item 7 - Copy of EU declaration of conformity

> a copy of the EU declaration of conformity;

_N/A - the EU Declaration of Conformity is generated separately via
`shipcheck doc declaration`. [TO BE FILLED BY MANUFACTURER: attach a
copy of the signed EU declaration of conformity drawn up in accordance
with Annex V.]_

---

## Item 8 - SBOM on market surveillance request

> where applicable, the software bill of materials, further to a reasoned request from a market surveillance authority provided that it is necessary in order for that authority to be able to check compliance with the essential cybersecurity requirements set out in Annex I.

The machine-readable Software Bill of Materials referenced in Item 2 is
made available on request from a market surveillance authority. See the
SBOM evidence table above for the findings collected from the current
scan.

[TO BE FILLED BY MANUFACTURER: confirm the SBOM distribution channel
used to respond to reasoned market surveillance requests.]
