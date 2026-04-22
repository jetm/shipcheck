# CRA Evidence Report

**Version:** 0.0.3
**Build directory:** tests/fixtures/pilot_real/build
**Timestamp:** 2026-04-23T22:29:42.865524+00:00
**Framework:** CRA (2024/2847)

## I.P1.d - Protection from unauthorised access

**Annex I, Part 1, item d**

> ensure protection from unauthorised access by appropriate control mechanisms, including but not limited to authentication, identity or access management systems, and report on possible unauthorised access;

- **[medium]** (secure-boot) No Secure Boot signing class found in IMAGE_CLASSES

## I.P1.f - Integrity of data

**Annex I, Part 1, item f**

> protect the integrity of stored, transmitted or otherwise processed data, personal or other, commands, programs and configuration against any manipulation or modification not authorised by the user, and report on corruptions;

- **[medium]** (image-signing) No FIT image files (.itb, .fit) found in deploy directory
- **[medium]** (image-signing) No dm-verity configuration or hash files found
- **[medium]** (secure-boot) No Secure Boot signing class found in IMAGE_CLASSES

## I.P1.k - Reduce incident impact

**Annex I, Part 1, item k**

> be designed, developed and produced to reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques;

- **[medium]** (image-signing) No dm-verity configuration or hash files found

## I.P2.1 - Identify and document vulnerabilities and components (SBOM)

**Annex I, Part 2, item 1**

> identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products;

- **[medium]** (license-audit) Unknown licence for package 'busybox': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'busybox-hwclock': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'busybox-syslog': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'busybox-udhcpc': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'liblzma': 'PD' not in canonical category map
- **[low]** (sbom-generation) Package 'tzdata': missing or invalid checksum
- **[low]** (sbom-generation) Package 'tzdata-source-1': missing or invalid licenseDeclared
- **[low]** (sbom-generation) Package 'tzdata-source-1': missing or invalid supplier
- **[low]** (sbom-generation) Package 'tzdata-source-1': missing or invalid versionInfo
- **[low]** (sbom-generation) Package 'tzdata-source-2': missing or invalid licenseDeclared
- **[low]** (sbom-generation) Package 'tzdata-source-2': missing or invalid supplier
- **[low]** (sbom-generation) Package 'tzdata-source-2': missing or invalid versionInfo

## I.P2.2 - Address and remediate vulnerabilities without delay

**Annex I, Part 2, item 2**

> in relation to the risks posed to products with digital elements, address and remediate vulnerabilities without delay, including by providing security updates; where technically feasible, new security updates shall be provided separately from functionality updates;

- **[low]** (cve-tracking) CVE-1999-0524: ICMP information such as (1) netmask and (2) timestamp is allowed from arbitrary hosts.
- **[high]** (cve-tracking) CVE-2008-4609: The TCP implementation in (1) Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4) Cisco products, and probably other operating systems allows remote attackers to cause a denial of service (connection queue exhaustion) via multiple vectors that manipulate information in the TCP state table, as demonstrated by sockstress.
- **[medium]** (cve-tracking) CVE-2010-4563: The Linux kernel, when using IPv6, allows remote attackers to determine whether a host is sniffing the network by sending an ICMPv6 Echo Request to a multicast address and determining whether an Echo Reply is sent, as demonstrated by thcping.
- **[medium]** (cve-tracking) CVE-2010-4756: The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.
- **[medium]** (cve-tracking) CVE-2026-1965: libcurl can in some circumstances reuse the wrong connection when asked to do
an Negotiate-authenticated HTTP or HTTPS request.

libcurl features a pool of recent connections so that subsequent requests can
reuse an existing connection to avoid overhead.

When reusing a connection a range of criterion must first be met. Due to a
logical error in the code, a request that was issued by an application could
wrongfully reuse an existing connection to the same server that was
authenticated using different credentials. One underlying reason being that
Negotiate sometimes authenticates *connections* and not *requests*, contrary
to how HTTP is designed to work.

An application that allows Negotiate authentication to a server (that responds
wanting Negotiate) with `user1:password1` and then does another operation to
the same server also using Negotiate but with `user2:password2` (while the
previous connection is still alive) - the second request wrongly reused the
same connection and since it then sees that the Negotiate negotiation is
already made, it just sends the request over that connection thinking it uses
the user2 credentials when it is in fact still using the connection
authenticated for user1...

The set of authentication methods to use is set with  `CURLOPT_HTTPAUTH`.

Applications can disable libcurl's reuse of connections and thus mitigate this
problem, by using one of the following libcurl options to alter how
connections are or are not reused: `CURLOPT_FRESH_CONNECT`,
`CURLOPT_MAXCONNECTS` and `CURLMOPT_MAX_HOST_CONNECTIONS` (if using the
curl_multi API).
- **[medium]** (cve-tracking) CVE-2026-3783: When an OAuth2 bearer token is used for an HTTP(S) transfer, and that transfer
performs a redirect to a second URL, curl could leak that token to the second
hostname under some circumstances.

If the hostname that the first request is redirected to has information in the
used .netrc file, with either of the `machine` or `default` keywords, curl
would pass on the bearer token set for the first host also to the second one.
- **[medium]** (cve-tracking) CVE-2026-3784: curl would wrongly reuse an existing HTTP proxy connection doing CONNECT to a
server, even if the new request uses different credentials for the HTTP proxy.
The proper behavior is to create or use a separate connection.
- **[high]** (cve-tracking) CVE-2026-4046: The iconv() function in the GNU C Library versions 2.43 and earlier may crash due to an assertion failure when converting inputs from the IBM1390 or IBM1399 character sets, which may be used to remotely crash an application.



This vulnerability can be trivially mitigated by removing the IBM1390 and IBM1399 character sets from systems that do not need them.
- **[high]** (cve-tracking) CVE-2026-4437: Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies the library's DNS backend in the GNU C Library version 2.34 to version 2.43 could, with a crafted response from the configured DNS server, result in a violation of the DNS specification that causes the application to treat a non-answer section of the DNS response as a valid answer.

## I.P2.3 - Regular security tests and reviews

**Annex I, Part 2, item 3**

> apply effective and regular tests and reviews of the security of the product with digital elements;

- **[low]** (cve-tracking) CVE-1999-0524: ICMP information such as (1) netmask and (2) timestamp is allowed from arbitrary hosts.
- **[high]** (cve-tracking) CVE-2008-4609: The TCP implementation in (1) Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4) Cisco products, and probably other operating systems allows remote attackers to cause a denial of service (connection queue exhaustion) via multiple vectors that manipulate information in the TCP state table, as demonstrated by sockstress.
- **[medium]** (cve-tracking) CVE-2010-4563: The Linux kernel, when using IPv6, allows remote attackers to determine whether a host is sniffing the network by sending an ICMPv6 Echo Request to a multicast address and determining whether an Echo Reply is sent, as demonstrated by thcping.
- **[medium]** (cve-tracking) CVE-2010-4756: The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.
- **[medium]** (cve-tracking) CVE-2026-1965: libcurl can in some circumstances reuse the wrong connection when asked to do
an Negotiate-authenticated HTTP or HTTPS request.

libcurl features a pool of recent connections so that subsequent requests can
reuse an existing connection to avoid overhead.

When reusing a connection a range of criterion must first be met. Due to a
logical error in the code, a request that was issued by an application could
wrongfully reuse an existing connection to the same server that was
authenticated using different credentials. One underlying reason being that
Negotiate sometimes authenticates *connections* and not *requests*, contrary
to how HTTP is designed to work.

An application that allows Negotiate authentication to a server (that responds
wanting Negotiate) with `user1:password1` and then does another operation to
the same server also using Negotiate but with `user2:password2` (while the
previous connection is still alive) - the second request wrongly reused the
same connection and since it then sees that the Negotiate negotiation is
already made, it just sends the request over that connection thinking it uses
the user2 credentials when it is in fact still using the connection
authenticated for user1...

The set of authentication methods to use is set with  `CURLOPT_HTTPAUTH`.

Applications can disable libcurl's reuse of connections and thus mitigate this
problem, by using one of the following libcurl options to alter how
connections are or are not reused: `CURLOPT_FRESH_CONNECT`,
`CURLOPT_MAXCONNECTS` and `CURLMOPT_MAX_HOST_CONNECTIONS` (if using the
curl_multi API).
- **[medium]** (cve-tracking) CVE-2026-3783: When an OAuth2 bearer token is used for an HTTP(S) transfer, and that transfer
performs a redirect to a second URL, curl could leak that token to the second
hostname under some circumstances.

If the hostname that the first request is redirected to has information in the
used .netrc file, with either of the `machine` or `default` keywords, curl
would pass on the bearer token set for the first host also to the second one.
- **[medium]** (cve-tracking) CVE-2026-3784: curl would wrongly reuse an existing HTTP proxy connection doing CONNECT to a
server, even if the new request uses different credentials for the HTTP proxy.
The proper behavior is to create or use a separate connection.
- **[high]** (cve-tracking) CVE-2026-4046: The iconv() function in the GNU C Library versions 2.43 and earlier may crash due to an assertion failure when converting inputs from the IBM1390 or IBM1399 character sets, which may be used to remotely crash an application.



This vulnerability can be trivially mitigated by removing the IBM1390 and IBM1399 character sets from systems that do not need them.
- **[high]** (cve-tracking) CVE-2026-4437: Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies the library's DNS backend in the GNU C Library version 2.34 to version 2.43 could, with a crafted response from the configured DNS server, result in a violation of the DNS specification that causes the application to treat a non-answer section of the DNS response as a valid answer.

## I.P2.5 - Coordinated vulnerability disclosure policy

**Annex I, Part 2, item 5**

> put in place and enforce a policy on coordinated vulnerability disclosure;

- **[high]** (vuln-reporting) product.yaml cvd.policy_url is a placeholder token 'VENDOR' (Annex I Part II §5): a real coordinated vulnerability disclosure policy URL must be declared

## I.P2.7 - Secure update distribution mechanisms

**Annex I, Part 2, item 7**

> provide for mechanisms to securely distribute updates for products with digital elements to ensure that vulnerabilities are fixed or mitigated in a timely manner and, where applicable for security updates, in an automatic manner;

- **[medium]** (vuln-reporting) product.yaml update_distribution.mechanism is a placeholder token 'VENDOR' (Annex I Part II §7): a real secure update distribution mechanism must be declared

## II.2 - Single point of contact for vulnerability reporting

**Annex II, item 2**

> the single point of contact where information about vulnerabilities of the product with digital elements can be reported and received, and where the manufacturer's policy on coordinated vulnerability disclosure can be found;

- **[high]** (vuln-reporting) product.yaml cvd.contact is a placeholder token 'VENDOR' (Annex II §2): a real single point of contact for vulnerability reports is required

## II.7 - Technical security support and support period end-date

**Annex II, item 7**

> the type of technical security support offered by the manufacturer and the end-date of the support period during which users can expect vulnerabilities to be handled and to receive security updates;

- **[high]** (vuln-reporting) product.yaml support_period.end_date is a placeholder token 'VENDOR' (Annex II §7): a real ISO 8601 YYYY-MM-DD support period end date must be declared

## VII.2 - Design, development, production and vulnerability handling

**Annex VII, item 2**

> a description of the design, development and production of the product with digital elements and vulnerability handling processes, including:
(a) necessary information on the design and development of the product with digital elements, including, where applicable, drawings and schemes and a description of the system architecture explaining how software components build on or feed into each other and integrate into the overall processing;
(b) necessary information and specifications of the vulnerability handling processes put in place by the manufacturer, including the software bill of materials, the coordinated vulnerability disclosure policy, evidence of the provision of a contact address for the reporting of the vulnerabilities and a description of the technical solutions chosen for the secure distribution of updates;
(c) necessary information and specifications of the production and monitoring processes of the product with digital elements and the validation of those processes;

- **[medium]** (license-audit) Unknown licence for package 'busybox': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'busybox-hwclock': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'busybox-syslog': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'busybox-udhcpc': 'GPL-2.0-only & bzip2-1.0.4' not in canonical category map
- **[medium]** (license-audit) Unknown licence for package 'liblzma': 'PD' not in canonical category map
- **[low]** (sbom-generation) Package 'tzdata': missing or invalid checksum
- **[low]** (sbom-generation) Package 'tzdata-source-1': missing or invalid licenseDeclared
- **[low]** (sbom-generation) Package 'tzdata-source-1': missing or invalid supplier
- **[low]** (sbom-generation) Package 'tzdata-source-1': missing or invalid versionInfo
- **[low]** (sbom-generation) Package 'tzdata-source-2': missing or invalid licenseDeclared
- **[low]** (sbom-generation) Package 'tzdata-source-2': missing or invalid supplier
- **[low]** (sbom-generation) Package 'tzdata-source-2': missing or invalid versionInfo

## Gaps

The following CRA requirements have no mapped evidence in this scan:

### I.P1.a - No known exploitable vulnerabilities

**Annex I, Part 1, item a**

> be made available on the market without known exploitable vulnerabilities;

_Status: no evidence_

### I.P1.b - Secure by default configuration

**Annex I, Part 1, item b**

> be made available on the market with a secure by default configuration, unless otherwise agreed between manufacturer and business user in relation to a tailor-made product with digital elements, including the possibility to reset the product to its original state;

_Status: no evidence_

### I.P1.c - Security updates

**Annex I, Part 1, item c**

> ensure that vulnerabilities can be addressed through security updates, including, where applicable, through automatic security updates that are installed within an appropriate timeframe enabled as a default setting, with a clear and easy-to-use opt-out mechanism, through the notification of available updates to users, and the option to temporarily postpone them;

_Status: no evidence_

### I.P1.e - Confidentiality of data

**Annex I, Part 1, item e**

> protect the confidentiality of stored, transmitted or otherwise processed data, personal or other, such as by encrypting relevant data at rest or in transit by state of the art mechanisms, and by using other technical means;

_Status: no evidence_

### I.P1.g - Data minimisation

**Annex I, Part 1, item g**

> process only data, personal or other, that are adequate, relevant and limited to what is necessary in relation to the intended purpose of the product with digital elements (data minimisation);

_Status: no evidence_

### I.P1.h - Availability of essential functions

**Annex I, Part 1, item h**

> protect the availability of essential and basic functions, also after an incident, including through resilience and mitigation measures against denial-of-service attacks;

_Status: no evidence_

### I.P1.i - Minimise impact on other devices/networks

**Annex I, Part 1, item i**

> minimise the negative impact by the products themselves or connected devices on the availability of services provided by other devices or networks;

_Status: no evidence_

### I.P1.j - Limit attack surfaces

**Annex I, Part 1, item j**

> be designed, developed and produced to limit attack surfaces, including external interfaces;

_Status: no evidence_

### I.P1.l - Security logging and monitoring

**Annex I, Part 1, item l**

> provide security related information by recording and monitoring relevant internal activity, including the access to or modification of data, services or functions, with an opt-out mechanism for the user;

_Status: no evidence_

### I.P1.m - Secure data and settings removal

**Annex I, Part 1, item m**

> provide the possibility for users to securely and easily remove on a permanent basis all data and settings and, where such data can be transferred to other products or systems, ensure that this is done in a secure manner.

_Status: no evidence_

### I.P2.4 - Public disclosure of fixed vulnerabilities

**Annex I, Part 2, item 4**

> once a security update has been made available, share and publicly disclose information about fixed vulnerabilities, including a description of the vulnerabilities, information allowing users to identify the product with digital elements affected, the impacts of the vulnerabilities, their severity and clear and accessible information helping users to remediate the vulnerabilities; in duly justified cases, where manufacturers consider the security risks of publication to outweigh the security benefits, they may delay making public information regarding a fixed vulnerability until after users have been given the possibility to apply the relevant patch;

_Status: no evidence_

### I.P2.6 - Facilitate vulnerability information sharing

**Annex I, Part 2, item 6**

> take measures to facilitate the sharing of information about potential vulnerabilities in their product with digital elements as well as in third-party components contained in that product, including by providing a contact address for the reporting of the vulnerabilities discovered in the product with digital elements;

_Status: no evidence_

### I.P2.8 - Timely, free dissemination of security updates

**Annex I, Part 2, item 8**

> ensure that, where security updates are available to address identified security issues, they are disseminated without delay and, unless otherwise agreed between a manufacturer and a business user in relation to a tailor-made product with digital elements, free of charge, accompanied by advisory messages providing users with the relevant information, including on potential action to be taken.

_Status: no evidence_

### II.1 - Manufacturer identification and contact

**Annex II, item 1**

> the name, registered trade name or registered trademark of the manufacturer, and the postal address, the email address or other digital contact as well as, where available, the website at which the manufacturer can be contacted;

_Status: no evidence_

### II.3 - Unique product identification

**Annex II, item 3**

> name and type and any additional information enabling the unique identification of the product with digital elements;

_Status: no evidence_

### II.4 - Intended purpose and security properties

**Annex II, item 4**

> the intended purpose of the product with digital elements, including the security environment provided by the manufacturer, as well as the product's essential functionalities and information about the security properties;

_Status: no evidence_

### II.5 - Foreseeable misuse risks

**Annex II, item 5**

> any known or foreseeable circumstance, related to the use of the product with digital elements in accordance with its intended purpose or under conditions of reasonably foreseeable misuse, which may lead to significant cybersecurity risks;

_Status: no evidence_

### II.6 - EU declaration of conformity address

**Annex II, item 6**

> where applicable, the internet address at which the EU declaration of conformity can be accessed;

_Status: no evidence_

### II.8 - Detailed instructions for secure use

**Annex II, item 8**

> detailed instructions or an internet address referring to such detailed instructions and information on:
(a) the necessary measures during initial commissioning and throughout the lifetime of the product with digital elements to ensure its secure use;
(b) how changes to the product with digital elements can affect the security of data;
(c) how security-relevant updates can be installed;
(d) the secure decommissioning of the product with digital elements, including information on how user data can be securely removed;
(e) how the default setting enabling the automatic installation of security updates, as required by Part I, point (2)(c), of Annex I, can be turned off;
(f) where the product with digital elements is intended for integration into other products with digital elements, the information necessary for the integrator to comply with the essential cybersecurity requirements set out in Annex I and the documentation requirements set out in Annex VII.

_Status: no evidence_

### II.9 - SBOM availability (optional disclosure)

**Annex II, item 9**

> If the manufacturer decides to make available the software bill of materials to the user, information on where the software bill of materials can be accessed.

_Status: no evidence_

### VII.1 - General product description

**Annex VII, item 1**

> a general description of the product with digital elements, including:
(a) its intended purpose;
(b) versions of software affecting compliance with essential cybersecurity requirements;
(c) where the product with digital elements is a hardware product, photographs or illustrations showing external features, marking and internal layout;
(d) user information and instructions as set out in Annex II;

_Status: no evidence_

### VII.3 - Cybersecurity risk assessment

**Annex VII, item 3**

> an assessment of the cybersecurity risks against which the product with digital elements is designed, developed, produced, delivered and maintained pursuant to Article 13, including how the essential cybersecurity requirements set out in Part I of Annex I are applicable;

_Status: no evidence_

### VII.4 - Support period determination

**Annex VII, item 4**

> relevant information that was taken into account to determine the support period pursuant to Article 13(8) of the product with digital elements;

_Status: no evidence_

### VII.5 - Harmonised standards and specifications applied

**Annex VII, item 5**

> a list of the harmonised standards applied in full or in part the references of which have been published in the Official Journal of the European Union, common specifications as set out in Article 27 of this Regulation or European cybersecurity certification schemes adopted pursuant to Regulation (EU) 2019/881 pursuant to Article 27(8) of this Regulation, and, where those harmonised standards, common specifications or European cybersecurity certification schemes have not been applied, descriptions of the solutions adopted to meet the essential cybersecurity requirements set out in Parts I and II of Annex I, including a list of other relevant technical specifications applied. In the event of partly applied harmonised standards, common specifications or European cybersecurity certification schemes, the technical documentation shall specify the parts which have been applied;

_Status: no evidence_

### VII.6 - Conformity test reports

**Annex VII, item 6**

> reports of the tests carried out to verify the conformity of the product with digital elements and of the vulnerability handling processes with the applicable essential cybersecurity requirements as set out in Parts I and II of Annex I;

_Status: no evidence_

### VII.7 - Copy of EU declaration of conformity

**Annex VII, item 7**

> a copy of the EU declaration of conformity;

_Status: no evidence_

### VII.8 - SBOM on market surveillance request

**Annex VII, item 8**

> where applicable, the software bill of materials, further to a reasoned request from a market surveillance authority provided that it is necessary in order for that authority to be able to check compliance with the essential cybersecurity requirements set out in Annex I.

_Status: no evidence_

