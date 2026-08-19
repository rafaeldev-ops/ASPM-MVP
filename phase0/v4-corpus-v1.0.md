# v4-corpus-v1.0 — annotation packet

KEV catalog `2026.08.14` · EPSS `v2026.06.15` as of `2026-08-14`

Evidence is frozen at build time. Do not re-fetch during annotation: a corpus that reads live EPSS changes its own inputs between annotators, and after a model bump changes all of them (`exp-001`).

Read the environment brief first (`v4-annotation-kit.md` §2).

## NW-001  ·  checkout-api  ·  sca/trivy

> log4j-core 2.14.1: JNDI lookup in log messages permits remote code execution

- **CVE-2021-44228** (advisory `GHSA-jfh8-c2jp-5v3q`)
- Package: `Maven/org.apache.logging.log4j:log4j-core` — **deployed `2.14.1`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H`
- EPSS: **0.99999** (pct 1.0, model `v2026.06.15`)
- CISA KEV: **listed 2021-12-10**, ransomware use: Known
- Affected ranges: introduced=2.13.0 fixed=2.15.0; introduced=2.0-beta9 fixed=2.3.1; introduced=2.4 fixed=2.12.2

## NW-002  ·  checkout-api  ·  sca/trivy

> activemq-client 5.17.3: OpenWire protocol deserialization of untrusted data

- **CVE-2023-46604** (advisory `GHSA-crg9-44h2-xw35`)
- Package: `Maven/org.apache.activemq:activemq-client` — **deployed `5.17.3`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H/E:H`
- EPSS: **0.99723** (pct 0.99952, model `v2026.06.15`)
- CISA KEV: **listed 2023-11-02**, ransomware use: Known
- Affected ranges: introduced=0 fixed=5.15.16; introduced=5.16.0 fixed=5.16.7; introduced=5.17.0 fixed=5.17.6; introduced=5.18.0 fixed=5.18.3

## NW-003  ·  checkout-api  ·  sca/trivy

> spring-cloud-gateway 3.1.0: SpEL expression injection via Actuator endpoint

- **CVE-2022-22947** (advisory `GHSA-3gx9-37ww-9qw6`)
- Package: `Maven/org.springframework.cloud:spring-cloud-gateway` — **deployed `3.1.0`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- EPSS: **0.98253** (pct 0.99912, model `v2026.06.15`)
- CISA KEV: **listed 2022-05-16**, ransomware use: Unknown
- Affected ranges: introduced=0 fixed=3.0.7; introduced=3.1.0 fixed=3.1.1

## NW-004  ·  checkout-api  ·  sca/trivy

> tomcat-tribes 10.1.53: missing encryption of sensitive data in cluster replication

- **CVE-2026-34486** (advisory `GHSA-69r9-qgr7-g2wj`)
- Package: `Maven/org.apache.tomcat:tomcat-tribes` — **deployed `10.1.53`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- EPSS: **0.82933** (pct 0.99645, model `v2026.06.15`)
- CISA KEV: **listed 2026-08-04**, ransomware use: Unknown
- Affected ranges: introduced=11.0.20 fixed=11.0.21; introduced=10.1.53 fixed=10.1.54; introduced=9.0.116 fixed=9.0.117

## NW-005  ·  checkout-api  ·  sca/trivy

> activemq-broker 5.19.2: improper input validation in the broker

- **CVE-2026-34197** (advisory `GHSA-rxpj-7qvf-xv32`)
- Package: `Maven/org.apache.activemq:activemq-broker` — **deployed `5.19.2`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- EPSS: **0.9722** (pct 0.99889, model `v2026.06.15`)
- CISA KEV: **listed 2026-04-16**, ransomware use: Unknown
- Affected ranges: introduced=0 fixed=5.19.5; introduced=6.0.0 fixed=6.2.3

## NW-006  ·  catalog-web  ·  sca/snyk

> systeminformation 5.2.0 as a direct dependency: command injection in si.inetLatency

- **CVE-2021-21315** (advisory `GHSA-2m8v-572m-ff2v`)
- Package: `npm/systeminformation` — **deployed `5.2.0`** (direct)
- CVSS: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H`
- EPSS: **0.90675** (pct 0.99795, model `v2026.06.15`)
- CISA KEV: **listed 2022-01-18**, ransomware use: Unknown
- Affected ranges: introduced=0 fixed=5.3.1

## NW-007  ·  checkout-api  ·  sca/trivy

> Spring4Shell reported against spring-boot-starter-web

- **CVE-2022-22965** (advisory `GHSA-36p3-wjmg-h94x`)
- Package: `Maven/org.springframework.boot:spring-boot-starter-web` — **deployed `3.2.4`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H`
- EPSS: **0.99677** (pct 0.99949, model `v2026.06.15`)
- CISA KEV: **listed 2022-04-04**, ransomware use: Unknown
- Affected ranges: introduced=0 fixed=2.5.12; introduced=2.6.0 fixed=2.6.6

## NW-008  ·  checkout-api  ·  sca/trivy

> tomcat-embed-core 10.1.53: path equivalence permits RCE when writes are enabled

- **CVE-2025-24813** (advisory `GHSA-83qj-6fr2-vhqg`)
- Package: `Maven/org.apache.tomcat.embed:tomcat-embed-core` — **deployed `10.1.53`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H`
- EPSS: **0.99925** (pct 0.99968, model `v2026.06.15`)
- CISA KEV: **listed 2025-04-01**, ransomware use: Unknown
- Affected ranges: introduced=11.0.0-M1 fixed=11.0.3; introduced=10.1.0-M1 fixed=10.1.35; introduced=9.0.0.M1 fixed=9.0.99; introduced=8.5.0 last_affected=8.5.100

## NW-009  ·  catalog-web  ·  sca/snyk

> lodash: command injection via template

- **CVE-2021-23337** (advisory `GHSA-35jh-r3h4-6jhm`)
- Package: `npm/lodash` — **deployed `4.17.21`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
- EPSS: **0.21333** (pct 0.97382, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=4.17.21

## NW-010  ·  inventory-sync  ·  sca/trivy

> urllib3: Cookie header leak on cross-origin redirect

- **CVE-2023-43804** (advisory `GHSA-v845-jxx5-vc9f`)
- Package: `PyPI/urllib3` — **deployed `2.2.2`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N`
- EPSS: **0.01207** (pct 0.65654, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=2.0.0 fixed=2.0.6; introduced=0 fixed=1.26.17

## NW-011  ·  inventory-sync  ·  sca/trivy

> setuptools: ReDoS in package_index

- **CVE-2022-40897** (advisory `GHSA-r9hx-vwmv-q579`)
- Package: `PyPI/setuptools` — **deployed `70.0.0`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- EPSS: **0.02617** (pct 0.84083, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=65.5.1

## NW-012  ·  catalog-web  ·  sca/snyk

> braces: uncontrolled resource consumption

- **CVE-2024-4068** (advisory `GHSA-grv7-fg5c-xmjg`)
- Package: `npm/braces` — **deployed `3.0.3`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- EPSS: **0.01471** (pct 0.7148, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=3.0.3

## NW-013  ·  analytics-etl  ·  sca/trivy

> setuptools 58.0.4 in the dev dependency group: ReDoS in package_index

- **CVE-2022-40897** (advisory `GHSA-r9hx-vwmv-q579`)
- Package: `PyPI/setuptools` — **deployed `58.0.4`** (dev_only)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- EPSS: **0.02617** (pct 0.84083, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=65.5.1

## NW-014  ·  analytics-etl  ·  sca/trivy

> requests 2.28.0: Proxy-Authorization leaked on redirect

- **CVE-2023-32681** (advisory `GHSA-j8r2-6x86-q33q`)
- Package: `PyPI/requests` — **deployed `2.28.0`** (dev_only)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N`
- EPSS: **0.02974** (pct 0.86049, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=2.3.0 fixed=2.31.0

## NW-015  ·  analytics-etl  ·  sca/trivy

> cryptography 41.0.0: Bleichenbacher timing oracle in RSA decryption

- **CVE-2023-50782** (advisory `GHSA-3ww4-gg4f-jr7f`)
- Package: `PyPI/cryptography` — **deployed `41.0.0`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- EPSS: **0.01118** (pct 0.63273, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=42.0.0

## NW-016  ·  analytics-etl  ·  sca/trivy

> requests 2.31.0: verify=False persists across session requests

- **CVE-2024-35195** (advisory `GHSA-9wx4-h78v-vm56`)
- Package: `PyPI/requests` — **deployed `2.31.0`** (dev_only)
- CVSS: `CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N`
- EPSS: **0.0034** (pct 0.26903, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=2.32.0

## NW-017  ·  analytics-etl  ·  sast/semgrep

> subprocess call with shell=True in etl/loaders/legacy_import.py:88

- Rule: `python.lang.security.audit.subprocess-shell-true` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-018  ·  analytics-etl  ·  container/trivy

> glibc 2.36-9 in the staging image: buffer overflow in ld.so GLIBC_TUNABLES

- **CVE-2023-4911** (advisory `CVE-2023-4911`)
- Package: `Debian/glibc` — **deployed `2.36-9`** (transitive)
- CVSS: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- EPSS: **0.81422** (pct 0.99605, model `v2026.06.15`)
- CISA KEV: **listed 2023-11-21**, ransomware use: Unknown
- Affected ranges: not published

## NW-019  ·  checkout-api  ·  sast/semgrep

> ObjectInputStream.readObject on request-derived bytes in checkout/api/LegacyCartCodec.java:142

- Rule: `java.lang.security.audit.object-deserialization` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-020  ·  checkout-api  ·  sast/semgrep

> String-concatenated JDBC query with request parameter in checkout/repo/OrderSearch.java:61

- Rule: `java.lang.security.audit.sqli.jdbc-sqli` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-021  ·  catalog-web  ·  sast/semgrep

> Unescaped request parameter written to response in pages/api/search.ts:34

- Rule: `javascript.express.security.audit.xss.direct-response-write` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-022  ·  checkout-api  ·  sast/semgrep

> SpEL expression built from request attribute in checkout/promo/RuleEval.java:77

- Rule: `java.spring.security.audit.spel-injection` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-023  ·  catalog-web  ·  sast/semgrep

> Request-derived path joined without normalization in pages/api/asset.ts:22

- Rule: `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-024  ·  catalog-web  ·  sca/snyk

> axios 1.5.0: XSRF-TOKEN leaked to third-party host

- **CVE-2023-45857** (advisory `GHSA-wf5p-g6vw-rhxx`)
- Package: `npm/axios` — **deployed `1.5.0`** (direct)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`
- EPSS: **0.00556** (pct 0.43628, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=1.0.0 fixed=1.6.0; introduced=0.8.1 fixed=0.28.0

## NW-025  ·  checkout-api  ·  sast/semgrep

> DocumentBuilderFactory without DOCTYPE restriction parsing a request body in checkout/edi/InvoiceParser.java:31

- Rule: `java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-026  ·  catalog-web  ·  sast/semgrep

> res.redirect with request-controlled target in pages/api/out.ts:12

- Rule: `javascript.express.security.audit.express-open-redirect` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-027  ·  catalog-web  ·  sca/snyk

> lodash 4.17.15 pulled in by a build-time plugin: prototype pollution in zipObjectDeep

- **CVE-2020-8203** (advisory `GHSA-p6mc-m468-83gw`)
- Package: `npm/lodash` — **deployed `4.17.15`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`
- EPSS: **0.05213** (pct 0.91767, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=3.7.0 fixed=4.17.19
- Scanner reachability verdict: **unknown**

## NW-028  ·  catalog-web  ·  sca/snyk

> semver 7.3.5: ReDoS in range parsing

- **CVE-2022-25883** (advisory `GHSA-c2qf-rxjj-qqgw`)
- Package: `npm/semver` — **deployed `7.3.5`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- EPSS: **0.02761** (pct 0.84976, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=7.0.0 fixed=7.5.2; introduced=6.0.0 fixed=6.3.1; introduced=2.0.0-alpha fixed=5.7.2
- Scanner reachability verdict: **unknown**

## NW-029  ·  checkout-api  ·  sca/trivy

> log4j-core 2.13.0: SMTP appender does not verify certificate hostname

- **CVE-2020-9488** (advisory `GHSA-vwqq-5vrc-xw9h`)
- Package: `Maven/org.apache.logging.log4j:log4j-core` — **deployed `2.13.0`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- EPSS: **0.08096** (pct 0.94307, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=2.13.0 fixed=2.13.2; introduced=2.4.0 fixed=2.12.3; introduced=0 fixed=2.3.2
- Scanner reachability verdict: **unknown**

## NW-030  ·  inventory-sync  ·  sca/trivy

> urllib3 2.0.4: Proxy-Authorization not stripped on cross-origin redirect

- **CVE-2024-37891** (advisory `GHSA-34jh-p97f-mpxf`)
- Package: `PyPI/urllib3` — **deployed `2.0.4`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N`
- EPSS: **0.01141** (pct 0.63836, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=1.26.19; introduced=2.0.0 fixed=2.2.2
- Scanner reachability verdict: **unknown**

## NW-031  ·  checkout-api  ·  sca/trivy

> spring-security-config 6.0.3: authorization rules may be misapplied with multiple servlets

- **CVE-2023-34035** (advisory `GHSA-4vpr-xfrp-cj64`)
- Package: `Maven/org.springframework.security:spring-security-config` — **deployed `6.0.3`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`
- EPSS: **0.00658** (pct 0.4841, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=5.8.0 fixed=5.8.5; introduced=6.0.0 fixed=6.0.5; introduced=6.1.0 fixed=6.1.2
- Scanner reachability verdict: **unknown**

## NW-032  ·  inventory-sync  ·  sca/trivy

> requests 2.28.1: Proxy-Authorization leaked on redirect

- **CVE-2023-32681** (advisory `GHSA-j8r2-6x86-q33q`)
- Package: `PyPI/requests` — **deployed `2.28.1`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N`
- EPSS: **0.02974** (pct 0.86049, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=2.3.0 fixed=2.31.0
- Scanner reachability verdict: **unknown**

## NW-033  ·  inventory-sync  ·  container/trivy

> glibc 2.35-1: local privilege escalation via GLIBC_TUNABLES. Local vector only

- **CVE-2023-4911** (advisory `CVE-2023-4911`)
- Package: `Debian/glibc` — **deployed `2.35-1`** (transitive)
- CVSS: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- EPSS: **0.81422** (pct 0.99605, model `v2026.06.15`)
- CISA KEV: **listed 2023-11-21**, ransomware use: Unknown
- Affected ranges: not published

## NW-034  ·  checkout-api  ·  sca/trivy

> spring-cloud-gateway 3.0.6: Actuator not exposed per the team's config

- **CVE-2022-22947** (advisory `GHSA-3gx9-37ww-9qw6`)
- Package: `Maven/org.springframework.cloud:spring-cloud-gateway` — **deployed `3.0.6`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- EPSS: **0.98253** (pct 0.99912, model `v2026.06.15`)
- CISA KEV: **listed 2022-05-16**, ransomware use: Unknown
- Affected ranges: introduced=0 fixed=3.0.7; introduced=3.1.0 fixed=3.1.1
- Scanner reachability verdict: **unknown**

## NW-035  ·  checkout-api  ·  sca/snyk

> log4j-core 2.12.0 inside a vendored analytics agent JAR

- **CVE-2021-44228** (advisory `GHSA-jfh8-c2jp-5v3q`)
- Package: `Maven/org.apache.logging.log4j:log4j-core` — **deployed `2.12.0`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H`
- EPSS: **0.99999** (pct 1.0, model `v2026.06.15`)
- CISA KEV: **listed 2021-12-10**, ransomware use: Known
- Affected ranges: introduced=2.13.0 fixed=2.15.0; introduced=2.0-beta9 fixed=2.3.1; introduced=2.4 fixed=2.12.2
- Scanner reachability verdict: **unknown**

## NW-036  ·  checkout-api  ·  sca/trivy

> activemq-broker 5.19.0 on the classpath; the team states the embedded broker is never started

- **CVE-2026-34197** (advisory `GHSA-rxpj-7qvf-xv32`)
- Package: `Maven/org.apache.activemq:activemq-broker` — **deployed `5.19.0`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- EPSS: **0.9722** (pct 0.99889, model `v2026.06.15`)
- CISA KEV: **listed 2026-04-16**, ransomware use: Unknown
- Affected ranges: introduced=0 fixed=5.19.5; introduced=6.0.0 fixed=6.2.3
- Scanner reachability verdict: **unknown**

## NW-037  ·  checkout-api  ·  sca/trivy

> activemq-client 5.16.5: OpenWire transport disabled in the broker config

- **CVE-2023-46604** (advisory `GHSA-crg9-44h2-xw35`)
- Package: `Maven/org.apache.activemq:activemq-client` — **deployed `5.16.5`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H/E:H`
- EPSS: **0.99723** (pct 0.99952, model `v2026.06.15`)
- CISA KEV: **listed 2023-11-02**, ransomware use: Known
- Affected ranges: introduced=0 fixed=5.15.16; introduced=5.16.0 fixed=5.16.7; introduced=5.17.0 fixed=5.17.6; introduced=5.18.0 fixed=5.18.3
- Scanner reachability verdict: **unknown**

## NW-038  ·  admin-console  ·  sca/trivy

> cryptography 40.0.1: RSA decryption timing oracle. No known exploitation

- **CVE-2023-50782** (advisory `GHSA-3ww4-gg4f-jr7f`)
- Package: `PyPI/cryptography` — **deployed `40.0.1`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- EPSS: **0.01118** (pct 0.63273, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=42.0.0

## NW-039  ·  inventory-sync  ·  sca/trivy

> requests 2.30.0: TLS verification bypass persists across a Session

- **CVE-2024-35195** (advisory `GHSA-9wx4-h78v-vm56`)
- Package: `PyPI/requests` — **deployed `2.30.0`** (direct)
- CVSS: `CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N`
- EPSS: **0.0034** (pct 0.26903, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=0 fixed=2.32.0

## NW-040  ·  admin-console  ·  sca/trivy

> urllib3 2.0.5: Cookie header leak on cross-origin redirect

- **CVE-2023-43804** (advisory `GHSA-v845-jxx5-vc9f`)
- Package: `PyPI/urllib3` — **deployed `2.0.5`** (transitive)
- CVSS: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N`
- EPSS: **0.01207** (pct 0.65654, model `v2026.06.15`)
- CISA KEV: **not listed**
- Affected ranges: introduced=2.0.0 fixed=2.0.6; introduced=0 fixed=1.26.17

## NW-041  ·  inventory-sync  ·  sast/semgrep

> yaml.load without SafeLoader on a config file read from the internal S3 bucket, sync/config.py:19

- Rule: `python.lang.security.deserialization.avoid-pyyaml-load` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-042  ·  admin-console  ·  sast/semgrep

> Raw SQL built with string formatting in admin/reports/views.py:203

- Rule: `python.django.security.audit.raw-query` (semgrep)
- Scanner reachability verdict: **reachable**

## NW-043  ·  checkout-api  ·  sast/semgrep

> MD5 used in src/test/java/checkout/FixtureBuilder.java:44

- Rule: `java.lang.security.audit.crypto.use-of-md5` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-044  ·  catalog-web  ·  sast/semgrep

> Dynamic code construction in generated file src/__generated__/graphql-types.ts:1180

- Rule: `javascript.lang.security.audit.code-string-concat` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-045  ·  inventory-sync  ·  sast/semgrep

> subprocess with a variable argument in tests/integration/conftest.py:57

- Rule: `python.lang.security.audit.dangerous-subprocess-use-audit` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-046  ·  checkout-api  ·  sast/semgrep

> NullCipher in src/test/java/checkout/crypto/CipherContractTest.java:28

- Rule: `java.lang.security.audit.crypto.no-null-cipher` (semgrep)
- Scanner reachability verdict: **unknown**

## NW-047  ·  checkout-api  ·  secret/gitleaks

> Stripe-shaped key in src/test/resources/payment-fixtures.json:12, prefix sk_test_

- Rule: `stripe-access-token` (gitleaks)

## NW-048  ·  catalog-web  ·  secret/gitleaks

> AWS access key id in cypress/fixtures/env.json:4, prefix AKIA

- Rule: `aws-access-token` (gitleaks)

## NW-049  ·  inventory-sync  ·  secret/gitleaks

> 40-char high-entropy string assigned to WAREHOUSE_API_KEY in tests/conftest.py:14

- Rule: `generic-api-key` (gitleaks)

## NW-050  ·  admin-console  ·  secret/gitleaks

> BEGIN RSA PRIVATE KEY block in admin/tests/data/signing_fixture.pem:1

- Rule: `private-key` (gitleaks)
