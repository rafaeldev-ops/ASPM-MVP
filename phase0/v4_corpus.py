#!/usr/bin/env python3
"""
V4 corpus builder -- assembles the 50-finding annotation corpus.

The DESIGN (which finding is in which stratum, on which Northwind service, at
which deployed version) is authored here. The EVIDENCE is fetched from the
feeds and never authored:

    KEV membership + dateAdded  <- CISA KEV catalog
    EPSS score + percentile     <- daily snapshot, WITH its model_version
    CVSS vector, affected ranges, fixed versions <- OSV / GHSA

Then it VALIDATES: each stratum asserts a property (S2 = deployed version must
fall OUTSIDE the affected range, S1 = must fall inside, etc.). If an assertion
fails the corpus is NOT emitted. A corpus whose strata do not hold is worse
than no corpus, because the kappa it produces looks fine.

See docs/evaluation/v4-annotation-kit.md sections 2-3.
Standard library only. Reused by V2 and V3 -- freeze and hash it (section 3.2).

    python v4_corpus.py            # fetch, build, validate, emit
    python v4_corpus.py --offline  # use cached feeds only
    python v4_corpus.py --check    # validate and report; emit nothing
"""

import csv
import gzip
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
OSV_URL = "https://api.osv.dev/v1/vulns/{id}"
SEMGREP_TREE_URL = ("https://api.github.com/repos/semgrep/semgrep-rules/"
                    "git/trees/develop?recursive=1")
GITLEAKS_TOML_URL = ("https://raw.githubusercontent.com/gitleaks/gitleaks/"
                     "master/config/gitleaks.toml")

EPSS_DATE = "2026-08-14"      # frozen. Do not float this -- see exp-001.
CORPUS_VERSION = "v4-corpus-v1.0"


# ==========================================================================
# THE SEED TABLE -- design decisions. Evidence is fetched, never written here.
#
# stratum, service, cls, tool, ident, package, deployed, scope, reach, message
# ==========================================================================
SEED = [
    # ---- S1  clear act-now: KEV-listed, affected, direct dep of checkout-api
    ("S1", "checkout-api", "sca", "trivy", "CVE-2021-44228",
     "Maven/org.apache.logging.log4j:log4j-core", "2.14.1", "direct", None,
     "log4j-core 2.14.1: JNDI lookup in log messages permits remote code execution"),
    ("S1", "checkout-api", "sca", "trivy", "CVE-2023-46604",
     "Maven/org.apache.activemq:activemq-client", "5.17.3", "direct", None,
     "activemq-client 5.17.3: OpenWire protocol deserialization of untrusted data"),
    ("S1", "checkout-api", "sca", "trivy", "CVE-2022-22947",
     "Maven/org.springframework.cloud:spring-cloud-gateway", "3.1.0", "direct", None,
     "spring-cloud-gateway 3.1.0: SpEL expression injection via Actuator endpoint"),
    ("S1", "checkout-api", "sca", "trivy", "CVE-2026-34486",
     "Maven/org.apache.tomcat:tomcat-tribes", "10.1.53", "direct", None,
     "tomcat-tribes 10.1.53: missing encryption of sensitive data in cluster replication"),
    ("S1", "checkout-api", "sca", "trivy", "CVE-2026-34197",
     "Maven/org.apache.activemq:activemq-broker", "5.19.2", "direct", None,
     "activemq-broker 5.19.2: improper input validation in the broker"),
    ("S1", "catalog-web", "sca", "snyk", "CVE-2021-21315",
     "npm/systeminformation", "5.2.0", "direct", None,
     "systeminformation 5.2.0 as a direct dependency: command injection in si.inetLatency"),

    # ---- S2  clear no-action: affected range EXCLUDES the deployed version
    ("S2", "checkout-api", "sca", "trivy", "CVE-2022-22965",
     "Maven/org.springframework.boot:spring-boot-starter-web", "3.2.4", "direct", None,
     "Spring4Shell reported against spring-boot-starter-web"),
    # Deliberate pair with NW-004: same service, same Tomcat 10.1.53, two real
    # Tomcat CVEs -- one applies and one does not. Q5 is decidable only by
    # reading the actual ranges, which is the entire point of this stratum.
    ("S2", "checkout-api", "sca", "trivy", "CVE-2025-24813",
     "Maven/org.apache.tomcat.embed:tomcat-embed-core", "10.1.53", "direct", None,
     "tomcat-embed-core 10.1.53: path equivalence permits RCE when writes are enabled"),
    ("S2", "catalog-web", "sca", "snyk", "CVE-2021-23337",
     "npm/lodash", "4.17.21", "direct", None,
     "lodash: command injection via template"),
    ("S2", "inventory-sync", "sca", "trivy", "CVE-2023-43804",
     "PyPI/urllib3", "2.2.2", "transitive", None,
     "urllib3: Cookie header leak on cross-origin redirect"),
    ("S2", "inventory-sync", "sca", "trivy", "CVE-2022-40897",
     "PyPI/setuptools", "70.0.0", "transitive", None,
     "setuptools: ReDoS in package_index"),
    ("S2", "catalog-web", "sca", "snyk", "CVE-2024-4068",
     "npm/braces", "3.0.3", "transitive", None,
     "braces: uncontrolled resource consumption"),

    # ---- S3  not deployed: analytics-etl is staging-only, dev deps included
    ("S3", "analytics-etl", "sca", "trivy", "CVE-2022-40897",
     "PyPI/setuptools", "58.0.4", "dev_only", None,
     "setuptools 58.0.4 in the dev dependency group: ReDoS in package_index"),
    ("S3", "analytics-etl", "sca", "trivy", "CVE-2023-32681",
     "PyPI/requests", "2.28.0", "dev_only", None,
     "requests 2.28.0: Proxy-Authorization leaked on redirect"),
    ("S3", "analytics-etl", "sca", "trivy", "CVE-2023-50782",
     "PyPI/cryptography", "41.0.0", "transitive", None,
     "cryptography 41.0.0: Bleichenbacher timing oracle in RSA decryption"),
    ("S3", "analytics-etl", "sca", "trivy", "CVE-2024-35195",
     "PyPI/requests", "2.31.0", "dev_only", None,
     "requests 2.31.0: verify=False persists across session requests"),
    ("S3", "analytics-etl", "sast", "semgrep", "python.lang.security.audit.subprocess-shell-true",
     None, None, None, "unknown",
     "subprocess call with shell=True in etl/loaders/legacy_import.py:88"),
    ("S3", "analytics-etl", "container", "trivy", "CVE-2023-4911",
     "Debian/glibc", "2.36-9", "transitive", None,
     "glibc 2.36-9 in the staging image: buffer overflow in ld.so GLIBC_TUNABLES"),

    # ---- S4  WAF battleground: injection/deser class, internet-facing, CRS plausible
    ("S4", "checkout-api", "sast", "semgrep", "java.lang.security.audit.object-deserialization",
     None, None, None, "reachable",
     "ObjectInputStream.readObject on request-derived bytes in "
     "checkout/api/LegacyCartCodec.java:142"),
    ("S4", "checkout-api", "sast", "semgrep", "java.lang.security.audit.sqli.jdbc-sqli",
     None, None, None, "reachable",
     "String-concatenated JDBC query with request parameter in "
     "checkout/repo/OrderSearch.java:61"),
    ("S4", "catalog-web", "sast", "semgrep", "javascript.express.security.audit.xss.direct-response-write",
     None, None, None, "reachable",
     "Unescaped request parameter written to response in pages/api/search.ts:34"),
    ("S4", "checkout-api", "sast", "semgrep", "java.spring.security.audit.spel-injection",
     None, None, None, "reachable",
     "SpEL expression built from request attribute in checkout/promo/RuleEval.java:77"),
    ("S4", "catalog-web", "sast", "semgrep", "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal",
     None, None, None, "unknown",
     "Request-derived path joined without normalization in pages/api/asset.ts:22"),
    ("S4", "catalog-web", "sca", "snyk", "CVE-2023-45857",
     "npm/axios", "1.5.0", "direct", None,
     "axios 1.5.0: XSRF-TOKEN leaked to third-party host"),
    ("S4", "checkout-api", "sast", "semgrep", "java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing",
     None, None, None, "reachable",
     "DocumentBuilderFactory without DOCTYPE restriction parsing a request body in "
     "checkout/edi/InvoiceParser.java:31"),
    ("S4", "catalog-web", "sast", "semgrep", "javascript.express.security.audit.express-open-redirect",
     None, None, None, "unknown",
     "res.redirect with request-controlled target in pages/api/out.ts:12"),

    # ---- S5  transitive, unclear whether the vulnerable path is ever called
    ("S5", "catalog-web", "sca", "snyk", "CVE-2020-8203",
     "npm/lodash", "4.17.15", "transitive", "unknown",
     "lodash 4.17.15 pulled in by a build-time plugin: prototype pollution in zipObjectDeep"),
    ("S5", "catalog-web", "sca", "snyk", "CVE-2022-25883",
     "npm/semver", "7.3.5", "transitive", "unknown",
     "semver 7.3.5: ReDoS in range parsing"),
    ("S5", "checkout-api", "sca", "trivy", "CVE-2020-9488",
     "Maven/org.apache.logging.log4j:log4j-core", "2.13.0", "transitive", "unknown",
     "log4j-core 2.13.0: SMTP appender does not verify certificate hostname"),
    ("S5", "inventory-sync", "sca", "trivy", "CVE-2024-37891",
     "PyPI/urllib3", "2.0.4", "transitive", "unknown",
     "urllib3 2.0.4: Proxy-Authorization not stripped on cross-origin redirect"),
    ("S5", "checkout-api", "sca", "trivy", "CVE-2023-34035",
     "Maven/org.springframework.security:spring-security-config", "6.0.3", "transitive", "unknown",
     "spring-security-config 6.0.3: authorization rules may be misapplied with multiple servlets"),
    ("S5", "inventory-sync", "sca", "trivy", "CVE-2023-32681",
     "PyPI/requests", "2.28.1", "transitive", "unknown",
     "requests 2.28.1: Proxy-Authorization leaked on redirect"),

    # ---- S6  hard positive: framed as if it does not matter here, but KEV-listed.
    # Several reuse a CVE that also appears in S1 at a different service, version
    # and framing. That is deliberate: it tests whether annotators treat CONTEXT as
    # decisive rather than the CVE id, which is the product's entire thesis.
    ("S6", "inventory-sync", "container", "trivy", "CVE-2023-4911",
     "Debian/glibc", "2.35-1", "transitive", None,
     "glibc 2.35-1: local privilege escalation via GLIBC_TUNABLES. Local vector only"),
    ("S6", "checkout-api", "sca", "trivy", "CVE-2022-22947",
     "Maven/org.springframework.cloud:spring-cloud-gateway", "3.0.6", "transitive", "unknown",
     "spring-cloud-gateway 3.0.6: Actuator not exposed per the team's config"),
    ("S6", "checkout-api", "sca", "snyk", "CVE-2021-44228",
     "Maven/org.apache.logging.log4j:log4j-core", "2.12.0", "transitive", "unknown",
     "log4j-core 2.12.0 inside a vendored analytics agent JAR"),
    ("S6", "checkout-api", "sca", "trivy", "CVE-2026-34197",
     "Maven/org.apache.activemq:activemq-broker", "5.19.0", "transitive", "unknown",
     "activemq-broker 5.19.0 on the classpath; the team states the embedded broker is never started"),
    ("S6", "checkout-api", "sca", "trivy", "CVE-2023-46604",
     "Maven/org.apache.activemq:activemq-client", "5.16.5", "transitive", "unknown",
     "activemq-client 5.16.5: OpenWire transport disabled in the broker config"),

    # ---- S7  hard negative: high CVSS, no exploit, internal-only service
    ("S7", "admin-console", "sca", "trivy", "CVE-2023-50782",
     "PyPI/cryptography", "40.0.1", "transitive", None,
     "cryptography 40.0.1: RSA decryption timing oracle. No known exploitation"),
    ("S7", "inventory-sync", "sca", "trivy", "CVE-2024-35195",
     "PyPI/requests", "2.30.0", "direct", None,
     "requests 2.30.0: TLS verification bypass persists across a Session"),
    ("S7", "admin-console", "sca", "trivy", "CVE-2023-43804",
     "PyPI/urllib3", "2.0.5", "transitive", None,
     "urllib3 2.0.5: Cookie header leak on cross-origin redirect"),
    ("S7", "inventory-sync", "sast", "semgrep", "python.lang.security.deserialization.avoid-pyyaml-load",
     None, None, None, "reachable",
     "yaml.load without SafeLoader on a config file read from the internal S3 bucket, "
     "sync/config.py:19"),
    ("S7", "admin-console", "sast", "semgrep", "python.django.security.audit.raw-query",
     None, None, None, "reachable",
     "Raw SQL built with string formatting in admin/reports/views.py:203"),

    # ---- S8  SAST in test fixtures / generated code
    ("S8", "checkout-api", "sast", "semgrep", "java.lang.security.audit.crypto.use-of-md5",
     None, None, None, "unknown",
     "MD5 used in src/test/java/checkout/FixtureBuilder.java:44"),
    ("S8", "catalog-web", "sast", "semgrep", "javascript.lang.security.audit.code-string-concat",
     None, None, None, "unknown",
     "Dynamic code construction in generated file src/__generated__/graphql-types.ts:1180"),
    ("S8", "inventory-sync", "sast", "semgrep", "python.lang.security.audit.dangerous-subprocess-use-audit",
     None, None, None, "unknown",
     "subprocess with a variable argument in tests/integration/conftest.py:57"),
    ("S8", "checkout-api", "sast", "semgrep", "java.lang.security.audit.crypto.no-null-cipher",
     None, None, None, "unknown",
     "NullCipher in src/test/java/checkout/crypto/CipherContractTest.java:28"),

    # ---- S9  secret-shaped finding in a test file
    ("S9", "checkout-api", "secret", "gitleaks", "stripe-access-token",
     None, None, None, None,
     "Stripe-shaped key in src/test/resources/payment-fixtures.json:12, prefix sk_test_"),
    ("S9", "catalog-web", "secret", "gitleaks", "aws-access-token",
     None, None, None, None,
     "AWS access key id in cypress/fixtures/env.json:4, prefix AKIA"),
    ("S9", "inventory-sync", "secret", "gitleaks", "generic-api-key",
     None, None, None, None,
     "40-char high-entropy string assigned to WAREHOUSE_API_KEY in tests/conftest.py:14"),
    ("S9", "admin-console", "secret", "gitleaks", "private-key",
     None, None, None, None,
     "BEGIN RSA PRIVATE KEY block in admin/tests/data/signing_fixture.pem:1"),
]

# Which package ecosystems each Northwind service can plausibly contain, per the
# environment brief. A Maven package on a Node service is the error class that a
# sharp annotator notices and that quietly discredits the whole corpus.
SERVICE_ECOSYSTEM = {
    "checkout-api":   {"Maven"},                 # Java 17 / Spring Boot 3.2
    "catalog-web":    {"npm"},                   # Next.js 14 / Node 20
    "inventory-sync": {"PyPI", "Debian"},        # Python 3.11 + container base
    "admin-console":  {"PyPI", "Debian"},        # Django 4.2
    "analytics-etl":  {"PyPI", "Debian"},        # Python 3.11, staging only
}

STRATA = {
    "S1": ("Clear act-now: KEV-listed, affected, direct dep", 6),
    "S2": ("Clear no-action: affected range excludes deployed version", 6),
    "S3": ("Not deployed: analytics-etl is staging-only", 6),
    "S4": ("WAF battleground: injection/deser, internet-facing", 8),
    "S5": ("Transitive, vulnerable path unclear", 6),
    "S6": ("Hard positive: looks trivial, is KEV-listed", 5),
    "S7": ("Hard negative: high CVSS, no exploit, internal", 5),
    "S8": ("SAST in test fixtures or generated code", 4),
    "S9": ("Secret-shaped finding in a test file", 4),
}


# ==========================================================================
# Feeds
# ==========================================================================
def _get(url, path, binary=False):
    os.makedirs(CACHE, exist_ok=True)
    if os.path.exists(path):
        return path
    if "--offline" in sys.argv:
        raise SystemExit(f"offline: {path} not cached")
    print(f"  fetching {url}")
    with urllib.request.urlopen(url, timeout=90) as r, open(path, "wb") as f:
        f.write(r.read())
    return path


def load_kev():
    p = _get(KEV_URL, os.path.join(CACHE, "kev.json"))
    d = json.load(open(p, encoding="utf-8"))
    return d.get("catalogVersion"), {x["cveID"]: x for x in d["vulnerabilities"]}


def load_epss(date=EPSS_DATE):
    p = _get(EPSS_URL.format(date=date), os.path.join(CACHE, f"epss-{date}.csv.gz"))
    out, model = {}, None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        hdr = f.readline()
        m = re.search(r"model_version:([^,\s]+)", hdr)
        model = m.group(1) if m else "UNKNOWN"
        for r in csv.DictReader(f):
            out[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
    return model, out


def rule_registries():
    """
    Rule ids for the SAST and secret findings, from upstream sources.

    A plausible-looking rule id that does not exist is exactly the detail a
    senior practitioner spots, after which they discount the whole packet. So
    this is checked by the tool, not carried as a note for someone to remember.

    Returns (semgrep_ids, gitleaks_ids) or (None, None) when unavailable.
    """
    try:
        p = _get(SEMGREP_TREE_URL, os.path.join(CACHE, "semgrep-tree.json"))
        tree = json.load(open(p, encoding="utf-8"))
        sg = {t["path"].rsplit(".", 1)[0].replace("/", ".")
              for t in tree.get("tree", []) if t["path"].endswith((".yaml", ".yml"))}
        if tree.get("truncated"):
            sg = None          # a partial tree would produce false MISSes
    except Exception:
        sg = None
    try:
        p = _get(GITLEAKS_TOML_URL, os.path.join(CACHE, "gitleaks.toml"))
        txt = open(p, encoding="utf-8").read()
        gl = set(re.findall(r'^\s*id\s*=\s*"([^"]+)"', txt, re.M))
    except Exception:
        gl = None
    return sg, gl


_osv_cache = {}


def osv(ident):
    if ident in _osv_cache:
        return _osv_cache[ident]
    p = os.path.join(CACHE, f"osv-{ident}.json")
    if os.path.exists(p):
        d = json.load(open(p, encoding="utf-8"))
    elif "--offline" in sys.argv:
        d = None
    else:
        try:
            with urllib.request.urlopen(OSV_URL.format(id=ident), timeout=30) as r:
                d = json.load(r)
            os.makedirs(CACHE, exist_ok=True)
            json.dump(d, open(p, "w", encoding="utf-8"))
            time.sleep(0.12)
        except Exception:
            d = None
    _osv_cache[ident] = d
    return d


def advisory(cve):
    """CVE record, then its GHSA alias, which is where ecosystem ranges live."""
    base = osv(cve)
    if not base:
        return None, None
    ghsa = next((a for a in base.get("aliases", []) if a.startswith("GHSA")), None)
    return base, (osv(ghsa) if ghsa else None)


# ==========================================================================
# Version comparison. Loose on purpose, and it says when it is unsure.
# ==========================================================================
def vkey(v):
    v = re.sub(r"[-+.](RELEASE|Final|GA)$", "", str(v), flags=re.I)
    parts = re.split(r"[.\-+]", v)
    out = []
    for p in parts:
        m = re.match(r"^(\d+)", p)
        out.append(int(m.group(1)) if m else -1)
    return out


def vlt(a, b):
    ka, kb = vkey(a), vkey(b)
    n = max(len(ka), len(kb))
    ka += [0] * (n - len(ka))
    kb += [0] * (n - len(kb))
    return ka < kb


def covers(adv, ecosystem, name, deployed):
    """
    Does any affected range for this package cover the deployed version?
    Returns True / False / None (undeterminable -- reported, never guessed).
    """
    if not adv or deployed is None:
        return None
    seen = False
    for a in adv.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem") != ecosystem or p.get("name") != name:
            continue
        seen = True
        if deployed in (a.get("versions") or []):
            return True
        for rng in a.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            intro, fixed, last = None, None, None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                    fixed = last = None
                if "fixed" in ev:
                    fixed = ev["fixed"]
                if "last_affected" in ev:
                    last = ev["last_affected"]
                if intro is not None and (fixed or last):
                    lo_ok = intro == "0" or not vlt(deployed, intro)
                    hi_ok = (vlt(deployed, fixed) if fixed
                             else not vlt(last, deployed))
                    if lo_ok and hi_ok:
                        return True
                    intro, fixed, last = None, None, None
    return False if seen else None


# ==========================================================================
# Build
# ==========================================================================
def build():
    print("Loading feeds")
    kev_version, kev = load_kev()
    epss_model, epss = load_epss()
    print(f"  KEV catalog {kev_version} ({len(kev):,} entries)")
    print(f"  EPSS {EPSS_DATE} model_version {epss_model} ({len(epss):,} CVEs)")
    print("Enriching findings")

    out = []
    for i, (st, svc, cls, tool, ident, pkg, dep, scope, reach, msg) in enumerate(SEED, 1):
        rec = {
            "finding_id": f"NW-{i:03d}", "stratum": st, "service": svc,
            "class": cls, "tool": tool, "identifier": ident,
            "package": pkg, "deployed_version": dep,
            "dependency_scope": scope, "tool_reachability": reach,
            "scanner_message": msg,
        }
        if ident and ident.startswith("CVE-"):
            k = kev.get(ident)
            rec["kev"] = {"listed": bool(k),
                          "date_added": k["dateAdded"] if k else None,
                          "ransomware": k.get("knownRansomwareCampaignUse") if k else None}
            e = epss.get(ident)
            rec["epss"] = {"score": e[0] if e else None,
                           "percentile": e[1] if e else None,
                           "model_version": epss_model, "as_of": EPSS_DATE}
            base, gh = advisory(ident)
            adv = gh or base
            sev = [s["score"] for s in (adv or {}).get("severity", [])
                   if s.get("type", "").startswith("CVSS")]
            rec["cvss_vector"] = sev[0] if sev else None
            rec["advisory_id"] = (adv or {}).get("id")
            if pkg and "/" in pkg:
                eco, name = pkg.split("/", 1)
                rec["range_covers_deployed"] = covers(adv, eco, name, dep)
                rng = []
                for a in (adv or {}).get("affected", []):
                    p = a.get("package", {})
                    if p.get("ecosystem") == eco and p.get("name") == name:
                        for r in a.get("ranges", []):
                            rng.append({"type": r.get("type"), "events": r.get("events")})
                rec["affected_ranges"] = rng
            else:
                rec["range_covers_deployed"] = None
                rec["affected_ranges"] = []
            rec["evidence_source"] = "kev+epss+osv"
        else:
            rec["evidence_source"] = "rule_only"
            rec["rule_verification"] = "UNVERIFIED: check this rule id against the "\
                                       "scanner's public registry before annotation"
        out.append(rec)
        print(f"  {rec['finding_id']} {st} {(ident or '')[:46]:<46} "
              f"kev={rec.get('kev',{}).get('listed','-')} "
              f"epss={rec.get('epss',{}).get('score','-')} "
              f"covers={rec.get('range_covers_deployed','-')}")
    return out, {"kev_catalog": kev_version, "epss_model_version": epss_model,
                 "epss_as_of": EPSS_DATE}


# ==========================================================================
# Validate -- the part that makes this a corpus rather than a list
# ==========================================================================
def validate(recs):
    errs, warns = [], []

    counts = {}
    for r in recs:
        counts[r["stratum"]] = counts.get(r["stratum"], 0) + 1
    for st, (desc, want) in STRATA.items():
        got = counts.get(st, 0)
        if got != want:
            errs.append(f"{st}: expected {want} findings, got {got}")

    for r in recs:
        st, fid, cov = r["stratum"], r["finding_id"], r.get("range_covers_deployed")
        kev = r.get("kev", {}).get("listed")

        # Service/ecosystem consistency with the environment brief.
        pkg = r.get("package")
        if pkg and "/" in pkg:
            eco = pkg.split("/", 1)[0]
            allowed = SERVICE_ECOSYSTEM.get(r["service"], set())
            if eco not in allowed:
                errs.append(f"{fid} {eco} package on {r['service']}, which the brief "
                            f"says is {'/'.join(sorted(allowed))}")

        if st == "S1":
            if not kev:
                errs.append(f"{fid} S1 requires KEV-listed, {r['identifier']} is not")
            if cov is False:
                errs.append(f"{fid} S1 requires an affected deployed version; "
                            f"{r['deployed_version']} is outside the range")
            if cov is None:
                warns.append(f"{fid} S1 range undeterminable -- verify by hand")
        if st == "S2":
            if cov is True:
                errs.append(f"{fid} S2 requires the range to EXCLUDE "
                            f"{r['deployed_version']}, but it covers it")
            if cov is None:
                errs.append(f"{fid} S2 range undeterminable -- this stratum's whole "
                            f"point is a mechanically checkable Q5. Pick another CVE")
        if st == "S6":
            if not kev:
                errs.append(f"{fid} S6 requires KEV-listed, {r['identifier']} is not")
        if st == "S7":
            if kev:
                errs.append(f"{fid} S7 requires NOT KEV-listed, {r['identifier']} is")
        if st in ("S8", "S9") and r.get("evidence_source") != "rule_only":
            errs.append(f"{fid} {st} should be rule-based, not CVE-based")

    # Rule ids, checked against upstream rather than trusted.
    sg, gl = rule_registries()
    rule_recs = [r for r in recs if r.get("evidence_source") == "rule_only"]
    if sg is None and gl is None:
        warns.append(f"{len(rule_recs)} rule ids UNVERIFIED: registries unreachable. "
                     f"Re-run online before annotation")
    else:
        checked = missing = 0
        for r in rule_recs:
            src = {"semgrep": sg, "gitleaks": gl}.get(r["tool"])
            if src is None:
                warns.append(f"{r['finding_id']}: no registry for tool '{r['tool']}'")
                continue
            checked += 1
            if r["identifier"] not in src:
                missing += 1
                errs.append(f"{r['finding_id']} rule id not in the {r['tool']} registry: "
                            f"{r['identifier']}")
            else:
                r.pop("rule_verification", None)
                r["rule_verified_against"] = r["tool"] + " upstream registry"
        if not missing:
            warns.append(f"{checked} rule ids verified against upstream "
                         f"(semgrep-rules tree, gitleaks.toml)")
    return errs, warns


def packet(recs, meta):
    L = [f"# {CORPUS_VERSION} — annotation packet", "",
         f"KEV catalog `{meta['kev_catalog']}` · EPSS `{meta['epss_model_version']}` "
         f"as of `{meta['epss_as_of']}`", "",
         "Evidence is frozen at build time. Do not re-fetch during annotation: a corpus "
         "that reads live EPSS changes its own inputs between annotators, and after a "
         "model bump changes all of them (`exp-001`).", "",
         "Read the environment brief first (`v4-annotation-kit.md` §2).", ""]
    for r in recs:
        L.append(f"## {r['finding_id']}  ·  {r['service']}  ·  {r['class']}/{r['tool']}")
        L.append("")
        L.append(f"> {r['scanner_message']}")
        L.append("")
        if r.get("identifier", "").startswith("CVE-"):
            k = r["kev"]
            L.append(f"- **{r['identifier']}**"
                     + (f" (advisory `{r['advisory_id']}`)" if r.get("advisory_id") else ""))
            L.append(f"- Package: `{r['package']}` — **deployed `{r['deployed_version']}`** "
                     f"({r['dependency_scope']})")
            L.append(f"- CVSS: `{r.get('cvss_vector') or 'not published'}`")
            L.append(f"- EPSS: **{r['epss']['score']}** "
                     f"(pct {r['epss']['percentile']}, model `{r['epss']['model_version']}`)")
            L.append(f"- CISA KEV: **{'listed ' + k['date_added'] if k['listed'] else 'not listed'}**"
                     + (f", ransomware use: {k['ransomware']}" if k["listed"] else ""))
            rngs = "; ".join(
                " ".join(f"{list(e.items())[0][0]}={list(e.items())[0][1]}"
                         for e in rg["events"])
                for rg in r.get("affected_ranges", []) if rg.get("type") != "GIT") or "not published"
            L.append(f"- Affected ranges: {rngs}")
        else:
            L.append(f"- Rule: `{r['identifier']}` ({r['tool']})")
        if r.get("tool_reachability"):
            L.append(f"- Scanner reachability verdict: **{r['tool_reachability']}**")
        L.append("")
    return "\n".join(L)


def main():
    recs, meta = build()
    errs, warns = validate(recs)

    print("\n" + "=" * 72)
    print("VALIDATION")
    print("=" * 72)
    for w in warns:
        print(f"  WARN  {w}")
    for e in errs:
        print(f"  FAIL  {e}")
    if not errs:
        print("  All stratum assertions hold.")

    if errs:
        print("\nCorpus NOT emitted. A corpus whose strata do not hold is worse than")
        print("no corpus: the kappa it produces looks perfectly reasonable.")
        return 1
    if "--check" in sys.argv:
        print("\n--check: validation only, nothing emitted.")
        return 0

    here = os.path.dirname(os.path.abspath(__file__))
    body = json.dumps({"version": CORPUS_VERSION, "meta": meta, "findings": recs},
                      indent=2, sort_keys=True)
    h = hashlib.sha256(body.encode()).hexdigest()
    open(os.path.join(here, f"{CORPUS_VERSION}.json"), "w", encoding="utf-8").write(body)
    open(os.path.join(here, f"{CORPUS_VERSION}.md"), "w", encoding="utf-8").write(
        packet(recs, meta))
    print(f"\n  {CORPUS_VERSION}.json  sha256:{h}")
    print(f"  {CORPUS_VERSION}.md    annotation packet")
    print("\n  Record the hash in the V4 report. V2 and V3 reuse this corpus;")
    print("  a silent edit invalidates comparisons across all three.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
