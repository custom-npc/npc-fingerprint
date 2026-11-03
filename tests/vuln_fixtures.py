"""Builds a small but realistic vulnerability database (NVD-shaped rows + KEV/EPSS/Exploit-DB/Nuclei) and a fake OSV record."""
from __future__ import annotations

import gzip
import io
import json
import pathlib
import tempfile

from npc_fingerprint.vulns import db, enrich, nvd

METRICS_HIGH = {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]}


def cfg(*matches):
    return [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": list(matches)}]}]


def m(criteria, **kw):
    return {"vulnerable": True, "criteria": criteria, **kw}


def item(cid, desc, configs=None, status="Analyzed", pub="2020-01-01T00:00:00", metrics=None):
    cve = {"id": cid, "published": pub, "vulnStatus": status, "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics or {}}
    if configs is not None:
        cve["configurations"] = configs
    return {"cve": cve}


NVD_ITEMS = [
    item("CVE-2020-1927", "mod_rewrite open redirect in Apache HTTP Server 2.4.0 to 2.4.41",
         cfg(m("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionStartIncluding="2.4.0", versionEndIncluding="2.4.41")), metrics=METRICS_HIGH),
    item("CVE-2021-41773", "Path traversal in Apache HTTP Server 2.4.49", cfg(m("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")), metrics=METRICS_HIGH, pub="2021-10-05T00:00:00"),
    item("CVE-2019-0211", "Privilege escalation Apache 2.4.17 to 2.4.38",
         cfg(m("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionStartIncluding="2.4.17", versionEndIncluding="2.4.38")), metrics=METRICS_HIGH, pub="2019-04-08T00:00:00"),
    item("CVE-2019-11043", "PHP-FPM remote code execution in PHP 7.1 before 7.1.33, 7.2 before 7.2.24, 7.3 before 7.3.11",
         cfg(m("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding="7.3.0", versionEndExcluding="7.3.11"),
             m("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding="7.2.0", versionEndExcluding="7.2.24")), metrics=METRICS_HIGH, pub="2019-10-28T00:00:00"),
    item("CVE-2025-1111", "A flaw in nginx before 1.27.1 allows request smuggling", None, status="Awaiting Analysis", pub="2025-06-01T00:00:00"),
]


def make_vuln_db(directory: str | pathlib.Path | None = None) -> pathlib.Path:
    d = pathlib.Path(directory or tempfile.mkdtemp(prefix="npcfp-vdb-"))
    con = db.connect(d, create=True)
    nvd.ingest(con, io.BytesIO(json.dumps({"vulnerabilities": NVD_ITEMS}).encode()), nvd.wanted_products({}))
    kev = {"vulnerabilities": [{"cveID": f"CVE-2021-{i:05d}", "dateAdded": "2021-11-03", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown",
                                "vulnerabilityName": "x", "requiredAction": "Apply updates"} for i in range(40000, 40200)]
           + [{"cveID": "CVE-2021-41773", "dateAdded": "2021-11-03", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Apache path traversal", "requiredAction": "Apply updates."},
              {"cveID": "CVE-2020-1927", "dateAdded": "2022-05-01", "dueDate": "2022-05-22", "knownRansomwareCampaignUse": "Unknown", "vulnerabilityName": "Apache open redirect", "requiredAction": "Apply updates."}]}
    enrich.load_kev(con, json.dumps(kev).encode())
    epss = "#model_version:v2025.03.14,score_date:2026-10-29T00:00:00Z\ncve,epss,percentile\n" + "\n".join(f"CVE-2020-{i:05d},0.001,0.1" for i in range(2000))
    epss += "\nCVE-2020-11022,0.31,0.97\nCVE-2020-11023,0.04,0.8\nCVE-2019-0211,0.12,0.95\nCVE-2019-11043,0.97,0.999\n"
    enrich.load_epss(con, gzip.compress(epss.encode()))
    enrich.load_exploitdb(con, "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes\n47688,x,Apache - Privesc,2019-04-08,a,local,linux,,,,1,CVE-2019-0211\n")
    enrich.load_nuclei(con, '{"ID":"CVE-2021-41773","Info":{"Name":"Apache path traversal","Severity":"high"},"file_path":"http/cves/2021/CVE-2021-41773.yaml"}\n'
                            '{"ID":"CVE-2020-1927","Info":{"Name":"Apache mod_rewrite open redirect","Severity":"medium"},"file_path":"http/cves/2020/CVE-2020-1927.yaml"}\n',
                       json.dumps({"tags": [{"name": "apache", "count": 143}, {"name": "php", "count": 210}, {"name": "wordpress", "count": 1102}, {"name": "jquery", "count": 14}, {"name": "graphql", "count": 22}]}))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at','2026-10-30T00:00:00Z'),('kev_count','202'),('epss_count','2004'),('nuclei_templates','2'),('nvd_years','2010-2026')")
    con.commit()
    con.close()
    return d


def osv_jquery_vulns():
    mk = lambda i, cve, fixed: {  # noqa: E731
        "id": i, "aliases": [cve], "summary": "XSS in jQuery htmlPrefilter", "published": "2020-04-29T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}], "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"name": "jquery", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": fixed}]}]}],
        "references": [{"type": "ADVISORY", "url": f"https://github.com/advisories/{i}"}]}
    return [mk("GHSA-gxr4-xjj5-5px2", "CVE-2020-11022", "3.5.0"), mk("GHSA-jpcq-cgw6-v4j6", "CVE-2020-11023", "3.5.0")]
