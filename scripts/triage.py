#!/usr/bin/env python3
"""Normalize, deduplicate, enrich and prioritize security scanner findings.

Reads every report in a run folder (Semgrep/CodeQL SARIF, OSV-Scanner JSON,
Gitleaks JSON, Trivy JSON, optionally gzipped) and writes:

  <out>/findings.csv   one row per deduplicated finding
  <out>/summary.md     per-tool and per-priority counts

and appends a short summary to $GITHUB_STEP_SUMMARY when set.

Exit codes: 0 = no new P1, 1 = new P1 findings (the CI gate), 2 = bad input.
The prioritization formula is documented in docs/security/PRIORITIZATION.md.

Usage:
  scripts/triage.py security-reports/baseline
  scripts/triage.py reports/ --compare-to security-reports/baseline/findings.csv
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import fnmatch
import gzip
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests
import yaml

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}
SARIF_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
VULN_CATEGORIES = {"sca", "container"}

# Rules from different tools that report the same issue, so they deduplicate.
RULE_CLASS = {
    "DS-0002": "dockerfile-root-user",
    "DS002": "dockerfile-root-user",
    "dockerfile.security.missing-user.missing-user": "dockerfile-root-user",
    "dockerfile.security.missing-user-entrypoint.missing-user-entrypoint": "dockerfile-root-user",
}

# SAST classes that count as injection or auth findings for P2 (see PRIORITIZATION.md).
INJECTION_AUTH_CWES = {
    22, 23, 36, 73,            # path traversal / external control of file name
    77, 78, 88,                # command injection
    79, 80,                    # XSS
    89, 90, 643, 917, 1336,    # SQL / LDAP / XPath / expression / template injection
    94, 95,                    # code injection
    502, 611, 918,             # deserialization, XXE, SSRF
    284, 285, 287, 306, 639, 798, 862, 863,  # access control, authn, hardcoded credentials
}


@dataclasses.dataclass
class Finding:
    tool: str
    category: str                 # sast | sca | secret | container | iac
    rule_or_cve: str
    severity: str
    file_or_package: str
    line_or_version: str = ""
    fixed_version: str = ""
    description: str = ""
    aliases: set = dataclasses.field(default_factory=set)
    ecosystem: str = ""           # pypi | deb | npm ... (vulnerability findings only)
    location: set = dataclasses.field(default_factory=set)   # manifest path or image
    origin: set = dataclasses.field(default_factory=set)     # app-dep | app-os | base-os | base-lang
    fix_status: str = ""          # fixed | no-fix | unknown
    inferred: bool = False        # OSV inferred-transitive (not listed in the manifest)
    cwe: set = dataclasses.field(default_factory=set)
    cvss: float | None = None
    fingerprint: str = ""
    reported_by: list = dataclasses.field(default_factory=list)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool | None = None
    priority: str = ""
    triage_status: str = "open"
    triage_reason: str = ""
    new: bool = False

    @property
    def cves(self) -> set:
        return {a for a in self.aliases | {self.rule_or_cve} if a.startswith("CVE-")}

    @property
    def canonical_id(self) -> str:
        return min(self.cves) if self.cves else self.rule_or_cve

    @property
    def rule_class(self) -> str:
        if self.rule_or_cve in RULE_CLASS:
            return RULE_CLASS[self.rule_or_cve]
        if self.category == "sast" and self.cwe:
            return min(self.cwe)
        return self.rule_or_cve

    def dedup_key(self) -> tuple:
        if self.category in VULN_CATEGORIES:
            return ("vuln", self.ecosystem, norm_pkg(self.file_or_package))
        if self.category == "iac":
            return ("iac", self.rule_class, self.file_or_package)
        if self.category == "secret":
            return ("secret", self.file_or_package, self.line_or_version)
        return ("sast", self.rule_class, self.file_or_package, self.line_or_version)

    @property
    def id(self) -> str:
        if self.category in VULN_CATEGORIES:
            parts = ["vuln", self.ecosystem, norm_pkg(self.file_or_package), self.canonical_id]
        elif self.category == "sast" and self.fingerprint:
            parts = ["sast", self.rule_class, self.file_or_package, self.fingerprint]
        else:
            parts = list(self.dedup_key())
        return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


# ---------------------------------------------------------------- helpers

def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def norm_path(path: str, strip: list[str]) -> str:
    path = path.replace("\\", "/")
    if path.startswith("file://"):
        path = path[len("file://"):]
    for prefix in strip:
        prefix = prefix.replace("\\", "/").rstrip("/") + "/"
        if path.startswith(prefix):
            return path[len(prefix):]
    return path[2:] if path.startswith("./") else path


def band(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def max_sev(*sevs: str) -> str:
    return max(sevs, key=lambda s: SEV_RANK.get(s, 0))


def version_key(v: str) -> list:
    """Loose version ordering: numbers > end of version > letters ("1.0b1" < "1.0" < "1.0.1")."""
    key = []
    for tok in re.findall(r"\d+|[a-z]+", v.lower()):
        key.append((2, int(tok), "") if tok.isdigit() else (0, 0, tok))
    return key + [(1, 0, "")]


def load_json(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- parsers

def parse_sarif(data: dict, strip: list[str]) -> list[Finding]:
    out = []
    for run in data.get("runs", []):
        driver = run["tool"]["driver"]
        name = driver.get("name", "").lower()
        tool = "codeql" if "codeql" in name else "semgrep" if "semgrep" in name else name or "sarif"
        rules = {r["id"]: r for r in driver.get("rules", [])}
        for ext in run["tool"].get("extensions", []):
            rules.update({r["id"]: r for r in ext.get("rules", [])})
        for res in run.get("results", []):
            rule = rules.get(res["ruleId"], {})
            props = rule.get("properties", {})
            loc = res["locations"][0]["physicalLocation"]
            path = norm_path(loc["artifactLocation"]["uri"], strip)
            line = str(loc.get("region", {}).get("startLine", ""))
            if "security-severity" in props:
                sev = band(float(props["security-severity"]))
            else:
                sev = SARIF_LEVEL.get(res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning"), "MEDIUM")
            cwe = {int(m) for t in props.get("tags", []) for m in re.findall(r"\bCWE-(\d+)", t, re.I)}
            base = Path(path).name.lower()
            is_docker = base.startswith("dockerfile") or base.endswith(".dockerfile")
            fp = (res.get("partialFingerprints") or {}).get("primaryLocationLineHash", "")
            out.append(Finding(
                tool=tool, category="iac" if is_docker or res["ruleId"].startswith("dockerfile.") else "sast",
                rule_or_cve=res["ruleId"], severity=sev, file_or_package=path, line_or_version=line,
                description=res.get("message", {}).get("text", "")[:300], cwe=cwe, fingerprint=fp,
            ))
    return out


def osv_fixed_version(vulns: list[dict], pkg: str, version: str) -> str:
    """Lowest 'fixed' event above the installed version, across the group's advisories."""
    fixes = []
    for v in vulns:
        for aff in v.get("affected", []):
            if norm_pkg(aff.get("package", {}).get("name", "")) != norm_pkg(pkg):
                continue
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev and version_key(ev["fixed"]) > version_key(version):
                        fixes.append(ev["fixed"])
    return min(fixes, key=version_key) if fixes else ""


def parse_osv(data: dict, strip: list[str]) -> list[Finding]:
    out = []
    for res in data.get("results", []):
        src = norm_path(res["source"]["path"], strip)
        inferred = res["source"].get("type") != "lockfile"
        for p in res.get("packages", []):
            pkg = p["package"]
            vulns = {v["id"]: v for v in p.get("vulnerabilities", [])}
            for g in p.get("groups", []):
                members = [vulns[i] for i in g["ids"] if i in vulns]
                fixed = osv_fixed_version(members, pkg["name"], pkg.get("version", ""))
                score = float(g["max_severity"]) if g.get("max_severity") else None
                out.append(Finding(
                    tool="osv-scanner", category="sca", rule_or_cve=g["ids"][0],
                    severity=band(score), file_or_package=pkg["name"],
                    line_or_version=pkg.get("version", ""), fixed_version=fixed,
                    description=(members[0].get("summary") or members[0].get("details", ""))[:300] if members else "",
                    aliases=set(g["ids"]) | set(g.get("aliases", [])),
                    ecosystem=pkg.get("ecosystem", "").lower(), location={src}, origin={"app-dep"},
                    fix_status="fixed" if fixed else "no-fix", inferred=inferred, cvss=score,
                ))
    return out


def parse_gitleaks(data: list, strip: list[str]) -> list[Finding]:
    return [Finding(
        tool="gitleaks", category="secret", rule_or_cve=leak["RuleID"], severity="HIGH",
        file_or_package=norm_path(leak["File"], strip), line_or_version=str(leak.get("StartLine", "")),
        description=f'{leak.get("Description", "")} (commit {leak.get("Commit", "")[:8]})',
        fingerprint=leak.get("Fingerprint", ""),
    ) for leak in data or []]


def trivy_cvss(cvss: dict) -> float | None:
    scores = {vendor: v.get("V3Score") or v.get("V40Score") for vendor, v in (cvss or {}).items()}
    scores = {k: s for k, s in scores.items() if s}
    for vendor in ("nvd", "ghsa"):
        if vendor in scores:
            return float(scores[vendor])
    return float(max(scores.values())) if scores else None


TRIVY_ECOSYSTEM = {"python-pkg": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi",
                   "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm"}


def parse_trivy(data: dict, name: str, base_images: dict, strip: list[str]) -> list[Finding]:
    image = data.get("ArtifactType") == "container_image"
    tool = "trivy-image" if image else "trivy-config" if "config" in name else "trivy-fs"
    base_layers = None
    if image:
        info = base_images.get(data.get("ArtifactName", ""))
        diff_ids = data.get("Metadata", {}).get("DiffIDs", [])
        if info and diff_ids[:len(info["base_diff_ids"])] == info["base_diff_ids"]:
            base_layers = set(info["base_diff_ids"])
        else:
            print(f"warning: no verified base-image layers for {data.get('ArtifactName')}; "
                  "origin will be 'unknown'", file=sys.stderr)
    out = []
    for res in data.get("Results", []):
        target = data.get("ArtifactName", "") if image else norm_path(res["Target"], strip)
        os_pkgs = res.get("Class") == "os-pkgs"
        for v in res.get("Vulnerabilities") or []:
            if not image:
                origin = "app-dep"
            elif base_layers is None:
                origin = "unknown"
            else:
                in_base = v.get("Layer", {}).get("DiffID") in base_layers
                origin = ("base-" if in_base else "app-") + ("os" if os_pkgs else "lang")
                origin = "app-dep" if origin == "app-lang" else origin
            status = v.get("Status", "")
            score = trivy_cvss(v.get("CVSS"))
            out.append(Finding(
                tool=tool, category="container" if image else "sca", rule_or_cve=v["VulnerabilityID"],
                severity=v.get("Severity", "UNKNOWN"), file_or_package=v["PkgName"],
                line_or_version=v.get("InstalledVersion", ""), fixed_version=v.get("FixedVersion", ""),
                description=(v.get("Title") or v.get("Description", ""))[:300],
                # Not VendorIDs: one Debian DSA/DLA covers many distinct CVEs, so
                # treating it as an alias would merge unrelated vulnerabilities.
                aliases={v["VulnerabilityID"]},
                ecosystem=res.get("Type", "") if os_pkgs else TRIVY_ECOSYSTEM.get(res.get("Type", ""), res.get("Type", "")),
                location={target}, origin={origin},
                fix_status="fixed" if status == "fixed" or (not status and v.get("FixedVersion")) else "no-fix" if status else "unknown",
                cwe={int(c.split("-")[1]) for c in v.get("CweIDs") or [] if c.upper().startswith("CWE-")},
                cvss=score,
            ))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            out.append(Finding(
                tool=tool, category="iac", rule_or_cve=m["ID"], severity=m.get("Severity", "UNKNOWN"),
                file_or_package=target, line_or_version=str((m.get("CauseMetadata") or {}).get("StartLine") or ""),
                description=m.get("Title", "")[:300],
            ))
        for s in res.get("Secrets") or []:
            out.append(Finding(
                tool=tool, category="secret", rule_or_cve=s["RuleID"], severity=s.get("Severity", "UNKNOWN"),
                file_or_package=target, line_or_version=str(s.get("StartLine", "")), description=s.get("Title", ""),
            ))
    return out


def load_reports(report_dir: Path, strip: list[str]) -> list[Finding]:
    base_file = report_dir / "base-images.json"
    base_images = load_json(base_file) if base_file.exists() else {}
    findings = []
    for path in sorted(report_dir.iterdir()):
        name = path.name.lower()
        stem = name[:-3] if name.endswith(".gz") else name
        if stem.endswith(".sarif"):
            findings += parse_sarif(load_json(path), strip)
        elif stem.startswith("osv") and stem.endswith(".json"):
            findings += parse_osv(load_json(path), strip)
        elif stem.startswith("gitleaks") and stem.endswith(".json"):
            findings += parse_gitleaks(load_json(path), strip)
        elif stem.startswith("trivy") and stem.endswith(".json"):
            findings += parse_trivy(load_json(path), stem, base_images, strip)
    return findings


# ---------------------------------------------------------------- dedup

def merge(group: list[Finding]) -> Finding:
    f = dataclasses.replace(group[0], aliases=set(), location=set(), origin=set(), cwe=set(), reported_by=[])
    versions, fixes = [], []
    for g in group:
        f.aliases |= g.aliases | {g.rule_or_cve}
        f.location |= g.location
        f.origin |= g.origin
        f.cwe |= g.cwe
        f.severity = max_sev(f.severity, g.severity)
        if g.cvss is not None and (f.cvss is None or g.cvss > f.cvss):
            f.cvss = g.cvss
        for lst, val in ((versions, g.line_or_version), (fixes, g.fixed_version)):
            if val and val not in lst:
                lst.append(val)
        if g.tool not in f.reported_by:
            f.reported_by.append(g.tool)
        f.fingerprint = f.fingerprint or g.fingerprint
    f.line_or_version = "; ".join(versions)
    f.fixed_version = "; ".join(fixes)
    f.inferred = all(g.inferred for g in group)
    statuses = {g.fix_status for g in group}
    f.fix_status = "fixed" if "fixed" in statuses else "no-fix" if "no-fix" in statuses else group[0].fix_status
    if any(g.category == "sca" for g in group):
        f.category = "sca"
    f.rule_or_cve = f.canonical_id
    f.aliases.discard(f.rule_or_cve)
    return f


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Same advisory (by any shared ID/alias) on the same package; or same rule class at the same place."""
    merged = []
    by_key = defaultdict(list)
    for f in findings:
        by_key[f.dedup_key()].append(f)
    for key, group in by_key.items():
        if key[0] != "vuln":
            # A secret or SAST location reported by several rules is one finding per rule class.
            merged.append(merge(group))
            continue
        # Union-find over shared advisory IDs within one package.
        parent = list(range(len(group)))

        def root(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i
        seen = {}
        for i, f in enumerate(group):
            for a in f.aliases | {f.rule_or_cve}:
                if a in seen:
                    parent[root(i)] = root(seen[a])
                else:
                    seen[a] = i
        clusters = defaultdict(list)
        for i, f in enumerate(group):
            clusters[root(i)].append(f)
        merged += [merge(c) for c in clusters.values()]
    return merged


# ---------------------------------------------------------------- enrichment

def _cache_load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def fetch_epss(cves: set, cache_dir: Path, offline: bool, max_age_days: int = 7) -> dict:
    """EPSS per CVE, cached in <cache>/epss.json; entries older than max_age_days are refetched."""
    path = cache_dir / "epss.json"
    cache = _cache_load(path)
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max_age_days)).isoformat()
    todo = sorted(c for c in cves if c not in cache or cache[c].get("fetched", "") < cutoff)
    if todo and not offline:
        session = requests.Session()
        for i in range(0, len(todo), 100):
            batch = todo[i:i + 100]
            try:
                r = session.get(EPSS_URL, params={"cve": ",".join(batch), "limit": 100}, timeout=30)
                r.raise_for_status()
                now = dt.datetime.now(dt.timezone.utc).isoformat()
                got = {d["cve"]: d for d in r.json().get("data", [])}
                for c in batch:
                    d = got.get(c)
                    cache[c] = {"epss": float(d["epss"]) if d else None,
                                "percentile": float(d["percentile"]) if d else None,
                                "date": d["date"] if d else None, "fetched": now}
            except (requests.RequestException, ValueError, KeyError) as e:
                print(f"warning: EPSS lookup failed ({e}); continuing without it", file=sys.stderr)
                break
            time.sleep(0.2)
        cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, indent=0, sort_keys=True), encoding="utf-8")
    return cache


def fetch_kev(cache_dir: Path, offline: bool, max_age_hours: int = 24) -> dict | None:
    """CISA KEV catalog, cached in <cache>/kev.json. None if unavailable."""
    path = cache_dir / "kev.json"
    fresh = path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600
    if not offline and not fresh:
        try:
            r = requests.get(KEV_URL, timeout=60)
            r.raise_for_status()
            r.json()
            cache_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(r.text, encoding="utf-8")
        except (requests.RequestException, ValueError) as e:
            print(f"warning: KEV download failed ({e})", file=sys.stderr)
    return _cache_load(path) or None


def enrich(findings: list[Finding], cache_dir: Path, offline: bool) -> dict:
    cves = set().union(*(f.cves for f in findings)) if findings else set()
    epss = fetch_epss(cves, cache_dir, offline)
    kev = fetch_kev(cache_dir, offline)
    kev_ids = {v["cveID"] for v in kev["vulnerabilities"]} if kev else None
    for f in findings:
        scores = [epss[c] for c in f.cves if c in epss and epss[c].get("epss") is not None]
        if scores:
            top = max(scores, key=lambda s: s["epss"])
            f.epss, f.epss_percentile = top["epss"], top["percentile"]
        if f.cves:
            f.kev = bool(f.cves & kev_ids) if kev_ids is not None else None
    dates = sorted({epss[c]["date"] for c in cves if c in epss and epss[c].get("date")})
    return {
        "cves": len(cves),
        "epss_scored": sum(1 for c in cves if epss.get(c, {}).get("epss") is not None),
        "epss_dates": dates,
        "kev_version": kev.get("catalogVersion") if kev else None,
        "kev_released": kev.get("dateReleased") if kev else None,
    }


# ---------------------------------------------------------------- triage + priority

TRIAGE_STATUSES = {"false_positive", "accepted_risk", "confirmed_live"}


def load_triage(path: Path) -> list[dict]:
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    decisions = doc.get("decisions") or []
    for i, d in enumerate(decisions):
        where = f"{path}: decision {i + 1}"
        if not isinstance(d, dict):
            raise ValueError(f"{where}: must be a mapping")
        if d.get("status") not in TRIAGE_STATUSES:
            raise ValueError(f"{where}: status must be one of {sorted(TRIAGE_STATUSES)}")
        if not str(d.get("reason", "")).strip():
            raise ValueError(f"{where}: every decision needs a one-line reason")
        if not d.get("id") and not d.get("rule_or_cve"):
            raise ValueError(f"{where}: give an 'id' or a 'rule_or_cve'")
        if any(ch in str(d.get("rule_or_cve", "")) for ch in "*?["):
            raise ValueError(f"{where}: wildcards in rule_or_cve are blanket ignores and are not allowed")
    return decisions


def apply_triage(findings: list[Finding], decisions: list[dict], today: dt.date) -> list[str]:
    notes = []
    for d in decisions:
        expires = d.get("expires")
        if expires and dt.date.fromisoformat(str(expires)) < today:
            notes.append(f"expired (ignored): {d.get('id') or d.get('rule_or_cve')} - {d['reason']}")
            continue
        hits = 0
        for f in findings:
            if d.get("id") and d["id"] != f.id:
                continue
            if d.get("rule_or_cve") and d["rule_or_cve"] not in f.aliases | {f.rule_or_cve}:
                continue
            if d.get("file_or_package") and not fnmatch.fnmatch(f.file_or_package, d["file_or_package"]):
                continue
            f.triage_status, f.triage_reason = d["status"], str(d["reason"]).strip()
            hits += 1
        if not hits:
            notes.append(f"matched nothing: {d.get('id') or d.get('rule_or_cve')}")
    return notes


def prioritize(f: Finding, app_paths: list[str]) -> str:
    if f.kev or (f.category == "secret" and f.triage_status == "confirmed_live"):
        return "P1"
    if f.cvss is not None and f.cvss >= 9 and (f.epss or 0) >= 0.1:
        return "P1"
    if f.cvss is not None and f.cvss >= 7:
        return "P2"
    if f.cvss is None and f.severity in ("CRITICAL", "HIGH"):
        return "P2"
    reachable = any(f.file_or_package.startswith(p) for p in app_paths)
    if f.category == "sast" and reachable and f.cwe & INJECTION_AUTH_CWES:
        return "P2"
    return "P3"


# ---------------------------------------------------------------- reporting

CSV_FIELDS = ["id", "tool", "reported_by", "category", "rule_or_cve", "aliases", "severity", "cvss",
              "epss", "epss_percentile", "kev", "priority", "file_or_package", "line_or_version",
              "fixed_version", "fix_status", "origin", "inferred", "location", "triage_status",
              "triage_reason", "new", "description"]


def write_csv(findings: list[Finding], path: Path) -> None:
    order = {"P1": 0, "P2": 1, "P3": 2}
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, CSV_FIELDS)
        w.writeheader()
        for f in sorted(findings, key=lambda f: (order[f.priority], -(f.cvss or 0), f.file_or_package, f.rule_or_cve)):
            w.writerow({
                "id": f.id, "tool": f.tool, "reported_by": ";".join(f.reported_by), "category": f.category,
                "rule_or_cve": f.rule_or_cve, "aliases": ";".join(sorted(f.aliases)), "severity": f.severity,
                "cvss": "" if f.cvss is None else f.cvss, "epss": "" if f.epss is None else f.epss,
                "epss_percentile": "" if f.epss_percentile is None else f.epss_percentile,
                "kev": "" if f.kev is None else f.kev, "priority": f.priority,
                "file_or_package": f.file_or_package, "line_or_version": f.line_or_version,
                "fixed_version": f.fixed_version, "fix_status": f.fix_status,
                "origin": ";".join(sorted(f.origin)), "inferred": f.inferred if f.category in VULN_CATEGORIES else "",
                "location": ";".join(sorted(f.location)), "triage_status": f.triage_status,
                "triage_reason": f.triage_reason, "new": f.new, "description": f.description,
            })


def tool_metrics(raw: list[Finding]) -> dict:
    """Per-tool headline numbers. Vulnerability tools count unique (package, advisory) pairs,
    not raw entries; other tools count unique findings after same-tool dedup."""
    by_tool = defaultdict(list)
    for f in raw:
        by_tool[f.tool].append(f)
    metrics = {}
    for tool, items in sorted(by_tool.items()):
        vulns = [f for f in items if f.category in VULN_CATEGORIES]
        other = deduplicate([f for f in items if f.category not in VULN_CATEGORIES])
        pairs = defaultdict(list)
        for f in vulns:
            pairs[(f.ecosystem, norm_pkg(f.file_or_package), f.canonical_id)].append(f)
        sev, fix, origin, inferred = Counter(), Counter(), Counter(), Counter()
        for group in pairs.values():
            sev[max_sev(*(g.severity for g in group))] += 1
            fix["fixed" if any(g.fix_status == "fixed" for g in group) else "no-fix"] += 1
            for o in set().union(*(g.origin for g in group)):
                origin[o] += 1
            inferred["inferred" if all(g.inferred for g in group) else "direct"] += 1
        for f in other:
            sev[f.severity] += 1
        metrics[tool] = {
            "raw_entries": len(items),
            "advisories": len({f.canonical_id for f in vulns}),
            "pairs": len(pairs),
            "other": len(other),
            "severity": sev, "fix": fix, "origin": origin, "inferred": inferred,
        }
    return metrics


def table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def render_summary(run: str, metrics: dict, findings: list[Finding], meta: dict, notes: list[str]) -> tuple[str, str]:
    open_f = [f for f in findings if f.triage_status in ("open", "confirmed_live")]
    tools = list(metrics)
    vuln_rows, sev_rows = [], []
    for t in tools:
        m = metrics[t]
        if m["pairs"]:
            vuln_rows.append([t, m["advisories"], m["pairs"], m["fix"]["fixed"], m["fix"]["no-fix"],
                              m["origin"]["app-dep"], m["origin"]["app-os"], m["origin"]["base-os"],
                              m["origin"]["base-lang"], m["origin"]["unknown"],
                              m["inferred"]["inferred"], m["raw_entries"]])
        sev_rows.append([t] + [m["severity"][s] for s in SEVERITIES] + [sum(m["severity"].values())])
    prio = Counter(f.priority for f in open_f)
    prio_rows = []
    for p in ("P1", "P2", "P3"):
        fs = [f for f in open_f if f.priority == p]
        cats = Counter(f.category for f in fs)
        advisories = {f.canonical_id for f in fs if f.category in VULN_CATEGORIES}
        prio_rows.append([p, len(fs), len(advisories), sum(f.new for f in fs), cats["sast"], cats["sca"],
                          cats["container"], cats["iac"], cats["secret"], sum(f.fix_status == "fixed" for f in fs),
                          sum(f.inferred for f in fs)])
    multi = sum(1 for f in findings if len(f.reported_by) > 1)
    triaged = Counter(f.triage_status for f in findings if f.triage_status not in ("open", "confirmed_live"))
    new_p1 = [f for f in open_f if f.priority == "P1" and f.new]

    md = [f"# Triage summary: {run}", "",
          f"Generated {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M} UTC by `scripts/triage.py`. "
          "Formula: `docs/security/PRIORITIZATION.md`.", "",
          "## Vulnerabilities per tool (unique package + advisory pairs)", "",
          "Headline unit is a unique (package, advisory) pair per tool: the same advisory on the same "
          "package counts once, however many manifests, images or layers report it. "
          "Raw entries are shown only for traceability.", "",
          table(["Tool", "Unique advisory IDs", "Unique (pkg, advisory)", "Fixable", "No fix",
                 "App deps", "App-added OS pkgs", "Base-image OS pkgs", "Base-image lang pkgs",
                 "Origin unknown", "OSV inferred-transitive", "Raw entries"], vuln_rows) if vuln_rows else "_None._", "",
          "## Severity per tool (unique)", "",
          table(["Tool"] + [s.title() for s in SEVERITIES] + ["Total"], sev_rows), "",
          "## Priority (deduplicated across tools, open findings)", "",
          "A finding is one (package, advisory) pair, or one rule class at one location. "
          "*OSV inferred-only*: reported only from OSV-Scanner's inferred transitive versions and not "
          "confirmed by any scan of an installed package; check the installed version before acting.", "",
          table(["Priority", "Findings", "Unique advisories", "New", "SAST", "SCA", "Container", "IaC",
                 "Secret", "Fixable", "OSV inferred-only"], prio_rows), "",
          f"Deduplicated findings: {len(findings)} ({multi} reported by more than one tool). "
          f"Triaged out: {dict(triaged) or 0}.", "",
          "## Enrichment", "",
          f"- CVEs: {meta['cves']}, with an EPSS score: {meta['epss_scored']} "
          f"(EPSS dates: {', '.join(meta['epss_dates']) or 'n/a'})",
          f"- CISA KEV catalog: {meta['kev_version'] or 'NOT AVAILABLE: KEV status unknown'}"
          + (f" (released {meta['kev_released']})" if meta['kev_released'] else ""),
          f"- KEV matches: {sum(1 for f in findings if f.kev)}", ""]
    if notes:
        md += ["## Triage file notes", ""] + [f"- {n}" for n in notes] + [""]
    if new_p1:
        md += ["## New P1 findings", "", table(["ID", "Rule/CVE", "Package/file", "Why"], [
            [f.id, f.rule_or_cve, f.file_or_package,
             "KEV" if f.kev else "confirmed live secret" if f.category == "secret" else f"CVSS {f.cvss}, EPSS {f.epss}"]
            for f in new_p1]), ""]
    short = ["### Security triage: " + run, "",
             table(["Priority", "Open", "New"], [[p, prio[p], sum(f.new for f in open_f if f.priority == p)] for p in ("P1", "P2", "P3")]),
             "", f"New P1: **{len(new_p1)}**" + (" (gate fails)" if new_p1 else " (gate passes)"), ""]
    return "\n".join(md), "\n".join(short)


# ---------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", type=Path, help="folder with scanner reports")
    ap.add_argument("--out", type=Path, help="output folder (default: the reports folder)")
    ap.add_argument("--triage-file", type=Path, default=Path(".security/triage.yaml"))
    ap.add_argument("--compare-to", type=Path,
                    help="previous findings.csv; findings not in it at the same or higher priority are 'new'")
    ap.add_argument("--cache-dir", type=Path, default=Path("security-reports/cache"))
    ap.add_argument("--offline", action="store_true", help="use cached EPSS/KEV only")
    ap.add_argument("--strip-prefix", action="append", default=["/src"],
                    help="path prefix to remove from reported paths (repeatable; $GITHUB_WORKSPACE is added)")
    ap.add_argument("--app-path", action="append", default=None,
                    help="path prefix of shipped app code, for SAST reachability (default: p2p/)")
    args = ap.parse_args(argv)

    strip = args.strip_prefix + ([os.environ["GITHUB_WORKSPACE"]] if os.environ.get("GITHUB_WORKSPACE") else [])
    app_paths = args.app_path or ["p2p/"]
    out = args.out or args.reports
    try:
        decisions = load_triage(args.triage_file)
        raw = load_reports(args.reports, strip)
    except (ValueError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    metrics = tool_metrics(raw)
    findings = deduplicate(raw)
    meta = enrich(findings, args.cache_dir, args.offline)
    notes = apply_triage(findings, decisions, dt.date.today())
    # A finding is "new" unless the comparison run already had it at the same or a
    # higher priority, so a known P2 that becomes P1 (e.g. newly on KEV) is new.
    previous = {}
    if args.compare_to:
        with open(args.compare_to, newline="", encoding="utf-8") as fh:
            previous = {row["id"]: row["priority"] for row in csv.DictReader(fh)}
    for f in findings:
        f.priority = prioritize(f, app_paths)
        f.new = f.id not in previous or previous[f.id] > f.priority

    out.mkdir(parents=True, exist_ok=True)
    write_csv(findings, out / "findings.csv")
    summary, short = render_summary(args.reports.name, metrics, findings, meta, notes)
    (out / "summary.md").write_text(summary, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(short + "\n")
    print(short)

    new_p1 = [f for f in findings if f.priority == "P1" and f.new and f.triage_status in ("open", "confirmed_live")]
    return 1 if new_p1 else 0


if __name__ == "__main__":
    sys.exit(main())
