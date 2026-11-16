"""Vulnerability triage engine - stage 1: normalize and deduplicate.

Reads the raw JSON reports from Semgrep, Trivy, Gitleaks and OWASP ZAP,
converts every finding into one common format, and merges duplicates.

Usage:  py triage.py sample-reports
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def load(folder, name):
    """Load one JSON report. Returns None if the file is missing."""
    path = Path(folder) / name
    if not path.exists():
        print(f"  (skipped: {name} not found)")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def finding(tool, category, title, severity, location, key, cve=None, cwe=None, detail=""):
    """Every scanner's finding is converted into this one shape."""
    return {
        "tool": tool,
        "category": category,
        "title": title,
        "severity": severity,
        "location": location,
        "cve": cve,
        "cwe": cwe,
        "detail": detail,
        "key": key,          # two findings with the same key are duplicates
        "occurrences": 1,
    }


def parse_semgrep(data):
    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
               "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        cwe = extra.get("metadata", {}).get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        line = r.get("start", {}).get("line")
        out.append(finding(
            tool="semgrep", category="SAST",
            title=r.get("check_id", "").split(".")[-1],
            severity=sev_map.get(str(extra.get("severity", "")).upper(), "MEDIUM"),
            location=f"{r.get('path')}:{line}",
            key=("semgrep", r.get("check_id"), r.get("path"), line),
            cwe=cwe, detail=extra.get("message", ""),
        ))
    return out


def parse_trivy(data):
    out = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            pkg, ver = v.get("PkgName"), v.get("InstalledVersion")
            sev = v.get("Severity", "MEDIUM").upper()
            out.append(finding(
                tool="trivy", category="SCA",
                title=f"{pkg} {ver}: {v.get('Title') or v.get('VulnerabilityID')}",
                severity=sev if sev in SEVERITY_ORDER else "INFO",
                location=result.get("Target", ""),
                key=("trivy", v.get("VulnerabilityID"), pkg, ver),
                cve=v.get("VulnerabilityID"),
                cwe=(v.get("CweIDs") or [None])[0],
                detail=f"Fixed in: {v.get('FixedVersion') or 'no fix yet'}",
            ))
    return out


def parse_gitleaks(data):
    out = []
    for g in data or []:
        # Never store the secret itself - keep only a short hash to spot repeats.
        secret_hash = hashlib.sha256(str(g.get("Secret", "")).encode()).hexdigest()[:12]
        out.append(finding(
            tool="gitleaks", category="Secrets",
            title=g.get("Description") or g.get("RuleID", "secret"),
            severity="HIGH",
            location=f"{g.get('File')}:{g.get('StartLine')}",
            key=("gitleaks", g.get("RuleID"), secret_hash),
            cwe="CWE-798", detail=f"Rule: {g.get('RuleID')}",
        ))
    return out


def parse_zap(data):
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            cweid = str(a.get("cweid", ""))
            out.append(finding(
                tool="zap", category="DAST",
                title=a.get("name") or a.get("alert", ""),
                severity=risk_map.get(str(a.get("riskcode")), "INFO"),
                location=site.get("@name", ""),
                key=("zap", a.get("pluginid"), site.get("@name")),
                cwe=f"CWE-{cweid}" if cweid.isdigit() and int(cweid) > 0 else None,
                detail=f"{a.get('count', '?')} affected URLs",
            ))
    return out


def deduplicate(findings):
    """Merge findings that share a key, counting how often each one appeared."""
    merged = {}
    for f in findings:
        if f["key"] in merged:
            merged[f["key"]]["occurrences"] += 1
        else:
            merged[f["key"]] = f
    return list(merged.values())


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "sample-reports"
    parsers = [("semgrep.json", parse_semgrep), ("trivy.json", parse_trivy),
               ("gitleaks.json", parse_gitleaks), ("zap.json", parse_zap)]

    print(f"Reading reports from: {folder}")
    raw = []
    for filename, parser in parsers:
        data = load(folder, filename)
        if data is not None:
            raw.extend(parser(data))

    unique = deduplicate(raw)
    unique.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))

    print(f"\nRaw findings:    {len(raw)}")
    print(f"After dedup:     {len(unique)}")
    if raw:
        print(f"Noise removed:   {100 * (len(raw) - len(unique)) / len(raw):.0f}%")

    print("\nBy tool (raw -> unique):")
    raw_count = Counter(f["tool"] for f in raw)
    uniq_count = Counter(f["tool"] for f in unique)
    for tool in raw_count:
        print(f"  {tool:<10} {raw_count[tool]:>4} -> {uniq_count[tool]:>4}")

    print("\nBy severity (unique):")
    sev_count = Counter(f["severity"] for f in unique)
    for sev in SEVERITY_ORDER:
        print(f"  {sev:<10} {sev_count.get(sev, 0):>4}")

    for f in unique:
        f.pop("key")
    with open("findings.json", "w", encoding="utf-8") as out:
        json.dump(unique, out, indent=2)
    print(f"\nSaved {len(unique)} findings to findings.json")


if __name__ == "__main__":
    main()