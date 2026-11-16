"""Vulnerability triage engine - stage 2: enrich, score and report.

Reads findings.json (made by triage.py), looks up every CVE in two public
threat-intelligence sources, gives each finding a 0-100 risk score, and
writes a prioritized report.

  EPSS (first.org) - probability a CVE is exploited in the next 30 days
  KEV  (cisa.gov)  - CVEs already being exploited in real attacks

Usage:  py enrich.py
"""
import json
import urllib.request
from collections import Counter

EPSS_URL = "https://api.first.org/data/v1/epss?cve="
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10, "INFO": 0}


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "vuln-triage-pipeline"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def get_kev():
    """Return the set of CVE IDs on the CISA Known Exploited Vulnerabilities list."""
    for url in KEV_URLS:
        try:
            data = fetch_json(url)
            return {v["cveID"] for v in data["vulnerabilities"]}
        except Exception as error:
            print(f"  KEV source failed ({error}), trying next...")
    print("  WARNING: could not download KEV list, continuing without it")
    return set()


def get_epss(cves):
    """Return {cve: probability} for a list of CVE IDs, asking 50 at a time."""
    scores = {}
    for i in range(0, len(cves), 50):
        batch = cves[i:i + 50]
        try:
            data = fetch_json(EPSS_URL + ",".join(batch))
            for row in data.get("data", []):
                scores[row["cve"]] = float(row["epss"])
        except Exception as error:
            print(f"  WARNING: EPSS lookup failed for one batch ({error})")
    return scores


TEST_PATH_MARKERS = ("test/", "tests/", "/test", ".test.", ".spec.", "cypress/", "__tests__")


def in_test_code(f):
    """True if the finding sits in test code rather than the real application."""
    location = f["location"].lower()
    return any(marker in location for marker in TEST_PATH_MARKERS)


def score(f):
    """Risk score from 0 to 100.

    severity   up to 40 points
    EPSS       up to 40 points (exploit probability x 40)
    KEV        20 points if already exploited in the wild
    Secrets    25 points, because a leaked credential needs no exploit
    Test code  minus 30 points: likely dummy data, not shipped to production
    """
    points = SEVERITY_POINTS[f["severity"]]
    points += (f.get("epss") or 0) * 40
    if f.get("kev"):
        points += 20
    if f["category"] == "Secrets":
        points += 25
    if in_test_code(f):
        points -= 30
    return round(max(0, min(points, 100)), 1)


def priority(f):
    if f.get("kev") or f["score"] >= 70:
        return "P1"
    if f["score"] >= 50:
        return "P2"
    if f["score"] >= 30:
        return "P3"
    return "P4"


def write_report(findings, counts):
    lines = [
        "# Vulnerability Triage Report",
        "",
        f"Total unique findings: **{len(findings)}**",
        "",
        "| Priority | Meaning | Count |",
        "|---|---|---|",
        f"| P1 | Fix now: actively exploited or very likely to be | {counts.get('P1', 0)} |",
        f"| P2 | Fix this sprint | {counts.get('P2', 0)} |",
        f"| P3 | Schedule | {counts.get('P3', 0)} |",
        f"| P4 | Backlog | {counts.get('P4', 0)} |",
        "",
        "## Top 15 findings",
        "",
        "| # | Priority | Score | Severity | Tool | Finding | EPSS | KEV |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for n, f in enumerate(findings[:15], start=1):
        epss = f"{f['epss'] * 100:.1f}%" if f.get("epss") is not None else "-"
        title = f["title"].replace("|", "/")[:70]
        lines.append(f"| {n} | {f['priority']} | {f['score']} | {f['severity']} | {f['tool']} "
                     f"| {title} | {epss} | {'YES' if f.get('kev') else '-'} |")
    with open("report.md", "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")


def main():
    with open("findings.json", encoding="utf-8") as f:
        findings = json.load(f)

    cves = sorted({f["cve"] for f in findings if f.get("cve") and f["cve"].startswith("CVE-")})
    print(f"Loaded {len(findings)} findings, {len(cves)} unique CVEs")

    print("Downloading CISA KEV list...")
    kev = get_kev()
    print(f"  {len(kev)} known exploited vulnerabilities")

    print("Looking up EPSS scores...")
    epss = get_epss(cves)
    print(f"  got scores for {len(epss)} CVEs")

    for f in findings:
        f["epss"] = epss.get(f.get("cve"))
        f["kev"] = f.get("cve") in kev
        f["score"] = score(f)
        f["priority"] = priority(f)
    findings.sort(key=lambda f: f["score"], reverse=True)

    counts = Counter(f["priority"] for f in findings)
    print("\nPriority breakdown:")
    for p in ["P1", "P2", "P3", "P4"]:
        print(f"  {p}  {counts.get(p, 0):>4}")
    print(f"\nOn the KEV list: {sum(1 for f in findings if f['kev'])}")

    print("\nTop 5:")
    for f in findings[:5]:
        print(f"  [{f['priority']}] {f['score']:>5}  {f['tool']:<8} {f['title'][:60]}")

    with open("prioritized.json", "w", encoding="utf-8") as out:
        json.dump(findings, out, indent=2)
    write_report(findings, counts)
    print("\nSaved prioritized.json and report.md")


if __name__ == "__main__":
    main()