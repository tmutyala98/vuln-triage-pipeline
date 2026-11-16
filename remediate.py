"""Vulnerability triage engine - stage 3: prepare AI remediation guidance.

Reads prioritized.json (made by enrich.py), picks the top distinct findings
and writes ai_prompt.txt. The pipeline then sends that prompt to an LLM
through GitHub's official actions/ai-inference action and appends the
answer to report.md.

No secret values are ever sent: triage.py only stores a hash of each secret.

Usage:  py remediate.py
"""
import json

TOP_N = 5
FIELDS = ("priority", "tool", "category", "title", "severity", "location", "cve", "cwe", "detail")

INSTRUCTIONS = """Write remediation guidance for each security finding listed below.
Be specific and brief. Do not invent details that are not in the finding.

For every finding, output exactly this Markdown and nothing else:

### [<priority>] <short title, at most 10 words>
Location: `<location>`
- **Risk:** one sentence on what an attacker could do.
- **Fix:** one or two sentences on the concrete change to make.
- **Verify:** one sentence on how to confirm the fix worked.
"""


def pick_top(findings, n):
    """Top n findings, skipping repeats of the same issue type."""
    seen, picked = set(), []
    for f in findings:
        kind = (f["tool"], f.get("cve") or f["title"].split(",")[0])
        if kind in seen:
            continue
        seen.add(kind)
        picked.append(f)
        if len(picked) == n:
            break
    return picked


def main():
    with open("prioritized.json", encoding="utf-8") as f:
        findings = json.load(f)

    top = pick_top(findings, TOP_N)
    facts = [{key: f.get(key) for key in FIELDS} for f in top]
    prompt = INSTRUCTIONS + "\nFindings:\n" + json.dumps(facts, indent=2) + "\n"

    with open("ai_prompt.txt", "w", encoding="utf-8") as out:
        out.write(prompt)
    print(f"Wrote ai_prompt.txt with {len(top)} findings:")
    for f in top:
        print(f"  [{f['priority']}] {f['title'].split(',')[0][:70]}")


if __name__ == "__main__":
    main()