"""Vulnerability triage engine - stage 3: AI-drafted remediation guidance.

Reads prioritized.json (made by enrich.py), picks the top distinct findings,
asks an LLM for short fix guidance on each, and appends it to report.md.

Uses GitHub Models, which is free inside GitHub Actions and needs no extra
API key. No secret values are ever sent: triage.py only stores a hash.

Usage (in the pipeline):  python3 remediate.py
"""
import json
import os
import urllib.error

API_URL = "https://models.github.ai/inference/chat/completions"
MODEL = os.environ.get("TRIAGE_MODEL", "openai/gpt-4o-mini")
TOP_N = 5

SYSTEM_PROMPT = (
    "You are an application security engineer writing remediation guidance "
    "for developers. Be specific and brief. Do not invent details that are "
    "not in the finding. Answer in exactly three short labelled lines:\n"
    "Risk: what an attacker could do.\n"
    "Fix: the concrete change to make.\n"
    "Verify: how to confirm the fix worked."
)


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


def ask_model(f, token):
    facts = {key: f.get(key) for key in
             ("tool", "category", "title", "severity", "location", "cve", "cwe", "detail")}
    body = json.dumps({
        "model": MODEL,
        "temperature": 0.2,
        "max_tokens": 250,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Finding:\n" + json.dumps(facts, indent=2)},
        ],
    }).encode()
    request = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status, text = response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        status, text = error.code, error.read().decode("utf-8", "replace")
    try:
        return json.loads(text)["choices"][0]["message"]["content"].strip()
    except Exception:
        raise RuntimeError(f"HTTP {status}, model={MODEL}, reply starts: {text[:300]!r}")


def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("No GITHUB_TOKEN found - skipping AI remediation (this step runs in the pipeline).")
        return

    with open("prioritized.json", encoding="utf-8") as f:
        findings = json.load(f)

    lines = ["", "## AI-drafted remediation guidance", "",
             f"Drafted by `{MODEL}` for the top {TOP_N} distinct findings. "
             "Review before applying: this text is machine-generated.", ""]
    written = 0
    for f in pick_top(findings, TOP_N):
        title = f["title"].split(",")[0][:80]
        try:
            advice = ask_model(f, token)
        except Exception as error:
            print(f"  WARNING: no guidance for '{title}' ({error})")
            continue
        print(f"  drafted guidance for: {title}")
        lines += [f"### [{f['priority']}] {title}", "",
                  f"Location: `{f['location']}`", ""]
        lines += [line + "  " for line in advice.splitlines() if line.strip()]
        lines.append("")
        written += 1

    if written == 0:
        print("No guidance was generated - report.md left unchanged.")
        return
    with open("report.md", "a", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
    print(f"Added guidance for {written} findings to report.md")


if __name__ == "__main__":
    main()