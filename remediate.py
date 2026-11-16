"""Vulnerability triage engine - stage 3: AI-drafted remediation guidance.

Reads prioritized.json (made by enrich.py), picks the top distinct findings,
asks an LLM for short fix guidance and appends it to report.md.

Uses the Gemini API through its OpenAI-compatible endpoint. The API key is
read from the GEMINI_API_KEY environment variable (a GitHub Actions secret)
and is never written to the code or the logs. Without a key the script only
writes ai_prompt.txt so you can see what would be sent.

No secret values from the scan are ever sent: triage.py only stores a hash.

Usage:  py remediate.py
"""
import json
import os
import time
import urllib.error
import urllib.request

API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
# Models are tried in this order. If one is overloaded, the next is used.
MODELS = [os.environ.get("TRIAGE_MODEL", "gemini-3.8-flash"), "gemini-3.6-flash", "gemini-3.5-flash-lite"]
ATTEMPTS_PER_MODEL = 2
WAIT_SECONDS = 15
TOP_N = 5
FIELDS = ("priority", "tool", "category", "title", "severity", "location", "cve", "cwe", "detail")

SYSTEM_PROMPT = "You are an application security engineer writing remediation guidance for developers."

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


def ask_model(prompt, key, model):
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }).encode()
    request = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status, text = response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        status, text = error.code, error.read().decode("utf-8", "replace")
    try:
        return json.loads(text)["choices"][0]["message"]["content"].strip()
    except Exception:
        raise RuntimeError(f"HTTP {status}: {' '.join(text.split())[:160]}")


def ask_with_fallback(prompt, key):
    """Try each model in turn, retrying once, so one busy model does not block us."""
    for model in MODELS:
        for attempt in range(1, ATTEMPTS_PER_MODEL + 1):
            print(f"Asking {model} (attempt {attempt})...")
            try:
                return ask_model(prompt, key, model), model
            except Exception as error:
                print(f"  failed: {error}")
                time.sleep(WAIT_SECONDS)
    return None, None


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

    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        print("\nNo GEMINI_API_KEY set - skipping the AI call.")
        return

    print()
    advice, model = ask_with_fallback(prompt, key)
    if advice is None:
        print("WARNING: no model answered, report left unchanged.")
        return

    section = ["", "## AI-drafted remediation guidance", "",
               f"Drafted by `{model}` for the top {len(top)} distinct findings. "
               "Review before applying: this text is machine-generated.", "",
               advice, ""]
    with open("report.md", "a", encoding="utf-8") as out:
        out.write("\n".join(section))
    print("Added AI remediation guidance to report.md")


if __name__ == "__main__":
    main()