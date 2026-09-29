"""Write reports/<timestamp>.md and .json, optionally redacted for public sharing."""
import json
import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from .judge import EMAIL_RE
from .runner import ROOT

REPORTS = ROOT / "reports"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
REDACT_FIELDS = ("message", "reply", "raw", "reason", "error")
SNIPPET = 500


def redact_text(s):
    if not isinstance(s, str):
        return s
    return re.sub(r"\d", "#", EMAIL_RE.sub("[email]", s))


def redact(data):
    data = json.loads(json.dumps(data))
    data["target"]["url"] = "[redacted]"  # webhook paths are secrets too
    for row in data["results"]:
        for f in REDACT_FIELDS:
            row[f] = redact_text(row.get(f))
    data["redacted"] = True
    return data


def build(results, target, started):
    return {
        "started": started,
        "target": {"name": target["name"], "url": target["url"]},
        "redacted": False,
        "results": results,
    }


def summary_by_category(results):
    cats = OrderedDict()
    for r in results:
        c = cats.setdefault(r["category"], {"pass": 0, "fail": 0, "unclear": 0})
        c[r["verdict"]] += 1
    return cats


def _cell(s, n=None):
    s = " ".join(str(s or "").split()).replace("|", "\\|")
    return s if n is None or len(s) <= n else s[:n] + "…"


def _snippet(s):
    s = s or ""
    if len(s) > SNIPPET:
        s = s[:SNIPPET] + f"\n... [truncated, {len(s)} chars total]"
    return s.replace("```", "'''")


def render_md(data):
    res = data["results"]
    lines = [
        f"# Red-team report: {data['target']['name']}",
        "",
        f"- Target: `{data['target']['url']}`",
        f"- Started: {data['started']}",
        f"- Attacks: {len(res)}. Fail: {sum(r['verdict'] == 'fail' for r in res)}, "
        f"pass: {sum(r['verdict'] == 'pass' for r in res)}, "
        f"unclear: {sum(r['verdict'] == 'unclear' for r in res)}"
        + (" (redacted)" if data.get("redacted") else ""),
        "",
        "## Results",
        "",
        "| Attack | Category | Severity | Verdict | Reason |",
        "|---|---|---|---|---|",
    ]
    for r in res:
        verdict = {"fail": "**FAIL**", "pass": "pass", "unclear": "unclear"}[r["verdict"]]
        lines.append(f"| {_cell(r['id'])} | {_cell(r['category'])} | {_cell(r['severity'])} "
                     f"| {verdict} | {_cell(r['reason'], 160)} |")
    lines += ["", "## Summary by category", "",
              "Pass rate = pass / (pass + fail). Unclear verdicts are excluded from the rate.", "",
              "| Category | Pass | Fail | Unclear | Pass rate |", "|---|---|---|---|---|"]
    for cat, c in summary_by_category(res).items():
        judged = c["pass"] + c["fail"]
        rate = f"{100 * c['pass'] / judged:.0f}%" if judged else "n/a"
        lines.append(f"| {cat} | {c['pass']} | {c['fail']} | {c['unclear']} | {rate} |")
    fails = sorted((r for r in res if r["verdict"] == "fail"),
                   key=lambda r: SEVERITY_RANK.get(r["severity"], 9))[:5]
    lines += ["", "## Top failures", ""]
    if not fails:
        lines.append("No failures.")
    for i, r in enumerate(fails, 1):
        lines += [f"### {i}. {r['id']} ({r['category']}, {r['severity']})", "",
                  f"**Why:** {_cell(r['reason'])}", "",
                  "Attack:", "```", _snippet(r["message"]), "```",
                  "Reply:", "```", _snippet(r["reply"] or r.get("error")), "```", ""]
    return "\n".join(lines) + "\n"


def write(data, out_dir=REPORTS, stem=None, redacted=False):
    """Write <stem>.json and <stem>.md. Returns the .md path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = stem or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if redacted:
        data, stem = redact(data), stem + "-redacted"
    (out_dir / f"{stem}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False))
    md = out_dir / f"{stem}.md"
    md.write_text(render_md(data))
    return md


def latest_json(out_dir=REPORTS):
    files = sorted(p for p in Path(out_dir).glob("*.json") if not p.stem.endswith("-redacted"))
    return files[-1] if files else None
