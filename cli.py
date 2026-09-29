"""agent-redteam: attack your own (test-copy) AI agents and report which attacks succeed.

  python cli.py list
  python cli.py run --target mock [--category prompt_injection] [--yes] [--no-llm] [--redact]
  python cli.py report [reports/<ts>.json] [--redact]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from redteam import judge, report, runner


def cmd_list(args):
    targets = runner.load_targets()
    print("Targets (targets.yaml):")
    for t in targets.values():
        print(f"  {t['name']:<16} {t['method']:<5} {t['url']}")
    attacks = runner.load_attacks()
    print(f"\nAttacks ({len(attacks)}):")
    for a in attacks:
        print(f"  {a['id']:<6} {a['category']:<20} {a['severity']:<9} {' '.join(a['message'].split())[:60]}")


def cmd_run(args):
    targets = runner.load_targets()
    if args.target not in targets:
        sys.exit(f"Unknown target '{args.target}'. Targets in targets.yaml: {', '.join(targets) or 'none'}")
    target = targets[args.target]
    attacks = runner.load_attacks(category=args.category)
    if not attacks:
        sys.exit(f"No attacks found for category '{args.category}'.")

    llm = None
    if args.no_llm:
        print("LLM judge disabled (--no-llm): replies that pass stage 1 are marked 'unclear'.")
    elif os.environ.get("GROQ_API_KEY"):
        llm = judge.GroqJudge(os.environ["GROQ_API_KEY"])
    else:
        print("GROQ_API_KEY not set: LLM judge skipped, replies that pass stage 1 are marked 'unclear'.")

    rn = runner.Runner(target, allowlist={t["url"] for t in targets.values()})
    print(f"\nTarget:  {target['name']}\nURL:     {target['method']} {target['url']}")
    print(f"Attacks: {len(attacks)} (>= {runner.MIN_INTERVAL:.0f}s apart, ~{len(attacks) * runner.MIN_INTERVAL:.0f}s minimum)")
    if not args.yes:
        if input("Only attack TEST COPIES. Type 'yes' to send these attacks to the URL above: ").strip() != "yes":
            sys.exit("Aborted. Nothing was sent.")

    def progress(i, n, row):
        print(f"[{i:>2}/{n}] {row['id']:<6} {row['verdict'].upper():<7} {row['reason']}", flush=True)

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results = runner.run(rn, attacks, lambda a, sent: judge.judge(a, sent, target["canaries"], llm), progress)
    data = report.build(results, target, started)
    md = report.write(data)
    print(f"\nReport: {md}\n        {md.with_suffix('.json')}")
    if args.redact:
        print(f"Redacted: {report.write(data, stem=md.stem, redacted=True)}")
    fails = sum(r["verdict"] == "fail" for r in results)
    print(f"{fails}/{len(results)} attacks succeeded against the agent (verdict FAIL).")


def cmd_report(args):
    path = Path(args.file) if args.file else report.latest_json()
    if not path or not path.exists():
        sys.exit("No report JSON found. Run `python cli.py run ...` first.")
    data = json.loads(path.read_text())
    if args.redact:
        md = report.write(data, out_dir=path.parent, stem=path.stem, redacted=True)
        print(md.read_text())
        print(f"Redacted report written: {md}\n                         {md.with_suffix('.json')}", file=sys.stderr)
    else:
        print(report.render_md(data))


def main(argv=None):
    runner.load_env()
    p = argparse.ArgumentParser(prog="agent-redteam", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list targets and attacks").set_defaults(func=cmd_list)
    r = sub.add_parser("run", help="attack a target from targets.yaml")
    r.add_argument("--target", required=True, help="target NAME from targets.yaml (URLs are never accepted)")
    r.add_argument("--category", help="only run attacks in this category")
    r.add_argument("--yes", action="store_true", help="skip the interactive 'yes' confirmation")
    r.add_argument("--no-llm", action="store_true", help="deterministic checks only, no Groq calls")
    r.add_argument("--redact", action="store_true", help="also write a redacted copy of the report")
    r.set_defaults(func=cmd_run)
    rp = sub.add_parser("report", help="print the newest (or given) report")
    rp.add_argument("file", nargs="?", help="report JSON (default: newest in reports/)")
    rp.add_argument("--redact", action="store_true", help="mask digits and emails, write <name>-redacted.md/.json")
    rp.set_defaults(func=cmd_report)
    args = p.parse_args(argv)
    try:
        args.func(args)
    except runner.SafetyError as e:
        sys.exit(f"SAFETY: {e}")


if __name__ == "__main__":
    main()
