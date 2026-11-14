"""CLI. inspect already works; admit is the piece to implement."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from namecage.load import LoadError, load_bundle, load_keys, load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="namecage")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show subjects, issuers, and name constraints")
    ins.add_argument("--bundle", required=True)
    adm = sub.add_parser("admit", help="decide whether the leaf has a valid path under the lab rules")
    adm.add_argument("--bundle", required=True)
    adm.add_argument("--policy", required=True)
    adm.add_argument("--keys", required=True)
    adm.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        bundle = load_bundle(args.bundle)
    except (LoadError, OSError, KeyError, ValueError) as exc:
        print(f"failed to load bundle: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps({
            "hostname": bundle["hostname"],
            "leaf_id": bundle["leaf_id"],
            "trust_anchors": bundle["trust_anchors"],
            "certs": [{"id": c.get("id"), "subject": (c.get("tbs") or {}).get("subject"), "issuer": (c.get("tbs") or {}).get("issuer")} for c in bundle["certs"]],
        }, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "admit":
        try:
            policy = load_policy(args.policy)
            keys = load_keys(args.keys)
        except (LoadError, OSError) as exc:
            print(f"failed to load policy or keys: {exc}", file=sys.stderr)
            return 2
        from namecage.engine import admit
        try:
            report = admit(bundle, policy, keys)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
