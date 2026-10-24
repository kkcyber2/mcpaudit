"""Command line: append events, verify a log, prove one entry."""

from __future__ import annotations

import argparse
import json
import sys
import time

from .log import AuditLog, LogError, replay


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpaudit",
        description="Tamper-evident audit log for agent tool calls.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    append = sub.add_parser("append", help="add an event and print the new head")
    append.add_argument("log", help="path to the JSON log")
    append.add_argument("--kind", required=True)
    append.add_argument("--subject", required=True)
    append.add_argument("--decision", required=True, choices=["allow", "deny", "note"])
    append.add_argument("--reason", default="")

    verify = sub.add_parser("verify", help="check every inclusion proof")
    verify.add_argument("log")

    head = sub.add_parser("head", help="print the current tree head")
    head.add_argument("log")

    prove = sub.add_parser("prove", help="print one entry and its inclusion proof")
    prove.add_argument("log")
    prove.add_argument("seq", type=int)

    args = parser.parse_args(argv)

    try:
        log = _load(args.log)
    except FileNotFoundError:
        if args.command != "append":
            print(f"error: no log at {args.log}", file=sys.stderr)
            return 2
        log = AuditLog(clock=time.time)

    if args.command == "append":
        try:
            event = log.append(args.kind, args.subject, args.decision, args.reason)
        except LogError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        _save(args.log, log)
        print(json.dumps({"seq": event.seq, "head": log.head().as_dict()}, indent=2))
        return 0

    if args.command == "head":
        print(json.dumps(log.head().as_dict(), indent=2))
        return 0

    if args.command == "verify":
        broken = log.verify_all()
        if broken:
            print(f"FAIL: {len(broken)} entr(ies) do not prove into the head: "
                  f"{broken[:10]}", file=sys.stderr)
            return 1
        print(f"OK: all {len(log)} entr(ies) prove into head {log.head().root}")
        return 0

    if not 0 <= args.seq < len(log):
        print(f"error: no entry {args.seq}", file=sys.stderr)
        return 2
    print(json.dumps({
        "event": log.events[args.seq].as_dict(),
        "proof": log.inclusion_proof(args.seq),
        "head": log.head().as_dict(),
        "verified": log.verify(args.seq),
    }, indent=2))
    return 0


def _load(path: str) -> AuditLog:
    try:
        return replay(path)
    except FileNotFoundError:
        raise
    except (LogError, KeyError, ValueError) as exc:
        raise SystemExit(f"error: {path} is not a valid log ({exc})") from exc


def _save(path: str, log: AuditLog) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(log.to_json())


if __name__ == "__main__":
    raise SystemExit(main())
