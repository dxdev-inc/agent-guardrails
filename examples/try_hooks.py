#!/usr/bin/env python3
"""Check an installed settings file the way Claude Code would use it.

    python examples/try_hooks.py --settings FILE --tool Bash --command "until grep -q X f; do sleep 5; done"
    python examples/try_hooks.py --settings FILE --tool Read --file-path .env

It finds every PreToolUse hook whose matcher covers the tool, feeds each one the
same JSON on stdin that Claude Code sends, and prints the exit code and what the
agent would be told. Exit code 2 means the call is blocked; 0 means it goes ahead.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--settings", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--command")
    ap.add_argument("--file-path")
    ap.add_argument("--content")
    args = ap.parse_args()

    tool_input = {k: v for k, v in
                  {"command": args.command, "file_path": args.file_path, "content": args.content}.items() if v}
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": args.tool, "tool_input": tool_input})

    settings = json.loads(Path(args.settings).expanduser().read_text(encoding="utf-8"))
    blocked = False
    for entry in settings.get("hooks", {}).get("PreToolUse", []):
        if not re.fullmatch(entry.get("matcher") or ".*", args.tool):
            continue
        for hook in entry.get("hooks", []):
            proc = subprocess.run(hook["command"], shell=True, input=payload,
                                  capture_output=True, text=True, timeout=30)
            name = Path(hook["command"].split('"')[1]).name if '"' in hook["command"] else hook["command"]
            print(f"[{name}] exit code {proc.returncode}")
            if proc.returncode == 2:
                blocked = True
                print("  agent is told:", proc.stderr.strip().splitlines()[0])
    print("RESULT:", "BLOCKED" if blocked else "allowed")
    return 2 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
