#!/usr/bin/env python3
"""Add the guardrail hooks to a Claude Code settings file.

    python install.py                       # edits ~/.claude/settings.json
    python install.py --settings FILE       # edits another settings file
    python install.py --dry-run             # show the hooks it would add or remove, write nothing
    python install.py --remove              # take the guardrails back out

Safe to run twice: a hook that is already registered is not added again, and
every other setting in the file is left alone. The file is only written after
the new JSON has been built successfully.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent / "hooks"

# (script, matcher). The matcher is the set of tools the hook is told about.
HOOKS = [
    ("block_unbounded_wait.py", "Bash"),
    ("block_secret_file_read.py", "Bash|PowerShell|Read|Grep"),
    ("block_unbounded_sql_scan.py", "Bash|PowerShell"),
    ("block_unbounded_powershell_output.py", "Write|Edit|MultiEdit"),
]


def command_for(script: str) -> str:
    # Plain `python` on Windows, `python3` elsewhere, resolved from PATH when the
    # hook runs. That interpreter must exist on PATH (a venv that is not active
    # when Claude Code starts will not do); see the README.
    python = "python" if sys.platform == "win32" else "python3"
    return f'{python} "{(HOOKS_DIR / script).as_posix()}"'


def _norm(path: str) -> str:
    return os.path.normcase(path).replace("\\", "/")


def is_ours(command: str) -> bool:
    """True for a command this installer wrote: `python "<dir>/hooks/<script>"`.

    Ours means one of two things: the script is exactly the one in THIS checkout,
    or it is one of our four file names inside a directory called `hooks` whose
    parent directory name contains `agent-guardrails` (an earlier or moved clone of
    this tool, which `--remove` and a reinstall should clean up). A same-named hook
    from any other project (`/foreign/block_unbounded_wait.py`, or `.../hooks/` under
    a differently named project) is never touched. A checkout renamed to something
    without `agent-guardrails` in it is only recognised while it stays put."""
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if len(parts) != 2 or parts[0] not in ("python", "python3"):
        return False
    script_path = _norm(parts[1])
    if any(script_path == _norm((HOOKS_DIR / script).as_posix()) for script, _ in HOOKS):
        return True
    pieces = script_path.rstrip("/").split("/")
    return (
        len(pieces) >= 3
        and pieces[-1] in {os.path.normcase(script) for script, _ in HOOKS}
        and pieces[-2] == "hooks"
        and "agent-guardrails" in pieces[-3]
    )


def add(settings: dict) -> dict:
    """Register the four hooks. An older copy of one of them (a moved or
    re-cloned checkout, see `is_ours`) is replaced, not left beside the new one."""
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    current = {command_for(script) for script, _ in HOOKS}
    cleaned = []
    for entry in pre:
        hooks = [h for h in entry.get("hooks", [])
                 if h.get("command", "") in current or not is_ours(h.get("command", ""))]
        if hooks:
            cleaned.append({**entry, "hooks": hooks})
    pre[:] = cleaned
    present = {h.get("command", "") for entry in pre for h in entry.get("hooks", [])}
    for script, matcher in HOOKS:
        cmd = command_for(script)
        if cmd not in present:
            pre.append({"matcher": matcher, "hooks": [{"type": "command", "command": cmd}]})
    return settings


def remove(settings: dict) -> dict:
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    kept = []
    for entry in pre:
        hooks = [h for h in entry.get("hooks", []) if not is_ours(h.get("command", ""))]
        if hooks:
            kept.append({**entry, "hooks": hooks})
    if "PreToolUse" in settings.get("hooks", {}):
        settings["hooks"]["PreToolUse"] = kept
    return settings


def write_settings(path: Path, text: str) -> None:
    """Replace `path` atomically: write a temp file in the same directory, then
    os.replace it in, so an interrupted run never leaves truncated JSON. The
    previous file is kept next to it as `<name>.bak`."""
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--settings", default=str(Path.home() / ".claude" / "settings.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--remove", action="store_true")
    args = ap.parse_args(argv)

    path = Path(args.settings)
    settings = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    original = copy.deepcopy(settings)
    settings = remove(settings) if args.remove else add(settings)
    text = json.dumps(settings, indent=2) + "\n"

    if args.dry_run:
        # Never print the whole file: it may hold credentials, private paths or
        # internal hosts, and this output lands in an agent transcript.
        before = {h.get("command", "") for e in original.get("hooks", {}).get("PreToolUse", []) for h in e.get("hooks", [])}
        after = {h.get("command", "") for e in settings.get("hooks", {}).get("PreToolUse", []) for h in e.get("hooks", [])}
        verb, changed = ("remove", before - after) if args.remove else ("add", after - before)
        print(f"Dry run, nothing written. Would {verb} {len(changed)} hook(s) in {path}:")
        for command in sorted(changed):
            print(f"  {command}")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    write_settings(path, text)
    print(f"{'Removed from' if args.remove else 'Installed into'} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
