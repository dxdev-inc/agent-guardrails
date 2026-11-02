"""Make the hook scripts importable, and give tests a way to run one the way Claude Code does."""
import json
import os
import subprocess
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS))


def run_hook(name, payload, env_extra=None, raw=None):
    """Run hooks/<name>.py as a real subprocess: JSON on stdin, return (exit code, stderr)."""
    env = dict(os.environ)
    env.update(env_extra or {})
    proc = subprocess.run(
        [sys.executable, str(HOOKS / f"{name}.py")],
        input=raw if raw is not None else json.dumps(payload),
        capture_output=True, text=True, env=env, timeout=30,
    )
    return proc.returncode, proc.stderr
