"""install.py: adds the hooks once, keeps other settings, removes only its own."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import install  # noqa: E402


def commands(settings):
    return [h["command"] for e in settings["hooks"]["PreToolUse"] for h in e["hooks"]]


def test_install_is_idempotent_and_keeps_other_settings(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}]}}))
    assert install.main(["--settings", str(f)]) == 0
    assert install.main(["--settings", str(f)]) == 0
    s = json.loads(f.read_text())
    assert s["model"] == "x"
    cmds = commands(s)
    assert "echo mine" in cmds
    assert len(cmds) == 1 + len(install.HOOKS)


def test_remove_only_takes_out_ours(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}]}}))
    install.main(["--settings", str(f)])
    install.main(["--settings", str(f), "--remove"])
    assert commands(json.loads(f.read_text())) == ["echo mine"]


def test_new_file_and_dry_run(tmp_path, capsys):
    f = tmp_path / "sub" / "settings.json"
    install.main(["--settings", str(f), "--dry-run"])
    assert not f.exists() and "block_secret_file_read.py" in capsys.readouterr().out
    install.main(["--settings", str(f)])
    assert len(commands(json.loads(f.read_text()))) == len(install.HOOKS)


def test_dry_run_does_not_print_the_rest_of_the_settings_file(tmp_path, capsys):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"env": {"PRIVATE_SETTING": "private-value-123"}, "model": "x"}))
    before = f.read_text()
    assert install.main(["--settings", str(f), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "private-value-123" not in out and "PRIVATE_SETTING" not in out
    assert "block_secret_file_read.py" in out
    assert f.read_text() == before


def test_remove_ignores_a_foreign_hook_that_only_mentions_our_file_name(tmp_path):
    f = tmp_path / "settings.json"
    foreign = 'echo "log: block_unbounded_wait.py ran" >> /tmp/audit.log'
    f.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": foreign}]}]}}))
    install.main(["--settings", str(f)])
    install.main(["--settings", str(f), "--remove"])
    assert commands(json.loads(f.read_text())) == [foreign]


def test_remove_keeps_a_same_named_hook_from_another_directory(tmp_path):
    f = tmp_path / "settings.json"
    foreign = 'python "/foreign/block_unbounded_wait.py"'
    assert not install.is_ours(foreign)
    f.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": foreign}]}]}}))
    install.main(["--settings", str(f)])
    install.main(["--settings", str(f), "--remove"])
    assert commands(json.loads(f.read_text())) == [foreign]


def test_is_ours_accepts_what_the_installer_writes():
    for script, _ in install.HOOKS:
        assert install.is_ours(install.command_for(script))


def test_try_hooks_expands_a_tilde_settings_path(tmp_path, monkeypatch):
    import subprocess
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    install.main(["--settings", str(home / ".claude" / "settings.json")])
    env = dict(__import__("os").environ, HOME=str(home), USERPROFILE=str(home))
    script = Path(__file__).resolve().parent.parent / "examples" / "try_hooks.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--settings", "~/.claude/settings.json",
         "--tool", "Read", "--file-path", ".env"],
        capture_output=True, text=True, env=env, timeout=60)
    assert "RESULT: BLOCKED" in proc.stdout, proc.stderr


def _old_clone_settings(prefix):
    return {"hooks": {"PreToolUse": [
        {"matcher": m, "hooks": [{"type": "command", "command": f'python "{prefix}/hooks/{s}"'}]}
        for s, m in install.HOOKS]}}


def test_reinstall_replaces_an_old_clone_instead_of_doubling(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps(_old_clone_settings("C:/old/agent-guardrails")))
    install.main(["--settings", str(f)])
    cmds = commands(json.loads(f.read_text()))
    assert len(cmds) == len(install.HOOKS)
    assert not any("C:/old" in c for c in cmds)


def test_remove_cleans_an_old_clone_but_not_lookalikes(tmp_path):
    f = tmp_path / "settings.json"
    s = _old_clone_settings("/home/me/src/agent-guardrails-v1")
    keep = [
        'python "/foreign/block_unbounded_wait.py"',
        'python "/work/otherproj/hooks/block_unbounded_wait.py"',
        'python "/work/agent-guardrails/scripts/block_unbounded_wait.py"',
        'python "/work/agent-guardrails/hooks/not_ours.py"',
    ]
    s["hooks"]["PreToolUse"].append(
        {"matcher": "Bash", "hooks": [{"type": "command", "command": c} for c in keep]})
    f.write_text(json.dumps(s))
    install.main(["--settings", str(f), "--remove"])
    assert commands(json.loads(f.read_text())) == keep


def test_write_keeps_a_backup_and_leaves_no_temp_file(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"model": "x"}))
    install.main(["--settings", str(f)])
    assert json.loads((tmp_path / "settings.json.bak").read_text()) == {"model": "x"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json", "settings.json.bak"]


def test_failed_replace_leaves_the_original_intact(tmp_path, monkeypatch):
    f = tmp_path / "settings.json"
    f.write_text('{"model": "x"}')

    def boom(*a, **k):
        raise OSError("disk")
    monkeypatch.setattr(install.os, "replace", boom)
    try:
        install.main(["--settings", str(f)])
    except OSError:
        pass
    assert f.read_text() == '{"model": "x"}'
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []
