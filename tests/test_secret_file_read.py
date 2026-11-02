"""block_secret_file_read: fires on anything that prints a credential file or a secret variable,
quiet on look-alikes. Every name and value here is made up.
"""
import pytest

import block_secret_file_read as hook
from conftest import run_hook


def bash(cmd, tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": cmd}}


ALLOWED_SHELL = [
    "ls .secrets",
    "ls -la .secrets/*.env",
    "ls .env.local",
    "test -f .env && echo yes",
    "git status .env",
    "git add .env.example",
    "git diff --stat -- .env.local",
    "git check-ignore .env",
    "cat src/environment.py",
    "cat src/envelope.py",
    "cat .envrc",
    "cat .env.example",
    "cat .env.sample",
    "cat .env.template",
    "cat .env-dev-template",
    "cat README.md",
    "cat .secrets/README.md",
    "python -m pytest tests/test_env_loader.py -q",
    'grep -rn ".env" src',
    "grep -n load_dotenv src/config.py",
    "rg 'dotenv' src",
    # reduced output: names of matches or counts, never values
    "grep -l KEY .env.local",
    "grep -c KEY .env.local",
    "grep -q TOKEN .env",
    "rg -l TOKEN .secrets",
    "rg --files-with-matches TOKEN .env.local",
    "cat .env | wc -l",
    # writes and moves are not reads
    "cp .env.local .env.local.bak",
    "echo hello > .env.local",
    "sed -i s/a/b/ src/foo.py",
    "sed -i s/a/b/ .env.local",
    "rm .env.local",
    "mv .env.local .env.old",
    "head -5 notes.txt",
    # heredoc bodies are text, not commands
    "git commit -F - <<EOF\nstop running cat .env\nEOF",
    "cat > .env.local <<'EOF'\nA=1\nEOF",
    "grep -v OLD_KEY .env.local > .env.local.tmp && mv .env.local.tmp .env.local",
    # option values that are exclusions or patterns, not targets
    "grep -rn foo src --exclude=.env",
    "grep --regexp=.env -rn src",
    "sed 's/.env/.env.local/' notes.txt",
    # variables: presence and length are fine, safe names are fine
    "echo $HOME",
    "echo $PWD",
    "echo 'literal $SMB_PASSWORD stays literal'",
    'echo "set: ${SMB_PASSWORD:+yes}"',
    'echo "len: ${#SMB_PASSWORD}"',
    "echo $SMB_PASSWORD > out.txt",
    "echo $SMB_PASSWORD > /dev/null",
    '[ -n "$SMB_PASSWORD" ] && echo present',
    "source venv/bin/activate",
    ". ./venv/bin/activate",
    "source .env.example",
]


@pytest.mark.parametrize("cmd", ALLOWED_SHELL)
def test_shell_allowed(cmd):
    assert hook.evaluate(bash(cmd)) is None, cmd


@pytest.mark.parametrize("cmd", [
    "Get-Content .env.example",
    "gc src/environment.py",
    "Test-Path .env",
    "Get-ChildItem .secrets",
    "(Get-Content .env.local) -replace 'a','b' | Set-Content .env.local",
    "Get-Content .env.local | Out-File backup.txt",
    "Get-Content .env.local > $null",
])
def test_powershell_allowed(cmd):
    assert hook.evaluate(bash(cmd, "PowerShell")) is None, cmd


ALLOWED_TOOLS = [
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/src/environment.py"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.env.example"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.secrets/README.md"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.envrc"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": "src", "output_mode": "content"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": ".env.local", "output_mode": "files_with_matches"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": ".secrets", "output_mode": "count"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "glob": "!*.env", "output_mode": "content"}},
    {"tool_name": "Glob", "tool_input": {"pattern": ".secrets/*.env"}},
    {"tool_name": "Edit", "tool_input": {"file_path": ".env.local", "old_string": "a", "new_string": "b"}},
    {"tool_name": "Write", "tool_input": {"file_path": ".env.local", "content": "A=1"}},
    {"tool_name": "Read", "tool_input": {}},
    {"tool_name": "Bash", "tool_input": {}},
    {"tool_name": "Bash"},
    {"tool_name": "Bash", "tool_input": None},
]


@pytest.mark.parametrize("payload", ALLOWED_TOOLS)
def test_tool_allowed(payload):
    assert hook.evaluate(payload) is None, payload


def test_odd_payloads_fail_open():
    assert hook.evaluate(None) is None
    assert hook.evaluate("x") is None


def test_internal_error_fails_open(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")
    monkeypatch.setattr(hook, "_evaluate", boom)
    assert hook.evaluate(bash("cat .env")) is None


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SECRET_READ_GATE", "off")
    assert hook.evaluate(bash("cat .env")) is None


BLOCKED_SHELL = [
    "cat .env",
    "cat .env.local",
    "cat .env-dev",
    "cat .env.production",
    "cat ./.env.local",
    "cat /home/me/proj/.secrets/service.env",
    "cat '/home/me/proj/.secrets/service.env'",
    "cat .secrets\\service.env",
    "cat .secrets/*.env",
    "cat .secrets/google/key.json",
    "cat prod.env",
    "cat .env*",
    "head -20 .env.local",
    "tail -f .env",
    "less .env",
    "grep KEY .env.local",
    "grep -n TOKEN .secrets/github.env",
    "grep -rn PASSWORD .secrets",
    "grep -e KEY -e TOKEN .env",
    "egrep 'KEY|TOKEN' .env.local",
    "rg TOKEN .env",
    "rg TOKEN -g '*.env'",
    "grep TOKEN --include=*.env -r .",
    "type .env",
    "sed -n 1,5p .env.local",
    "awk '{print}' .env",
    "cat .env | head",
    "cat .env | grep KEY",
    "ls && cat .env.local",
    "cd x; cat .env",
    "cat < .env",
    "xargs -n1 cat .env",
    "sudo cat .env",
    # wrapper options that take a value
    "sudo -u nobody cat .env",
    "sudo --user=nobody cat .env",
    "sudo --user nobody cat .env",
    "env -u FOO cat .env",
    "env -u FOO -u BAR cat .env.local",
    "xargs -n 1 cat .env",
    "/usr/bin/cat .env",
    "bash -c 'cat .env.local'",
    'powershell -Command "Get-Content .env"',
    "cat .env 2>&1",
    "cat .env > /dev/stdout",
    "cat .env >&2",
    "FOO=1 cat .env",
    "diff .env.example .env",
    "sed -n p .env.local",
    "awk -f prog.awk .env",
    "cat <<EOF\nx\nEOF\ncat .env",
    # sourcing loads every value into the shell
    "source .secrets/cloud.env",
    "set -a; source .secrets/cloud.env; set +a; curl x",
    ". .secrets/cloud.env",
    "bash -c 'source /proj/.secrets/cloud.env && env'",
    "builtin source .env.local",
    # printing a secret-looking variable
    "echo $CLOUD_PASSWORD",
    'echo "pw=${SMB_PASSWORD}"',
    "printf '%s\\n' \"$API_TOKEN\"",
    "printenv CLOUD_PASSWORD",
    "printenv",
    "echo $DB_PASS | tee out.txt",
]


@pytest.mark.parametrize("cmd", BLOCKED_SHELL)
def test_shell_blocked(cmd):
    assert hook.evaluate(bash(cmd)), cmd


BLOCKED_PS = [
    "Get-Content .env",
    "Get-Content -Path .env.local",
    "gc .secrets\\service.env",
    "Get-Content C:\\proj\\.secrets\\x.env | Select-String KEY",
    "Select-String -Pattern KEY -Path .env",
    "Select-String KEY .env.local",
    "Select-String -SimpleMatch KEY .env",
    "sls -Path .secrets\\*.env -Pattern TOKEN",
    "type .env",
    "Get-Content .env -Raw",
    "(Get-Content .env.local)",
    "Get-Content .env | Tee-Object x.txt",
    r". .\.secrets\cloud.env",
    'Write-Host "pw=$env:SMB_PASSWORD"',
    "Write-Output $env:CLOUD_API_TOKEN",
]


@pytest.mark.parametrize("cmd", BLOCKED_PS)
def test_powershell_blocked(cmd):
    assert hook.evaluate(bash(cmd, "PowerShell")), cmd


BLOCKED_TOOLS = [
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.env"}},
    {"tool_name": "Read", "tool_input": {"file_path": "C:\\proj\\.secrets\\service.env"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.env.local"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.env-dev"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/proj/.secrets/google/sa.json"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": ".env.local", "output_mode": "content"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": "/proj/.secrets", "output_mode": "content"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "glob": "*.env", "output_mode": "content"}},
    {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "glob": ".env*", "output_mode": "content", "-n": True}},
]


@pytest.mark.parametrize("payload", BLOCKED_TOOLS)
def test_tool_blocked(payload):
    assert hook.evaluate(payload), payload


def test_file_message_names_the_file_not_the_contents():
    msg = hook.evaluate(bash("cat .secrets/service.env"))
    assert ".secrets/service.env" in msg and "transcript" in msg


def test_variable_message_names_the_variable():
    msg = hook.evaluate(bash("echo $CLOUD_PASSWORD"))
    assert "$CLOUD_PASSWORD" in msg and "presence" in msg


def test_exit_code_contract():
    code, err = run_hook("block_secret_file_read", bash("cat .env.local"))
    assert code == 2 and "credential file" in err
    code, err = run_hook("block_secret_file_read", bash("cat .env.example"))
    assert code == 0 and err == ""
    code, err = run_hook("block_secret_file_read", {"tool_name": "Read", "tool_input": {"file_path": "/p/.env"}})
    assert code == 2
    code, _ = run_hook("block_secret_file_read", bash("cat .env"), env_extra={"SECRET_READ_GATE": "off"})
    assert code == 0
    code, _ = run_hook("block_secret_file_read", None, raw="not json")
    assert code == 0


@pytest.mark.parametrize("cmd", [
    "env -S 'cat .env'",
    "env --split-string 'cat .env'",
    "env --split-string='cat .env'",
    "env -S'cat .env'",
    "env FOO=1 -S 'cat .secrets/key.json'",
])
def test_env_split_string_value_is_the_command(cmd):
    assert hook.evaluate(bash(cmd)) is not None


def test_env_split_string_with_a_harmless_command_passes():
    assert hook.evaluate(bash("env -S 'ls -la'")) is None


@pytest.mark.parametrize("path", [
    "C:\\proj\\.SECRETS\\key.json",
    "/home/u/proj/.Secrets/key.json",
])
def test_secrets_directory_is_matched_case_insensitively(path):
    assert hook.evaluate({"tool_name": "Read", "tool_input": {"file_path": path}}) is not None
    assert hook.evaluate(bash(f"cat '{path}'")) is not None


def test_secrets_readme_stays_allowed_in_any_case():
    assert hook.evaluate({"tool_name": "Read", "tool_input": {"file_path": "x/.SECRETS/README.md"}}) is None


def test_non_object_json_exits_quietly():
    for raw in ("null", "[]", "5", '"x"'):
        code, err = run_hook("block_secret_file_read", None, raw=raw)
        assert code == 0 and err == ""
