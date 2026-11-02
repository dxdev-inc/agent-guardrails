"""block_unbounded_wait: fires on a sleep loop that can never end, quiet on bounded look-alikes."""
import pytest

import block_unbounded_wait as hook
from conftest import run_hook


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


BLOCKED = [
    "until grep -q DONE job.log; do sleep 5; done",
    "while true; do sleep 10; done",
    "while ! test -f /tmp/ready; do sleep 2; done",
    "until [ -f /tmp/x ]; do sleep 1; done",
    "for ((;;)); do sleep 3; done",
    # a trailing sleep after an inner loop still belongs to the unbounded outer loop
    "while true; do for i in {1..3}; do :; done; sleep 5; done",
    # an && keeps an `until` running: the counter compare alone cannot end it
    "n=0; until grep -q X f && [ $n -ge 10 ]; do sleep 5; n=$((n+1)); done",
    # an || keeps a `while` running
    "n=0; while [ $n -lt 10 ] || true; do sleep 5; n=$((n+1)); done",
    # a timeout that does not wrap the loop does not bound it
    "timeout 1 true; while true; do sleep 1; done",
    "timeout 5 true && until grep -q X f; do sleep 5; done",
    "timeout 5 true\nwhile true; do sleep 1; done",
]

ALLOWED = [
    # the same shapes, made safe
    "end=$((SECONDS+300)); until grep -q X f || [ \"$SECONDS\" -ge \"$end\" ]; do sleep 5; done",
    "timeout 300 bash -c 'until grep -q X f; do sleep 5; done'",
    "timeout 300 bash -c \"until grep -q X f; do sleep 5; done\"",
    "for i in {1..60}; do test -f /tmp/x && break; sleep 1; done",
    "for i in $(seq 1 30); do sleep 2; done",
    "n=0; until [ $n -ge 10 ]; do sleep 5; n=$((n+1)); done",
    "while true; do sleep 5; [ $(date +%s) -gt $DEADLINE ] && break; done",
    "MAX_TRIES=20; i=0; while true; do sleep 1; i=$((i+1)); [ $i -ge $MAX_TRIES ] && break; done",
    "for ((i=0; i<10; i++)); do sleep 1; done",
    # no sleep in the loop, or no loop at all
    "while read line; do echo $line; done < file.txt",
    "sleep 5",
    "ls -la",
    "echo 'wait for it'",
]


@pytest.mark.parametrize("cmd", BLOCKED)
def test_blocks_unbounded_loop(cmd):
    assert hook.evaluate(bash(cmd)), cmd


@pytest.mark.parametrize("cmd", ALLOWED)
def test_allows_bounded_or_unrelated(cmd):
    assert hook.evaluate(bash(cmd)) is None, cmd


def test_ignores_other_tools_and_odd_payloads():
    assert hook.evaluate({"tool_name": "Read", "tool_input": {"file_path": "x"}}) is None
    assert hook.evaluate({"tool_name": "Bash", "tool_input": {}}) is None
    assert hook.evaluate({"tool_name": "Bash"}) is None


def test_message_explains_the_fix():
    msg = hook.evaluate(bash("while true; do sleep 1; done"))
    assert "deadline" in msg and "timeout" in msg


def test_env_override(monkeypatch):
    monkeypatch.setenv("UNBOUNDED_WAIT_OK", "1")
    assert hook.evaluate(bash("while true; do sleep 1; done")) is None


def test_flag_file_override_is_one_shot(tmp_path, monkeypatch):
    flag = tmp_path / "ok"
    flag.write_text("")
    monkeypatch.setattr(hook, "OVERRIDE_FLAG", str(flag))
    cmd = "while true; do sleep 1; done"
    assert hook.evaluate(bash(cmd)) is None      # consumes the flag
    assert not flag.exists()
    assert hook.evaluate(bash(cmd))               # blocked again


def test_exit_code_contract():
    code, err = run_hook("block_unbounded_wait", bash("until grep -q X f; do sleep 5; done"))
    assert code == 2 and "unbounded wait loop" in err
    code, err = run_hook("block_unbounded_wait", bash("timeout 60 bash -c 'until grep -q X f; do sleep 5; done'"))
    assert code == 0 and err == ""
    code, _ = run_hook("block_unbounded_wait", None, raw="not json")
    assert code == 0  # bad input never blocks the agent


def test_escaped_quote_does_not_hide_a_finished_timeout_command():
    # the \" is a literal quote inside the string, so `timeout 1 bash -c "..."` ends at the `;`
    cmd = 'timeout 1 bash -c "echo \\""; while true; do sleep 1; done'
    assert hook.evaluate(bash(cmd)) is not None


def test_escaped_quote_inside_a_real_timeout_wrapper_still_passes():
    cmd = 'timeout 300 bash -c "echo \\"hi\\"; until grep -q X f; do sleep 5; done"'
    assert hook.evaluate(bash(cmd)) is None


@pytest.mark.parametrize("raw", ["null", "[]", "5", '"x"', '{"tool_name": "Bash", "tool_input": null}'])
def test_non_object_json_exits_quietly(raw):
    code, err = run_hook("block_unbounded_wait", None, raw=raw)
    assert code == 0 and err == ""


@pytest.mark.parametrize("cmd", [
    'echo "timeout 1 x"; while true; do sleep 1; done',
    "echo 'timeout 1 x'; while true; do sleep 1; done",
    'echo "timeout 5 true" && until grep -q X f; do sleep 5; done',
])
def test_timeout_text_inside_a_string_is_not_a_wrapper(cmd):
    assert hook.evaluate(bash(cmd)) is not None


def test_timeout_inside_an_outer_string_that_also_holds_the_loop_still_counts():
    cmd = "bash -c 'timeout 60 bash -c \"until grep -q X f; do sleep 5; done\"'"
    assert hook.evaluate(bash(cmd)) is None
