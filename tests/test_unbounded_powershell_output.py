"""block_unbounded_powershell_output: fires on unbounded native output to a file, quiet on bounded look-alikes."""
import block_unbounded_powershell_output as hook
from conftest import run_hook


def write(path, content):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content}}


def test_the_classic_unbounded_capture_line_is_refused():
    f = hook.lint("Set-Location C:/x\n& C:/Python313/python.exe $argline *> 'C:/out.txt'\n")
    assert len(f) == 1 and f[0].line == 2 and f[0].operator == "*>"


def test_merge_and_bare_pipe_to_a_file_are_refused():
    assert hook.lint("& git.exe status 2>&1 > s.txt\n")
    assert hook.lint("& python -m foo 2>&1 | Out-File x.txt\n")
    assert hook.lint("python -m foo | Out-File x.txt\n")
    assert hook.lint("& 'C:/Program Files/Git/git.exe' log |\n    Out-File x\n")
    assert hook.lint("& python.exe $a 2>&1 | Tee-Object out.txt\n")
    assert hook.lint("$o = & git log 2>&1 | Set-Content out.txt\n")
    assert hook.lint("$o = git log *> out.txt\n")


def test_a_later_safe_sink_does_not_hide_an_earlier_unbounded_write():
    assert hook.lint("python x 2>&1 | Tee-Object out.txt | Out-Null\n")
    assert hook.lint("python x 2>&1 | Out-File out.txt | Out-Null\n")
    assert hook.lint("python x *> out.txt | Out-Null\n")
    # Out-Null after a memory-only pipe still writes nothing to disk
    assert not hook.lint("python x 2>&1 | Out-Null\n")
    # -First stops everything before it, so a Tee-Object ahead of it is bounded
    assert not hook.lint("python x 2>&1 | Tee-Object out.txt | Select-Object -First 100\n")


def test_bounded_sinks_and_waiver_are_allowed():
    assert not hook.lint("& python.exe x 2>&1 | Select-Object -First 200\n")
    assert not hook.lint("& python.exe x 2>&1 | Select-Object -First 50 | Out-String -Width 200\n")
    assert not hook.lint("& python.exe x *> out  # ps-lint: bounded (watchdog kills at 50MB)\n")
    assert not hook.lint("$o = & git log 2>&1 | Select-Object -First 5\n")


def test_non_merging_forms_and_non_natives_are_not_flagged():
    assert not hook.lint("& python.exe x 2>$null\n")
    assert not hook.lint("& python.exe x 2> err.txt\n")
    assert not hook.lint("& python.exe x > out.txt\n")
    assert not hook.lint("Get-ChildItem | Select-Object -First 3\n")
    assert not hook.lint("Get-Process *> out.txt\n")                  # a cmdlet, not a native program
    assert not hook.lint("Write-Host 'a *> b | python.exe 2>&1'\n")   # inside a string
    assert not hook.lint("# & python.exe x *> out\n")                  # a comment


def test_memory_only_pipes_are_not_flagged():
    for ok in (
        "$o = & git log 2>&1\n",
        "git -C $wt status --porcelain | Where-Object { $_ }\n",
        "$r = & powershell -File x.ps1 2>&1 | Out-String\n",
        "python -m foo 2>&1 | Select-String ok\n",
    ):
        assert not hook.lint(ok), ok


def test_hook_checks_ps1_writes_and_edits_only():
    bad = "& python.exe $a *> out\n"
    assert hook.check(write("C:/work/g.ps1", bad))
    edit = {"tool_name": "Edit", "tool_input": {"file_path": "C:/work/g.ps1", "new_string": bad}}
    assert hook.check(edit)
    multi = {"tool_name": "MultiEdit", "tool_input": {"file_path": "g.ps1", "edits": [{"new_string": bad}]}}
    assert hook.check(multi)
    assert hook.check(write("C:/work/g.py", bad)) == ""
    assert hook.check(write("C:/work/g.ps1", "Get-Date\n")) == ""
    assert hook.check({"tool_name": "Write", "tool_input": None}) == ""


def test_exit_code_contract():
    code, err = run_hook("block_unbounded_powershell_output", write("run.ps1", "& python.exe $a *> out.txt\n"))
    assert code == 2 and "run.ps1" in err and "Select-Object -First" in err
    ok = write("run.ps1", "& python.exe $a 2>&1 | Select-Object -First 100\n")
    code, err = run_hook("block_unbounded_powershell_output", ok)
    assert code == 0 and err == ""
    code, _ = run_hook("block_unbounded_powershell_output", None, raw="")
    assert code == 0


def test_first_n_does_not_bless_a_file_write_it_cannot_stop():
    # *> and Out-File write everything before Select-Object sees any of it
    assert hook.lint("python x *> out.txt | Select-Object -First 100\n")
    assert hook.lint("python x 2>&1 | Out-File out.txt | Select-Object -First 100\n")
    assert hook.lint("python x 2>&1 | Set-Content out.txt | select -First 100\n")
    # Tee-Object passes data on, so -First does stop it
    assert not hook.lint("python x 2>&1 | Tee-Object out.txt | Select-Object -First 100\n")


def test_partial_edit_that_completes_a_hazardous_line_is_refused(tmp_path):
    f = tmp_path / "a.ps1"
    f.write_text("python x 2>&1 | $sink\n", encoding="utf-8")
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": str(f), "old_string": "$sink", "new_string": "Out-File out.txt"}}
    assert hook.evaluate(payload) is not None
    code, err = run_hook("block_unbounded_powershell_output", payload)
    assert code == 2 and "a.ps1" in err


def test_multiedit_pieces_are_applied_in_order(tmp_path):
    f = tmp_path / "b.ps1"
    f.write_text("python x 2>&1 | $sink\n", encoding="utf-8")
    payload = {"tool_name": "MultiEdit", "tool_input": {"file_path": str(f), "edits": [
        {"old_string": "$sink", "new_string": "$s2"},
        {"old_string": "$s2", "new_string": "Out-File out.txt"}]}}
    assert hook.evaluate(payload) is not None


def test_partial_edit_that_leaves_the_statement_safe_or_unrelated_is_allowed(tmp_path):
    f = tmp_path / "c.ps1"
    f.write_text("python x 2>&1 | $sink\nWrite-Host hi\n", encoding="utf-8")
    safe = {"tool_name": "Edit", "tool_input": {
        "file_path": str(f), "old_string": "$sink", "new_string": "Select-String foo"}}
    assert hook.evaluate(safe) is None
    # an existing hazard elsewhere in the file is not blamed on an unrelated edit
    g = tmp_path / "d.ps1"
    g.write_text("python x *> old.txt\nWrite-Host hi\n", encoding="utf-8")
    unrelated = {"tool_name": "Edit", "tool_input": {
        "file_path": str(g), "old_string": "hi", "new_string": "there"}}
    assert hook.evaluate(unrelated) is None


def test_edit_of_a_missing_file_still_lints_the_new_text(tmp_path):
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": str(tmp_path / "nope.ps1"), "old_string": "a", "new_string": "python x *> o.txt"}}
    assert hook.evaluate(payload) is not None


import pytest  # noqa: E402


@pytest.mark.parametrize("raw", ["null", "[]", "5", '"x"'])
def test_non_object_json_exits_quietly(raw):
    code, err = run_hook("block_unbounded_powershell_output", None, raw=raw)
    assert code == 0 and err == ""


def test_helper_name_after_the_call_or_inside_a_longer_word_bounds_nothing():
    assert hook.lint("python x *> out.txt | Invoke-BoundedNative\n")
    assert hook.lint("python x *> out.txt | Invoke-BoundedNativeEvil\n")
    assert hook.lint("python x 2>&1 | Out-File o.txt # Limit-Output\n")


def test_helper_that_wraps_the_call_is_allowed():
    assert not hook.lint("Invoke-BoundedNative python x *> out.txt\n")
    assert not hook.lint("Limit-Output -Max 1MB python x 2>&1 | Out-File o.txt\n")


def test_a_duplicate_of_an_existing_hazard_is_still_new(tmp_path):
    f = tmp_path / "dup.ps1"
    f.write_text("python x 2>&1 | Out-File o.txt\npython x 2>&1 | $sink\n", encoding="utf-8")
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": str(f), "old_string": "$sink", "new_string": "Out-File o.txt"}}
    assert hook.evaluate(payload) is not None
