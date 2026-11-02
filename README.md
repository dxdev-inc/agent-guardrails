# agent-guardrails

Small hooks that stop a coding agent before it makes a known mistake.

A coding agent is fast and tireless, which is also how it ends up running a wait loop that never finishes or printing a credentials file into its own conversation. These hooks catch those mistakes at the moment the agent tries them, and tell the agent what to do instead.

Each hook is one Python file with no dependencies beyond Python (tested on 3.13). They work with [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks).

## What it stops

| Hook | The mistake | What the agent is told |
|---|---|---|
| `block_unbounded_wait.py` | A shell loop that sleeps and waits for something that may never happen, such as `until grep -q DONE log; do sleep 5; done` after the job already exited. It runs forever and keeps launching processes. | Add a deadline, wrap it in `timeout`, or do not poll. |
| `block_secret_file_read.py` | Printing a credentials file (`.env`, `.env.local`, anything in a `.secrets` folder) or a secret variable (`echo $DB_PASSWORD`) into the conversation. The transcript is saved and re-sent every turn, so the secret leaks for good. | Check presence or names only, or pass the value straight to the program. |
| `block_unbounded_sql_scan.py` | Running `psql`, `mysql`, `sqlcmd` and friends with `LIKE '%text%'` or a recursive query with no starting key. Both are likely to force a full table scan. | Anchor the pattern, look up by key, or run it with a timeout. |
| `block_unbounded_powershell_output.py` | Writing a PowerShell script that sends a native program's output to a file with `*>` or `2>&1` and no size limit. A looping program can fill a disk. | Add `Select-Object -First N`, or redirect errors on their own. |

Each hook also stays quiet on the safe version of the same thing. `grep -l KEY .env` (just asks which files match) passes. `LIKE 'abc%'` passes. A loop with `timeout` around it passes. The tests check both directions.

These are guards against habitual mistakes, not security sandboxes. Each file's top docstring says exactly what it does not cover.

## Not a sandbox: known limits

Every hook is a text heuristic over the command or file the agent is about to use. A determined or unusual command can get past it, and a harmless one can occasionally be blocked. Specifically:

- **`@`-mentioned files skip every hook.** When you type `@.env` in your own prompt, Claude Code inserts the file contents itself, with no tool call, so no `PreToolUse` hook (including `Read` matchers) fires. The Claude Code hooks reference documents this. To cover it, add `Read` deny rules to your settings. This is a starting point that matches every shape the secret hook blocks, in any directory:

  ```json
  "permissions": { "deny": [
    "Read(**/.env)", "Read(**/.env.*)", "Read(**/.env-*)", "Read(**/.env_*)",
    "Read(**/*.env)", "Read(**/.secrets/**)"
  ] }
  ```

  These also deny template files such as `.env.example`, which the hook allows; narrow them if you need those. They are case-sensitive on some platforms, so a `.SECRETS` folder may need its own line. Check the pattern syntax against the permissions documentation for your Claude Code version. The other option is to set `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` (newer Claude Code versions; check the docs for yours) so mentions go through the `Read` tool.
- **Wait loops:** the `timeout` wrapper check and the loop counting are text scans, not a shell parser. Odd quoting, `$(...)` or here-documents can fool them either way.
- **SQL scans:** a leading-wildcard `LIKE` is treated as a likely full scan, but some indexes (trigram, full-text) can serve it, and the hook cannot see your schema. The recursive-query check judges the anchor by its `WHERE` shape and column name only; it cannot know which columns are really keys.
- **PowerShell output:** a statement built up across several separate edits, or assembled from variables at run time, can slip through.
- **Secret reads:** the list of reader commands is finite. See the hook's docstring for what is not covered.

The hooks run `python` (Windows) or `python3` (elsewhere) from your `PATH`, so that interpreter must be available when Claude Code starts. A virtual environment that is not active at that moment will not be found.

On macOS and Linux many systems have `python3` but no `python`. Wherever this README says `python`, use `python3` there (and `python3 -m pip` for `pip`).

## Install in two minutes

You need Python 3 (tested on 3.13) and Claude Code.

```
git clone https://github.com/dxdev-inc/agent-guardrails.git
cd agent-guardrails
python install.py --dry-run     # shows what would change in ~/.claude/settings.json
python install.py               # does it
```

The installer adds four `PreToolUse` entries, leaves your other settings alone, and is safe to run twice. `python install.py --remove` takes them out again, including the entries of an earlier or moved clone of this repository (a `hooks/` folder under a directory with `agent-guardrails` in its name). Hooks of the same file names from other projects are left alone. Before each write the installer saves the old file as `settings.json.bak` and replaces the file atomically. To try it on a throwaway file first, add `--settings /tmp/test-settings.json`.

Check it works, without running an agent:

```
python examples/try_hooks.py --settings ~/.claude/settings.json --tool Read --file-path .env
```

You should see `exit code 2` and `RESULT: BLOCKED`. Change the file to `.env.example` and it says `allowed`.

If you would rather wire a hook by hand, this is the whole entry:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "python /full/path/to/hooks/block_unbounded_wait.py" }]
      }
    ]
  }
}
```

## How a hook works

Before Claude Code runs a tool, it starts your command and writes a JSON description of the call to its standard input:

```json
{ "tool_name": "Bash", "tool_input": { "command": "until grep -q X f; do sleep 5; done" } }
```

Your script answers with its exit code:

- `0`: go ahead.
- `2`: block it. Whatever you wrote to standard error is shown to the agent as the reason, so say what to do instead.

That is the whole contract. Any other failure should also exit `0`, so a bug in a guard never freezes your agent.

## Add your own

1. Copy the smallest hook (`hooks/block_unbounded_sql_scan.py` is a good model) to `hooks/block_my_thing.py`.
2. Keep the shape: a function `evaluate(payload) -> str | None` that returns the block message or `None`, and a `main()` that reads stdin and exits `0` or `2`.
3. Write two lists in `tests/test_my_thing.py`: calls that must be blocked, and similar-looking calls that must pass. Write the "must pass" list first. A guard that blocks good work gets switched off.
4. Add a line to `HOOKS` in `install.py` with the tools it should see.
5. Run the tests.

## Overrides

Sometimes a human really does want the blocked thing. The wait, SQL and secret-file hooks each have an off switch for that, named in their docstrings (for example `UNBOUNDED_WAIT_OK=1`, `SQL_SCAN_OK=1`, `SECRET_READ_GATE=off`). The wait and SQL hooks also accept a one-shot flag file under `~/.claude/` that is deleted the first time it is used, so every override is a fresh decision. The PowerShell hook has no switch; to turn it off, remove its entry from your settings.

## Tests

```
python -m pip install pytest
python -m pytest -q
```

The tests cover the blocked and allowed cases for every hook, plus a subprocess check of the real stdin and exit-code contract.

## License

MIT. Copyright (c) 2026 DXdev.
