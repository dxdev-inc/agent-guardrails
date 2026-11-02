"""PreToolUse hook: block a shell wait loop that sleeps and can never end on its own.

THE FAILURE: an agent starts a background wait such as
`until grep PATTERN file; do sleep 5; done`. The thing it was waiting for
finishes or dies first, so the pattern can never appear and the loop sleeps
forever. Each pass launches new processes, so a forgotten loop keeps costing
CPU for hours. Agents reach for this shape naturally, so the fix belongs at
the point of creation: refuse it before it runs.

WHAT IT BLOCKS: a loop (`while`/`until`, or an infinite/arithmetic `for`) whose
body sleeps and whose only exit condition may never become true. No deadline,
no iteration cap, no external timeout.

WHAT IT ALLOWS:
  - `for i in <a fixed list>` (`{1..60}`, `$(seq 1 60)`): finite by construction.
  - A condition or body that checks elapsed time or a deadline (`SECONDS`,
    `EPOCHSECONDS`, `date +%s`, a `DEADLINE` / `END_TIME` / `ELAPSED` variable,
    a `MAX_TRIES` style cap).
  - A counter that is incremented and compared against a bound in the loop
    condition, or compared with a `break` / `exit` / `return` in scope.
  - An external `timeout N ...` wrapper that encloses the loop (a `timeout`
    earlier in a separate `;`/`&&`/`|` segment does not count).
  - A loop with no `sleep` in it (a busy loop is a different problem).
  - A bare `sleep N` with no loop.

THIS IS A REGEX HEURISTIC OVER SHELL TEXT, not a parser. Nested loops are
handled by counting balanced `do` / `done` tokens, so a trailing `sleep` after
an inner loop is still seen as part of the outer loop's body. It is not
quote-aware when counting loops: the word `do` or `done` inside a string or
heredoc is counted as a real token. (The `timeout` wrapper check is quote- and
backslash-aware, but it is still a text scan, so unusual quoting such as nested
`$(...)` or here-documents can fool it either way. Not a sandbox.) It leans toward blocking, because a false block is visible and
overridable, while a false allow lets a runaway loop through.

Hook input on stdin (JSON):
  { "tool_name": "Bash", "tool_input": { "command": "..." } }

Exit codes:
  0 - allow
  2 - block (stderr becomes the reason the agent sees)

Override: set UNBOUNDED_WAIT_OK=1 in the hook's environment, or create the
one-shot flag file ~/.claude/unbounded_wait_ok (it is deleted when used).
"""

from __future__ import annotations

import json
import os
import re
import sys

# Cheap bail: every blockable shape needs at least one loop keyword.
_HAS_LOOP_RE = re.compile(r"\b(while|until|for)\b")

# An external deadline wrapper -- `timeout 300 ...` (or `timeout 30s ...`).
# It only bounds a loop it actually wraps: see `_covered_by_timeout`.
_TIMEOUT_WRAPPER_RE = re.compile(r"\btimeout\s+\d+[a-zA-Z]*\s")

# while/until CONDITION do -- header only, up to and including its own `do`.
# The BODY is found separately by `_scoped_body()` (balanced do/done depth
# counting), not by a naive non-greedy `.*?done` -- see that function's
# docstring for why: a loop nested inside this one's body used to make the
# non-greedy form stop at the INNER loop's `done`, silently truncating the
# body before it ever reached this loop's own trailing `sleep`.
_WHILE_UNTIL_HEAD_RE = re.compile(r"\b(while|until)\b(?P<cond>.*?)\bdo\b", re.DOTALL)

# for VAR in LIST do BODY done -- always bounded (a fixed list), regardless
# of body content. (Body scoping doesn't matter here since this shape is
# never inspected further -- see `_find_unbounded_wait`.)
_FOR_IN_RE = re.compile(r"\bfor\b\s+\S+\s+in\b(?P<list>.*?)\bdo\b(?P<body>.*?)\bdone\b", re.DOTALL)

# C-style for ((init; cond; incr)) do -- header only, up to and including its
# own `do`. Bounded only if `cond` is non-empty and is itself a bounded/
# deadline signal (checked below); an empty cond (`for ((;;))`) is an
# explicit infinite loop.
_FOR_ARITH_HEAD_RE = re.compile(
    r"\bfor\s*\(\(\s*(?P<init>[^;]*);\s*(?P<cond>[^;]*);\s*(?P<incr>[^)]*)\)\)\s*;?\s*\bdo\b",
    re.DOTALL,
)

# A bare `do`/`done` token scan used to find the body that
# belongs to a given `do` -- walking through ANY loop nested inside via
# depth counting, rather than stopping at the first `done` encountered.
# Every loop construct (while/until/for, of any kind) closes its body with
# `done`, so counting bare do/done tokens correctly scopes nesting no matter
# which loop type introduced each pair -- this is balanced-token matching
# (like matching parentheses), not a shell grammar parser.
_DO_DONE_TOKEN_RE = re.compile(r"\b(do|done)\b")


def _quote_at(cmd: str, pos: int) -> "str | None":
    """The quote character still open just before `pos`, or None."""
    quote = None
    escaped = False
    for ch in cmd[:pos]:
        if escaped:
            escaped = False
        elif ch == "\\" and quote != "'":
            escaped = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
    return quote


def _covered_by_timeout(cmd: str, loop_start: int) -> bool:
    """True if a `timeout N` wrapper encloses the loop starting at `loop_start`.

    The wrapper must come before the loop with no command separator (`;`, `&`,
    `|`, newline) between them outside quotes. `timeout 300 bash -c 'until ...;
    do sleep 5; done'` is covered (the separators sit inside the quotes);
    `timeout 1 true; while true; do sleep 1; done` is not (the `;` ends the
    timed command before the loop starts)."""
    for t in _TIMEOUT_WRAPPER_RE.finditer(cmd, 0, loop_start):
        # The word `timeout` may itself sit inside a quoted string
        # (`echo "timeout 1 x"; while ...`). Then it is text, not a wrapper,
        # unless the loop is inside that same string (`bash -c 'timeout 5 ...'`),
        # in which case the string's own contents are scanned as the top level.
        base = _quote_at(cmd, t.start())
        quote = base
        escaped = False
        for ch in cmd[t.end():loop_start]:
            if escaped:  # the character after a backslash is literal (not in single quotes)
                escaped = False
            elif ch == "\\" and quote != "'":
                escaped = True
            elif quote != base:
                if ch == quote:
                    quote = base
            elif base and ch == base:
                break  # the string holding the `timeout` text closed before the loop
            elif ch in "'\"":
                quote = ch
            elif ch in ";&|\n":
                break
        else:
            return True
    return False


def _scoped_body(cmd: str, do_end: int) -> "str | None":
    """The text between a `do` (whose match ends at `do_end` -- the caller
    already consumed that keyword) and ITS matching `done`, walking through
    any loop nested inside via do/done depth counting.

    THE GAP THIS FIXES: `while true; do for i in {1..3}; do :; done; sleep 5;
    done` is a genuinely unbounded loop -- the trailing `sleep 5` runs every
    iteration of an outer loop with no exit condition. The old non-greedy
    `.*?\\bdone\\b` stopped at the FIRST `done`, which belongs to the INNER
    `for`, so the captured "body" was `for i in {1..3}; do :;` -- missing
    the `sleep 5` entirely, so the guard never saw it and allowed the
    command through. Depth counting instead finds the outer loop's OWN
    matching `done`, so its body correctly includes everything up to that
    point, inner loops and all.

    STILL NOT A PARSER: a literal `do`/`done` word inside a quoted string,
    heredoc body, or comment is still counted as a real token (same
    limitation the old regex had) -- this only fixes the nesting-depth
    scoping, not quote-awareness. Returns None if the command is unbalanced
    (no matching `done` found) -- callers treat "can't tell" as "don't
    block on a guess", matching this guard's existing conservative-in-the-
    allow-direction convention elsewhere.
    """
    depth = 1
    for m in _DO_DONE_TOKEN_RE.finditer(cmd, do_end):
        depth += 1 if m.group(1) == "do" else -1
        if depth == 0:
            return cmd[do_end:m.start()]
    return None

_SLEEP_RE = re.compile(r"\bsleep\b")

# Elapsed-time / deadline signals: bash's own elapsed-seconds builtin, a Unix
# epoch snapshot, or a plainly-named deadline/cap variable.
_BOUNDED_SIGNAL_RE = re.compile(
    r"\bSECONDS\b|\bEPOCHSECONDS\b|date\s+\+%s"
    r"|\bDEADLINE\b|\bEND_TIME\b|\bELAPSED\b"
    r"|\bMAX_(TRIES|ATTEMPTS|RETRIES|WAIT|ITER)\b",
    re.IGNORECASE,
)
# A counter with a compare-and-break: increment + numeric compare + an exit
# out of the loop, all present in the same scoped (condition + body) text.
_COUNTER_INCREMENT_RE = re.compile(r"\+\+|\+=\s*1\b|\+\s*1\s*\)\)")
# The variable being incremented, so the loop condition can be
# required to compare THAT variable (`n=$((n+1))`, `n++`, `((++n))`, `n+=1`).
_COUNTER_VAR_RES = (
    re.compile(r"\b([A-Za-z_]\w*)\s*=\s*\$\(\(\s*\$?\{?\1\}?\s*\+\s*1\s*\)\)"),
    re.compile(r"\b([A-Za-z_]\w*)\s*\+\+"),
    re.compile(r"\+\+\s*([A-Za-z_]\w*)\b"),
    re.compile(r"\b([A-Za-z_]\w*)\s*\+=\s*1\b"),
)
_COUNTER_COMPARE_RE = re.compile(r"-ge\b|-gt\b|-le\b|-lt\b|-eq\b|[<>]=?")
_COUNTER_BREAK_RE = re.compile(r"\bbreak\b|\bexit\b|\breturn\b")

# One-shot override flag: consumed (deleted) the first time it is used.
OVERRIDE_FLAG = os.path.expanduser("~/.claude/unbounded_wait_ok")


def _cond_combines_safely(cond: str, kind: str) -> bool:
    """A counter compare only bounds the loop when it can end it alone.
    `until` exits when the condition is TRUE, so an `&&` operand
    (`until grep -q X f && [ $n -ge 10 ]`) needs the other operand true too and
    never ends; `while` exits when it is FALSE, so an `||` operand
    (`while [ $n -lt 10 ] || true`) keeps it running. Allow the compare only
    when the condition has no such combinator for this loop kind."""
    return ("&&" if kind == "until" else "||") not in cond


def _counter_compared_in_cond(scoped_text: str, cond: str) -> bool:
    """True if the loop increments a variable AND `cond` compares that same
    variable (`$n -ge 10`, `${n} -gt`, `10 -le $n`, `(( n >= 10 ))`,
    `[[ $n -lt 5 ]]`). A bare `<`/`>` elsewhere in the condition (e.g.
    `2>/dev/null`) or a compare of some other value never counts."""
    names = set()
    for rx in _COUNTER_VAR_RES:
        names.update(m.group(1) for m in rx.finditer(scoped_text))
    for name in names:
        v = re.escape(name)
        ref = r"\$\{?" + v + r"\}?"
        ops = r"-(?:ge|gt|le|lt|eq|ne)\b"
        if re.search(ref + r"\"?\s+" + ops, cond):
            return True
        if re.search(ops + r"\s+\"?" + ref, cond):
            return True
        for arith in re.finditer(r"\(\(([^)]*)\)\)|\[\[([^\]]*)\]\]", cond):
            body = arith.group(1) or arith.group(2) or ""
            if re.search(r"(?<![\w$])\$?\{?" + v + r"\}?\"?\s*(?:[<>]=?|" + ops + ")", body):
                return True
            if re.search(r"[<>]=?\s*\$?\{?" + v + r"\b", body):
                return True
    return False


def _is_bounded(scoped_text: str, cond: str = "", kind: str = "until") -> bool:
    if _BOUNDED_SIGNAL_RE.search(scoped_text):
        return True
    # The counter form `until [ $n -ge 110 ]; do sleep 5; n=$((n+1));
    # done` bounds the loop through its own CONDITION (the compare is the
    # exit), so no break/exit/return is needed -- an increment in the loop plus
    # a numeric compare in the condition is enough.
    if cond and _cond_combines_safely(cond, kind) and _counter_compared_in_cond(scoped_text, cond):
        return True
    if (
        _COUNTER_INCREMENT_RE.search(scoped_text)
        and _COUNTER_COMPARE_RE.search(scoped_text)
        and _COUNTER_BREAK_RE.search(scoped_text)
    ):
        return True
    return False


def _find_unbounded_wait(cmd: str) -> bool:
    """True if `cmd` contains at least one loop that sleeps in its (properly
    nesting-scoped, via `_scoped_body`) body and has no bounded/deadline
    signal. Each loop occurrence -- at any nesting depth -- is found and
    checked independently, so an unbounded sleep loop is caught whether it
    is the outermost loop, nested inside a bounded one, or wraps a bounded
    one itself; see `_scoped_body`'s docstring for the nesting fix this
    relies on."""
    for m in _FOR_ARITH_HEAD_RE.finditer(cmd):
        body = _scoped_body(cmd, m.end())
        if body is None or not _SLEEP_RE.search(body):
            continue
        cond = m.group("cond") or ""
        incr = m.group("incr") or ""
        # A real counting loop: `for ((i=0; i<10; i++))` has a numeric compare and an increment.
        if cond.strip() and incr.strip() and _COUNTER_COMPARE_RE.search(cond):
            continue
        if cond.strip() and _is_bounded(cond):
            continue
        if _is_bounded(cond + body):
            continue
        if _covered_by_timeout(cmd, m.start()):
            continue
        return True

    # for-in loops are always structurally bounded (a fixed list) -- never a
    # block source, no need to inspect them further.

    for m in _WHILE_UNTIL_HEAD_RE.finditer(cmd):
        body = _scoped_body(cmd, m.end())
        if body is None or not _SLEEP_RE.search(body):
            continue
        cond = m.group("cond") or ""
        if _is_bounded(cond + body, cond, m.group(1)):
            continue
        if _covered_by_timeout(cmd, m.start()):
            continue
        return True

    return False


MESSAGE = (
    "Blocked: this looks like an unbounded wait loop. It sleeps, and its exit "
    "condition may never become true.\n"
    "\n"
    "A typical failure: `until grep PATTERN file; do sleep N; done` where the "
    "thing being waited on has already exited, so the pattern can never "
    "appear and the loop relaunches grep and sleep forever.\n"
    "\n"
    "Two ways to fix it:\n"
    "  1. Do not poll. Start long work in the background and let the tool "
    "notify you when it finishes, or use a built-in way to wait on a "
    "condition.\n"
    "  2. If a wait loop is genuinely needed, give it a deadline so it ends "
    "on its own:\n"
    "     end=$((SECONDS+300)); until grep -q PATTERN file || "
    "[ \"$SECONDS\" -ge \"$end\" ]; do sleep 5; done\n"
    "  or wrap it from outside:\n"
    "     timeout 300 bash -c 'until grep -q PATTERN file; do sleep 5; done'\n"
    "\n"
    "Override (rare, needs a deliberate human go): create the one-shot flag "
    "file\n"
    f"  {OVERRIDE_FLAG}\n"
    "and retry. It is deleted on use, so each override needs a fresh decision. "
    "Setting UNBOUNDED_WAIT_OK=1 in the hook's environment also works.\n"
)


def evaluate(payload: dict) -> "str | None":
    """The block message if `payload` is a Bash call containing an
    unbounded wait loop, else None."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return None

    tool_input = payload.get("tool_input")
    cmd = tool_input.get("command") if isinstance(tool_input, dict) else ""
    if not isinstance(cmd, str) or not cmd:
        return None

    # Cheap bail: every blockable shape needs a loop keyword and a sleep.
    if not _SLEEP_RE.search(cmd) or not _HAS_LOOP_RE.search(cmd):
        return None

    if not _find_unbounded_wait(cmd):
        return None

    if os.environ.get("UNBOUNDED_WAIT_OK") == "1":
        return None

    try:
        if os.path.isfile(OVERRIDE_FLAG):
            os.remove(OVERRIDE_FLAG)
            return None
    except Exception:
        pass

    return MESSAGE


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    try:
        message = evaluate(payload)
    except Exception:
        return 0  # a bug in the guard must never block the agent
    if message is None:
        return 0

    sys.stderr.write(message)
    return 2


if __name__ == "__main__":
    sys.exit(main())
