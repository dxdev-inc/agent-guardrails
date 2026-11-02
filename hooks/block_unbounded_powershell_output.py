"""PreToolUse hook for Write / Edit / MultiEdit of PowerShell scripts: refuse unbounded
output capture from a native program.

THE FAILURE: a generated script runs `& python.exe $args *> out.txt`. If the
program misbehaves (here, an empty argument list started an interactive loop
that failed over and over), nothing limits how much it writes. In Windows
PowerShell 5.1, `*>` and `2>&1` on a native program wrap every stderr line in a
multi-line ErrorRecord, so one repeating error grew into a file large enough to
fill a disk. The footgun is the merged redirection (`*>`, `2>&1`) or a bare pipe
straight off a native program into a file, with nothing bounding how much can flow.

WHAT IT BLOCKS: a `.ps1` file written with a statement that sends a native
program's merged output to a file with no bound. A native program is one whose
command ends in `.exe`, or a well-known tool name (python, git, node, npm,
curl, docker, ...).

WHAT IT ALLOWS, per statement:
  - an explicit bound on the same logical line: `Select-Object -First N`,
    `Out-Null`, or a size-capped helper (`Invoke-BoundedNative`, `Limit-Output`)
  - a waiver comment: `# ps-lint: bounded (<reason>)`
  - plain `2>$null`, `2> file` and `> file`
  - merged output that stays in memory (a variable, `Select-String`,
    `Where-Object`, `Out-String`): that cannot fill a drive
  - cmdlets (only native programs are checked), and text inside comments or quotes

This is a heuristic, not a PowerShell parser. Comments and quoted strings are
blanked before operators are looked for. Here-string bodies are linted as code
on purpose, because a script that generates another script often holds the native
call inside a here-string.

For Edit and MultiEdit the hook rebuilds the file as it would be after the edit
(when the file exists and the old text is found) and flags statements that are new
compared with the file before the edit, so an edit that completes a hazardous line
out of separate pieces is seen. If the file cannot be read, only the new text is
linted. A statement assembled across several separate edits, or from variables at
run time, can still slip through. Not a sandbox.

Hook input on stdin (JSON): {"tool_name": ..., "tool_input": {"file_path": ...,
"content" | "new_string" | "edits": [...]}}

Exit codes: 0 allow, 2 block (stderr is the reason the agent sees). Fails open
on unreadable input: a lint must never wedge every write.
"""
from __future__ import annotations

import re
import json
import sys
from collections import Counter
from dataclasses import dataclass

# Native tools commonly invoked by bare name in these scripts. `.exe`-suffixed
# commands are native by definition and need no entry here.
NATIVE_NAMES = (
    "python", "python3", "pythonw", "py", "git", "gh", "node", "npm", "npx",
    "pytest", "pip", "schtasks", "robocopy",
    "powershell", "pwsh", "cmd", "curl", "ssh", "scp", "docker",
)

_CMD = (
    r"(?:\"[^\"]*?\.exe\"|'[^']*?\.exe'|[^\s'\"|;&(){}]+?\.exe"
    r"|(?:%s)(?![\w.\-]))" % "|".join(NATIVE_NAMES)
)
# Start of a native call: statement start, `&`/`.` call operator, or after an
# opening `{`, `(` or `;`. `if (...)`/`foreach` heads are not special-cased:
# a native call inside them still starts after `(` or `{`.
_NATIVE_RE = re.compile(
    r"(?:^|[;{(]|\|\s*|\bthen\b|(?<![=<>!])=)\s*(?:&\s*|\.\s+)?(?P<cmd>%s)" % _CMD,
    re.IGNORECASE,
)

_MERGE_RE = re.compile(r"\*>>?|\b[12]>>?&[12]\b|(?<![|])\|(?![|])")
# A stage that ends the whole pipeline early (`-First N` stops the stages before it).
_STOP_SINK_RE = re.compile(
    r"Select-Object\s+(?:[^|]*\s)?-First\b|\bselect\s+(?:[^|]*\s)?-First\b",
    re.IGNORECASE,
)
# A size-capped helper wraps the whole call.
# It counts only when it WRAPS the native call: named before it in the same statement
# (`Invoke-BoundedNative python x *> f`). The name after a pipe, or as part of a longer
# word, bounds nothing.
_HELPER_RE = re.compile(r"(?<![\w-])(?:Invoke-BoundedNative|Limit-Output)(?![\w-])[^|;]*$", re.IGNORECASE)
_TEE_RE = re.compile(r"Tee-Object", re.IGNORECASE)
# A stage that only throws away what reaches it. It does NOT stop the stages
# before it, so a file writer ahead of it still writes everything.
_DISCARD_SINK_RE = re.compile(
    r"Select-Object\s+(?:[^|]*\s)?-Last\b|\bselect\s+(?:[^|]*\s)?-Last\b|Out-Null",
    re.IGNORECASE,
)
# Where a merged stream can reach the DISK. A pipe or `2>&1` that ends in memory
# (a variable, Select-String, Where-Object, Out-String) cannot fill a drive, and
# flagging those gave false blocks on ordinary `git ... | Select-String` style
# filters.
_FILE_SINK_RE = re.compile(r"(?:Out-File|Set-Content|Add-Content|Tee-Object)", re.IGNORECASE)
_STRIP_REDIR_RE = re.compile(r"\*>>?|\d?>>?&\d|\d>>?\s*\$null", re.IGNORECASE)
_WAIVER_RE = re.compile(r"#\s*ps-lint:\s*bounded\b", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    line: int
    operator: str
    statement: str

    def __str__(self) -> str:
        return (f"line {self.line}: unbounded output capture from a native exe "
                f"({self.operator}): {self.statement.strip()[:120]}")


def _scrub(line: str) -> tuple[str, str, list[bool]]:
    """(blanked, commentless, in_string) for one line, all the same length.

    `blanked` has quoted-string contents and any trailing comment replaced by
    spaces, so operator regexes cannot match inside them. `commentless` keeps
    the strings (a quoted exe path is still a native call). `in_string[i]` is
    True for characters inside a quoted string's contents."""
    blank, keep, mask = [], [], []
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "`" and quote == '"' and i + 1 < len(line):
                blank.append("  ")
                keep.append(line[i:i + 2])
                mask += [True, True]
                i += 2
                continue
            if ch == quote:
                quote = ""
                blank.append(ch)
                keep.append(ch)
                mask.append(False)
            else:
                blank.append(" ")
                keep.append(ch)
                mask.append(True)
        elif ch in "'\"":
            quote = ch
            blank.append(ch)
            keep.append(ch)
            mask.append(False)
        elif ch == "#":
            pad = " " * (len(line) - i)
            blank.append(pad)
            keep.append(pad)
            mask += [False] * len(pad)
            break
        else:
            blank.append(ch)
            keep.append(ch)
            mask.append(False)
        i += 1
    return "".join(blank), "".join(keep), mask


def _logical_lines(text: str):
    """Yield (first_line_number, raw, blanked, commentless, in_string), joining
    backtick continuations and lines that end in a pipe, so a native call and
    its sink on adjacent lines are judged as one statement."""
    raws: list[str] = []
    blanks: list[str] = []
    keeps: list[str] = []
    mask: list[bool] = []
    start = 0
    for n, raw in enumerate(text.splitlines(), 1):
        if not raws:
            start = n
        scr, keep, m = _scrub(raw)
        raws.append(raw)
        stripped = scr.rstrip()
        if stripped.endswith("`"):
            scr = stripped[:-1] + " "
            keep = keep.rstrip()[:-1] + " "
            m = m[:len(scr)]
        blanks.append(scr)
        keeps.append(keep)
        mask += list(m) + [False]  # the joining space
        if stripped.endswith("`") or stripped.endswith("|"):
            continue
        yield start, "\n".join(raws), " ".join(blanks), " ".join(keeps), mask
        raws, blanks, keeps, mask = [], [], [], []
    if raws:
        yield start, "\n".join(raws), " ".join(blanks), " ".join(keeps), mask


def lint(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, raw, scr, keep, in_str in _logical_lines(text):
        if _WAIVER_RE.search(raw):
            continue
        for m in _NATIVE_RE.finditer(keep):
            start = m.start("cmd")
            if start < len(in_str) and in_str[start]:
                continue
            tail = scr[m.end("cmd"):]
            seg = tail.split(";", 1)[0]
            op = _MERGE_RE.search(seg)
            if not op:
                continue
            if _HELPER_RE.search(scr[:start]):
                continue
            stop = _STOP_SINK_RE.search(seg)
            if stop:
                # `-First N` stops the stages ahead of it only if they pass data
                # down the pipe. `*>` and Out-File/Set-Content/Add-Content write
                # everything regardless; Tee-Object passes through and is stopped.
                seg = _TEE_RE.sub("", seg[:stop.start()])
                op = _MERGE_RE.search(seg)
                if not op:
                    continue
            discard = _DISCARD_SINK_RE.search(seg)
            if discard:
                seg = seg[:discard.start()]  # judge only what runs before the discard
            op = _MERGE_RE.search(seg)
            if not op:
                continue
            if op.group(0) != "*>" and not op.group(0).startswith("*>"):
                if not (_FILE_SINK_RE.search(seg) or re.search(r"(?<![-=])>", _STRIP_REDIR_RE.sub("", seg))):
                    continue  # merged/piped output stays in memory: cannot fill the disk
            findings.append(Finding(lineno, op.group(0), raw.replace("\n", " ")))
            break
    return findings


def refusal_message(findings: list[Finding], name: str = "script") -> str:
    lines = "\n".join(f"  {f}" for f in findings)
    return (
        f"Blocked: {name} sends a native program's output to `*>`, `2>&1` or a bare "
        "pipe with no bound. In Windows PowerShell 5.1 that wraps every stderr line in an "
        "ErrorRecord, and a looping child can fill a disk.\n"
        f"{lines}\n"
        "Bound it: end the statement with `| Select-Object -First N` (`Out-String -Width` "
        "and `Tee-Object -FilePath` do NOT bound volume), run it through a size-capped "
        "launcher, or redirect stderr alone (`2>$null` / `2>file`). A deliberate, "
        "already-bounded case takes a `# ps-lint: bounded (<reason>)` comment on the line."
    )


def _is_powershell_script(path: str) -> bool:
    return (path or "").lower().endswith(".ps1")


def _texts(tool_input: dict) -> list[str]:
    out = [tool_input.get("content"), tool_input.get("new_string")]
    out += [e.get("new_string") for e in (tool_input.get("edits") or []) if isinstance(e, dict)]
    return [t for t in out if isinstance(t, str)]


def _edit_pairs(tool_input: dict) -> list:
    pairs = []
    if isinstance(tool_input.get("old_string"), str) and isinstance(tool_input.get("new_string"), str):
        pairs.append((tool_input["old_string"], tool_input["new_string"], bool(tool_input.get("replace_all"))))
    for e in tool_input.get("edits") or []:
        if isinstance(e, dict) and isinstance(e.get("old_string"), str) and isinstance(e.get("new_string"), str):
            pairs.append((e["old_string"], e["new_string"], bool(e.get("replace_all"))))
    return pairs


def _after_edit_findings(path: str, tool_input: dict) -> list[Finding]:
    """Findings in the file as it will be after the edit that were not already in it."""
    pairs = _edit_pairs(tool_input)
    if not pairs:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            before = fh.read(5_000_000)
    except OSError:
        return []
    after = before
    for old, new, every in pairs:
        if not old or old not in after:
            return []
        after = after.replace(old, new) if every else after.replace(old, new, 1)
    known = Counter(f.statement for f in lint(before))
    new: list[Finding] = []
    for f in lint(after):
        if known[f.statement] > 0:  # a pre-existing copy of this exact statement
            known[f.statement] -= 1
        else:
            new.append(f)
    return new


def check(payload: dict) -> str:
    """Refusal message, or "" to allow."""
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return ""
    path = ti.get("file_path") or ""
    if not _is_powershell_script(path):
        return ""
    findings = [f for t in _texts(ti) for f in lint(t)]
    seen = {f.statement for f in findings}
    findings += [f for f in _after_edit_findings(path, ti) if f.statement not in seen]
    return refusal_message(findings, path) if findings else ""


def evaluate(payload: dict) -> "str | None":
    """Refusal message, or None to allow."""
    return check(payload) or None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        msg = check(payload if isinstance(payload, dict) else {})
    except Exception:
        return 0  # a bug in the guard must never block the agent
    if msg:
        print(msg, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
