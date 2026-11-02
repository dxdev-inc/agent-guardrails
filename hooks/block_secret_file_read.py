"""PreToolUse hook: refuse a read that would print a credential file into the transcript.

THE FAILURE: an agent greps or cats `.env.local` or `secrets/*.env` to find one
variable, and every value in the file lands in the conversation transcript. The
transcript is stored on disk and re-sent on every later turn, so one careless
`cat` leaks every credential in the file for good.

BLOCKED
  Bash / PowerShell: a content-printing reader (cat head tail less more bat nl tac
    strings xxd od hexdump type Get-Content gc sed awk cut sort uniq grep egrep fgrep
    rg ag ack findstr Select-String sls) with an argument that is a sensitive path,
    unless the output is reduced (below). Looks through `;` `&&` `||` `|` chains,
    `bash -c` / `powershell -Command` strings and the wrappers sudo, env, time,
    command, nohup, xargs, builtin, exec.
  Bash / PowerShell: `source F` / `. F` of a sensitive path (loads every value
    into the shell, and the next echo or set prints it), and a printer (echo printf
    print Write-Host Write-Output Write-Warning Write-Error) or `printenv NAME` that
    expands a secret-looking variable. A name is secret-looking when it contains
    PASSWORD PASSWD SECRET TOKEN CREDENTIAL APIKEY API_KEY PRIVATE_KEY ACCESS_KEY,
    ends in _KEY, _PASS or _PW, or is PASS / PW: `echo $DB_PASSWORD`,
    `Write-Host "pw=$env:SMB_PASSWORD"`. Single-quoted text does not expand;
    `${X:+set}` and `${#X}` (presence, length) and output sent to a file pass.
  Read: file_path is a sensitive path.
  Grep: output_mode "content" with a sensitive path or a non-negated sensitive glob.

SENSITIVE PATH = any path with a `.secrets` directory component (except README.md),
or a basename that is `.env`, `.env.<anything>` / `.env-<anything>` /
`.env_<anything>` (`.env.local`, `.env-dev`, `.env.production`), or ends in `.env`
(`prod.env`). Template names (`.env.example`, `.env.sample`, `.env.template`,
`.env.dist`, `.env-dev-template`: the LAST `.`/`-`/`_` segment decides) are NOT
sensitive.

DECIDED, NOT BLOCKED
  `.envrc`, `environment.py`, `envelope.py` and any other name that merely starts
  with or contains "env". Non-readers: ls, Glob, test, cp, mv, rm, git (any
  subcommand, so `git add .env` and `git status` pass), python, pytest.
  Editing: Edit/Write are not registered; `sed -i` is an edit, not a read.
  The first positional argument of a search command is its pattern, so
  `grep -rn ".env" src` (searching source for the text ".env") is allowed;
  likewise the first positional of sed/awk is the script unless -e/-f gave one.
  `--exclude=.env` / `--regexp=.env` values are not targets (only --glob/--include are).
  Heredoc bodies and PowerShell here-strings are text, not commands (a ticket body
  that mentions `cat .env` passes). A stage whose stdout goes to a file or $null
  prints nothing (`cat > .env <<EOF`, `grep -v X .env > .env.tmp`); `>&2` and
  `> /dev/stdout` still print. PowerShell writers Set-Content / Add-Content /
  Out-File are sinks, so the `(gc F) -replace .. | Set-Content F` edit passes.

REDUCED (allowed): a grep-family call with -l -L -c -q (or the long forms, or
rg --files), or a later pipeline stage that is `wc`, `Measure-Object`,
`Out-Null`, or such a grep. Grep tool modes files_with_matches and count show
no content.

NOT COVERED (stated so nobody assumes it is): a recursive search of a whole
directory that happens to contain a non-ignored .env file, python/node one-liners
that open the file, `git show REF:.env`, base64/encoding tricks, a bare `env` /
`set` / `Get-ChildItem env:` dump, and a secret held in a variable whose name does
not look secret. This is a guard against the habitual mistake, not a sandbox.

KNOWN LIMITATION, @-MENTIONS: a file the user references with `@path` in their own
prompt is inserted into the conversation by Claude Code itself, with no tool call,
so no PreToolUse hook (this one included) ever sees it. The Claude Code hooks
reference documents this. Two mitigations: add a permissions deny rule such as
`"permissions": {"deny": ["Read(**/.env)", "Read(**/.env.*)", "Read(**/.env-*)",
"Read(**/.env_*)", "Read(**/*.env)", "Read(**/.secrets/**)"]}` to settings.json
(a starting point covering each shape this hook blocks; it also denies templates
such as .env.example, and a .SECRETS folder in odd case may need its own line;
confirm the syntax in the permissions docs for your version), or set
CLAUDE_CODE_DISABLE_FILE_MENTIONS=1 (recent Claude Code versions; check the docs for
yours) so mentions go through the Read tool and this hook.

FAILS OPEN: any internal error allows the call. Kill switch: SECRET_READ_GATE=off.

Hook input on stdin (JSON): {"tool_name": ..., "tool_input": {...}}
Exit codes: 0 allow, 2 block (stderr is the reason the agent sees).
"""

from __future__ import annotations

import json
import os
import re
import sys

BLOCK_TOOLS = frozenset({"Bash", "PowerShell", "Read", "Grep"})

READERS = frozenset({
    "cat", "head", "tail", "less", "more", "most", "bat", "nl", "tac", "strings", "xxd",
    "od", "hexdump", "type", "get-content", "gc", "sed", "awk", "gawk", "cut", "sort",
    "uniq", "grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr", "select-string", "sls",
    "diff",
})
SEARCHERS = frozenset({"grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr", "select-string", "sls"})
PS_SEARCHERS = frozenset({"select-string", "sls"})  # -SimpleMatch is a parameter, not -s -i -m -p -l ...
SCRIPTED = frozenset({"sed", "awk", "gawk"})  # first positional is the script, not a file
WRAPPERS = frozenset({"sudo", "env", "time", "command", "nohup", "xargs", "builtin", "exec"})
# Wrapper options that take a separate value (`sudo -u nobody cat .env`): the
# value is not the command, so it must be skipped along with its flag.
WRAPPER_VALUE_OPTS = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
                       "--user", "--group", "--host", "--prompt", "--chdir", "--chroot",
                       "--role", "--type", "--other-user", "--close-from"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "xargs": frozenset({"-a", "-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s",
                        "--arg-file", "--delimiter", "--max-args", "--max-procs"}),
    "exec": frozenset({"-a"}),
}
SHELLS = frozenset({"bash", "sh", "zsh", "powershell", "pwsh", "cmd"})
# A later stage that swallows the text: counters, and PowerShell's file writers
# (`(Get-Content .env) -replace 'a','b' | Set-Content .env` is the PS edit idiom).
SINK_WORDS = frozenset({"wc", "measure-object", "measure", "out-null", "set-content", "add-content", "out-file"})

PATTERN_OPTS = frozenset({"-e", "--regexp", "-f", "--file", "-pattern"})
GLOB_OPTS = frozenset({"-g", "--glob", "--iglob", "--include", "-include", "-path", "-literalpath"})
SCRIPT_OPTS = frozenset({"-e", "--expression", "-f", "--file"})  # sed/awk: script given, all positionals are files
SCRIPT_VALUE_OPTS = frozenset({"-v", "-F", "-l", "--assign", "--field-separator", "--line-length"})
VALUE_OPTS = frozenset({
    "-A", "-B", "-C", "-m", "-t", "-T", "-j", "-M", "-d", "-D", "--max-count", "--type",
    "--type-not", "--context", "--after-context", "--before-context", "--threads",
    "--max-columns", "--exclude", "--exclude-dir", "--max-depth",
})
REDUCING_LONG = frozenset({
    "--files-with-matches", "--files-without-match", "--count", "--count-matches", "--quiet",
    "--files", "-quiet", "-count",
})
TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template", "dist"})
_ENV_BASE = re.compile(r"^\.env(?:[._*-](.*))?$", re.I)
_ASSIGN_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Printers that put a secret-looking variable's value into the transcript.
PRINTERS = frozenset({
    "echo", "printf", "print", "write-host", "write-output", "write-warning", "write-error",
})
_VAR_REF = re.compile(r"\$\{?(?:env:)?([A-Za-z_][A-Za-z0-9_]*)([^}\s\"']*)", re.I)
_BRACED_ENV = re.compile(r"\$\{env:([^}]+)\}", re.I)  # PowerShell names may hold - and .
_SECRET_NAME = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY"
    r"|_KEY$|_PASS$|_PW$|^PASS$|^PW$",
    re.I,
)

MESSAGE = (
    "Blocked (secret_file_read): this would print the contents of a credential file ({what}) "
    "into the transcript, where every value is stored on disk and re-sent on each later turn.\n"
    "Use instead: a presence test with grep -l / -c / -q, or the Grep tool in "
    "files_with_matches or count mode; list variable NAMES only (for example "
    "`cut -d= -f1 FILE > /tmp/names.txt` and read that file); or load the value in "
    "code and hand it to the program, never to your own output. To EDIT the file "
    "without reading it, use `sed -i` or `(Get-Content F) -replace 'a','b' | "
    "Set-Content F`; output sent to a file is not blocked. Do not `source` the file "
    "into a shell either: it puts every value in the environment for the next echo "
    "to print."
)

ECHO_MESSAGE = (
    "Blocked (secret_file_read): this would print the value of a secret variable ({what}) "
    "into the transcript, where it is stored on disk and re-sent on each later turn.\n"
    "Use instead: test presence without printing (`[ -n \"$X\" ]`, `${{X:+set}}`, "
    "`if ($env:X) {{ 'set' }}`) or print its length, and pass the value straight to "
    "the program that needs it instead of to your own output."
)


def is_sensitive_path(token: str) -> bool:
    t = token.strip().strip("'\"").rstrip(")};,")
    t = t.lstrip("<@({")
    if not t or t.startswith("!"):
        return False
    t = t.replace("\\", "/")
    parts = [p for p in t.split("/") if p]
    if not parts:
        return False
    base = parts[-1]
    if ".secrets" in (p.lower() for p in parts):  # Windows and macOS filesystems ignore case
        return base.lower() != "readme.md"
    m = _ENV_BASE.match(base)
    if m:
        tail = (m.group(1) or "").lower()
        return not tail or re.split(r"[._-]", tail)[-1] not in TEMPLATE_SUFFIXES
    return base.lower().endswith(".env") and len(base) > 4


# ---- command parsing -------------------------------------------------------

def _split(s: str, seps: "tuple[str, ...]") -> list[str]:
    """Split on unquoted separators; `2>&1` / `&>` are redirects, not separators."""
    out: list[str] = []
    cur: list[str] = []
    q = ""
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            cur.append(c)
            if c == q:
                q = ""
            i += 1
            continue
        if c in "'\"":
            q = c
            cur.append(c)
            i += 1
            continue
        hit = None
        for sep in seps:
            if s.startswith(sep, i):
                hit = sep
                break
        if hit == "&" and ((i > 0 and s[i - 1] == ">") or s[i + 1:i + 2] == ">"):
            hit = None
        if hit:
            out.append("".join(cur))
            cur = []
            i += len(hit)
            continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return [x for x in (p.strip() for p in out) if x]


_HEREDOC = re.compile(r"(?<!<)<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_HERESTRING = re.compile(r"@(['\"])[ \t]*\r?\n.*?\r?\n\1@", re.S)


def _unquoted_at(line: str, pos: int) -> bool:
    q = ""
    for c in line[:pos]:
        if q:
            q = "" if c == q else q
        elif c in "'\"":
            q = c
    return not q


def _strip_bodies(cmd: str) -> str:
    """Drop heredoc bodies and PowerShell here-strings: their lines are text, not commands."""
    cmd = _HERESTRING.sub("''", cmd)
    lines = cmd.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in _HEREDOC.finditer(line):
            if not _unquoted_at(line, m.start()):
                continue
            while i < len(lines) and lines[i].strip() != m.group(2):
                i += 1
            i += 1
    return "\n".join(out)


def _qtokens(seg: str) -> "list[tuple[str, bool]]":
    """(token, any part was quoted) -- a quoted ">" is a grep pattern, not a redirect."""
    toks: list[tuple[str, bool]] = []
    cur: list[str] = []
    q = ""
    has = False
    for c in seg:
        if q:
            if c == q:
                q = ""
            else:
                cur.append(c)
            continue
        if c in "'\"":
            q = c
            has = True
            continue
        if c.isspace():
            if cur or has:
                toks.append(("".join(cur), has))
            cur, has = [], False
            continue
        cur.append(c)
    if cur or has:
        toks.append(("".join(cur), has))
    return toks


def _tokens(seg: str) -> list[str]:
    return [t for t, _ in _qtokens(seg)]


_REDIR = re.compile(r"^(\d|&|\*)?(>>?|<)(.*)$")
_PRINTING_TARGETS = frozenset({"&1", "&2", "/dev/stdout", "/dev/stderr", "/dev/tty", "con"})


def _redirects(qtoks: "list[tuple[str, bool]]") -> "tuple[list[str], list[str], bool]":
    """(tokens without redirections, input-redirect paths, stdout goes somewhere not printed)."""
    toks: list[str] = []
    inputs: list[str] = []
    stdout_away = False
    i = 0
    while i < len(qtoks):
        tok, quoted = qtoks[i]
        m = None if quoted else _REDIR.match(tok)
        if not m:
            toks.append(tok)
            i += 1
            continue
        fd, op, target = m.groups()
        i += 1
        if op == "<" and target.startswith("<"):
            # heredoc / herestring operator; its word (if separate) is not a file
            if target in ("<", "<-") and i < len(qtoks):
                i += 1
            continue
        if not target and i < len(qtoks):
            target = qtoks[i][0]
            i += 1
        if op == "<":
            inputs.append(target)
        elif fd in (None, "1", "&", "*") and target.lower() not in _PRINTING_TARGETS:
            stdout_away = True
    return toks, inputs, stdout_away


def _word(tok: str) -> str:
    w = tok.lstrip("(&{$.").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return w[:-4] if w.endswith(".exe") else w


def _skip_wrapper(toks: list[str], i: int) -> int:
    """Index of the first token after the wrapper at toks[i] and its options,
    consuming the value of options that take one (`sudo -u nobody`, `env -u FOO`)."""
    takes_value = WRAPPER_VALUE_OPTS.get(_word(toks[i]), frozenset())
    i += 1
    while i < len(toks):
        t = toks[i]
        if _ASSIGN_WORD.match(t):
            i += 1
        elif t == "--":
            return i + 1
        elif t.startswith("-"):
            i += 2 if t in takes_value else 1
        else:
            break
    return i


def _expand_env_split(toks: list[str]) -> list[str]:
    """The `-S` / `--split-string` option of the env wrapper runs its VALUE as the
    command, so splice that value's words in where the option was."""
    out: list[str] = []
    i = 0
    in_env = False
    while i < len(toks):
        t = toks[i]
        if _word(t) == "env" and not in_env:
            in_env = True
            out.append(t)
        elif in_env and (t == "-S" or t == "--split-string") and i + 1 < len(toks):
            out += _tokens(toks[i + 1])
            i += 1
        elif in_env and t.startswith("--split-string="):
            out += _tokens(t.split("=", 1)[1])
        elif in_env and t.startswith("-S") and not t.startswith("--"):
            out += _tokens(t[2:])
        else:
            out.append(t)
        i += 1
    return out


def _head(toks: list[str]) -> "tuple[str, list[str]]":
    """(command word, remaining args) after env assignments and wrappers."""
    i = 0
    while i < len(toks):
        if _ASSIGN_WORD.match(toks[i]):
            i += 1
            continue
        w = _word(toks[i])
        if w in WRAPPERS:
            i = _skip_wrapper(toks, i)
            continue
        return w, toks[i + 1:]
    return "", []


def _search_args(args: list[str], ps: bool = False) -> "tuple[list[str], bool]":
    """(tokens that may be file targets, reduces_output) for a grep-family call."""
    has_pat_opt = any(a.lower().split("=", 1)[0] in PATTERN_OPTS for a in args)
    targets: list[str] = []
    reduces = False
    dropped = has_pat_opt
    i = 0
    while i < len(args):
        a = args[i]
        low = a.lower()
        if low in PATTERN_OPTS:
            i += 2
            continue
        if low in REDUCING_LONG:
            reduces = True
        if a.startswith("--") and "=" in a:
            # only a glob/include value names files; --exclude=.env and --regexp=.env do not
            opt, val = a.split("=", 1)
            if opt.lower() in GLOB_OPTS:
                targets.append(val)
            i += 1
            continue
        if low in GLOB_OPTS:
            if i + 1 < len(args):
                targets.append(args[i + 1])
            i += 2
            continue
        if a in VALUE_OPTS:
            i += 2
            continue
        if not ps and a.startswith("-") and not a.startswith("--") and len(a) > 1 and a[1:].isalpha():
            if set(a[1:]) & set("lLcq"):
                reduces = True
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        if not dropped:
            dropped = True  # first positional is the pattern, not a file
            i += 1
            continue
        targets.append(a)
        i += 1
    return targets, reduces


def _script_files(args: list[str]) -> list[str]:
    """sed/awk positionals that are files: the first one is the script unless -e/-f gave it."""
    script_given = any(a.split("=", 1)[0] in SCRIPT_OPTS for a in args)
    files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in SCRIPT_OPTS or a in SCRIPT_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            i += 1
            continue
        if not script_given:
            script_given = True
        else:
            files.append(a)
        i += 1
    return files


def _stage_verdict(qtoks: "list[tuple[str, bool]]", depth: int) -> "tuple[str | None, bool, bool]":
    """(sensitive path hit or None, stage reduces/redacts its own output, stage is a redacting sink)."""
    toks, inputs, stdout_away = _redirects(qtoks)
    toks = _expand_env_split(toks)
    lead_i = 0
    while lead_i < len(toks) and (_ASSIGN_WORD.match(toks[lead_i]) or _word(toks[lead_i]) in WRAPPERS):
        lead_i = lead_i + 1 if _ASSIGN_WORD.match(toks[lead_i]) else _skip_wrapper(toks, lead_i)
    if lead_i < len(toks) and (toks[lead_i] == "." or _word(toks[lead_i]) == "source"):
        # Sourcing loads every value into the shell, whatever prints them next.
        # Only the first operand is the file; later ones are the script's arguments.
        rest = toks[lead_i + 1:]
        if "--" in rest:
            rest = rest[rest.index("--") + 1:]  # after `--` a dash-prefixed name is the file
            operand = rest[0] if rest else ""
        else:
            operand = next((a for a in rest if not a.startswith("-")), "")
        return (operand if is_sensitive_path(operand) else None), False, False
    word, args = _head(toks)
    if not word:
        return None, False, False
    if word in SHELLS and depth < 2:
        for j, a in enumerate(args[:-1]):
            if a.lower() in ("-c", "-command", "/c", "-lc"):
                hit = _command_hit(args[j + 1], depth + 1)
                return hit, False, False
        return None, False, False
    if word in SINK_WORDS:
        return None, True, True
    if word not in READERS or stdout_away:
        # stdout to a file or $null: nothing reaches the transcript or the next stage
        return None, False, False
    input_hit = next((t for t in inputs if is_sensitive_path(t)), None)
    if word in SCRIPTED:
        if any(a.startswith("-i") or a.startswith("--in-place") for a in args):
            return None, False, False
        return input_hit or next((a for a in _script_files(args) if is_sensitive_path(a)), None), False, False
    if word in SEARCHERS:
        targets, reduces = _search_args(args, ps=word in PS_SEARCHERS)
        hit = input_hit or next((t for t in targets if is_sensitive_path(t)), None)
        return hit, reduces, reduces
    reduces = word == "diff" and any(a in ("-q", "--brief") for a in args)
    hit = input_hit or next((a for a in args if not a.startswith("-") and is_sensitive_path(a)), None)
    return hit, reduces, reduces


def _echo_hit(stage: str) -> "str | None":
    """`$NAME` of a secret-looking variable expanded by a printer stage, else None."""
    toks, _inputs, stdout_away = _redirects(_qtokens(stage))
    word, args = _head(_expand_env_split(toks))
    if stdout_away:
        return None
    if word == "printenv":
        names = [a for a in args if not a.startswith("-")]
        if not names:
            return "$(all environment variables)"  # bare printenv dumps every secret
        name = next((a for a in names if _SECRET_NAME.search(a)), None)
        return "$" + name if name else None
    if word not in PRINTERS:
        return None
    return _expansion_hit(_drop_single_quoted(stage), 0)


def _drop_single_quoted(s: str) -> str:
    """Remove '...' spans that are real single quotes; a ' inside "..." is just a character."""
    out: list[str] = []
    q = ""
    skip = False
    for c in s:
        if skip:  # the character after a backslash is literal, never a delimiter
            skip = False
            out.append(c)
            continue
        if c == "\\" and q != "'":
            skip = True
            out.append(c)
            continue
        if q == "'":
            if c == "'":
                q = ""
            continue
        if c == "'" and q == "":
            q = "'"
            continue
        if c == '"':
            q = "" if q == '"' else '"'
        out.append(c)
    return "".join(out)


def _expansion_hit(text: str, depth: int) -> "str | None":
    """A secret-looking variable expanded in `text`, looking into ${X:+...} and $(...) bodies."""
    for m in _BRACED_ENV.finditer(text):
        if _SECRET_NAME.search(m.group(1)):
            return "$" + m.group(1)
    for m in _VAR_REF.finditer(text):
        name, tail = m.group(1), m.group(2)
        if tail.startswith((":+", "+")) and depth < 3:
            nested = _expansion_hit(tail[2:] if tail.startswith(":+") else tail[1:], depth + 1)
            if nested:
                return nested
            continue  # ${X:+static text} is a presence test
        if _SECRET_NAME.search(name):
            return "$" + name
    if depth < 3:
        for m in re.finditer(r"\$\(([^()]*)\)|`([^`]*)`", text):
            inner = m.group(1) or m.group(2) or ""
            hit = _command_hit(inner, 1)
            if hit:
                return hit if hit.startswith("$") else "$(" + hit + ")"
    return None


def _command_hit(command: str, depth: int = 0) -> "str | None":
    for pipeline in _split(_strip_bodies(command), ("&&", "||", ";", "\n", "&")):
        raw_stages = _split(pipeline, ("|",))
        for raw in raw_stages:
            echoed = _echo_hit(raw)
            if echoed:
                return echoed
        stages = [_qtokens(s) for s in raw_stages]
        verdicts = [_stage_verdict(t, depth) for t in stages]
        for idx, (hit, self_reduces, _sink) in enumerate(verdicts):
            if not hit or self_reduces:
                continue
            if any(v[2] for v in verdicts[idx + 1:]):
                continue
            return hit
    return None


# ---- evaluate --------------------------------------------------------------

def _label(path: str) -> str:
    p = path.strip().strip("'\"").replace("\\", "/")
    return ".secrets/" + p.rsplit("/", 1)[-1] if ".secrets" in p.lower().split("/") else p.rsplit("/", 1)[-1]


def _evaluate(payload: dict) -> "str | None":
    tool = payload.get("tool_name")
    if tool not in BLOCK_TOOLS:
        return None
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return None
    if tool == "Read":
        fp = ti.get("file_path")
        return MESSAGE.format(what=_label(fp)) if isinstance(fp, str) and is_sensitive_path(fp) else None
    if tool == "Grep":
        if ti.get("output_mode") != "content":
            return None
        for key in ("path", "glob"):
            v = ti.get(key)
            if isinstance(v, str) and is_sensitive_path(v):
                return MESSAGE.format(what=_label(v))
        return None
    cmd = ti.get("command") or ti.get("script")
    if not isinstance(cmd, str) or not cmd.strip():
        return None
    hit = _command_hit(cmd)
    if hit and hit.startswith("$"):
        return ECHO_MESSAGE.format(what=hit)
    return MESSAGE.format(what=_label(hit)) if hit else None


def evaluate(payload: dict) -> "str | None":
    """Block message, or None to allow. Fails open on any error or odd payload."""
    try:
        if os.environ.get("SECRET_READ_GATE", "").lower() == "off":
            return None
        if not isinstance(payload, dict):
            return None
        return _evaluate(payload)
    except Exception:
        return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    message = evaluate(payload)
    if message is None:
        return 0
    sys.stderr.write(message)
    return 2


if __name__ == "__main__":
    sys.exit(main())
