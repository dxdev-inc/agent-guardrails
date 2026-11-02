"""PreToolUse hook: block an ad hoc database command that is likely to scan a whole table.

THE FAILURE: an agent opens a raw database client against a shared or
production database and runs a query that usually cannot use an index, such as
`WHERE name LIKE '%smith%'` (a leading wildcard) or a recursive query with no
narrow starting row. On a large table that is a full scan. It ties up the
database and slows down everything else that uses it, and the agent often
retries with the same query.

WHAT IT BLOCKS: a Bash or PowerShell command that BOTH
  (a) names a raw SQL client: psql, mysql, mariadb, sqlcmd, Invoke-Sqlcmd,
      sqlite3, pyodbc, psycopg, pymysql; AND
  (b) contains a leading-wildcard `LIKE '%...'` / `ILIKE '%...'`, OR a recursive
      CTE whose first (anchor) query is not tied to a specific key, OR
      `MAXRECURSION 0` (no limit).

WHAT IT ALLOWS: any query without those shapes (`LIKE 'abc%'` can use an index),
a recursive CTE whose anchor is an equality or `IN (...)` on a key, and any
command that does not name a SQL client (grep for a `LIKE` pattern in source
code is fine).

A leading-wildcard LIKE is a risk, not a certainty: a trigram or full-text style
index can serve it, and the hook has no schema or index knowledge. Likewise the
"narrow key" test for a recursive anchor looks only at the column name and the
shape of the WHERE (a flag-like column such as status or type does not count);
it cannot know your keys.

THIS IS A NUDGE, NOT A BOUNDARY. Other scan shapes (functions over every row,
`COUNT(*)` on a huge table) are not matched, because they also have heavy
legitimate use. Set statement timeouts on the database user as the real
backstop.

Hook input on stdin (JSON):
  { "tool_name": "Bash|PowerShell", "tool_input": { "command": "..." } }

Exit codes:
  0 - allow
  2 - block (stderr becomes the reason the agent sees)

Override: set SQL_SCAN_OK=1 in the hook's environment, or create the one-shot
flag file ~/.claude/sql_scan_ok (it is deleted when used).
"""

from __future__ import annotations

import json
import os
import re
import sys

# (a) a raw SQL client. Table names are deliberately not markers.
CLIENT_RE = re.compile(
    r"\b(psql|mysql|mariadb|sqlcmd|sqlite3)\b|Invoke-Sqlcmd|pyodbc|psycopg2?|pymysql",
    re.IGNORECASE,
)

# (b) leading-wildcard LIKE: LIKE '%x', LIKE"%x", LIKE N'%x'. Zero spaces before
# the quote is valid SQL, so \s* not \s+. The python %-escaped form
# (LIKE '%%x%%') also opens with a literal % right after the quote.
SCAN_RE = re.compile(r"I?LIKE\s*N?['\"]\s*%", re.IGNORECASE)

# (c) recursive CTE. A depth cap is not the fix: the damage comes from how many
# rows each level fans out to. The signal is whether the anchor (the seed SELECT
# before the CTE's first top-level UNION ALL) is tied to a narrow key: a top-level
# WHERE with an equality against a literal or parameter, or IN (...), on a column
# that is not an obviously low-cardinality flag. Without a schema this is a guess:
# `WHERE status = 'active'` is not a key, `WHERE root = 5` probably is.
# An optional column list, `r(id, depth)`, may follow the CTE name.
CTE_HEAD_RE = re.compile(r"WITH\s+(?:RECURSIVE\s+)?(?P<name>\w+)\s*(?:\([^)]*\)\s*)?AS\s*\(", re.IGNORECASE)
UNION_ALL_RE = re.compile(r"\bUNION\s+ALL\b", re.IGNORECASE)
WHERE_RE = re.compile(r"\bWHERE\b", re.IGNORECASE)
# Placeholder-agnostic on purpose: do not chase one client library's spelling.
_COL = r"(?P<col>[A-Za-z_\[\"`][\w.\[\]\"`]*)"
ANCHOR_BOUND_RE = re.compile(
    _COL + r"\s*(?:=\s*(?:'|\"|[@?:$]|\d)|\s+IN\s*\()", re.IGNORECASE
)
# Columns that are almost never a narrowing key.
FLAG_COLUMN_RE = re.compile(
    r"(?:^|[._\[\"`])(status|state|type|kind|active|enabled|deleted|flag|category|is_\w+|has_\w+)[\]\"`]?$",
    re.IGNORECASE,
)
# MAXRECURSION 0 means "no limit" in T-SQL.
# Only the OPTION (... MAXRECURSION 0 ...) form counts, and not inside a `-- ` line
# comment. The same words inside a string literal are not told apart (a known limit).
MAXRECURSION_ZERO_RE = re.compile(r"\bOPTION\s*\([^)]*\bMAXRECURSION\s+0\b", re.IGNORECASE)
SQL_LINE_COMMENT_RE = re.compile(r"(?:^|\s)--(?:\s|$)[^\n]*")

# One-shot override flag: consumed (deleted) the first time it is used.
OVERRIDE_FLAG = os.path.expanduser("~/.claude/sql_scan_ok")


def _anchors(text: str):
    """Yield the anchor text (before the first top-level UNION ALL) of every
    RECURSIVE CTE: one whose part after the UNION ALL refers to the CTE's own name.
    A plain `WITH r AS (SELECT .. UNION ALL SELECT ..)` is not recursive and is
    not yielded. Parentheses are counted outside single-quoted literals."""
    for head in CTE_HEAD_RE.finditer(text):
        depth, quote, start = 1, False, head.end()
        union_start = union_end = None
        for i in range(start, len(text)):
            c = text[i]
            if c == "'":
                quote = not quote
            elif quote:
                continue
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    if union_end is not None and re.search(
                            r"\b" + re.escape(head.group("name")) + r"\b", text[union_end:i], re.IGNORECASE):
                        yield text[start:union_start]
                    break
            elif depth == 1 and union_start is None and UNION_ALL_RE.match(text, i) \
                    and not (text[i - 1].isalnum() or text[i - 1] == "_"):
                union_start = i
                union_end = UNION_ALL_RE.match(text, i).end()


def _top_level(anchor: str) -> str:
    """The anchor with string literals reduced to '' and nested parens (kept for
    IN lists) intact, but any `(...)` subquery bodies and CAST(...) arguments
    removed, so predicates inside them do not count."""
    out, quote, depth = [], False, 0
    for c in anchor:
        if c == "'":
            quote = not quote
            if depth == 0:
                out.append(c)
        elif quote:
            continue
        elif c == "(":
            depth += 1
            if depth == 1:
                out.append("(")
        elif c == ")":
            depth -= 1
            if depth == 0:
                out.append(")")
        elif depth == 0:
            out.append(c)
    return "".join(out)


def _anchor_bound(anchor: str) -> bool:
    """True if the anchor's top-level WHERE ties EVERY `OR` branch to a key. One
    key equality is not enough: `WHERE id = 5 OR 1 = 1` selects everything."""
    flat = _top_level(anchor)
    w = WHERE_RE.search(flat)
    if not w:
        return False
    for branch in re.split(r"\bOR\b", flat[w.end():], flags=re.IGNORECASE):
        if not any(not FLAG_COLUMN_RE.search(m.group("col")) for m in ANCHOR_BOUND_RE.finditer(branch)):
            return False
    return True


def _recursive_cte_unbounded(text: str) -> bool:
    if MAXRECURSION_ZERO_RE.search(SQL_LINE_COMMENT_RE.sub(" ", text)):
        return True
    return any(not _anchor_bound(a) for a in _anchors(text))


OVERRIDE_TEXT = (
    "Override (rare, needs a deliberate human go): create the one-shot flag file\n"
    f"  {OVERRIDE_FLAG}\n"
    "and retry. It is deleted on use. SQL_SCAN_OK=1 in the hook's environment also works.\n"
)

LIKE_MESSAGE = (
    "Blocked: this command runs a raw SQL client with a leading-wildcard LIKE "
    "('%...'). That usually cannot use an index, so it is likely a full table scan on a database "
    "other people may be using.\n"
    "\n"
    "Instead:\n"
    "  - Look up one row by an indexed key: SELECT ... WHERE id = <one value> LIMIT 1\n"
    "  - Anchor the pattern: LIKE 'abc%' can use an index\n"
    "  - For a real search, use a full-text index or a read replica with a statement timeout\n"
    "  - If a big scan is truly needed, run it off-peak and ask the owner first\n"
    "\n"
) + OVERRIDE_TEXT

CTE_MESSAGE = (
    "Blocked: this command runs a raw SQL client with a recursive query whose "
    "starting rows are not tied to a specific key (or MAXRECURSION 0). The "
    "recursion can fan out over a whole table. A depth cap does not help; the "
    "damage comes from how many rows each level adds.\n"
    "\n"
    "Instead:\n"
    "  - Bind the anchor: WHERE key = '<one value>' or key IN (<small set>)\n"
    "  - Run it with a statement timeout so a runaway query cancels itself\n"
    "  - If an unbounded traversal is truly needed, run it off-peak and ask the owner first\n"
    "\n"
) + OVERRIDE_TEXT


def evaluate(payload: dict) -> "str | None":
    """The block message if this command pairs a raw SQL client with an
    unbounded scan, else None."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in ("Bash", "PowerShell"):
        return None
    tool_input = payload.get("tool_input") or {}
    text = str(tool_input.get("command") or "") if isinstance(tool_input, dict) else ""

    like_trip = bool(SCAN_RE.search(text))
    cte_trip = _recursive_cte_unbounded(text)
    if not (CLIENT_RE.search(text) and (like_trip or cte_trip)):
        return None

    if os.environ.get("SQL_SCAN_OK") == "1":
        return None
    try:
        if os.path.isfile(OVERRIDE_FLAG):
            os.remove(OVERRIDE_FLAG)
            return None
    except OSError:
        pass

    return CTE_MESSAGE if (cte_trip and not like_trip) else LIKE_MESSAGE


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
