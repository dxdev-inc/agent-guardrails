"""block_unbounded_sql_scan: fires on a raw client plus a guaranteed scan, quiet on indexed look-alikes."""
import pytest

import block_unbounded_sql_scan as hook
from conftest import run_hook

WILD = "select 1 from t where a like '%b'"
ANCHORED = "select 1 from t where a like 'b%'"


def bash(cmd, tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": cmd}}


BLOCKED = [
    "psql -c \"SELECT id FROM users WHERE name LIKE '%smith%'\"",
    "mysql -e \"select * from orders where note like '%refund'\"",
    "sqlite3 app.db \"SELECT * FROM t WHERE x LIKE'%y'\"",
    "psql -c \"SELECT * FROM t WHERE x ILIKE '%y%'\"",
    "python -c \"import psycopg2; cur.execute(\\\"select 1 from t where a like N'%q'\\\")\"",
    "sqlcmd -Q \"WITH r AS (SELECT id FROM nodes UNION ALL SELECT n.id FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
    "psql -c \"WITH RECURSIVE r AS (SELECT id FROM nodes UNION ALL SELECT n.id FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
    "sqlcmd -Q \"select * from r option (MAXRECURSION 0)\"",
    # the column-list form of a recursive CTE
    "psql -c \"WITH RECURSIVE r(id) AS (SELECT id FROM nodes UNION ALL SELECT n.id FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
    "psql -c \"WITH RECURSIVE r(id, depth) AS (SELECT id, 0 FROM nodes UNION ALL SELECT n.id, depth+1 FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
]

ALLOWED = [
    # indexed or anchored
    "psql -c \"SELECT id FROM users WHERE name LIKE 'smith%'\"",
    "psql -c \"SELECT id FROM users WHERE id = 7 LIMIT 1\"",
    # recursive query with a bound anchor
    "psql -c \"WITH RECURSIVE r AS (SELECT id FROM nodes WHERE id = 5 UNION ALL SELECT n.id FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
    "sqlcmd -Q \"WITH r AS (SELECT id FROM nodes WHERE root IN (1,2) UNION ALL SELECT n.id FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
    "psql -c \"WITH RECURSIVE r(id) AS (SELECT id FROM nodes WHERE id = 5 UNION ALL SELECT n.id FROM nodes n JOIN r ON n.p=r.id) SELECT * FROM r\"",
    # a wildcard LIKE with no SQL client in the command is just text
    "grep -rn \"LIKE '%\" src/",
    "echo \"WHERE name LIKE '%x'\" > notes.txt",
    "ls",
]


@pytest.mark.parametrize("cmd", BLOCKED)
def test_blocks(cmd):
    assert hook.evaluate(bash(cmd)), cmd


@pytest.mark.parametrize("cmd", ALLOWED)
def test_allows(cmd):
    assert hook.evaluate(bash(cmd)) is None, cmd


def test_powershell_tool_is_covered():
    assert hook.evaluate(bash("Invoke-Sqlcmd -Query \"" + WILD + "\"", "PowerShell"))


def test_other_tools_ignored():
    assert hook.evaluate({"tool_name": "Write", "tool_input": {"content": "psql LIKE '%x'"}}) is None
    assert hook.evaluate({"tool_name": "Bash", "tool_input": None}) is None


def test_message_kinds():
    assert "leading-wildcard" in hook.evaluate(bash(f'psql -c "{WILD}"'))
    assert "recursive" in hook.evaluate(bash('sqlcmd -Q "select 1 option (MAXRECURSION 0)"'))


def test_env_override(monkeypatch):
    monkeypatch.setenv("SQL_SCAN_OK", "1")
    assert hook.evaluate(bash(f'psql -c "{WILD}"')) is None


def test_flag_file_override_is_one_shot(tmp_path, monkeypatch):
    flag = tmp_path / "ok"
    flag.write_text("")
    monkeypatch.setattr(hook, "OVERRIDE_FLAG", str(flag))
    cmd = f'psql -c "{WILD}"'
    assert hook.evaluate(bash(cmd)) is None
    assert not flag.exists()
    assert hook.evaluate(bash(cmd))


def test_exit_code_contract():
    code, err = run_hook("block_unbounded_sql_scan", bash(f'psql -c "{WILD}"'))
    assert code == 2 and "full table scan" in err
    code, err = run_hook("block_unbounded_sql_scan", bash(f'psql -c "{ANCHORED}"'))
    assert code == 0 and err == ""
    code, _ = run_hook("block_unbounded_sql_scan", None, raw="{broken")
    assert code == 0


def _cte(anchor):
    return f'psql -c "WITH RECURSIVE t AS ({anchor} UNION ALL SELECT n.id FROM nodes n JOIN t ON n.p=t.id) SELECT * FROM t"'


@pytest.mark.parametrize("anchor", [
    "SELECT CAST(id AS bigint) FROM nodes",                      # nested paren used to end the scan early
    "SELECT 'x=1', id FROM nodes",                               # '=' inside a string literal is not a predicate
    "SELECT id FROM nodes WHERE status = 'active'",              # a flag column is not a narrowing key
])
def test_recursive_anchor_not_tied_to_a_key_is_blocked(anchor):
    assert hook.evaluate(bash(_cte(anchor))) is not None


@pytest.mark.parametrize("anchor", [
    "SELECT CAST(id AS bigint) FROM nodes WHERE id = 5",
    "SELECT id FROM nodes WHERE id = @root",
    "SELECT id FROM nodes WHERE root IN (1,2)",
    "SELECT 'x=1', id FROM nodes WHERE parent_id = 7",
])
def test_recursive_anchor_tied_to_a_key_is_allowed(anchor):
    assert hook.evaluate(bash(_cte(anchor))) is None


@pytest.mark.parametrize("raw", ["null", "[]", "5", '"x"'])
def test_non_object_json_exits_quietly(raw):
    code, err = run_hook("block_unbounded_sql_scan", None, raw=raw)
    assert code == 0 and err == ""


def test_wording_is_a_risk_not_a_guarantee():
    assert "guarantee" not in hook.__doc__.lower()
    assert "likely" in hook.evaluate(bash("psql -c \"select * from t where n like '%x'\"")).lower()


def _psql(body):
    return 'psql -c "' + body + '"'


def test_plain_union_all_cte_is_not_recursive():
    assert hook.evaluate(bash(_psql("WITH r AS (SELECT id FROM a UNION ALL SELECT id FROM b) SELECT * FROM r"))) is None


def test_recursive_cte_that_refers_to_itself_is_still_checked():
    assert hook.evaluate(bash(_psql(
        "WITH r AS (SELECT id FROM a UNION ALL SELECT n.id FROM a n JOIN r ON n.p = r.id) SELECT * FROM r"))) is not None


@pytest.mark.parametrize("body", [
    "SELECT 'MAXRECURSION 0'",
    "SELECT 1 -- MAXRECURSION 0",
    "SELECT 1 /* nothing */ -- OPTION (MAXRECURSION 0)",
])
def test_maxrecursion_text_that_is_not_an_option_is_allowed(body):
    assert hook.evaluate(bash(_psql(body))) is None


def test_maxrecursion_zero_option_is_blocked():
    assert hook.evaluate(bash(_psql("SELECT * FROM r OPTION (MAXRECURSION 0)"))) is not None
    assert hook.evaluate(bash(_psql("SELECT * FROM r OPTION (MAXDOP 1, MAXRECURSION 0)"))) is not None


@pytest.mark.parametrize("where, blocked", [
    ("id = 5 OR 1=1", True),
    ("id = 5 OR status = 'x'", True),
    ("id = 5 OR id = 6", False),
    ("id = 5 AND status = 'x'", False),
])
def test_every_or_branch_needs_a_key(where, blocked):
    sql = (f"WITH RECURSIVE t AS (SELECT id FROM nodes WHERE {where} "
           "UNION ALL SELECT n.id FROM nodes n JOIN t ON n.p = t.id) SELECT * FROM t")
    assert (hook.evaluate(bash(_psql(sql))) is not None) is blocked
