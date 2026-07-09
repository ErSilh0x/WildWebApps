"""
Database layer for the Citizen Services SQLi lab.

This module owns four real database engines (MariaDB/MySQL, PostgreSQL, SQL
Server, Oracle XE), seeds each with the SAME relational schema, and exposes the
DELIBERATELY VULNERABLE query builders the portal uses. Every builder concatenates
the caller's input straight into the SQL text - that is the whole point.

Schema (identical on every engine):

    group_table(group_id PK, "group")
    user_table(id PK, username, password_hash, salt, "group" -> group_table.group_id)
    customer_table(id PK, name, surname, national_id, address)

The per-process MD5 flag is seeded as the password_hash of the `wwa_admin` row in
user_table on every engine, so a UNION/error/blind extraction from user_table
recovers it. The flag rotates on restart because the tables are dropped and
reseeded each boot.
"""
import os
import threading
import time

import pymysql
import psycopg2
import pymssql
import oracledb

# ── Static seed data (trusted, inlined) ──────────────────────────────────────
GROUPS = [
    (1, "administrators"),
    (2, "citizens"),
]

# (id, username, password_hash, salt, group_id). Row 4 gets the flag at runtime.
USERS_TEMPLATE = [
    (1, "admin", "5f4dcc3b5aa765d61d8327deb882cf99", "a1b2c3d4", 1),
    (2, "jkowalski", "e10adc3949ba59abbe56e057f20f883e", "9f8e7d6c", 2),
    (3, "mnowak", "25f9e794323b453885f5181f1b624d0b", "1122abcd", 2),
    (4, "wwa_admin", "__FLAG__", "f1a9c0de", 1),
]

CUSTOMERS = [
    (1, "Anna", "Kowalski", "85010112345", "12 Market St, Springfield"),
    (2, "Piotr", "Kowalski", "88052256789", "5 River Rd, Springfield"),
    (3, "Maria", "Nowak", "90113098765", "7 Hill Ave, Rivertown"),
    (4, "Jan", "Wisniewski", "75032011223", "9 Oak Ln, Lakeside"),
    (5, "Ewa", "Lewandowska", "92070744556", "3 Elm St, Rivertown"),
    (6, "Tomasz", "Kaminski", "80121599001", "21 Pine Rd, Springfield"),
    (7, "Katarzyna", "Zielinska", "86091377889", "8 Cedar Ct, Lakeside"),
    (8, "Marek", "Szymanski", "79040366777", "14 Birch Way, Rivertown"),
]

# Engine display metadata (also drives the per-database pages / selectors).
ENGINES = {
    "mariadb": {
        "label": "MariaDB / MySQL",
        "port": "3306/tcp",
        "admin": "root",
        "concat": "CONCAT(a,b)",
        "comment": "-- , #, /* */",
        "version_fn": "SELECT @@version;",
        "user_fn": "SELECT current_user();",
        "install": "/usr/sbin/mysqld  ·  data: /var/lib/mysql/",
        "config": "my.cnf / my.ini  (/etc/mysql/my.cnf)",
        "client": "mysql / mariadb",
    },
    "postgres": {
        "label": "PostgreSQL",
        "port": "5432/tcp",
        "admin": "postgres",
        "concat": "a || b",
        "comment": "-- , /* */",
        "version_fn": "SELECT version();",
        "user_fn": "SELECT current_user;",
        "install": "/usr/lib/postgresql/<ver>/  ·  data: /var/lib/postgresql/<ver>/main/",
        "config": "postgresql.conf + pg_hba.conf (data dir)",
        "client": "psql",
    },
    "mssql": {
        "label": "Microsoft SQL Server",
        "port": "1433/tcp (+1434/udp browser)",
        "admin": "sa",
        "concat": "a + b",
        "comment": "-- , /* */",
        "version_fn": "SELECT @@version;",
        "user_fn": "SELECT SYSTEM_USER;",
        "install": "/opt/mssql/  ·  data: /var/opt/mssql/data/",
        "config": "mssql-conf -> /var/opt/mssql/mssql.conf",
        "client": "sqlcmd",
    },
    "oracle": {
        "label": "Oracle Database (XE)",
        "port": "1521/tcp (TNS listener)",
        "admin": "SYS / SYSTEM",
        "concat": "a || b",
        "comment": "-- , /* */",
        "version_fn": "SELECT banner FROM v$version;",
        "user_fn": "SELECT user FROM dual;",
        "install": "$ORACLE_HOME e.g. /opt/oracle/product/<ver>/  ·  data: oradata/",
        "config": "init<SID>.ora / spfile, listener.ora, tnsnames.ora",
        "client": "sqlplus",
    },
}

# Ready-state, protected by a lock. The web app never blocks on a slow engine:
# background warming plus lazy init keep the portal responsive while the heavy
# engines (SQL Server, Oracle) finish booting.
_STATE = {k: {"ready": False, "error": "starting"} for k in ENGINES}
_LOCK = threading.Lock()
_FLAG = None


def _env(name, default):
    return os.environ.get(name, default)


# ── Connections ──────────────────────────────────────────────────────────────
def _connect_mariadb(db=True):
    return pymysql.connect(
        host=_env("MARIADB_HOST", "mariadb"),
        port=int(_env("MARIADB_PORT", "3306")),
        user=_env("MARIADB_USER", "root"),
        password=_env("MARIADB_PASSWORD", "labpass"),
        database=_env("MARIADB_DB", "citizen") if db else None,
        connect_timeout=5,
        autocommit=True,
    )


def _connect_postgres():
    return psycopg2.connect(
        host=_env("POSTGRES_HOST", "postgres"),
        port=int(_env("POSTGRES_PORT", "5432")),
        user=_env("POSTGRES_USER", "postgres"),
        password=_env("POSTGRES_PASSWORD", "labpass"),
        dbname=_env("POSTGRES_DB", "citizen"),
        connect_timeout=5,
    )


def _connect_mssql(db=True):
    return pymssql.connect(
        server=_env("MSSQL_HOST", "mssql"),
        port=_env("MSSQL_PORT", "1433"),
        user=_env("MSSQL_USER", "sa"),
        password=_env("MSSQL_PASSWORD", "Labpass_2024#"),
        database=_env("MSSQL_DB", "citizen") if db else "master",
        login_timeout=5,
        timeout=15,
        autocommit=True,
    )


def _connect_oracle():
    dsn = "{}:{}/{}".format(
        _env("ORACLE_HOST", "oracle"),
        _env("ORACLE_PORT", "1521"),
        _env("ORACLE_SERVICE", "XEPDB1"),
    )
    return oracledb.connect(
        user=_env("ORACLE_USER", "system"),
        password=_env("ORACLE_PASSWORD", "labpass"),
        dsn=dsn,
    )


def get_conn(engine):
    """Fresh connection to the engine's application database."""
    if engine == "mariadb":
        return _connect_mariadb()
    if engine == "postgres":
        return _connect_postgres()
    if engine == "mssql":
        return _connect_mssql()
    if engine == "oracle":
        return _connect_oracle()
    raise ValueError("unknown engine: %s" % engine)


# ── Schema + seed (per engine dialect) ───────────────────────────────────────
def _users(flag):
    return [
        (i, u, (flag if h == "__FLAG__" else h), s, g)
        for (i, u, h, s, g) in USERS_TEMPLATE
    ]


def _init_mariadb(flag):
    conn = _connect_mariadb()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS user_table")
    cur.execute("DROP TABLE IF EXISTS group_table")
    cur.execute("DROP TABLE IF EXISTS customer_table")
    cur.execute(
        "CREATE TABLE group_table ("
        "group_id INT PRIMARY KEY, `group` VARCHAR(64))"
    )
    cur.execute(
        "CREATE TABLE user_table ("
        "id INT PRIMARY KEY, username VARCHAR(64), password_hash VARCHAR(128), "
        "salt VARCHAR(64), `group` INT, "
        "FOREIGN KEY (`group`) REFERENCES group_table(group_id))"
    )
    cur.execute(
        "CREATE TABLE customer_table ("
        "id INT PRIMARY KEY, name VARCHAR(64), surname VARCHAR(64), "
        "national_id VARCHAR(32), address VARCHAR(255))"
    )
    for gid, gname in GROUPS:
        cur.execute("INSERT INTO group_table (group_id, `group`) VALUES (%s,%s)", (gid, gname))
    for row in _users(flag):
        cur.execute(
            "INSERT INTO user_table (id, username, password_hash, salt, `group`) "
            "VALUES (%s,%s,%s,%s,%s)", row)
    for row in CUSTOMERS:
        cur.execute(
            "INSERT INTO customer_table (id, name, surname, national_id, address) "
            "VALUES (%s,%s,%s,%s,%s)", row)
    cur.close()
    conn.close()


def _init_postgres(flag):
    conn = _connect_postgres()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS user_table")
    cur.execute("DROP TABLE IF EXISTS group_table")
    cur.execute("DROP TABLE IF EXISTS customer_table")
    cur.execute(
        'CREATE TABLE group_table (group_id INT PRIMARY KEY, "group" VARCHAR(64))')
    cur.execute(
        'CREATE TABLE user_table ('
        'id INT PRIMARY KEY, username VARCHAR(64), password_hash VARCHAR(128), '
        'salt VARCHAR(64), "group" INT REFERENCES group_table(group_id))')
    cur.execute(
        "CREATE TABLE customer_table ("
        "id INT PRIMARY KEY, name VARCHAR(64), surname VARCHAR(64), "
        "national_id VARCHAR(32), address VARCHAR(255))")
    for gid, gname in GROUPS:
        cur.execute('INSERT INTO group_table (group_id, "group") VALUES (%s,%s)', (gid, gname))
    for row in _users(flag):
        cur.execute(
            'INSERT INTO user_table (id, username, password_hash, salt, "group") '
            'VALUES (%s,%s,%s,%s,%s)', row)
    for row in CUSTOMERS:
        cur.execute(
            "INSERT INTO customer_table (id, name, surname, national_id, address) "
            "VALUES (%s,%s,%s,%s,%s)", row)
    cur.close()
    conn.close()


def _init_mssql(flag):
    # Create the citizen database first (from master), then seed it.
    master = _connect_mssql(db=False)
    mcur = master.cursor()
    mcur.execute(
        "IF DB_ID('citizen') IS NULL CREATE DATABASE citizen")
    mcur.close()
    master.close()

    conn = _connect_mssql()
    cur = conn.cursor()
    for t in ("user_table", "group_table", "customer_table"):
        cur.execute("IF OBJECT_ID('%s','U') IS NOT NULL DROP TABLE %s" % (t, t))
    cur.execute(
        "CREATE TABLE group_table (group_id INT PRIMARY KEY, [group] NVARCHAR(64))")
    cur.execute(
        "CREATE TABLE user_table ("
        "id INT PRIMARY KEY, username NVARCHAR(64), password_hash NVARCHAR(128), "
        "salt NVARCHAR(64), [group] INT "
        "REFERENCES group_table(group_id))")
    cur.execute(
        "CREATE TABLE customer_table ("
        "id INT PRIMARY KEY, name NVARCHAR(64), surname NVARCHAR(64), "
        "national_id NVARCHAR(32), address NVARCHAR(255))")
    for gid, gname in GROUPS:
        cur.execute("INSERT INTO group_table (group_id, [group]) VALUES (%s,%s)", (gid, gname))
    for row in _users(flag):
        cur.execute(
            "INSERT INTO user_table (id, username, password_hash, salt, [group]) "
            "VALUES (%s,%s,%s,%s,%s)", row)
    for row in CUSTOMERS:
        cur.execute(
            "INSERT INTO customer_table (id, name, surname, national_id, address) "
            "VALUES (%s,%s,%s,%s,%s)", row)
    cur.close()
    conn.close()


def _init_oracle(flag):
    conn = _connect_oracle()
    cur = conn.cursor()
    for t in ("user_table", "group_table", "customer_table"):
        try:
            cur.execute("DROP TABLE %s CASCADE CONSTRAINTS" % t)
        except Exception:
            pass  # table did not exist yet
    cur.execute(
        'CREATE TABLE group_table (group_id NUMBER PRIMARY KEY, "group" VARCHAR2(64))')
    cur.execute(
        'CREATE TABLE user_table ('
        'id NUMBER PRIMARY KEY, username VARCHAR2(64), password_hash VARCHAR2(128), '
        'salt VARCHAR2(64), "group" NUMBER REFERENCES group_table(group_id))')
    cur.execute(
        "CREATE TABLE customer_table ("
        "id NUMBER PRIMARY KEY, name VARCHAR2(64), surname VARCHAR2(64), "
        "national_id VARCHAR2(32), address VARCHAR2(255))")
    for gid, gname in GROUPS:
        cur.execute('INSERT INTO group_table (group_id, "group") VALUES (:1,:2)', [gid, gname])
    for row in _users(flag):
        cur.execute(
            'INSERT INTO user_table (id, username, password_hash, salt, "group") '
            'VALUES (:1,:2,:3,:4,:5)', list(row))
    for row in CUSTOMERS:
        cur.execute(
            "INSERT INTO customer_table (id, name, surname, national_id, address) "
            "VALUES (:1,:2,:3,:4,:5)", list(row))
    conn.commit()
    cur.close()
    conn.close()


_INITIALISERS = {
    "mariadb": _init_mariadb,
    "postgres": _init_postgres,
    "mssql": _init_mssql,
    "oracle": _init_oracle,
}


def _ensure_ready(engine):
    """Try to (re)initialise one engine. Returns True if it is ready."""
    with _LOCK:
        if _STATE[engine]["ready"]:
            return True
    try:
        _INITIALISERS[engine](_FLAG)
        with _LOCK:
            _STATE[engine] = {"ready": True, "error": ""}
        return True
    except Exception as exc:  # engine still booting, or a driver/config problem
        with _LOCK:
            _STATE[engine] = {"ready": False, "error": str(exc)[:300]}
        return False


def status():
    with _LOCK:
        return {k: dict(v) for k, v in _STATE.items()}


def is_ready(engine):
    with _LOCK:
        return _STATE.get(engine, {}).get("ready", False)


def _warm_loop():
    """Background thread: keep trying to seed every engine until all are ready."""
    while True:
        pending = [e for e in ENGINES if not is_ready(e)]
        if not pending:
            time.sleep(30)
            continue
        for e in pending:
            _ensure_ready(e)
        time.sleep(3)


def start(flag):
    """Store the flag and kick off background seeding of all four engines."""
    global _FLAG
    _FLAG = flag
    threading.Thread(target=_warm_loop, daemon=True).start()


# ── Raw executor ─────────────────────────────────────────────────────────────
def _paramless_execute(engine, sql, fetch=True):
    """
    Run an already-built SQL string (the vulnerable path: input is baked in).
    Returns (columns, rows, error). For non-SELECT, fetch=False.
    """
    conn = None
    try:
        conn = get_conn(engine)
        cur = conn.cursor()
        cur.execute(sql)
        cols, rows = [], []
        if fetch and cur.description is not None:
            cols = [d[0] for d in cur.description]
            fetched = cur.fetchall()
            rows = [[("" if v is None else str(v)) for v in r] for r in fetched]
        if engine == "oracle":
            conn.commit()
        cur.close()
        return cols, rows, None
    except Exception as exc:
        return [], [], str(exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── Vulnerable query builders (one per portal form) ──────────────────────────
# Every builder below is intentionally vulnerable: the raw input is concatenated
# straight into the SQL text with no parameterization. The FIXED equivalent is in
# the writeup's 8-language section and the in-lab code switcher.

def q_search(engine, value):
    """Enumeration / general practice: 5 visible columns, string context."""
    sql = ("SELECT id, name, surname, national_id, address "
           "FROM customer_table WHERE surname = '" + value + "'")
    cols, rows, err = _paramless_execute(engine, sql)
    return {"sql": sql, "columns": cols, "rows": rows, "error": err}


def q_union(engine, value):
    """UNION target: 3 visible columns (name, surname, address)."""
    sql = ("SELECT name, surname, address "
           "FROM customer_table WHERE surname = '" + value + "'")
    cols, rows, err = _paramless_execute(engine, sql)
    return {"sql": sql, "columns": cols, "rows": rows, "error": err}


def q_error(engine, value):
    """
    Error-based practice: only a status line is meant to be shown, but the raw
    database error is exposed - the channel error-based SQLi rides on.
    """
    sql = ("SELECT national_id FROM customer_table "
           "WHERE national_id = '" + value + "'")
    cols, rows, err = _paramless_execute(engine, sql)
    status_line = None
    if err is None:
        status_line = ("Record located." if rows else "No matching record.")
    return {"sql": sql, "columns": cols, "rows": rows, "error": err,
            "status": status_line}


def q_stacked(engine, value):
    """
    Stacked-query practice: an UPDATE whose new value is concatenated in, so a
    terminating ';' can append a second statement (works on PostgreSQL and SQL
    Server; blocked on MySQL/MariaDB and Oracle by their single-statement APIs).
    """
    sql = ("UPDATE customer_table SET address = '" + value + "' WHERE id = 1")
    _c, _r, err = _paramless_execute(engine, sql, fetch=False)
    # Show the current row so the effect (and any stacked side effect) is visible.
    after = _paramless_execute(
        engine, "SELECT id, name, surname, address FROM customer_table WHERE id = 1")
    return {"sql": sql, "columns": after[0], "rows": after[1],
            "error": err, "status": ("Statement executed." if err is None else None)}


def q_blind(engine, value):
    """
    Boolean/time-based blind practice: returns only 'taken' or 'available'. No
    rows and no error text are shown, so the only channel is the true/false
    difference (or the response time for a time-based payload).
    """
    sql = ("SELECT username FROM user_table WHERE username = '" + value + "'")
    _cols, rows, _err = _paramless_execute(engine, sql)
    taken = bool(rows)
    return {"sql": sql, "taken": taken,
            "status": ("Username is taken." if taken else "Username is available.")}


# File-read primitive per engine. The input is the path, which is exactly the
# abusable surface: the query runs with the database account's privileges.
def q_file(engine, path):
    if engine == "mariadb":
        sql = "SELECT LOAD_FILE('" + path + "') AS contents"
    elif engine == "postgres":
        sql = "SELECT pg_read_file('" + path + "') AS contents"
    elif engine == "mssql":
        sql = ("SELECT BulkColumn AS contents FROM "
               "OPENROWSET(BULK '" + path + "', SINGLE_CLOB) AS x")
    else:  # oracle
        return {"sql": "-- Oracle file read uses PL/SQL UTL_FILE + a DIRECTORY object",
                "columns": [], "rows": [],
                "error": ("Oracle reads files via PL/SQL (UTL_FILE.GET_LINE) against a "
                          "DIRECTORY object, not a plain SELECT. See the writeup's "
                          "'Reading and writing files' section.")}
    cols, rows, err = _paramless_execute(engine, sql)
    return {"sql": sql, "columns": cols, "rows": rows, "error": err}
