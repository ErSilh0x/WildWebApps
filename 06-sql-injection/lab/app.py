"""
WildWebApps lab - SQL Injection (Citizen Services portal).

One Flask portal in front of FOUR real database engines (MariaDB/MySQL,
PostgreSQL, SQL Server, Oracle XE). Every lookup form concatenates the caller's
input straight into a SQL string (see db.py), so the engine-specific injection
syntax in the writeup works exactly as it does in the wild.

The per-process MD5 flag is seeded as the password_hash of the `wwa_admin` row in
`user_table` on every engine. Recover it (UNION-based is the most direct route;
error-based and blind also work) and submit it. The flag rotates on restart.
"""
import os

from flask import Flask, render_template, request, jsonify

import vulnlab
import db

app = Flask(__name__)

# Fresh random MD5 flag for this process; seeded into every engine's user_table.
FLAG = vulnlab.generate_flag()
db.start(FLAG)

# ── Portal forms (each maps to a deliberately vulnerable builder in db.py) ────
FORMS = [
    {
        "key": "search", "builder": db.q_search,
        "title": "Citizen record search",
        "tag": "Enumeration practice",
        "desc": ("Look up citizens by surname. Five columns are shown "
                 "(id, name, surname, national_id, address), a roomy string-context "
                 "injection point for fingerprinting and enumeration."),
        "label": "Surname", "placeholder": "Kowalski",
    },
    {
        "key": "error", "builder": db.q_error,
        "title": "Verify national ID",
        "tag": "Error-based",
        "desc": ("Confirms whether a national ID exists. Only a status line is "
                 "meant to show, but the raw database error is exposed: the channel "
                 "error-based extraction rides on."),
        "label": "National ID", "placeholder": "85010112345",
    },
    {
        "key": "union", "builder": db.q_union,
        "title": "Benefits eligibility lookup",
        "tag": "UNION-based",
        "desc": ("Returns three columns (name, surname, address). Graft a "
                 "UNION SELECT onto it to exfiltrate another table. The flag is the "
                 "password_hash of wwa_admin in user_table."),
        "label": "Surname", "placeholder": "Nowak",
    },
    {
        "key": "stacked", "builder": db.q_stacked,
        "title": "Update contact address",
        "tag": "Stacked queries",
        "desc": ("Updates a citizen's address. The value is concatenated in, so a "
                 "terminating ';' can append a second statement. Works on PostgreSQL "
                 "and SQL Server; blocked on MySQL/MariaDB and Oracle."),
        "label": "New address", "placeholder": "10 New Street, Springfield",
    },
    {
        "key": "blind", "builder": db.q_blind,
        "title": "Check username availability",
        "tag": "Blind (boolean / time)",
        "desc": ("Replies only 'taken' or 'available'. No rows, no errors, so the "
                 "only channel is the true/false difference (or response time for a "
                 "time-based payload)."),
        "label": "Username", "placeholder": "admin",
    },
    {
        "key": "file", "builder": db.q_file,
        "title": "Municipal notice reader",
        "tag": "Reading files",
        "desc": ("Reads a file through the database engine's file primitive "
                 "(LOAD_FILE / pg_read_file / OPENROWSET). The path is the abusable "
                 "surface: the read runs with the DB account's privileges. Try "
                 "/labfiles/notice.txt, then something you should not reach."),
        "label": "File path", "placeholder": "/labfiles/notice.txt",
    },
]
FORMS_BY_KEY = {f["key"]: f for f in FORMS}

# In-lab code switcher: the same parameterized-query fix, eight languages.
LANGUAGES = {
    "Python": {
        "vuln": ("# VULNERABLE: input concatenated into the SQL text\n"
                 "sql = \"SELECT * FROM customer_table WHERE surname = '\" + surname + \"'\"\n"
                 "db.execute(sql)"),
        "fixed": ("# FIXED: ? placeholder - the driver binds the value, never parses it\n"
                  "db.execute(\"SELECT * FROM customer_table WHERE surname = ?\", (surname,))"),
        "doc": "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders",
    },
    "Java": {
        "vuln": ("// VULNERABLE: string built from user input\n"
                 "st.executeQuery(\"SELECT * FROM customer_table WHERE surname = '\" + surname + \"'\");"),
        "fixed": ("// FIXED: PreparedStatement binds the parameter\n"
                  "PreparedStatement ps = conn.prepareStatement(\n"
                  "  \"SELECT * FROM customer_table WHERE surname = ?\");\n"
                  "ps.setString(1, surname);"),
        "doc": "https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html",
    },
    "JavaScript": {
        "vuln": ("// VULNERABLE: template literal concatenates the value in\n"
                 "await conn.query(`SELECT * FROM customer_table WHERE surname = '${surname}'`);"),
        "fixed": ("// FIXED: placeholder + values array (mysql2 / pg)\n"
                  "await conn.query('SELECT * FROM customer_table WHERE surname = ?', [surname]);"),
        "doc": "https://github.com/sidorares/node-mysql2#using-prepared-statements",
    },
    "TypeScript": {
        "vuln": ("// VULNERABLE: types do not stop SQLi - this still concatenates\n"
                 "await pool.query(`SELECT * FROM customer_table WHERE surname = '${surname}'`);"),
        "fixed": ("// FIXED: parameterized query ($1 bound by node-postgres)\n"
                  "await pool.query('SELECT * FROM customer_table WHERE surname = $1', [surname]);"),
        "doc": "https://node-postgres.com/features/queries#parameterized-query",
    },
    "PHP": {
        "vuln": ("// VULNERABLE: value interpolated into the SQL string\n"
                 "$pdo->query(\"SELECT * FROM customer_table WHERE surname = '\".$surname.\"'\");"),
        "fixed": ("// FIXED: PDO prepared statement with a bound parameter\n"
                  "$st = $pdo->prepare('SELECT * FROM customer_table WHERE surname = ?');\n"
                  "$st->execute([$surname]);"),
        "doc": "https://www.php.net/manual/en/pdo.prepared-statements.php",
    },
    "Ruby": {
        "vuln": ("# VULNERABLE: interpolated input in a raw SQL string\n"
                 "conn.exec(\"SELECT * FROM customer_table WHERE surname = '#{surname}'\")"),
        "fixed": ("# FIXED: bound parameter ($1 placeholder, pg gem)\n"
                  "conn.exec_params('SELECT * FROM customer_table WHERE surname = $1', [surname])"),
        "doc": "https://www.rubydoc.info/gems/pg/PG/Connection#exec_params-instance_method",
    },
    "Go": {
        "vuln": ("// VULNERABLE: fmt.Sprintf builds the query from user input\n"
                 "db.Query(fmt.Sprintf(\"SELECT * FROM customer_table WHERE surname = '%s'\", surname))"),
        "fixed": ("// FIXED: placeholder + argument - database/sql binds it\n"
                  "db.Query(\"SELECT * FROM customer_table WHERE surname = ?\", surname)"),
        "doc": "https://go.dev/doc/database/sql-injection",
    },
    "C#": {
        "vuln": ("// VULNERABLE: interpolated command text\n"
                 "new SqlCommand($\"SELECT * FROM customer_table WHERE surname = '{surname}'\", conn);"),
        "fixed": ("// FIXED: parameterized command\n"
                  "var cmd = new SqlCommand(\"SELECT * FROM customer_table WHERE surname = @s\", conn);\n"
                  "cmd.Parameters.AddWithValue(\"@s\", surname);"),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.data.sqlclient.sqlcommand.parameters",
    },
}

INSTRUCTIONS = [
    "The Citizen Services portal runs on top of four REAL databases. Pick an engine "
    "in any form's dropdown; the same form works against all four.",
    "Confirm injection: put a single quote (') in a search field and watch the "
    "database error come back. Then try ' OR '1'='1 to return every row.",
    "Enumerate the backend with the engine-specific syntax from the writeup: "
    "version, current user, databases, tables, columns.",
    "Exfiltrate the flag: it is the password_hash of the wwa_admin row in "
    "user_table. UNION-based via the 'Benefits eligibility lookup' (3 columns) is "
    "the most direct route; error-based and blind also reach it.",
    "Submit the 32-char MD5 flag in the answer box. It rotates on every restart.",
]

HINTS = [
    "Break out of the string first. In 'Benefits eligibility lookup' the query is "
    "SELECT name, surname, address FROM customer_table WHERE surname = '<you>'. It "
    "has 3 columns, so a UNION needs 3 items.",
    "UNION payload (MySQL/PostgreSQL/SQL Server): "
    "' UNION SELECT username, password_hash, NULL FROM user_table-- -   "
    "On Oracle add FROM dual only if you drop the table source; here user_table is "
    "the source, so the same payload works (mind UPPERCASE identifiers).",
    "Prefer error-based? In 'Verify national ID' (MySQL) try: "
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password_hash FROM user_table WHERE "
    "username='wwa_admin')))-- -   The value appears after the ~ in the error.",
    "Prefer blind? In 'Check username availability' use "
    "wwa_admin' AND SUBSTRING(password_hash,1,1)='a'-- -  and binary-search each "
    "character (SUBSTR on Oracle; SUBSTRING on the others). Time-based: swap in "
    "SLEEP(3) / pg_sleep(3) / WAITFOR DELAY '0:0:3' / dbms_session.sleep(3).",
    "Real-world control: parameterized queries (prepared statements) send the SQL "
    "structure and the value on separate channels, so none of these payloads change "
    "the query. Least-privilege DB accounts and hidden error messages shrink the "
    "blast radius further. This portal is exploitable precisely because it "
    "concatenates input and shows raw errors.",
]

REFERENCES = [
    ("OWASP - SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
    ("OWASP Cheat Sheet - SQL Injection Prevention",
     "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    ("PortSwigger - SQL injection", "https://portswigger.net/web-security/sql-injection"),
    ("PortSwigger - SQLi cheat sheet",
     "https://portswigger.net/web-security/sql-injection/cheat-sheet"),
]


def _page(result=None, active_form=None):
    return render_template(
        "index.html",
        title="Citizen Services - SQL Injection",
        engines=db.ENGINES,
        status=db.status(),
        forms=FORMS,
        instructions=INSTRUCTIONS,
        hints=HINTS,
        references=REFERENCES,
        languages=LANGUAGES,
        result=result,
        active_form=active_form,
    )


def _run_form(form_key, engine, value):
    """Shared runner for the portal and the per-database pages. Returns a result
    dict (or None if the request is malformed)."""
    spec = FORMS_BY_KEY.get(form_key)
    if spec is None or engine not in db.ENGINES:
        return None
    if not db.is_ready(engine):
        st = db.status().get(engine, {})
        return {"form": form_key, "engine": engine, "not_ready": True,
                "input": value,
                "error": "This database is still starting: %s" % st.get("error", "")}
    # === VULNERABILITY ======================================================
    # The builder concatenates `value` straight into the SQL text. No engine
    # here parameterizes it - that is the flaw the lab teaches.
    # ========================================================================
    out = spec["builder"](engine, value)
    out["form"] = form_key
    out["engine"] = engine
    out["input"] = value
    return out


@app.get("/")
def index():
    return _page()


@app.post("/run")
def run():
    result = _run_form(
        request.form.get("form", ""),
        request.form.get("engine", "mariadb"),
        request.form.get("q", ""),
    )
    if result is None:
        return _page()
    return _page(result=result, active_form=result["form"])


@app.route("/db/<engine>", methods=["GET", "POST"])
def db_page(engine):
    if engine not in db.ENGINES:
        return _page()
    result = None
    if request.method == "POST":
        # Engine is fixed by the URL; run the submitted form and render the
        # result on THIS page (no redirect to the portal).
        result = _run_form(request.form.get("form", ""), engine, request.form.get("q", ""))
    return render_template(
        "db.html",
        engine=engine,
        meta=db.ENGINES[engine],
        status=db.status().get(engine, {}),
        forms=FORMS,
        result=result,
        active_form=(result["form"] if result else None),
    )


@app.post("/check")
def check():
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    # threaded=True so the portal stays responsive while background seeding runs.
    app.run(host=host, port=port, debug=False, threaded=True)
