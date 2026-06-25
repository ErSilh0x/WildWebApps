"""
WildWebApps protection lab - SameSite cookie attribute (demonstrated against CSRF).

SameSite is real here, not simulated: the browser itself decides whether a cookie
rides a cross-site request, based on the cookie's SameSite value and the kind of
request. This lab lets you SEE that decision for all three values, then turns the
control against a real CSRF.

Two sites, one app, split by Host
---------------------------------
SameSite only means something across *sites*, so this single Flask app answers on two
of them:

  * the BANK (victim app) at     http://localhost:8000   - the admin bot is logged in here
  * the ATTACKER console at      http://127.0.0.1:8000    - where you host the exploit

`localhost` and `127.0.0.1` are different *sites* (different registrable domains), so a
request from the console to the bank is cross-site, exactly what SameSite reasons about.
(Two ports would be same-site and would not work; this host split is the same one the
CSRF lab uses.) Everything stays on loopback and runs offline.

Layer 1 - the playground (show + practice every SameSite value)
---------------------------------------------------------------
On its index the bank sets three marker cookies, one per SameSite value:

  * m_strict  SameSite=Strict
  * m_lax     SameSite=Lax
  * m_none    SameSite=None; Secure   (Secure is required for None; localhost is a
                                       secure context, so it is honored over http)

From the console you fire each kind of cross-site request at the bank's /inspect
endpoint and watch which markers arrive:

  * a subresource fetch / image   -> only m_none (None) rides
  * a top-level GET navigation     -> m_lax and m_none ride; m_strict does not
  * a top-level POST navigation    -> only m_none rides

(A cookie with no SameSite attribute behaves like Lax, but Chrome's transitional
"Lax+POST" window can briefly let a freshly set one ride a cross-site POST, so it is
left out of the live markers and covered in the writeup instead.)

That matrix is the whole mechanism, observed live in a real browser.

Layer 2 - the challenge (the control working, and the gap it leaves)
--------------------------------------------------------------------
WildBank's /account/email changes the admin's email and is authenticated by the
`session` cookie alone (SameSite=Lax), with NO anti-CSRF token. You hold no admin
session; only the logged-in admin bot does. To win you must:

  1. first try the classic CSRF: an auto-submitting cross-site POST. SameSite=Lax
     withholds the session cookie on a cross-site POST, so the bank sees no session and
     rejects it. That is the defense working (watch the "last delivered request" line
     show session present: NO).
  2. escalate to a top-level cross-site GET navigation, the one case Lax still allows.
     The session cookie rides it, the bank acts as the admin, and the email changes.
  3. read the flag that then appears on the console and submit it.

SameSite=Strict would have withheld the cookie even on that top-level GET; the durable
fix is a server-validated anti-CSRF token. The admin bot is a headless Chromium driven
by Playwright and only ever browses 127.0.0.1 / localhost.
"""
import os
import time

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response,
    make_response,
)

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart).
FLAG = vulnlab.generate_flag()

PORT = int(os.environ.get("PORT", "8000"))
BANK_ORIGIN = f"http://localhost:{PORT}"      # victim app (admin is logged in here)
ATTACKER_ORIGIN = f"http://127.0.0.1:{PORT}"  # where the attacker hosts the exploit

DEFAULT_EMAIL = "admin@wildbank.local"

# Per-process admin session token. The admin bot's browser carries it as a SameSite=Lax
# cookie; the attacker never sees it and does not need to. The browser attaches it
# automatically, but only when SameSite lets it, which is the whole point of the lab.
ADMIN_SESSION = vulnlab.generate_flag()

# The three playground markers, one per SameSite value: (name, SameSite, needs Secure).
MARKERS = [
    ("m_strict", "Strict", False),
    ("m_lax", "Lax", False),
    ("m_none", "None", True),   # None is only honored with Secure
]
MARKER_NAMES = [m[0] for m in MARKERS]

# A scaffold shown in the console textarea. It is deliberately NOT a working exploit:
# a cross-site POST is blocked by SameSite=Lax, so completing it (escalating to a
# top-level GET) is the exercise. The hints contain a full example.
DEFAULT_EXPLOIT = """<!-- SameSite / CSRF exploit (hosted on your attacker origin, 127.0.0.1).
     Target:  http://localhost:8000/account/email   field: email  (accepts GET and POST)
     A cross-site POST is blocked: SameSite=Lax withholds the session cookie on it.
     You need the one case Lax still allows. See the hints for a complete example. -->
<html>
  <body>
    <!-- TODO: forge the email change so the admin's Lax session cookie rides along -->
  </body>
</html>
"""

# Mutable lab state (resets to defaults on restart).
STATE = {
    "email": DEFAULT_EMAIL,      # the admin account's email - what CSRF changes
    "done": False,               # True once a forged request changed the email
    "forged_email": "",          # the value it was changed to
    "exploit": DEFAULT_EXPLOIT,  # attacker-authored HTML served at /exploit
}

# Last delivered forged request to /account/email, so the console can show WHY a POST
# was blocked (no session cookie) but a top-level GET succeeded (session present).
ATTEMPT = {"method": "", "had_session": None}

# Playground inspector ring buffer: which markers arrived on each probe.
INSPECT_LOG: list[dict] = []
INSPECT_MAX = 12

# 1x1 transparent GIF, so an `<img>` probe loads cleanly.
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
       b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
       b"\x00\x00\x02\x02D\x01\x00;")


def site() -> str:
    """Which site is addressed: 'attacker' (127.0.0.1) or 'bank' (localhost)."""
    return "attacker" if request.host.startswith("127.0.0.1") else "bank"


def set_marker_cookies(resp):
    """Issue the three playground markers on a bank response (one per SameSite value)."""
    for name, samesite, secure in MARKERS:
        # samesite="None" (string) sets SameSite=None and needs Secure; "Strict"/"Lax"
        # set those values. The cookie value just echoes the policy for readability.
        resp.set_cookie(
            name, samesite.upper(),
            samesite=samesite, secure=secure, httponly=False, path="/",
        )
    return resp


# -- The admin victim ---------------------------------------------------------
def admin_visit(url: str) -> str:
    """
    Open `url` in a headless browser logged in to the BANK as the admin: its context
    carries the `session` cookie (SameSite=Lax), scoped to the bank site. If the page
    forges a request to the bank, the browser attaches that cookie only when SameSite
    permits it. Returns "" on success or a short error string.
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
                # The admin's logged-in session at the BANK. SameSite=Lax is still sent
                # on a TOP-LEVEL cross-site GET navigation (the gap the exploit must
                # use) but NOT on a cross-site POST or subresource (the classic CSRF the
                # control blocks). No Secure flag needed: Lax rides http on localhost.
                ctx.add_cookies([{
                    "name": "session",
                    "value": ADMIN_SESSION,
                    "url": BANK_ORIGIN,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }])
                page = ctx.new_page()
                # The exploit auto-submits, so the page navigates away almost at once.
                # Wait only for the initial commit, then give the forged request time to
                # reach the bank and redirect.
                try:
                    page.goto(url, wait_until="commit", timeout=8000)
                except Exception:
                    pass
                page.wait_for_timeout(1200)
            finally:
                browser.close()
        return ""
    except Exception as exc:
        return f"admin visit failed: {exc}"


# -- In-lab code switcher: cookie WITHOUT SameSite (Vulnerable) vs WITH it (Fixed) ----
LANGUAGES = {
    "Python": {
        "vuln": (
            "# VULNERABLE: no SameSite, so the session rides cross-site POSTs (CSRF)\n"
            "resp.set_cookie('session', token)"
        ),
        "fixed": (
            "# FIXED: Lax baseline (Strict for cookies that never need an inbound link)\n"
            "resp.set_cookie('session', token,\n"
            "                samesite='Lax', secure=True, httponly=True)"
        ),
        "doc": "https://flask.palletsprojects.com/en/stable/api/#flask.Response.set_cookie",
    },
    "JavaScript": {
        "vuln": (
            "// VULNERABLE: no SameSite attribute set\n"
            "res.cookie('session', token);"
        ),
        "fixed": (
            "// FIXED: withhold the cookie on cross-site POST / subresource requests\n"
            "res.cookie('session', token, { sameSite: 'lax', secure: true, httpOnly: true });"
        ),
        "doc": "https://expressjs.com/en/api.html#res.cookie",
    },
    "TypeScript": {
        "vuln": (
            "// VULNERABLE: no SameSite attribute set\n"
            "res.cookie('session', token);"
        ),
        "fixed": (
            "import { CookieOptions } from 'express';\n"
            "const opts: CookieOptions = { sameSite: 'lax', secure: true, httpOnly: true };\n"
            "res.cookie('session', token, opts);"
        ),
        "doc": "https://expressjs.com/en/api.html#res.cookie",
    },
    "PHP": {
        "vuln": (
            "// VULNERABLE: no SameSite attribute\n"
            "setcookie('session', $token);"
        ),
        "fixed": (
            "// FIXED: SameSite=Lax (+ Secure, HttpOnly)\n"
            "setcookie('session', $token,\n"
            "    ['samesite' => 'Lax', 'secure' => true, 'httponly' => true]);"
        ),
        "doc": "https://www.php.net/manual/en/function.setcookie.php",
    },
    "Java": {
        "vuln": (
            "// VULNERABLE: Servlet Cookie has no SameSite; default omits it\n"
            "Cookie c = new Cookie(\"session\", token);\n"
            "response.addCookie(c);"
        ),
        "fixed": (
            "// FIXED: set SameSite on the header (Servlet has no setSameSite())\n"
            "response.setHeader(\"Set-Cookie\",\n"
            "    \"session=\" + token + \"; Path=/; SameSite=Lax; Secure; HttpOnly\");"
        ),
        "doc": "https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/cookie",
    },
    "Ruby": {
        "vuln": (
            "# VULNERABLE: no SameSite attribute\n"
            "cookies[:session] = token"
        ),
        "fixed": (
            "# FIXED: SameSite=Lax (+ Secure, HttpOnly)\n"
            "cookies[:session] = { value: token,\n"
            "    same_site: :lax, secure: true, httponly: true }"
        ),
        "doc": "https://api.rubyonrails.org/classes/ActionDispatch/Cookies.html",
    },
    "Go": {
        "vuln": (
            "// VULNERABLE: SameSite unset (rides cross-site requests)\n"
            "http.SetCookie(w, &http.Cookie{Name: \"session\", Value: token})"
        ),
        "fixed": (
            "// FIXED: SameSite=Lax (+ Secure, HttpOnly)\n"
            "http.SetCookie(w, &http.Cookie{Name: \"session\", Value: token,\n"
            "    SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})"
        ),
        "doc": "https://pkg.go.dev/net/http#Cookie",
    },
    "C#": {
        "vuln": (
            "// VULNERABLE: no SameSite set\n"
            "Response.Cookies.Append(\"session\", token);"
        ),
        "fixed": (
            "// FIXED: SameSite=Lax (+ Secure, HttpOnly)\n"
            "Response.Cookies.Append(\"session\", token, new CookieOptions {\n"
            "    SameSite = SameSiteMode.Lax, Secure = true, HttpOnly = true });"
        ),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions",
    },
}

CONTEXT = vulnlab.lab_context(
    title="SameSite Cookie - WildBank",
    owasp="Defense: SameSite cookie attribute",
    summary=(
        "WildBank answers on two sites: the bank at localhost and your console at "
        "127.0.0.1. First practice every SameSite value in the playground: fire each "
        "kind of cross-site request at the bank and watch which marker cookies arrive. "
        "Then attack: /account/email trusts the SameSite=Lax session cookie and checks "
        "no anti-CSRF token. A classic cross-site POST is blocked (Lax withholds the "
        "cookie), so escalate to the one request Lax still allows, a top-level GET, and "
        "make the admin bot forge the change. The flag then appears."
    ),
    instructions=[
        "Open WildBank (link below) once: it issues you three marker cookies, one per "
        "SameSite value: Strict, Lax, and None.",
        "In the Playground, fire each cross-site request type at the bank's inspector "
        "and open the inspector to see which markers rode: None rides everything, "
        "Strict rides nothing cross-site, and Lax rides only the top-level GET.",
        "Now the challenge. /account/email (field email, accepts GET and POST) trusts "
        "the SameSite=Lax session cookie and validates no token. You have no admin "
        "session; the logged-in admin bot opens any page you host here.",
        "Store an exploit that auto-submits a cross-site POST and Deliver it: the Lax "
        "cookie is withheld, so nothing changes (watch 'last delivered request' show "
        "session present: NO). That is the defense working.",
        "Escalate: make your exploit a top-level cross-site GET navigation to the same "
        "endpoint. Lax rides that, the admin's email changes, and the flag appears. "
        "Submit it to confirm.",
    ],
    hints=[
        "Playground first. A cross-site fetch or <img> is a subresource: only m_none "
        "(SameSite=None) rides it. A top-level GET navigation also carries m_lax, but "
        "never m_strict. A top-level POST navigation carries only m_none. The session "
        "cookie behaves exactly like m_lax.",
        "So a classic CSRF POST cannot work here: SameSite=Lax withholds the session "
        "cookie on a cross-site POST. You need a top-level GET navigation, which Lax "
        "still allows. The endpoint conveniently accepts GET.",
        "Paste this as your exploit, then Store + Deliver to admin:  "
        "<html><body><form action=\"http://localhost:8000/account/email\" "
        "method=\"GET\"><input type=\"hidden\" name=\"email\" "
        "value=\"attacker@evil.example\"></form>"
        "<script>document.forms[0].submit()</script></body></html>",
        "Why it works, and the fix: the form lives on a different site (127.0.0.1), but "
        "a top-level GET navigation still carries the admin's Lax session cookie. "
        "SameSite=Strict would withhold it even here; never changing state on GET would "
        "remove the sink; and a server-validated anti-CSRF token blocks the forgery "
        "regardless of method. SameSite is defense-in-depth, not the whole answer.",
    ],
    languages=LANGUAGES,
    references=[
        ("MDN - Set-Cookie SameSite", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value"),
        ("OWASP Cheat Sheet - CSRF Prevention (SameSite)", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute"),
        ("PortSwigger - Bypassing SameSite restrictions", "https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions"),
        ("IETF RFC 6265bis - Cookies (SameSite)", "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis"),
    ],
)


# -- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if site() == "attacker":
        # The attacker console: playground launchers, exploit hosting, delivery, flag.
        return render_template(
            "index.html",
            bank_url=BANK_ORIGIN,
            console_url=ATTACKER_ORIGIN,
            exploit_url=ATTACKER_ORIGIN + "/exploit",
            exploit_html=STATE["exploit"],
            attack_done=STATE["done"],
            flag=(FLAG if STATE["done"] else ""),
            forged_email=STATE["forged_email"],
            attempt=ATTEMPT,
            err=request.args.get("err", ""),
            **CONTEXT,
        )
    # The bank (victim app). Visiting it issues the three playground markers.
    resp = make_response(render_template(
        "bank.html",
        email=STATE["email"],
        markers=MARKERS,
        bank_url=BANK_ORIGIN,
        console_url=ATTACKER_ORIGIN,
    ))
    return set_marker_cookies(resp)


@app.route("/inspect", methods=["GET", "POST"])
def inspect():
    """Bank playground endpoint: record which markers arrived on this request."""
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/inspect")
    kind = request.values.get("kind", "(direct visit)")
    present = [n for n in MARKER_NAMES if n in request.cookies]
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "kind": kind,
        "method": request.method,
        "markers": present,
        "session": ("session" in request.cookies),
    }
    INSPECT_LOG.append(entry)
    del INSPECT_LOG[:-INSPECT_MAX]
    if request.args.get("fmt") == "gif":
        # The <img> probe expects an image; record happened above.
        return Response(GIF, mimetype="image/gif")
    return render_template(
        "inspector.html",
        entries=list(reversed(INSPECT_LOG)),
        latest=entry,
        marker_names=MARKER_NAMES,
        bank_url=BANK_ORIGIN,
        console_url=ATTACKER_ORIGIN,
    )


@app.route("/account/email", methods=["GET", "POST"])
def change_email():
    # === THE PROTECTED ACTION ===============================================
    # State-changing action authenticated ONLY by the ambient `session` cookie,
    # with NO anti-CSRF token. The cookie is SameSite=Lax, so a cross-site POST or
    # subresource request arrives WITHOUT it (request rejected: the control working);
    # only a top-level cross-site GET still carries it (the gap Lax leaves).
    # ========================================================================
    if site() != "bank":
        return redirect(BANK_ORIGIN + "/account/email")
    had_session = request.cookies.get("session") == ADMIN_SESSION
    ATTEMPT["method"] = request.method
    ATTEMPT["had_session"] = had_session
    if not had_session:
        # No admin session on the request (e.g. SameSite stripped it from a cross-site
        # POST). Nothing to change - this is why a classic CSRF POST fails here.
        return redirect(BANK_ORIGIN + "/")
    new_email = (request.values.get("email", "") or "").strip()[:120]
    if new_email:
        STATE["email"] = new_email
        if new_email != DEFAULT_EMAIL:
            STATE["done"] = True
            STATE["forged_email"] = new_email
    return redirect(BANK_ORIGIN + "/")


@app.get("/exploit")
def serve_exploit():
    """Serve the attacker's page from the ATTACKER origin (127.0.0.1)."""
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/exploit")
    return Response(STATE["exploit"], mimetype="text/html")


@app.post("/exploit")
def save_exploit():
    """Attacker hosting: store the exploit HTML (served from the attacker origin)."""
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/")
    STATE["exploit"] = request.form.get("html", "")
    return redirect(ATTACKER_ORIGIN + "/")


@app.post("/deliver")
def deliver():
    """Have the logged-in admin bot open the hosted exploit page."""
    if site() != "attacker":
        return redirect(ATTACKER_ORIGIN + "/")
    err = admin_visit(ATTACKER_ORIGIN + "/exploit")
    return redirect(url_for("index", err=err) if err else url_for("index"))


@app.post("/check")
def check():
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    # threaded=True so the admin bot's inbound page loads are served while the /deliver
    # request that launched the bot is still open.
    app.run(host=host, port=PORT, debug=False, threaded=True)
