"""
WildWebApps lab - Cross-Site Request Forgery (CSRF).

The vulnerability is real: WildBank changes a logged-in user's email through
``/account/email`` that is authenticated by the **session cookie alone** - there
is NO anti-CSRF token and no Origin/Referer check. The endpoint also accepts a
**GET**, and the session cookie is ``SameSite=Lax``, which the browser still
attaches to a top-level cross-site GET navigation (the case Lax does not cover).
Any page the logged-in admin visits can therefore forge that request and change
the admin's email without consent.

Two origins, one app (so the attack is genuinely *cross-site*)
--------------------------------------------------------------
CSRF only means something across origins, so this single Flask app answers on two
of them, split by Host header:

  * the BANK (victim app) at  http://localhost:8000   - the admin is logged in here
  * the ATTACKER site at      http://127.0.0.1:8000    - where you host the exploit

`localhost` and `127.0.0.1` are different *sites*, so a request from the attacker
page to the bank is cross-site - exactly what CSRF needs. (Two ports would not
work: they would be same-site.) Everything stays on loopback and runs offline.

How the flag is gated behind exploitation
-----------------------------------------
The flag never appears until the admin's email is actually changed by a forged
request. You cannot change it yourself: the endpoint acts on whoever holds the
admin session cookie, and only the admin bot does. To win you must:

  1. write an exploit page that auto-submits a cross-site GET (a top-level
     navigation) to the bank's change-email endpoint with an email you choose,
     and host it on the attacker origin (POST /exploit),
  2. deliver it to the logged-in admin bot (POST /deliver). Its browser attaches
     the admin's bank session cookie to your forged request and the email changes,
  3. read the flag that now appears on the attacker panel and submit it.

The admin bot is a headless Chromium driven by Playwright. It only ever browses
127.0.0.1 / localhost.
"""
import os

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response,
)

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart).
FLAG = vulnlab.generate_flag()

PORT = int(os.environ.get("PORT", "8000"))
BANK_ORIGIN = f"http://localhost:{PORT}"      # victim app (admin is logged in here)
ATTACKER_ORIGIN = f"http://127.0.0.1:{PORT}"  # where the attacker hosts the exploit

DEFAULT_EMAIL = "admin@wildbank.local"

# Per-process admin session token. The admin bot's browser carries it as a
# cookie; the attacker never sees it - and does not need to. The browser attaches
# it automatically to the forged request, which is exactly what makes CSRF work.
ADMIN_SESSION = vulnlab.generate_flag()

# A scaffold shown in the attacker panel's textarea. It is deliberately NOT a
# working exploit - completing it (an auto-submitting cross-site GET form) is
# the exercise. The hints contain a full example.
DEFAULT_EXPLOIT = """<!-- WildBank CSRF exploit (hosted on the attacker origin, 127.0.0.1).
     Target:  http://localhost:8000/account/email   field: email  (accepts GET)
     Build a form that submits to the bank as a top-level GET, then auto-submit
     it on load. See the hints for a complete example. -->
<html>
  <body>
    <!-- TODO: add a cross-site GET <form> targeting the bank, then submit it -->
  </body>
</html>
"""

# Mutable lab state (resets to defaults on restart).
STATE = {
    "email": DEFAULT_EMAIL,    # the admin account's email - what CSRF changes
    "done": False,             # True once a forged request changed the email
    "forged_email": "",        # the value it was changed to
    "exploit": DEFAULT_EXPLOIT,  # attacker-authored HTML served at /exploit
}


def site() -> str:
    """Which origin is addressed: 'attacker' (127.0.0.1) or 'bank' (localhost)."""
    return "attacker" if request.host.startswith("127.0.0.1") else "bank"


# ── The admin victim ─────────────────────────────────────────────────────────
def admin_visit(url: str) -> str:
    """
    Open `url` in a headless browser that is "logged in" to the BANK as the admin
    (its context carries the bank session cookie). If the page forges a request
    to the bank, the browser attaches that cookie and the bank acts on it.
    Returns "" on success or a short error string.
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
                # The admin's logged-in session at the BANK origin. SameSite=Lax
                # (the modern default) is still sent on TOP-LEVEL cross-site GET
                # navigations, which is exactly what the exploit performs - so the
                # forged request carries this cookie even though it is cross-site.
                # (No Secure flag needed: Lax cookies ride http on localhost, which
                # avoids the brittle SameSite=None + Secure-over-http path.)
                ctx.add_cookies([{
                    "name": "session",
                    "value": ADMIN_SESSION,
                    "url": BANK_ORIGIN,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }])
                page = ctx.new_page()
                # The exploit auto-submits a form, so the page navigates away
                # almost at once. Wait only for the initial commit (so the second
                # navigation cannot interrupt goto), then give the forged request
                # time to reach the bank and redirect.
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


# ── Page content (themed lab chrome) ─────────────────────────────────────────
# CSRF is a server-side flaw (a missing control), so all eight languages host it
# idiomatically: a state-changing endpoint that trusts the session cookie and
# checks no anti-CSRF token. Each fix uses the framework's CSRF protection.
LANGUAGES = {
    "Python": {
        "vuln": (
            "@app.post('/account/email')\n"
            "def change_email():\n"
            "    # VULNERABLE: trusts the session cookie, checks no CSRF token\n"
            "    current_user.email = request.form['email']; db.commit()"
        ),
        "fixed": (
            "from flask_wtf.csrf import CSRFProtect\n"
            "csrf = CSRFProtect(app)   # FIXED: validates a per-session token\n"
            "# the form must send {{ csrf_token() }} (or an X-CSRFToken header)"
        ),
        "doc": "https://flask-wtf.readthedocs.io/en/latest/csrf/",
    },
    "Java": {
        "vuln": (
            "// VULNERABLE: CSRF protection explicitly disabled\n"
            "http.csrf(csrf -> csrf.disable());"
        ),
        "fixed": (
            "// FIXED: Spring Security ships CSRF tokens on by default - keep them\n"
            "http.csrf(Customizer.withDefaults());"
        ),
        "doc": "https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html",
    },
    "JavaScript": {
        "vuln": (
            "app.post('/account/email', (req, res) => {\n"
            "  // VULNERABLE: acts on the session cookie, no CSRF token checked\n"
            "  req.user.email = req.body.email; save(); res.send('ok');\n"
            "});"
        ),
        "fixed": (
            "const { doubleCsrfProtection } = require('csrf-csrf')({ getSecret });\n"
            "// FIXED: require a valid CSRF token on state-changing routes\n"
            "app.post('/account/email', doubleCsrfProtection, handler);"
        ),
        "doc": "https://www.npmjs.com/package/csrf-csrf",
    },
    "TypeScript": {
        "vuln": (
            "app.post('/account/email', (req: Request, res: Response) => {\n"
            "  // VULNERABLE: session cookie alone authorizes the state change\n"
            "  req.user.email = req.body.email as string; save(); res.send('ok');\n"
            "});"
        ),
        "fixed": (
            "import { doubleCsrfProtection } from './csrf';\n"
            "// FIXED: types don't stop CSRF - validate a token on every POST\n"
            "app.post('/account/email', doubleCsrfProtection, handler);"
        ),
        "doc": "https://www.npmjs.com/package/csrf-csrf",
    },
    "PHP": {
        "vuln": (
            "// VULNERABLE: acts on the session alone, no token check\n"
            "$_SESSION['email'] = $_POST['email'];"
        ),
        "fixed": (
            "// FIXED: synchronizer token - compare a per-session secret\n"
            "if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {\n"
            "    http_response_code(403); exit;\n"
            "}\n"
            "$_SESSION['email'] = $_POST['email'];"
        ),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    "Ruby": {
        "vuln": (
            "# VULNERABLE: forgery protection turned off for this action\n"
            "skip_before_action :verify_authenticity_token, only: :update_email"
        ),
        "fixed": (
            "# FIXED: keep Rails' default protection (raises on a bad/missing token)\n"
            "protect_from_forgery with: :exception"
        ),
        "doc": "https://guides.rubyonrails.org/security.html#csrf-countermeasures",
    },
    "Go": {
        "vuln": (
            "// VULNERABLE: the POST handler mutates state with no token check\n"
            "r.HandleFunc(\"/account/email\", changeEmail).Methods(\"POST\")"
        ),
        "fixed": (
            "import \"github.com/gorilla/csrf\"\n"
            "// FIXED: middleware rejects POSTs without a valid CSRF token\n"
            "http.ListenAndServe(\":8000\", csrf.Protect(key)(r))"
        ),
        "doc": "https://pkg.go.dev/github.com/gorilla/csrf",
    },
    "C#": {
        "vuln": (
            "// VULNERABLE: no antiforgery validation on the state change\n"
            "[HttpPost]\n"
            "public IActionResult ChangeEmail(string email) { /* ... */ }"
        ),
        "fixed": (
            "// FIXED: validate the antiforgery token (with @Html.AntiForgeryToken())\n"
            "[HttpPost][ValidateAntiForgeryToken]\n"
            "public IActionResult ChangeEmail(string email) { /* ... */ }"
        ),
        "doc": "https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery",
    },
}

CONTEXT = vulnlab.lab_context(
    title="Cross-Site Request Forgery (CSRF) - WildBank",
    owasp="A01:2025 - Broken Access Control",
    summary=(
        "WildBank changes an account's email through a request authenticated by "
        "the session cookie alone, with no anti-CSRF token. The endpoint accepts "
        "GET and the cookie is SameSite=Lax, which still rides a top-level "
        "cross-site GET. You cannot touch the admin's session directly, but the "
        "logged-in admin bot will open any page you host on your attacker origin. "
        "Forge a cross-site request so the admin's own browser changes their email "
        "for you, and the flag appears."
    ),
    instructions=[
        "The target is WildBank at the bank origin (open it from the link on this "
        "panel). Its change-email endpoint, /account/email (which also accepts "
        "GET), trusts the admin session cookie and checks no anti-CSRF token.",
        "You are not the admin and have no link to their session - but the admin "
        "bot is logged in at the bank and will open any page you deliver.",
        "Write an exploit page (it is served from your attacker origin, 127.0.0.1) "
        "that auto-submits a cross-site GET (a top-level navigation) to the bank's "
        "change-email endpoint with an email you choose. Save it with 'Store exploit'.",
        "Click 'Deliver to admin'. The bot opens your page; its browser attaches "
        "the admin's bank session cookie to your forged request and the email "
        "changes.",
        "When the forged change lands, the flag appears in the Result section "
        "below. Submit it to confirm the solve.",
    ],
    hints=[
        "The endpoint is  http://localhost:8000/account/email  with a single "
        "field, email, and it also accepts GET. The session cookie is "
        "SameSite=Lax, which still rides a top-level cross-site GET. Open the bank "
        "to confirm the field name and that the form carries no token.",
        "Submit a top-level cross-site GET (SameSite=Lax allows that, but not a "
        "cross-site POST). Paste this as your exploit page, then Store + Deliver:  "
        "<html><body><form action=\"http://localhost:8000/account/email\" "
        "method=\"GET\"><input type=\"hidden\" name=\"email\" "
        "value=\"attacker@evil.example\"></form>"
        "<script>document.forms[0].submit()</script></body></html>",
        "Why it works: the form lives on a different site (127.0.0.1), but a "
        "top-level GET navigation still carries the admin's localhost session "
        "cookie (SameSite=Lax permits that); with no anti-CSRF token to validate, "
        "the bank accepts it as the admin. You never see the cookie - you don't need it.",
        "Real-world controls: a per-session anti-CSRF token validated on the "
        "server is the primary fix (the attacker cannot read or guess it); "
        "SameSite=Strict would block even this top-level GET; and an Origin/Referer "
        "check rejects the foreign origin. This lab is exploitable precisely "
        "because it pairs SameSite=Lax with a state-changing GET, which Lax does "
        "not protect - so never change state on GET, and always require a token.",
    ],
    languages=LANGUAGES,
    references=[
        ("OWASP - Cross-Site Request Forgery (CSRF)", "https://owasp.org/www-community/attacks/csrf"),
        ("OWASP Cheat Sheet - CSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
        ("PortSwigger - CSRF", "https://portswigger.net/web-security/csrf"),
        ("MDN - SameSite cookies", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"),
    ],
)


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if site() == "attacker":
        # The attacker control panel: exploit hosting, delivery, and the flag.
        return render_template(
            "index.html",
            attack_done=STATE["done"],
            flag=(FLAG if STATE["done"] else ""),
            forged_email=STATE["forged_email"],
            bank_url=BANK_ORIGIN,
            exploit_url=ATTACKER_ORIGIN + "/exploit",
            exploit_html=STATE["exploit"],
            err=request.args.get("err", ""),
            **CONTEXT,
        )
    # The bank (victim app) the admin is logged into.
    signed_in = request.cookies.get("session") == ADMIN_SESSION
    return render_template(
        "bank.html",
        signed_in=signed_in,
        email=STATE["email"],
        attacker_url=ATTACKER_ORIGIN,
    )


@app.route("/account/email", methods=["GET", "POST"])
def change_email():
    # === VULNERABILITY ======================================================
    # State-changing action authenticated ONLY by the ambient session cookie,
    # with NO anti-CSRF token and NO Origin/Referer check. It also accepts a
    # GET, and the session cookie is SameSite=Lax, so a top-level cross-site GET
    # navigation from any page the admin visits forges this request.
    # ========================================================================
    if request.cookies.get("session") != ADMIN_SESSION:
        # Anonymous visitor (no admin session): nothing to change. This is why
        # YOU cannot win by requesting it directly - only the admin's browser can.
        return redirect(BANK_ORIGIN + "/")
    # request.values covers both the query string (forged GET) and a form POST.
    new_email = (request.values.get("email", "") or "").strip()[:120]
    if new_email:
        STATE["email"] = new_email
        if new_email != DEFAULT_EMAIL:
            STATE["done"] = True
            STATE["forged_email"] = new_email
    return redirect(BANK_ORIGIN + "/")


@app.post("/exploit")
def save_exploit():
    """Attacker hosting: store the exploit HTML (served from the attacker origin)."""
    STATE["exploit"] = request.form.get("html", "")
    return redirect(ATTACKER_ORIGIN + "/")


@app.get("/exploit")
def serve_exploit():
    """Serve the attacker's page from the ATTACKER origin (127.0.0.1)."""
    return Response(STATE["exploit"], mimetype="text/html")


@app.post("/deliver")
def deliver():
    """Have the logged-in admin bot open the hosted exploit page."""
    err = admin_visit(ATTACKER_ORIGIN + "/exploit")
    return redirect(url_for("index", err=err) if err else url_for("index"))


@app.post("/check")
def check():
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    # threaded=True so the admin bot's inbound page loads are served while the
    # /deliver request that launched the bot is still open.
    app.run(host=host, port=PORT, debug=False, threaded=True)
