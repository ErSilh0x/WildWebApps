"""
WildWebApps lab - Insecure Direct Object Reference (IDOR).

"WildVault" is a members' account portal. You arrive signed in as an ordinary
customer, Carol Nguyen. Your account dashboard has a "My profile" button that opens
your profile page:

    GET /profile?id=1003

The whole bug is that the profile page trusts the id in the URL and never checks
that the account belongs to whoever is signed in. Account ids are plain sequential
numbers (1001, 1002, 1003, 1004, 1005), so tampering the id in the URL (in the
address bar, or with an intercepting proxy like Burp Suite) hands you another
customer's profile. That is an Insecure Direct Object Reference: a direct reference
to an object (the account id) with no authorization check behind it.

Five accounts exist:

    1001  Alice Reyes       administrator   <- private recovery key = the secret
    1002  David Okoro       customer
    1003  Carol Nguyen      customer         <- YOU (the signed-in session)
    1004  Emma Thompson     customer (premium)
    1005  Bob Carter        customer

You can view your own profile (1003). Walking the id down to 1001 reaches the
administrator's profile, whose private "account recovery key" is the per-process MD5
secret you submit to solve. It rotates on every restart.

To keep the app realistic there is deliberately NO account-id input box and no member
directory on the page: a real portal does not offer either. The id lives only in the
profile URL, exactly where you tamper it. All the teaching material (how it works,
hints, code, the answer box) is tucked into a collapsed "Training notes" panel at the
bottom of the page.

=== VULNERABILITY =========================================================
show_profile() below reads the id straight from the query string, looks the
account up, and returns it. It never compares the requested id against the id of
the signed-in session (session["uid"]), and it never checks a role. Any signed-in
customer can therefore read any account, including the administrator's, simply by
changing the number. That missing ownership/authorization check is the flaw.

The fix (see the writeup) is to enforce authorization on every object access:
after loading the account, verify that it belongs to the current user (or that the
current user is explicitly allowed to see it), and return 403/404 otherwise.
===========================================================================
"""
import os

from flask import Flask, render_template, request, jsonify, session

import vulnlab

app = Flask(__name__)

# A fixed secret key so the demo session cookie is stable across the process.
# (The secret is irrelevant to the bug: the flaw is missing authorization, not a
# forgeable cookie.)
app.secret_key = os.environ.get("SECRET_KEY", "wildvault-demo-session-key")

# ---------------------------------------------------------------------------
# The secret: one fresh random MD5 per process, planted as the administrator's
# private account recovery key. Reading account 1001 via the IDOR reveals it.
# Rotates on every restart.
# ---------------------------------------------------------------------------
SECRET = vulnlab.generate_flag()

# The id of the account the visitor is signed in as. An ordinary customer.
CURRENT_USER_ID = 1003


def build_accounts():
    """Return the five member accounts, keyed by their sequential account id.

    Each account carries public/personal fields (name, email, phone, address,
    membership) and a private security section (account recovery key) that only the
    account owner is meant to see. The administrator's recovery key is the secret.
    """
    return {
        1001: {
            "id": 1001,
            "name": "Alice Reyes",
            "initials": "AR",
            "email": "alice.reyes@wildvault.example",
            "role": "administrator",
            "tier": "Staff",
            "status": "Active",
            "phone": "+1 (202) 555-0101",
            "address": "1 Vault Plaza, Suite 900, Arlington, VA",
            "member_since": "March 2019",
            "member_no": "WV-100001",
            # PRIVATE: the administrator's account recovery key is the secret.
            "recovery_key": SECRET,
        },
        1002: {
            "id": 1002,
            "name": "David Okoro",
            "initials": "DO",
            "email": "david.okoro@wildvault.example",
            "role": "customer",
            "tier": "Standard",
            "status": "Active",
            "phone": "+1 (202) 555-0142",
            "address": "88 Cedar Street, Apt 4B, Columbus, OH",
            "member_since": "July 2021",
            "member_no": "WV-100002",
            "recovery_key": "rk_david_9f2c41a7b6",
        },
        1003: {
            "id": 1003,
            "name": "Carol Nguyen",
            "initials": "CN",
            "email": "carol.nguyen@wildvault.example",
            "role": "customer",
            "tier": "Standard",
            "status": "Active",
            "phone": "+1 (202) 555-0178",
            "address": "412 Larkspur Lane, Portland, OR",
            "member_since": "November 2022",
            "member_no": "WV-100003",
            "recovery_key": "rk_carol_3d8e17c0f4",
        },
        1004: {
            "id": 1004,
            "name": "Emma Thompson",
            "initials": "ET",
            "email": "emma.thompson@wildvault.example",
            "role": "customer",
            "tier": "Premium",
            "status": "Active",
            "phone": "+1 (202) 555-0199",
            "address": "27 Harbour View, Boston, MA",
            "member_since": "January 2020",
            "member_no": "WV-100004",
            "recovery_key": "rk_emma_a71b90d2e5",
        },
        1005: {
            "id": 1005,
            "name": "Bob Carter",
            "initials": "BC",
            "email": "bob.carter@wildvault.example",
            "role": "customer",
            "tier": "Standard",
            "status": "Active",
            "phone": "+1 (202) 555-0164",
            "address": "5 Maple Court, Denver, CO",
            "member_since": "May 2023",
            "member_no": "WV-100005",
            "recovery_key": "rk_bob_5c33e8f1a9",
        },
    }


ACCOUNTS = build_accounts()

# A little fake activity so the dashboard reads like a real portal.
RECENT_ACTIVITY = [
    {"when": "Today, 09:14", "what": "Signed in from Portland, OR"},
    {"when": "Yesterday, 18:02", "what": "Statement for October is ready"},
    {"when": "Oct 21, 11:37", "what": "Recovery key rotated"},
    {"when": "Oct 19, 08:20", "what": "Payment method updated"},
]


def current_user():
    """Return the account of the signed-in session, defaulting to CURRENT_USER_ID.

    On first visit we seed the session so the demo always has a signed-in customer
    without needing a real login form.
    """
    uid = session.get("uid", CURRENT_USER_ID)
    session["uid"] = uid
    return ACCOUNTS.get(uid)


@app.get("/")
def index():
    """Account dashboard for the signed-in customer, with a My profile button."""
    me = current_user()
    return _page(me=me, view="dashboard")


@app.get("/profile")
def show_profile():
    """Show the account named by ?id=. THE VULNERABLE ENDPOINT.

    === THE BUG ===========================================================
    The id comes straight from the query string. We load that account and
    return it with NO check that it belongs to the signed-in user and NO role
    check. Any signed-in customer can read any account by changing the number,
    which is the Insecure Direct Object Reference.
    =======================================================================
    """
    me = current_user()

    # Default to the signed-in user's own id when none is supplied (the My profile
    # button links here with ?id=<me>), so the page always has something to show.
    raw_id = request.args.get("id", str(me["id"])).strip()
    try:
        requested_id = int(raw_id)
    except ValueError:
        return _page(me=me, view="profile", error="That account id is not valid.")

    account = ACCOUNTS.get(requested_id)
    if account is None:
        return _page(me=me, view="profile",
                     error="We could not find an account with that number.")

    # VULNERABLE: no authorization check here. We simply hand back whatever
    # account the id points at. The correct code would verify ownership, e.g.:
    #     if account["id"] != me["id"] and me["role"] != "administrator":
    #         abort(403)
    is_own = account["id"] == me["id"]
    return _page(me=me, view="profile", profile=account, is_own=is_own)


@app.post("/check")
def check():
    """Validate a submitted value (used by the training-notes answer box)."""
    return jsonify(correct=vulnlab.check_flag(SECRET, request.form.get("flag", "")))


# ---------------------------------------------------------------------------
# In-lab code switcher: reading a record by id, unsafe vs authorized, 8 languages.
# The fix idea is the same everywhere: after loading the object, verify the caller
# is allowed to see THIS object (ownership or role) before returning it.
# ---------------------------------------------------------------------------
LANGUAGES = {
    "Python": {
        "vuln": ("# VULNERABLE: returns whatever account the id points at, no ownership check\n"
                 "uid = int(request.args[\"id\"])\n"
                 "account = db.get_account(uid)\n"
                 "return render(account)  # any signed-in user can read any id"),
        "fixed": ("# FIXED: load the object, then authorize THIS object for the current user\n"
                  "uid = int(request.args[\"id\"])\n"
                  "account = db.get_account(uid)\n"
                  "if account is None: abort(404)\n"
                  "if account.owner_id != session[\"uid\"] and not current_user.is_admin:\n"
                  "    abort(403)\n"
                  "return render(account)"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    },
    "Java": {
        "vuln": ("// VULNERABLE: fetches by the id in the request, returns it directly\n"
                 "long id = Long.parseLong(req.getParameter(\"id\"));\n"
                 "Account a = repo.findById(id);\n"
                 "return a;  // no check that a belongs to the caller"),
        "fixed": ("// FIXED: verify ownership (or an admin role) before returning\n"
                  "long id = Long.parseLong(req.getParameter(\"id\"));\n"
                  "Account a = repo.findById(id);\n"
                  "if (a == null) throw new NotFound();\n"
                  "if (a.getOwnerId() != session.getUserId() && !session.isAdmin())\n"
                  "    throw new Forbidden();\n"
                  "return a;"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    },
    "JavaScript": {
        "vuln": ("// VULNERABLE: looks up the record by req.params.id with no auth check\n"
                 "const acc = await db.accounts.findById(req.params.id);\n"
                 "res.json(acc);  // any authenticated user can read any id"),
        "fixed": ("// FIXED: confirm the record belongs to the signed-in user (or admin)\n"
                  "const acc = await db.accounts.findById(req.params.id);\n"
                  "if (!acc) return res.sendStatus(404);\n"
                  "if (acc.ownerId !== req.session.uid && !req.session.isAdmin)\n"
                  "    return res.sendStatus(403);\n"
                  "res.json(acc);"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    },
    "TypeScript": {
        "vuln": ("// VULNERABLE: types do not authorize - still returns any id\n"
                 "const acc = await accounts.findById(req.params.id);\n"
                 "res.json(acc);"),
        "fixed": ("// FIXED: ownership / role check before returning the object\n"
                  "const acc = await accounts.findById(req.params.id);\n"
                  "if (!acc) return res.sendStatus(404);\n"
                  "if (acc.ownerId !== req.session.uid && req.session.role !== 'admin')\n"
                  "    return res.sendStatus(403);\n"
                  "res.json(acc);"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    },
    "PHP": {
        "vuln": ("// VULNERABLE: selects by the id in the query string and prints it\n"
                 "$id = (int)$_GET[\"id\"];\n"
                 "$acc = $db->query(\"SELECT * FROM accounts WHERE id=$id\")->fetch();\n"
                 "echo render($acc);  // no owner check"),
        "fixed": ("// FIXED: load, then require the row to belong to the session user (or admin)\n"
                  "$id = (int)$_GET[\"id\"];\n"
                  "$acc = $db->prepare(\"SELECT * FROM accounts WHERE id=?\");\n"
                  "$acc->execute([$id]); $acc = $acc->fetch();\n"
                  "if (!$acc) { http_response_code(404); exit; }\n"
                  "if ($acc[\"owner_id\"] !== $_SESSION[\"uid\"] && !$_SESSION[\"is_admin\"]) {\n"
                  "    http_response_code(403); exit;\n"
                  "}\n"
                  "echo render($acc);"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    },
    "Ruby": {
        "vuln": ("# VULNERABLE: finds any record by params[:id] and renders it\n"
                 "acc = Account.find(params[:id])\n"
                 "render json: acc  # no scoping to the current user"),
        "fixed": ("# FIXED: scope the lookup to the current user's records (or allow admins)\n"
                  "acc = if current_user.admin?\n"
                  "        Account.find_by(id: params[:id])\n"
                  "      else\n"
                  "        current_user.accounts.find_by(id: params[:id])\n"
                  "      end\n"
                  "return head(:not_found) unless acc\n"
                  "render json: acc"),
        "doc": "https://guides.rubyonrails.org/security.html#insecure-direct-object-references-or-forceful-browsing",
    },
    "Go": {
        "vuln": ("// VULNERABLE: reads the id from the request and returns the record\n"
                 "id := r.URL.Query().Get(\"id\")\n"
                 "acc := store.Get(id)\n"
                 "json.NewEncoder(w).Encode(acc)  // no owner check"),
        "fixed": ("// FIXED: verify the record's owner matches the session user (or admin)\n"
                  "id := r.URL.Query().Get(\"id\")\n"
                  "acc := store.Get(id)\n"
                  "if acc == nil { http.Error(w, \"not found\", 404); return }\n"
                  "if acc.OwnerID != session.UserID && !session.IsAdmin {\n"
                  "    http.Error(w, \"forbidden\", 403); return\n"
                  "}\n"
                  "json.NewEncoder(w).Encode(acc)"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    },
    "C#": {
        "vuln": ("// VULNERABLE: returns the account named by the id, no authorization\n"
                 "var acc = await _db.Accounts.FindAsync(id);\n"
                 "return Ok(acc);"),
        "fixed": ("// FIXED: check ownership (or an admin role) before returning\n"
                  "var acc = await _db.Accounts.FindAsync(id);\n"
                  "if (acc == null) return NotFound();\n"
                  "if (acc.OwnerId != User.GetUserId() && !User.IsInRole(\"Admin\"))\n"
                  "    return Forbid();\n"
                  "return Ok(acc);"),
        "doc": "https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased",
    },
}

INSTRUCTIONS = [
    "You are signed in as Carol Nguyen. Click My profile and look at the address "
    "bar: the page is /profile?id=1003. Your account is addressed by its id.",
    "That id is the only thing selecting whose profile is shown, and the server "
    "never checks it belongs to you. Change it, in the address bar or with an "
    "intercepting proxy like Burp Suite, to another customer's number such as "
    "/profile?id=1002, and their profile loads. That missing check is the IDOR.",
    "Account ids are sequential. Walk the number down toward the start of the "
    "range: account 1001 is the first account and belongs to an administrator. "
    "Open /profile?id=1001.",
    "On the administrator's profile, read the private Account recovery key in the "
    "Security section. That 32-char value is the answer.",
    "Paste it into the box below to confirm. It rotates every time the service "
    "restarts.",
]

HINTS = [
    "The number that decides whose profile you see is right there in the URL: "
    "/profile?id=1003. The server uses it to look up the account but never checks "
    "the account is yours. Try changing it.",
    "The ids are not random. They run 1001, 1002, 1003, 1004, 1005. You are 1003. "
    "Lower numbers were created earlier, and the very first account is usually an "
    "administrator or staff account.",
    "Open /profile?id=1001. The administrator's profile has the same layout as "
    "yours, including the Security section a customer is only meant to see for "
    "their own account.",
    "The value to submit is the administrator's Account recovery key (a 32-char "
    "MD5). Every account has a recovery key, but only the admin's solves this.",
    "Real-world fix: after loading the account, the server must verify it belongs "
    "to the signed-in user (or that the user is an admin) before returning it. "
    "Sequential ids make this easy to find, but the true bug is the missing "
    "authorization check, not the numbering.",
]

REFERENCES = [
    ("OWASP - Insecure Direct Object Reference (IDOR)",
     "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"),
    ("OWASP Cheat Sheet - IDOR Prevention",
     "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"),
    ("OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization",
     "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
    ("OWASP WSTG - Testing for IDOR",
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"),
    ("PortSwigger - Insecure direct object references (IDOR)",
     "https://portswigger.net/web-security/access-control/idor"),
    ("MITRE - CWE-639 (Authorization Bypass Through User-Controlled Key)",
     "https://cwe.mitre.org/data/definitions/639.html"),
]


def _page(me=None, view="dashboard", profile=None, is_own=False, error=None):
    """Render the lab page (dashboard or profile view) plus the training notes."""
    return render_template(
        "index.html",
        me=me,
        view=view,
        profile=profile,
        is_own=is_own,
        error=error,
        activity=RECENT_ACTIVITY,
        instructions=INSTRUCTIONS,
        hints=HINTS,
        references=REFERENCES,
        languages=LANGUAGES,
    )


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, threaded=True)
