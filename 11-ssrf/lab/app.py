"""
WildWebApps lab - Server-Side Request Forgery (SSRF).

"WildMarks" is a realistic saved-links (bookmarks) app. A bookmark shows a
preview thumbnail and a "Refresh preview" button. Both are backed by features
that fetch a URL SERVER-SIDE:

  - the thumbnail loads through an image proxy:  GET /img?u=<url>
  - "Refresh preview" unfurls the saved link:    POST /unfurl  (url=<url>)

There is deliberately NO visible URL input box on the page. The URL each feature
fetches travels in the request only (the img src query string, and a hidden form
field). To exploit this you tamper that parameter with an intercepting proxy such
as Burp Suite: send the request to Repeater and change the URL.

The bug is that both features fetch WHATEVER URL you supply, with no restriction
on scheme or destination, so you can point the server at places your own browser
cannot reach:

  - file:///etc/passwd                    read a local file off the server's disk
  - http://127.0.0.1:8080/internal/status reach an internal service that is not
                                           published to the network
  - http://169.254.169.254/latest/...     the cloud metadata service

The per-process MD5 secret is reachable several ways (all give the same value):
it is planted into /etc/passwd as a service-account key, served by the internal
status endpoint, and returned by the mock metadata credentials. It rotates on
every restart.

=== VULNERABILITY =========================================================
fetch() below passes the user-supplied URL straight into urllib.urlopen() with
no allowlist and no scheme restriction. urlopen speaks file://, http://,
https://, ftp:// and data:, and it will connect to loopback, private, and
link-local addresses. That is SSRF: the request is forged by the attacker but
SENT by the server, from inside the trusted network.

The fix (see the writeup) is to validate the destination: allow only http/https,
resolve the hostname, reject any address in a private / loopback / link-local
range, pin to the resolved address, and do not follow redirects.
===========================================================================
"""
import os
import json
import urllib.request
import urllib.error
from urllib.parse import quote
from threading import Thread

from flask import Flask, render_template, request, jsonify, Response
from werkzeug.serving import make_server

import vulnlab

# ---------------------------------------------------------------------------
# Secret: one fresh random MD5 per process. Reachable via file:///etc/passwd
# (planted below), the internal status endpoint, and the mock metadata service.
# Rotates on every restart.
# ---------------------------------------------------------------------------
SECRET = vulnlab.generate_flag()

# Where the secret is planted so file:///etc/passwd leaks it. In the container
# this is the real /etc/passwd (the app runs as root). In a sandbox without root
# you can point it at a writable temp path with PASSWD_FILE.
PASSWD_FILE = os.environ.get("PASSWD_FILE", "/etc/passwd")

# How long (seconds) to let a fetch run before giving up.
FETCH_TIMEOUT = int(os.environ.get("FETCH_TIMEOUT", "6"))

# Cap the amount of a fetched body we read back.
MAX_BODY_CHARS = 12000
MAX_IMG_BYTES = 2_000_000

# Listener configuration. Only the PUBLIC listener is published by docker-compose
# (127.0.0.1:8000). The internal and metadata listeners live inside the container
# and are NOT reachable from the host, which is what makes them "internal".
PUBLIC_HOST = os.environ.get("HOST", "127.0.0.1")
PUBLIC_PORT = int(os.environ.get("PORT", "8000"))
INTERNAL_HOST = os.environ.get("INTERNAL_HOST", "127.0.0.1")
INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", "8080"))
METADATA_HOST = os.environ.get("METADATA_HOST", "169.254.169.254")
METADATA_PORT = int(os.environ.get("METADATA_PORT", "80"))

# The app's own base URL as seen from inside the container. Used for the benign
# default preview target and thumbnail, so a normal page load looks real.
SELF_BASE = "http://127.0.0.1:%d" % PUBLIC_PORT

# Seed bookmarks for the saved-links page. The featured one drives the preview
# feature; the rest are there so the page looks like a real product.
FEATURED = {
    "id": "bm-3182",
    "title": "WildMarks Weekly - product digest",
    "source": "digest.wildmarks.io",
    "saved": "saved 2 days ago",
    # What "Refresh preview" fetches (benign by default; the SSRF target you tamper).
    "url": SELF_BASE + "/p/digest",
    # What the thumbnail image proxy fetches (also an SSRF target you tamper).
    "thumb": SELF_BASE + "/static/thumb.svg",
}
OTHER_BOOKMARKS = [
    {"title": "Q3 board report (draft)", "source": "reports.acme.example", "saved": "saved 5 days ago"},
    {"title": "Design system tokens", "source": "figma.com", "saved": "saved 1 week ago"},
    {"title": "On-call runbook", "source": "wiki.acme.example", "saved": "saved 2 weeks ago"},
]


def plant_secret_in_passwd():
    """Append a service-account line to /etc/passwd carrying the secret.

    A restart regenerates SECRET, so we strip any previous line with the same
    marker first, to keep the file clean and rotate the value. Fails quietly if
    the path is not writable (for example, unprivileged in a sandbox without
    PASSWD_FILE pointed at a temp path).
    """
    marker = "wm-preview:"
    try:
        lines = []
        if os.path.exists(PASSWD_FILE):
            with open(PASSWD_FILE, "r", encoding="utf-8", errors="replace") as fh:
                lines = [ln for ln in fh.readlines() if not ln.startswith(marker)]
        # A plausible service account; its comment (GECOS) field carries the key.
        account = ("wm-preview:x:1310:1310:WildMarks preview worker key=%s:"
                   "/var/lib/wildmarks:/usr/sbin/nologin\n" % SECRET)
        lines.append(account)
        with open(PASSWD_FILE, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    except OSError:
        # Not fatal: the internal-service and metadata paths still work.
        pass


def fetch(url):
    """Fetch a user-supplied URL from the SERVER. Returns a dict with either:
      - "status", "content_type", "raw" (bytes), "body" (decoded text)
      - "error": a note about why the fetch failed

    === THE BUG ===========================================================
    The URL is handed straight to urllib.urlopen with no validation. There is
    no scheme allowlist (so file:// reads local files) and no destination
    check (so http://127.0.0.1:8080 and http://169.254.169.254 reach internal
    services). The server makes the request the attacker cannot.
    =======================================================================
    """
    try:
        # THE VULNERABLE CALL: no scheme allowlist, no destination filtering.
        req = urllib.request.Request(url, headers={"User-Agent": "WildMarks/1.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as response:
            raw = response.read(MAX_IMG_BYTES + 1)
            content_type = response.headers.get("Content-Type", "application/octet-stream")
            status = getattr(response, "status", 200) or 200
            body = raw[:MAX_BODY_CHARS + 1].decode("utf-8", errors="replace")
            if len(body) > MAX_BODY_CHARS:
                body = body[:MAX_BODY_CHARS] + "\n... (truncated)"
            return {"url": url, "status": status, "content_type": content_type,
                    "raw": raw, "body": body if body.strip() else "(empty response body)"}
    except urllib.error.HTTPError as exc:
        # Reached the target but got a 4xx/5xx. Internal error pages still leak.
        try:
            raw = exc.read(MAX_BODY_CHARS)
        except OSError:
            raw = b""
        body = raw.decode("utf-8", errors="replace")
        return {"url": url, "status": exc.code,
                "content_type": exc.headers.get("Content-Type", "unknown") if exc.headers else "unknown",
                "raw": raw, "body": body if body.strip() else "(empty response body)"}
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return {"url": url, "error": "Could not fetch that URL: %s" % exc}


# ===========================================================================
# PUBLIC APP  (published on 127.0.0.1:8000) - the realistic WildMarks product.
# ===========================================================================
public_app = Flask(__name__)


@public_app.get("/p/<slug>")
def preview_target(slug):
    """Benign pages that a normal 'Refresh preview' fetches, so the feature has
    something real to show before anyone tampers with it.
    """
    pages = {
        "digest": ("<h1>WildMarks Weekly</h1><p>Issue 42 - the product digest. "
                   "This week: faster previews, shared collections, and tags.</p>"),
    }
    html = pages.get(slug, "<h1>Not found</h1>")
    return Response(html, mimetype="text/html")


@public_app.get("/img")
def image_proxy():
    """Image proxy (SSRF sink #1). Fetches the URL in ?u= server-side and returns
    the bytes. Normally used for bookmark thumbnails; tampering ?u= turns it into
    a server-side fetch of any URL.
    """
    target = request.args.get("u", "")
    if not target:
        return Response("missing u", status=400, mimetype="text/plain")
    result = fetch(target)
    if "error" in result:
        return Response(result["error"], status=502, mimetype="text/plain")
    # Pass the upstream content-type through, exactly as a naive proxy would.
    return Response(result["raw"], mimetype=result["content_type"].split(";")[0])


@public_app.get("/")
def index():
    """Render the saved-links page."""
    return _page()


@public_app.post("/unfurl")
def unfurl():
    """Refresh a bookmark's preview (SSRF sink #2). Fetches the hidden 'url' field
    server-side and shows the response as a preview.
    """
    url = request.form.get("url", "").strip()
    result = fetch(url) if url else {"url": url, "error": "No URL to preview."}
    return _page(preview=result, previewed_url=url)


@public_app.post("/check")
def check():
    """Validate a submitted secret (used by the training-panel verify box)."""
    return jsonify(correct=vulnlab.check_flag(SECRET, request.form.get("flag", "")))


# ===========================================================================
# INTERNAL APP  (bound inside the container only, NOT published)
# Serves an internal status endpoint and a mock cloud metadata service.
# Anything that can reach it is trusted, which is exactly the flaw SSRF abuses.
# ===========================================================================
internal_app = Flask("internal")


@internal_app.get("/")
def internal_index():
    """Landing page for the internal service."""
    return Response(
        "WildMarks internal worker (not for public access).\n"
        "Endpoints:\n"
        "  /internal/status                 preview-worker status + key\n"
        "  /latest/meta-data/               cloud metadata root\n",
        mimetype="text/plain",
    )


@internal_app.get("/internal/status")
def internal_status():
    """Internal preview-worker status. No auth: the service trusts the network,
    so simply being able to reach it is enough. That trust is the point.
    """
    return Response(
        "preview-worker: healthy\n"
        "queue_depth: 0\n"
        "service_api_key: %s\n" % SECRET,
        mimetype="text/plain",
    )


# --- Mock AWS-style instance metadata service (IMDS) -----------------------
@internal_app.get("/latest/meta-data/")
def imds_root():
    """List the top-level metadata categories."""
    return Response("iam/\ninstance-id\nlocal-ipv4\n", mimetype="text/plain")


@internal_app.get("/latest/meta-data/iam/security-credentials/")
def imds_role_list():
    """Return the IAM role name attached to the instance."""
    return Response("wildmarks-ec2-role", mimetype="text/plain")


@internal_app.get("/latest/meta-data/iam/security-credentials/wildmarks-ec2-role")
def imds_credentials():
    """Return temporary credentials. The SecretAccessKey carries the secret."""
    credentials = {
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIAWILDMARKSEXAMPLE",
        "SecretAccessKey": SECRET,
        "Token": "wm-session-token-example",
        "Expiration": "2030-01-01T00:00:00Z",
    }
    return Response(json.dumps(credentials, indent=2), mimetype="application/json")


@internal_app.get("/latest/meta-data/instance-id")
def imds_instance_id():
    """Return a fake instance id."""
    return Response("i-0wildmarks00example", mimetype="text/plain")


@internal_app.get("/latest/meta-data/local-ipv4")
def imds_local_ipv4():
    """Return a fake private address."""
    return Response("10.0.2.15", mimetype="text/plain")


# ---------------------------------------------------------------------------
# Training-panel code switcher: fetching a user URL, unsafe vs hardened, 8
# languages. The fix idea is the same everywhere: allow only http/https, resolve
# the host, and reject private / loopback / link-local addresses.
# ---------------------------------------------------------------------------
LANGUAGES = {
    "Python": {
        "vuln": ("# VULNERABLE: fetches any URL the user gives, any scheme, any host\n"
                 "url = request.form[\"url\"]\n"
                 "body = urllib.request.urlopen(url).read()  # file://, 127.0.0.1, 169.254..."),
        "fixed": ("# FIXED: only http/https, resolve host, block private/loopback/link-local\n"
                  "u = urlparse(url)\n"
                  "if u.scheme not in (\"http\", \"https\"): abort(400)\n"
                  "ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))\n"
                  "if ip.is_private or ip.is_loopback or ip.is_link_local: abort(400)\n"
                  "body = requests.get(url, timeout=5, allow_redirects=False).content"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    "Java": {
        "vuln": ("// VULNERABLE: opens whatever URL the user supplied\n"
                 "String url = req.getParameter(\"url\");\n"
                 "InputStream in = new URL(url).openStream();  // no scheme/host check"),
        "fixed": ("// FIXED: allow only http/https, resolve, reject private/loopback ranges\n"
                  "URI u = URI.create(url);\n"
                  "if (!Set.of(\"http\",\"https\").contains(u.getScheme())) throw new BadRequest();\n"
                  "InetAddress ip = InetAddress.getByName(u.getHost());\n"
                  "if (ip.isLoopbackAddress() || ip.isSiteLocalAddress() ||\n"
                  "    ip.isLinkLocalAddress()) throw new BadRequest();"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    "JavaScript": {
        "vuln": ("// VULNERABLE: server-side fetch of a user-controlled URL\n"
                 "const url = req.body.url;\n"
                 "const r = await fetch(url);  // reaches localhost, metadata, file via libs"),
        "fixed": ("// FIXED: scheme allowlist + block private ranges via a DNS lookup\n"
                  "const u = new URL(url);\n"
                  "if (!['http:','https:'].includes(u.protocol)) return res.sendStatus(400);\n"
                  "const { address } = await dns.promises.lookup(u.hostname);\n"
                  "if (ipaddr.parse(address).range() !== 'unicast') return res.sendStatus(400);\n"
                  "const r = await fetch(url, { redirect: 'error' });"),
        "doc": "https://nodejs.org/api/dns.html#dnspromiseslookuphostname-options",
    },
    "TypeScript": {
        "vuln": ("// VULNERABLE: same server-side fetch, types do not validate the target\n"
                 "const url: string = req.body.url;\n"
                 "const r = await fetch(url);"),
        "fixed": ("// FIXED: scheme allowlist + resolved-address range check, no redirects\n"
                  "const u = new URL(url);\n"
                  "if (!['http:','https:'].includes(u.protocol)) throw new Error('bad scheme');\n"
                  "const { address } = await dns.promises.lookup(u.hostname);\n"
                  "if (isPrivate(address)) throw new Error('blocked host');\n"
                  "const r = await fetch(url, { redirect: 'error' });"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    "PHP": {
        "vuln": ("// VULNERABLE: file_get_contents follows file://, http://, ftp://, etc.\n"
                 "$url = $_GET[\"url\"];\n"
                 "$body = file_get_contents($url);   // SSRF and local file read in one"),
        "fixed": ("// FIXED: allow only http/https, resolve, reject private/reserved ranges\n"
                  "$u = parse_url($url);\n"
                  "if (!in_array($u[\"scheme\"] ?? \"\", [\"http\",\"https\"])) exit(\"bad scheme\");\n"
                  "$ip = gethostbyname($u[\"host\"]);\n"
                  "if (!filter_var($ip, FILTER_VALIDATE_IP,\n"
                  "    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) exit(\"blocked\");\n"
                  "$body = file_get_contents($url);"),
        "doc": "https://www.php.net/manual/en/filter.filters.validate.php",
    },
    "Ruby": {
        "vuln": ("# VULNERABLE: open-uri opens any URL, including file:// and internal hosts\n"
                 "url = params[:url]\n"
                 "body = URI.open(url).read   # scheme and destination unchecked"),
        "fixed": ("# FIXED: allow only http/https, resolve host, reject private/loopback\n"
                  "u = URI.parse(url)\n"
                  "raise \"bad scheme\" unless %w[http https].include?(u.scheme)\n"
                  "ip = IPAddr.new(Resolv.getaddress(u.host))\n"
                  "raise \"blocked\" if ip.private? || ip.loopback? || ip.link_local?\n"
                  "body = Net::HTTP.get(u)"),
        "doc": "https://docs.ruby-lang.org/en/master/IPAddr.html",
    },
    "Go": {
        "vuln": ("// VULNERABLE: fetches the user URL with no restrictions\n"
                 "url := r.FormValue(\"url\")\n"
                 "resp, _ := http.Get(url)   // any scheme handler, any host"),
        "fixed": ("// FIXED: scheme allowlist + a DialContext that rejects private IPs\n"
                  "u, _ := neturl.Parse(url)\n"
                  "if u.Scheme != \"http\" && u.Scheme != \"https\" { http.Error(w, \"bad\", 400); return }\n"
                  "ips, _ := net.LookupIP(u.Hostname())\n"
                  "for _, ip := range ips {\n"
                  "    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() { return }\n"
                  "}"),
        "doc": "https://pkg.go.dev/net#IP.IsPrivate",
    },
    "C#": {
        "vuln": ("// VULNERABLE: HttpClient fetches whatever URL the user supplied\n"
                 "var url = Request.Form[\"url\"];\n"
                 "var body = await http.GetStringAsync(url);"),
        "fixed": ("// FIXED: allow only http/https, resolve, reject private/loopback/link-local\n"
                  "var u = new Uri(url);\n"
                  "if (u.Scheme != \"http\" && u.Scheme != \"https\") return BadRequest();\n"
                  "var ip = (await Dns.GetHostAddressesAsync(u.Host))[0];\n"
                  "if (IPAddress.IsLoopback(ip) || IsPrivate(ip)) return BadRequest();\n"
                  "var body = await http.GetStringAsync(url);"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
}

INSTRUCTIONS = [
    "This is a saved-links app. It has no URL input box: the preview URLs live "
    "only inside the requests. Put an intercepting proxy (Burp Suite) in front of "
    "your browser and load the page so the requests appear in the proxy history.",
    "Two requests fetch a URL server-side: the thumbnail GET /img?u=<url>, and "
    "the 'Refresh preview' button POST /unfurl with a hidden url=<url> field. Send "
    "either one to Repeater so you can edit the URL parameter.",
    "Read a local file: change the parameter to file:///etc/passwd. The response "
    "contains the file. Find the wm-preview service account line; the value after "
    "key= is the secret.",
    "Reach an internal service: change it to http://127.0.0.1:8080/internal/status. "
    "That worker is not published to the network, but the server can reach it. "
    "Read service_api_key.",
    "Cloud metadata: change it to "
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/wildmarks-ec2-role "
    "and read SecretAccessKey. Every path reveals the same secret.",
    "Copy the 32-char value and submit it below. It rotates on every restart.",
]

HINTS = [
    "There is no form field to type into on purpose. The vulnerable parameter is "
    "in the request, not the page. Intercept with Burp, find GET /img?u=... or "
    "POST /unfurl (url=...), and send it to Repeater to tamper the URL.",
    "Start with the scheme. Neither feature restricts it, so file:///etc/passwd "
    "makes the server read a local file instead of making a network request. The "
    "secret sits on the wm-preview line, after key=.",
    "The internal worker listens on port 8080 inside the container and is NOT "
    "published to your host, so http://127.0.0.1:8080/ is refused in YOUR browser "
    "but reachable by the SERVER. That gap is the whole point of SSRF: you borrow "
    "the server's network position. Read /internal/status.",
    "Cloud servers expose a metadata service at 169.254.169.254. Walk the path: "
    "/latest/meta-data/ then iam/security-credentials/ (role name) then that role "
    "name (credentials JSON). SecretAccessKey is the value.",
    "If a real target filtered 127.0.0.1, the writeup lists equivalents that slip "
    "through: 0.0.0.0, [::1], 127.1, 2130706433 (decimal), 0x7f000001 (hex), and "
    "DNS names that resolve inward. This app does not filter, so plain addresses "
    "work. Fix: allow only http/https, resolve, and block private/loopback/link-local.",
]

REFERENCES = [
    ("OWASP - Server-Side Request Forgery",
     "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
    ("OWASP Cheat Sheet - SSRF Prevention",
     "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
    ("PortSwigger - SSRF",
     "https://portswigger.net/web-security/ssrf"),
    ("MITRE - CWE-918",
     "https://cwe.mitre.org/data/definitions/918.html"),
]


def _page(preview=None, previewed_url=None):
    """Render the WildMarks page, optionally with a refreshed preview result."""
    default_thumb = "/img?u=" + quote(FEATURED["thumb"], safe="")
    return render_template(
        "index.html",
        featured=FEATURED,
        others=OTHER_BOOKMARKS,
        default_thumb=default_thumb,
        instructions=INSTRUCTIONS,
        hints=HINTS,
        references=REFERENCES,
        languages=LANGUAGES,
        preview=preview,
        previewed_url=previewed_url,
    )


def start_server(host, port, wsgi_app):
    """Build a threaded werkzeug server for one listener, or return None if the
    address cannot be bound (for example, 169.254.169.254 is not configured).

    werkzeug's make_server prints the OS error and raises SystemExit (not a plain
    OSError) when a bind fails, so both are caught here. A missing link-local
    metadata address then just skips that one listener.
    """
    try:
        return make_server(host, port, wsgi_app, threaded=True)
    except (OSError, SystemExit) as exc:
        print("Could not bind %s:%s (%s) - skipping this listener." % (host, port, exc))
        return None


def main():
    """Plant the secret, then start the public, internal, and metadata listeners."""
    plant_secret_in_passwd()

    servers = []
    public = start_server(PUBLIC_HOST, PUBLIC_PORT, public_app)
    if public is not None:
        servers.append(public)
    internal = start_server(INTERNAL_HOST, INTERNAL_PORT, internal_app)
    if internal is not None:
        servers.append(internal)
    metadata = start_server(METADATA_HOST, METADATA_PORT, internal_app)
    if metadata is not None:
        servers.append(metadata)

    threads = [Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    print("WildMarks running. Public on %s:%s." % (PUBLIC_HOST, PUBLIC_PORT))
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
