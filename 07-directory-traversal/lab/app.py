"""
WildWebApps lab - Directory Traversal (WildFiles Portal).

A small account portal with THREE real file-operation sinks, not a single text
box:

  * /            registration agreement viewer   (?doc=terms.txt)
  * /avatar      profile picture loader          (?img=avatar1.svg)
  * /            document download               (?file=receipt-001.txt)

Each sink joins the caller's value onto a base directory and reads the result
with NO confinement check, so a "../" climb or an absolute path escapes the base
directory and reaches any file the process can read.

The per-process MD5 flag is written into `secret/.env_backup`, a backup of the
environment file kept OUTSIDE the served base directories. Recover it by
traversing to that file through any of the three sinks (relative "../" climb or
an absolute path), then submit it. The flag rotates on restart.
"""
import os
import base64

from flask import Flask, render_template, request, jsonify, Response

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart).
FLAG = vulnlab.generate_flag()

# DATA_ROOT is the app directory by default (so the lab runs the same in the
# build sandbox and in Docker). In the container the image sets WORKDIR to
# /opt/wildfiles, so the paths match the ones quoted in the writeup.
DATA_ROOT = os.environ.get("DATA_ROOT", os.path.dirname(os.path.abspath(__file__)))

# The three sinks each serve from their own base directory under webroot/.
WEBROOT = os.path.join(DATA_ROOT, "webroot")
BASES = {
    "doc": os.path.join(WEBROOT, "agreements"),   # registration agreement viewer
    "img": os.path.join(WEBROOT, "avatars"),      # profile picture loader
    "file": os.path.join(WEBROOT, "documents"),   # document download
}

# The secret lives OUTSIDE every base directory: webroot's sibling. Reaching it
# is the whole exercise (relative climb ../../secret/.env_backup, or the absolute
# path /opt/wildfiles/secret/.env_backup in the container).
SECRET_DIR = os.path.join(DATA_ROOT, "secret")
SECRET_FILE = os.path.join(SECRET_DIR, ".env_backup")


def plant_secret():
    """Write the .env_backup file that holds the flag, outside the web root.

    It is shaped like a real environment backup so the flag reads as one of its
    values (SECRET_KEY). Rewritten on every start, so the flag rotates.
    """
    os.makedirs(SECRET_DIR, exist_ok=True)
    content = (
        "# WildFiles environment (backup copy - left behind by a deploy script)\n"
        "# This file lives OUTSIDE the web root and must never be reachable.\n"
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "DB_HOST=127.0.0.1\n"
        "DB_PORT=5432\n"
        "DB_NAME=wildfiles\n"
        "DB_USER=wildfiles_app\n"
        "DB_PASS=s3rvice-acct-not-the-flag\n"
        "# The lab flag is this app's secret key:\n"
        "SECRET_KEY=" + FLAG + "\n"
    )
    with open(SECRET_FILE, "w", encoding="utf-8") as fh:
        fh.write(content)


plant_secret()

# Sink metadata rendered as cards in the index page.
SINKS = [
    {
        "key": "doc",
        "title": "Registration agreement viewer",
        "tag": "?doc=",
        "desc": ("During sign-up the portal loads the agreement text from a file "
                 "named by the doc parameter. The name is joined onto the "
                 "agreements/ directory and read straight back, so a traversal "
                 "sequence escapes that directory."),
        "label": "Agreement file",
        "placeholder": "terms.txt",
        "samples": ["terms.txt", "privacy.txt"],
    },
    {
        "key": "img",
        "title": "Profile picture loader",
        "tag": "?img=",
        "desc": ("Your profile page loads its avatar from the avatars/ directory "
                 "by the img parameter. The loader reads whatever path you give "
                 "it, so it will happily read a file outside avatars/ too."),
        "label": "Avatar file",
        "placeholder": "avatar1.svg",
        "samples": ["avatar1.svg", "avatar2.svg"],
    },
    {
        "key": "file",
        "title": "Document download",
        "tag": "?file=",
        "desc": ("Account documents (receipts, letters) download from the "
                 "documents/ directory by the file parameter. Same flaw: the name "
                 "is concatenated onto the base directory and opened."),
        "label": "Document file",
        "placeholder": "receipt-001.txt",
        "samples": ["receipt-001.txt", "welcome.txt"],
    },
]
SINKS_BY_KEY = {s["key"]: s for s in SINKS}


def read_sink(sink_key, value):
    """Read a file for one sink and return a result dict.

    === VULNERABILITY ======================================================
    `value` is joined onto the sink's base directory with os.path.join and
    opened with no check that the result stays inside that base directory.
    os.path.join also discards the base entirely when `value` is an absolute
    path, so both relative ("../") and absolute traversal work. This is the
    flaw the lab teaches; the fix is to realpath the result and confirm it is
    still under the base before opening (see the writeup).
    ========================================================================
    """
    base = BASES.get(sink_key)
    if base is None:
        return None
    joined = os.path.join(base, value)     # no confinement check (the bug)
    result = {
        "sink": sink_key,
        "input": value,
        "resolved": os.path.normpath(joined),
    }
    try:
        with open(joined, "rb") as fh:
            raw = fh.read()
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
        return result

    # Decide how to present the bytes: render real images inline, everything
    # else (including a traversed text file) as text.
    lowered = value.lower()
    is_image = lowered.endswith((".svg", ".png", ".jpg", ".jpeg", ".gif"))
    if is_image and sink_key == "img":
        mime = "image/svg+xml" if lowered.endswith(".svg") else "image/png"
        result["image_data_uri"] = (
            "data:" + mime + ";base64," + base64.b64encode(raw).decode("ascii")
        )
    result["text"] = raw.decode("utf-8", errors="replace")
    return result


# In-lab code switcher: the resolve-then-confine fix, eight languages.
LANGUAGES = {
    "Python": {
        "vuln": ("# VULNERABLE: user input joined onto the base and opened, no check\n"
                 "path = os.path.join(BASE, request.args['doc'])\n"
                 "return open(path).read()"),
        "fixed": ("# FIXED: resolve to the real path, then confirm it is inside BASE\n"
                  "path = os.path.realpath(os.path.join(BASE, request.args['doc']))\n"
                  "if os.path.commonpath([BASE, path]) != BASE:\n"
                  "    abort(404)\n"
                  "return open(path).read()"),
        "doc": "https://docs.python.org/3/library/os.path.html#os.path.realpath",
    },
    "Java": {
        "vuln": ("// VULNERABLE: request value resolved against the base, no check\n"
                 "File f = new File(base, request.getParameter(\"doc\"));\n"
                 "return Files.readAllBytes(f.toPath());"),
        "fixed": ("// FIXED: canonicalize, then require the result to sit under base\n"
                  "Path f = base.resolve(request.getParameter(\"doc\")).normalize().toRealPath();\n"
                  "if (!f.startsWith(base)) throw new SecurityException(\"blocked\");\n"
                  "return Files.readAllBytes(f);"),
        "doc": "https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html#normalize--",
    },
    "JavaScript": {
        "vuln": ("// VULNERABLE: user input joined and served with no confinement\n"
                 "res.sendFile(path.join(BASE, req.query.doc));"),
        "fixed": ("// FIXED: resolve, then verify the result is still under BASE\n"
                  "const t = path.resolve(BASE, req.query.doc);\n"
                  "if (t !== BASE && !t.startsWith(BASE + path.sep)) return res.status(404).end();\n"
                  "res.sendFile(t);"),
        "doc": "https://nodejs.org/api/path.html#pathresolvepaths",
    },
    "TypeScript": {
        "vuln": ("// VULNERABLE: types do not stop traversal - still joins raw input\n"
                 "res.sendFile(path.join(BASE, req.query.doc as string));"),
        "fixed": ("// FIXED: resolve then confine to BASE\n"
                  "const t = path.resolve(BASE, req.query.doc as string);\n"
                  "if (t !== BASE && !t.startsWith(BASE + path.sep)) return res.status(404).end();\n"
                  "res.sendFile(t);"),
        "doc": "https://nodejs.org/api/path.html#pathresolvepaths",
    },
    "PHP": {
        "vuln": ("// VULNERABLE: input concatenated into a file read (include => LFI)\n"
                 "echo file_get_contents($base . $_GET['doc']);"),
        "fixed": ("// FIXED: realpath() resolves ../ and absolute paths; confirm prefix\n"
                  "$p = realpath($base . DIRECTORY_SEPARATOR . $_GET['doc']);\n"
                  "if ($p === false || strncmp($p, $base.'/', strlen($base)+1) !== 0) { http_response_code(404); exit; }\n"
                  "echo file_get_contents($p);"),
        "doc": "https://www.php.net/manual/en/function.realpath.php",
    },
    "Ruby": {
        "vuln": ("# VULNERABLE: params[:doc] joined and read with no check\n"
                 "send_file File.join(BASE, params[:doc])"),
        "fixed": ("# FIXED: expand to the real path, then require it under BASE\n"
                  "path = File.realpath(File.join(BASE, params[:doc])) rescue nil\n"
                  "raise 'not found' unless path && path.start_with?(BASE + File::SEPARATOR)\n"
                  "send_file path"),
        "doc": "https://docs.ruby-lang.org/en/3.3/File.html#method-c-realpath",
    },
    "Go": {
        "vuln": ("// VULNERABLE: filepath.Join cleans .. but still lets input climb out\n"
                 "http.ServeFile(w, r, filepath.Join(base, r.URL.Query().Get(\"doc\")))"),
        "fixed": ("// FIXED: resolve, then require the cleaned path to stay within base\n"
                  "p, _ := filepath.Abs(filepath.Join(base, r.URL.Query().Get(\"doc\")))\n"
                  "if p != base && !strings.HasPrefix(p, base+string(os.PathSeparator)) { http.NotFound(w, r); return }\n"
                  "http.ServeFile(w, r, p)"),
        "doc": "https://pkg.go.dev/path/filepath#Clean",
    },
    "C#": {
        "vuln": ("// VULNERABLE: Path.Combine drops the base if 'doc' is absolute\n"
                 "var path = Path.Combine(baseDir, Request.Query[\"doc\"]);\n"
                 "return File(System.IO.File.ReadAllBytes(path), \"application/octet-stream\");"),
        "fixed": ("// FIXED: full canonical path, then confirm it is under baseDir\n"
                  "var path = Path.GetFullPath(Path.Combine(baseDir, Request.Query[\"doc\"]));\n"
                  "if (!path.StartsWith(baseDir + Path.DirectorySeparatorChar, StringComparison.Ordinal)) return NotFound();\n"
                  "return File(System.IO.File.ReadAllBytes(path), \"application/octet-stream\");"),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getfullpath",
    },
}

INSTRUCTIONS = [
    "The WildFiles Portal has three file-operation sinks: the registration "
    "agreement viewer (?doc=), the profile picture loader (?img=), and the "
    "document download (?file=). Each reads a file named by your input from its "
    "own base directory.",
    "Confirm a sink works by requesting a known-good file (terms.txt, avatar1.svg, "
    "receipt-001.txt). You get its contents back, so the file is read from disk.",
    "Break out of the base directory. Try a relative climb "
    "(../../secret/.env_backup) or an absolute path (/opt/wildfiles/secret/"
    ".env_backup, the container path). Pad with extra ../ if unsure of the depth: "
    "extra ../ above the filesystem root are harmless.",
    "The flag is the SECRET_KEY value inside .env_backup, a backup env file kept "
    "outside the web root. Read it through any of the three sinks.",
    "Submit the 32-char MD5 flag in the answer box. It rotates on every restart.",
]

HINTS = [
    "Start by proving the sink reads from disk: load ?doc=terms.txt and read the "
    "agreement text. Now the value is a file path you control.",
    "Relative climb: the agreements/ directory sits under webroot/, and the "
    "secret is webroot's sibling. From the base, ../../secret/.env_backup reaches "
    "it. Not sure how deep you are? Use more dots-slashes: "
    "?doc=../../../../opt/wildfiles/secret/.env_backup works too (extra ../ above / "
    "are ignored).",
    "Absolute path also works: this app joins your value with os.path.join, which "
    "DROPS the base directory when the value is absolute. Try "
    "?doc=/opt/wildfiles/secret/.env_backup or /etc/passwd to prove it.",
    "Encoding practice: the server URL-decodes the query string once, so "
    "?doc=%2e%2e%2f%2e%2e%2fsecret%2f.env_backup (that is ../../ percent-encoded) "
    "reaches the same file. Double-encoding (%252e) would only help against a "
    "separate decoder in front of the app, so it will NOT work here (there is no "
    "second decode). That is the honest boundary.",
    "Real-world control: resolve the joined path to its canonical form "
    "(os.path.realpath) and confirm it is still inside the base directory before "
    "opening. That single check defeats ../, absolute paths, slash style, "
    "symlinks, and every encoding, because it acts on the real resolved path, not "
    "on the spelling of the input. Keeping secrets out of any web-served directory "
    "means even a successful read finds nothing.",
]

REFERENCES = [
    ("OWASP - Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
    ("OWASP WSTG - Directory Traversal / File Include",
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"),
    ("PortSwigger - Directory traversal", "https://portswigger.net/web-security/file-path-traversal"),
    ("MITRE - CWE-22", "https://cwe.mitre.org/data/definitions/22.html"),
]


def _page(result=None, active_sink=None):
    return render_template(
        "index.html",
        title="WildFiles Portal - Directory Traversal",
        sinks=SINKS,
        instructions=INSTRUCTIONS,
        hints=HINTS,
        references=REFERENCES,
        languages=LANGUAGES,
        result=result,
        active_sink=active_sink,
    )


@app.get("/")
def index():
    """Render the portal. If a sink's parameter (doc/img/file) is present in the
    query string, run that sink and show its result inline."""
    for sink in SINKS:
        key = sink["key"]
        if key in request.args:
            value = request.args.get(key, "")
            result = read_sink(key, value)
            return _page(result=result, active_sink=key)
    return _page()


@app.get("/avatar")
def avatar():
    """The genuine profile-picture loader used by the <img> tag on the profile
    card. Serves the raw bytes of the requested avatar file. Vulnerable in the
    same way as the other sinks: the img value is joined onto avatars/ and read
    with no confinement check."""
    value = request.args.get("img", "avatar1.svg")
    base = BASES["img"]
    joined = os.path.join(base, value)   # === VULNERABILITY: no confinement check
    try:
        with open(joined, "rb") as fh:
            raw = fh.read()
    except (OSError, ValueError):
        return Response("not found", status=404)
    mime = "image/svg+xml" if value.lower().endswith(".svg") else "application/octet-stream"
    return Response(raw, mimetype=mime)


@app.post("/check")
def check():
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, debug=False, threaded=True)
