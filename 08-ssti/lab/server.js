/*
 * WildWebApps lab - Server-Side Template Injection (SSTI) with Handlebars.
 *
 * "WildPortal" is a small app with THREE pages, as specified for this lab:
 *
 *   1. GET  /                     Front page: hello + welcome message.
 *   2. GET  /admin                Admin page: a menu plus an "Edit Page Template"
 *                                 button that opens the third page in a popup.
 *   3. GET  /admin/edit-template  A template editor (opened in a new popup
 *      POST /admin/edit-template  window). The administrator types a Handlebars
 *                                 template; the server COMPILES AND RENDERS it.
 *
 * === THE VULNERABILITY =====================================================
 * The editor takes the administrator's input and calls handlebars.compile() on
 * it, then executes the compiled template on the server. Because the input is
 * treated as a TEMPLATE (code) rather than as DATA, any Handlebars expression
 * the attacker writes runs server-side. The app also registers a custom `read`
 * helper that returns the contents of any file. Together these turn template
 * injection into arbitrary file read.
 *
 * The per-process MD5 flag is written as `export PASSWORD=<flag>` into the
 * target user's ~/.bashrc (/root/.bashrc in the container). Recover it with
 * {{read "/root/.bashrc"}} in the editor, then submit it. It rotates on restart.
 * ===========================================================================
 */
const express = require("express");
const handlebars = require("handlebars");
const fs = require("fs");
const os = require("os");
const path = require("path");

const vulnlab = require("./vulnlab");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// Flag setup: fresh MD5 each start, planted in the target user's .bashrc.
// ---------------------------------------------------------------------------
const FLAG = vulnlab.generateFlag();

// BASHRC_PATH lets the sandbox point the flag at a temp file. In the container
// HOME is /root, so the default is /root/.bashrc, matching the writeup.
const BASHRC_PATH = process.env.BASHRC_PATH || path.join("/root", ".bashrc");

// plantFlag writes the .bashrc holding the flag. If /root is not writable (for
// example when testing outside the container), fall back to the current user's
// home directory so the lab still runs.
function plantFlag() {
  try {
    vulnlab.plantBashrc(FLAG, BASHRC_PATH);
    return BASHRC_PATH;
  } catch (err) {
    const fallback = path.join(os.homedir(), ".bashrc_wwa_lab");
    vulnlab.plantBashrc(FLAG, fallback);
    return fallback;
  }
}

const FLAG_FILE = plantFlag();

// ---------------------------------------------------------------------------
// Handlebars setup. This ONE instance renders the app's own trusted pages AND
// (in the vulnerable endpoint) the administrator's template. The `read` helper
// is registered globally, the way a real app would add a convenience helper.
// ---------------------------------------------------------------------------
const hb = handlebars.create();

// read(path): return the contents of a file on the server.
//
// === VULNERABILITY ENABLER =================================================
// A helper that reads arbitrary files is safe only if templates are trusted.
// Once attacker input is compiled as a template, this helper hands the attacker
// arbitrary file read: {{read "/root/.bashrc"}}, {{read "/etc/passwd"}}, etc.
// ===========================================================================
hb.registerHelper("read", function (filePath) {
  try {
    const content = fs.readFileSync(String(filePath), "utf8");
    // Return the file contents verbatim (SafeString), the way a content helper
    // normally does. The editor page escapes it once for display, so the flag's
    // "=" shows correctly and any HTML in a read file is shown as inert text.
    return new handlebars.SafeString(content);
  } catch (err) {
    return new handlebars.SafeString("[read error: " + err.message + "]");
  }
});

// inc(n): 1-based index helper, used only by the trusted pages (hint numbering).
hb.registerHelper("inc", function (value) {
  return value + 1;
});

// Load and register the shared chrome partials (real Handlebars partial usage).
const PARTIALS_DIR = path.join(__dirname, "views", "partials");
for (const file of fs.readdirSync(PARTIALS_DIR)) {
  const name = path.basename(file, ".hbs");
  const source = fs.readFileSync(path.join(PARTIALS_DIR, file), "utf8");
  hb.registerPartial(name, source);
}

// Compile the three trusted page templates once at startup.
function loadView(name) {
  const source = fs.readFileSync(path.join(__dirname, "views", name), "utf8");
  return hb.compile(source);
}
const views = {
  front: loadView("front.hbs"),
  admin: loadView("admin.hbs"),
  edit: loadView("edit.hbs"),
};

// ---------------------------------------------------------------------------
// The legitimate context a page template is "supposed" to use. Passing data as
// context (this object) is the safe pattern; compiling user input is not.
// ---------------------------------------------------------------------------
const pageContext = {
  siteName: "WildPortal",
  tagline: "Your friendly community portal for events, notices, and updates.",
  user: { name: "guest", role: "administrator" },
};

// ---------------------------------------------------------------------------
// Learning scaffolding shown on the front page (instructions, hints, code,
// references) and the fingerprint probes shown on the editor page.
// ---------------------------------------------------------------------------
const INSTRUCTIONS = [
  "Open the admin area, then click \"Edit Page Template\". A small editor opens " +
    "in a new popup window. Whatever you type there is compiled and rendered on " +
    "the server by the Handlebars template engine.",
  "First identify the engine. Try the fingerprint probes listed in the editor. " +
    "Handlebars is logic-less: {{7*7}} does NOT print 49 (it raises a parse " +
    "error), which by itself rules out Jinja2, Twig, and friends and points at " +
    "Handlebars.",
  "Confirm you control the template by referencing a real variable, e.g. " +
    "{{siteName}} renders \"WildPortal\". Your input is being treated as code.",
  "The app registered a custom helper called read that returns the contents of " +
    "any file. Call it: {{read \"/root/.bashrc\"}} reads the target user's shell " +
    "start-up file.",
  "The flag is the PASSWORD environment variable exported inside /root/.bashrc. " +
    "Read that file, copy the 32-char MD5 value, and submit it in the flag box " +
    "on the front page. It rotates on every restart.",
];

const HINTS = [
  "Fingerprint first. In Handlebars, {{7*7}} throws a parse error rather than " +
    "printing 49, because Handlebars has no expression evaluation. A literal " +
    "{{this}} or {{siteName}} that renders a value confirms you are inside a " +
    "Handlebars template.",
  "Prove code execution with data you know: {{siteName}} should render " +
    "\"WildPortal\" and {{user.name}} should render \"guest\". If the output " +
    "changes based on your expression, your input is being compiled as a template.",
  "This app exposes a custom helper: read. Helpers are called by name with " +
    "quoted arguments. Try {{read \"/etc/hostname\"}} to confirm it reads files, " +
    "then aim it at the secret.",
  "The secret lives in a shell start-up file. Read {{read \"/root/.bashrc\"}} " +
    "and look for the line: export PASSWORD=... That value is the flag.",
  "Real-world fix: never compile untrusted input as a template. Pass user input " +
    "as DATA into a fixed, precompiled template (context values are escaped and " +
    "never executed), and do not register file-system or shell helpers that " +
    "attacker-controlled templates could reach.",
];

// Fingerprint probes: what to type in the editor to identify the engine. The
// strings are passed as DATA (context), so Handlebars renders them literally
// and never parses their braces.
const PROBES = [
  { payload: "{{7*7}}", note: "Handlebars: parse error (logic-less, no math). Jinja2/Twig would print 49. This mismatch is the Handlebars tell." },
  { payload: "${7*7}", note: "No change / literal: rules out FreeMarker and JSP EL style engines." },
  { payload: "<%= 7*7 %>", note: "Literal: rules out ERB (Ruby) and EJS." },
  { payload: "#{7*7}", note: "Literal: rules out some Ruby / Pug interpolation." },
  { payload: "{{this}}", note: "Renders the current context: valid Handlebars/Mustache syntax." },
  { payload: "{{siteName}}", note: "Renders \"WildPortal\": confirms your input is compiled as a template with the app context." },
  { payload: "{{#each this}}{{/each}}", note: "Block helper parses cleanly: confirms Handlebars block syntax." },
];

// In-lab code switcher: SSTI vulnerable + fixed, eight languages / engines.
const LANGUAGES = require("./languages.json");

const REFERENCES = [
  { label: "OWASP - Server-Side Template Injection (WSTG)", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection" },
  { label: "PortSwigger - Server-side template injection", url: "https://portswigger.net/web-security/server-side-template-injection" },
  { label: "PortSwigger Research - SSTI (James Kettle)", url: "https://portswigger.net/research/server-side-template-injection" },
  { label: "MITRE - CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)", url: "https://cwe.mitre.org/data/definitions/1336.html" },
  { label: "Handlebars - Expressions & helpers", url: "https://handlebarsjs.com/guide/expressions.html" },
];

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Page 1: front page (also carries the lab panel).
app.get("/", function (req, res) {
  const html = views.front(
    Object.assign({}, pageContext, {
      instructions: INSTRUCTIONS,
      hints: HINTS,
      references: REFERENCES,
      // languagesJson is emitted raw (triple-stache) for the code switcher.
      languagesJson: JSON.stringify(LANGUAGES),
    })
  );
  res.send(html);
});

// Page 2: admin page with the menu and the "Edit Page Template" button.
app.get("/admin", function (req, res) {
  res.send(views.admin(pageContext));
});

// Page 3 (GET): the vulnerable template editor, opened in a popup window.
app.get("/admin/edit-template", function (req, res) {
  res.send(views.edit(Object.assign({}, pageContext, { probes: PROBES, submitted: false })));
});

// Page 3 (POST): compile and render the administrator-supplied template.
app.post("/admin/edit-template", function (req, res) {
  const source = req.body.template || "";
  let rendered = "";
  let error = null;
  try {
    // === VULNERABILITY: attacker-controlled input is compiled AS A TEMPLATE
    // and executed on the server. {{read "..."}} now reads arbitrary files.
    const template = hb.compile(source);
    rendered = template(pageContext);
  } catch (err) {
    // Surfacing the parse/runtime error is realistic and also helps the
    // attacker fingerprint the engine from its distinctive error text.
    error = err.message;
  }
  res.send(
    views.edit(
      Object.assign({}, pageContext, {
        probes: PROBES,
        submitted: true,
        source: source,
        rendered: rendered,
        error: error,
      })
    )
  );
});

// Flag check endpoint (same contract as the other WildWebApps labs).
app.post("/check", function (req, res) {
  res.json({ correct: vulnlab.checkFlag(FLAG, req.body.flag || "") });
});

// ---------------------------------------------------------------------------
// Start the server.
// ---------------------------------------------------------------------------
const HOST = process.env.HOST || "127.0.0.1";
const PORT = parseInt(process.env.PORT || "8000", 10);

app.listen(PORT, HOST, function () {
  console.log("WildWebApps SSTI lab listening on http://" + HOST + ":" + PORT);
  console.log("Flag planted in " + FLAG_FILE + " (as export PASSWORD=...).");
});
