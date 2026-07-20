"""
WildWebApps lab - XML External Entity (XXE) injection.

"WildParts" is a small spare-parts store with a "Check stock" feature. The
browser sends an XML document describing the part to look up, and the server
parses that XML with an UNSAFE parser configuration that resolves external
entities. That single misconfiguration lets an attacker define an entity that
points at a local file (file:///etc/passwd) and have its contents pulled into
the document.

The response never echoes a successful lookup back verbatim, so this lab is
solved the ERROR-BASED way: when the looked-up product id is not a real id
(because it is now the contents of a file), the app returns an error message
that quotes the offending value. That error message is where the file contents
(and the flag) leak out.

The per-process MD5 flag is planted into /etc/passwd (in the GECOS comment field
of an extra "wwa-flag" account line), so reading file:///etc/passwd through the
XXE reveals it. The flag rotates on every restart.
"""
import os

from flask import Flask, render_template, request, jsonify
from lxml import etree

import vulnlab

app = Flask(__name__)

# Fresh random MD5 flag for this process (rotates on every restart).
FLAG = vulnlab.generate_flag()

# The file the flag is planted into. The whole point of the lab is to read this
# path via XXE, so it defaults to the real /etc/passwd. In the build sandbox it
# can be pointed at a temporary copy with the PASSWD_FILE env var.
PASSWD_FILE = os.environ.get("PASSWD_FILE", "/etc/passwd")


def plant_flag_in_passwd():
    """Append an extra account line to /etc/passwd that carries the flag.

    The flag lives in the GECOS (comment) field of a "wwa-flag" user, so that a
    successful read of /etc/passwd shows a normal-looking passwd file with the
    flag sitting in one of its lines. Any previous wwa-flag line is stripped
    first, so restarting the lab rotates the flag cleanly.
    """
    flag_line = (
        "wwa-flag:x:1337:1337:WildWebApps flag " + FLAG
        + ":/home/wwa-flag:/usr/sbin/nologin\n"
    )
    try:
        with open(PASSWD_FILE, "r", encoding="utf-8", errors="replace") as fh:
            existing = fh.readlines()
    except OSError:
        existing = []

    kept = [line for line in existing if not line.startswith("wwa-flag:")]
    kept.append(flag_line)

    try:
        with open(PASSWD_FILE, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
    except OSError:
        # If the file is not writable (for example when running unprivileged in
        # a sandbox), fall back to a local copy so the lab still functions.
        pass


plant_flag_in_passwd()


# A tiny in-memory product catalogue. A real lookup would hit a database; here a
# dict is enough to show the difference between a valid id (stock returned) and
# an unknown id (an error that quotes the value back, the error-based leak).
CATALOGUE = {
    1: {"name": "Brake pad set", "stock": 42},
    2: {"name": "Oil filter", "stock": 17},
    3: {"name": "Spark plug (4-pack)", "stock": 8},
    4: {"name": "Wiper blade", "stock": 0},
    5: {"name": "Cabin air filter", "stock": 23},
}

# The XML document the browser sends for a stock check. Shown pre-filled in the
# big input box so the student sees the exact shape they are tampering with.
SAMPLE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<stockCheck>\n"
    "  <productId>3</productId>\n"
    "  <storeId>1</storeId>\n"
    "</stockCheck>\n"
)


def parse_stock_request(xml_text):
    """Parse the submitted XML with the UNSAFE parser and run the stock lookup.

    Returns a result dict the template renders. The dict has one of:
      - "stock":  a successful lookup (valid numeric product id)
      - "error":  an application error that QUOTES the submitted product id
                  (this is the error-based leak path)
      - "parse_error": the raw XML parser error (verbose errors are on, which
                  helps a tester fingerprint the parser and confirm XXE)

    === VULNERABILITY ======================================================
    The parser is built with resolve_entities=True and load_dtd=True. That
    tells libxml2 to process the DTD and expand external entities, including
    ones whose SYSTEM identifier is a file:// URL. An attacker can therefore
    declare <!ENTITY xxe SYSTEM "file:///etc/passwd"> and reference &xxe;,
    and the parser will read that file and splice its contents into the
    document before the app ever sees it. The fix is to disable DTDs and
    entity resolution (see the writeup); a hardened parser rejects the DTD
    outright.
    ========================================================================
    """
    parser = etree.XMLParser(
        load_dtd=True,          # process the DTD, so entity declarations take effect
        no_network=True,        # do not fetch over the network (local files still read)
        resolve_entities=True,  # THE BUG: expand external entities, including file:// ones
    )

    try:
        root = etree.fromstring(xml_text.encode("utf-8"), parser)
    except etree.XMLSyntaxError as exc:
        # Verbose parser errors are surfaced to the user. This is realistic (many
        # apps leak stack traces / parser errors) and it is what makes error-based
        # testing possible: a tester reads these messages to confirm the parser.
        log_lines = [str(entry.message) for entry in parser.error_log]
        return {"parse_error": str(exc), "log": log_lines}

    # Pull the productId out of the (now entity-expanded) document.
    product_el = root.find(".//productId")
    if product_el is None or product_el.text is None:
        return {"error": "Request is missing a <productId> element.", "value": ""}

    product_value = product_el.text

    # Try to treat it as a real product id and look it up.
    try:
        product_id = int(product_value.strip())
    except (ValueError, AttributeError):
        # Not a number. The lookup fails and the app reports the bad value back
        # inside the error message. When the value is the contents of a file
        # pulled in by an external entity, the file leaks out through this error.
        return {
            "error": "Stock lookup failed: no product matches id",
            "value": product_value,
        }

    item = CATALOGUE.get(product_id)
    if item is None:
        # A numeric id that is not in the catalogue: still an error, still quotes
        # the value (a small numeric value here, but the same code path).
        return {
            "error": "Stock lookup failed: no product matches id",
            "value": product_value,
        }

    return {
        "stock": item["stock"],
        "name": item["name"],
        "product_id": product_id,
    }


# ---------------------------------------------------------------------------
# In-lab code switcher: the same lookup, unsafe vs hardened parser, 8 languages.
# The fix in every language is the same idea: turn OFF DTD processing and
# external-entity resolution before parsing untrusted XML.
# ---------------------------------------------------------------------------
LANGUAGES = {
    "Python": {
        "vuln": ("# VULNERABLE: lxml with DTD + external entity resolution enabled\n"
                 "parser = etree.XMLParser(load_dtd=True, resolve_entities=True)\n"
                 "root = etree.fromstring(data, parser)  # &xxe; is expanded from file://"),
        "fixed": ("# FIXED: refuse DTDs and never resolve entities\n"
                  "parser = etree.XMLParser(resolve_entities=False, no_network=True,\n"
                  "                         load_dtd=False, dtd_validation=False)\n"
                  "root = etree.fromstring(data, parser)  # or use defusedxml.lxml"),
        "doc": "https://lxml.de/api/lxml.etree.XMLParser-class.html",
    },
    "Java": {
        "vuln": ("// VULNERABLE: a default DocumentBuilderFactory resolves external entities\n"
                 "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                 "Document doc = f.newDocumentBuilder().parse(input);"),
        "fixed": ("// FIXED: disable DOCTYPE declarations entirely (OWASP-recommended)\n"
                  "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                  "f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                  "f.setExpandEntityReferences(false);\n"
                  "Document doc = f.newDocumentBuilder().parse(input);"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java",
    },
    "JavaScript": {
        "vuln": ("// VULNERABLE: libxmljs with entity + DTD loading turned on\n"
                 "const doc = libxmljs.parseXml(data, { noent: true, dtdload: true });\n"
                 "// noent expands &xxe; from file://"),
        "fixed": ("// FIXED: parse with entity expansion OFF and no DTD load (defaults)\n"
                  "const doc = libxmljs.parseXml(data, { noent: false, dtdload: false,\n"
                  "                                       nonet: true });\n"
                  "// or use a parser with no external-entity support at all"),
        "doc": "https://github.com/libxmljs/libxmljs",
    },
    "TypeScript": {
        "vuln": ("// VULNERABLE: same libxmljs flaw; types do not stop entity expansion\n"
                 "const doc = libxmljs.parseXml(data, { noent: true, dtdload: true });"),
        "fixed": ("// FIXED: entity expansion off, no DTD load, no network\n"
                  "const doc = libxmljs.parseXml(data, { noent: false, dtdload: false,\n"
                  "                                       nonet: true });"),
        "doc": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    },
    "PHP": {
        "vuln": ("// VULNERABLE: loading the DTD subset lets external entities resolve\n"
                 "$doc = new DOMDocument();\n"
                 "$doc->loadXML($data, LIBXML_DTDLOAD | LIBXML_NOENT);"),
        "fixed": ("// FIXED: do NOT pass LIBXML_NOENT / LIBXML_DTDLOAD; forbid the DTD\n"
                  "libxml_set_external_entity_loader(function () { return null; });\n"
                  "$doc = new DOMDocument();\n"
                  "$doc->loadXML($data);   // no entity expansion, no external fetch"),
        "doc": "https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php",
    },
    "Ruby": {
        "vuln": ("# VULNERABLE: Nokogiri with NOENT tells it to resolve external entities\n"
                 "doc = Nokogiri::XML(data) { |c| c.noblanks.dtdload.noent }"),
        "fixed": ("# FIXED: parse with the default (safe) options; do not enable NOENT\n"
                  "doc = Nokogiri::XML(data) { |c| c.nonet.strict }\n"
                  "# Nokogiri does not resolve external entities unless NOENT is set"),
        "doc": "https://nokogiri.org/rdoc/Nokogiri/XML/ParseOptions.html",
    },
    "Go": {
        "vuln": ("// VULNERABLE: some XML libs follow external entities. A DTD-processing\n"
                 "// decoder that resolves SYSTEM entities exposes local files.\n"
                 "dec := xmlLib.NewDecoderWithDTD(input)   // resolves <!ENTITY ... SYSTEM>"),
        "fixed": ("// FIXED: encoding/xml (stdlib) does NOT expand external entities at all.\n"
                  "// Leave Decoder.Entity empty and do not add a custom entity resolver.\n"
                  "dec := xml.NewDecoder(input)\n"
                  "for { tok, err := dec.Token(); if err != nil { break }; _ = tok }"),
        "doc": "https://pkg.go.dev/encoding/xml#Decoder",
    },
    "C#": {
        "vuln": ("// VULNERABLE: an XmlReader/XmlDocument with a DTD-resolving XmlResolver\n"
                 "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse,\n"
                 "                                       XmlResolver = new XmlUrlResolver() };\n"
                 "var reader = XmlReader.Create(input, settings);"),
        "fixed": ("// FIXED: prohibit DTDs and use no resolver (the .NET 4.0+ safe default)\n"
                  "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,\n"
                  "                                       XmlResolver = null };\n"
                  "var reader = XmlReader.Create(input, settings);"),
        "doc": "https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing",
    },
}

INSTRUCTIONS = [
    "The WildParts store checks stock by parsing an XML document you control. "
    "Send the sample request first and confirm it works: product id 3 returns a "
    "stock count.",
    "Test for XXE by adding a DOCTYPE with an entity and referencing it in "
    "<productId>. Start harmless: define <!ENTITY test \"1\"> and use &test; to "
    "confirm the parser expands your entities.",
    "Escalate to an EXTERNAL entity that reads a file: declare "
    "<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> and put &xxe; inside "
    "<productId>. The parser reads the file and drops its contents into the "
    "element before the lookup runs.",
    "The lookup then fails (the file's text is not a product id), and the app "
    "reports the failure by quoting your value back. That error message is where "
    "/etc/passwd (and the flag) leaks out: this is error-based exfiltration.",
    "Find the wwa-flag line in the leaked /etc/passwd. The 32-char MD5 flag sits "
    "in its comment field. Submit it below. It rotates on every restart.",
]

HINTS = [
    "Fingerprint first. Paste malformed XML or reference an undefined entity "
    "(&nope;) and read the error the app shows: a message like \"Entity 'nope' "
    "not defined\" tells you the parser processes your DTD and entities, the "
    "precondition for XXE.",
    "Internal entity as a warm-up (proves entity expansion is on):\n"
    "<?xml version=\"1.0\"?>\n"
    "<!DOCTYPE stockCheck [ <!ENTITY test \"3\"> ]>\n"
    "<stockCheck><productId>&test;</productId><storeId>1</storeId></stockCheck>\n"
    "If that returns stock for product 3, your entity was expanded.",
    "Now make it external. Swap the internal entity for a SYSTEM one that points "
    "at the file:\n"
    "<?xml version=\"1.0\"?>\n"
    "<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n"
    "<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>",
    "The file contents come back inside \"Stock lookup failed: no product "
    "matches id '...'\". Scroll the error box: /etc/passwd is multi-line, and the "
    "wwa-flag account line holds the flag in its comment (GECOS) field.",
    "Real-world fix: parse untrusted XML with DTDs and external-entity resolution "
    "turned OFF (in Python, do not pass resolve_entities=True / load_dtd=True, or "
    "use defusedxml). A parser that refuses the DOCTYPE cannot be tricked into "
    "reading files, reaching internal hosts (SSRF), or expanding a billion-laughs "
    "bomb.",
]

REFERENCES = [
    ("OWASP - XML External Entity (XXE) Processing",
     "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"),
    ("OWASP Cheat Sheet - XXE Prevention",
     "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"),
    ("OWASP WSTG - Testing for XML Injection",
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection"),
    ("PortSwigger - XML external entity (XXE) injection",
     "https://portswigger.net/web-security/xxe"),
    ("MITRE - CWE-611",
     "https://cwe.mitre.org/data/definitions/611.html"),
]


def _page(result=None, submitted_xml=None):
    """Render the lab page, optionally with a stock-check result."""
    return render_template(
        "index.html",
        title="WildParts Store - XML External Entity (XXE)",
        instructions=INSTRUCTIONS,
        hints=HINTS,
        references=REFERENCES,
        languages=LANGUAGES,
        sample_xml=SAMPLE_XML,
        submitted_xml=submitted_xml if submitted_xml is not None else SAMPLE_XML,
        result=result,
    )


@app.get("/")
def index():
    """Show the stock-check form pre-filled with the sample XML request."""
    return _page()


@app.post("/")
def check_stock():
    """Parse the submitted XML (unsafely) and show the stock result or error."""
    xml_text = request.form.get("xml", "")
    result = parse_stock_request(xml_text)
    return _page(result=result, submitted_xml=xml_text)


@app.post("/check")
def check():
    """Validate a submitted flag (used by the answer box)."""
    return jsonify(correct=vulnlab.check_flag(FLAG, request.form.get("flag", "")))


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, debug=False, threaded=True)
