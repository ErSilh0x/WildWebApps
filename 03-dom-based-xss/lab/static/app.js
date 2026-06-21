/* WildWebApps lab - vanilla JS: language/view switcher, syntax highlight, flag check.
   No external dependencies (offline). Mirrors the design system's CodeBlock. */
(function () {
  "use strict";

  // ── Syntax highlighter (ported from the design system CodeBlock) ──────────
  var KW = new Set([
    "function", "def", "class", "import", "from", "return", "if", "else", "elif",
    "for", "while", "in", "not", "and", "or", "const", "let", "var", "new", "this",
    "self", "True", "False", "None", "null", "undefined", "true", "false",
    "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "JOIN", "AND", "OR",
    "async", "await", "try", "catch", "finally", "throw", "with", "pass", "print",
    "public", "private", "static", "void", "string", "func", "package", "echo"
  ]);

  function escHtml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function highlightLine(raw) {
    var rem = raw, out = "";
    while (rem.length > 0) {
      if (rem[0] === "#" || rem.slice(0, 2) === "//") {
        out += '<span class="tok-com">' + escHtml(rem) + "</span>";
        break;
      }
      var ch = rem[0];
      if (ch === '"' || ch === "'" || ch === "`") {
        var i = 1;
        while (i < rem.length) {
          if (rem.charCodeAt(i) === 92) { i += 2; continue; } // backslash escape
          if (rem[i] === ch) { i++; break; }
          i++;
        }
        out += '<span class="tok-str">' + escHtml(rem.slice(0, i)) + "</span>";
        rem = rem.slice(i);
        continue;
      }
      var idm = rem.match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
      if (idm) {
        var w = idm[0];
        out += KW.has(w) ? '<span class="tok-kw">' + w + "</span>" : escHtml(w);
        rem = rem.slice(w.length);
        continue;
      }
      var nm = rem.match(/^\d+\.?\d*/);
      if (nm) {
        out += '<span class="tok-num">' + nm[0] + "</span>";
        rem = rem.slice(nm[0].length);
        continue;
      }
      out += escHtml(rem[0]);
      rem = rem.slice(1);
    }
    return out || "&nbsp;";
  }

  function highlight(code) {
    return code.split("\n").map(highlightLine).join("\n");
  }

  // ── Code switcher ─────────────────────────────────────────────────────────
  var DATA = {};
  try {
    DATA = JSON.parse(document.getElementById("lab-data").textContent || "{}");
  } catch (e) { DATA = {}; }

  var langTabs = document.getElementById("lang-tabs");
  var viewTabs = document.getElementById("view-tabs");
  var mount = document.getElementById("code-mount");
  var curLang = "";
  var curView = "vuln";

  function syncActive() {
    if (langTabs) {
      langTabs.querySelectorAll(".tab").forEach(function (b) {
        b.classList.toggle("tab--active", b.getAttribute("data-lang") === curLang);
      });
    }
    if (viewTabs) {
      viewTabs.querySelectorAll(".tab").forEach(function (b) {
        b.classList.toggle("tab--active", b.getAttribute("data-view") === curView);
      });
    }
  }

  function renderCode() {
    if (!mount) return;
    var d = DATA[curLang] || {};
    var code = (curView === "vuln" ? d.vuln : d.fixed) || "";
    var label = curView === "vuln" ? "[VULNERABLE]" : "[FIXED]";
    var variant = curView === "vuln" ? "code--vulnerable" : "code--fixed";
    mount.innerHTML =
      '<div class="code ' + variant + '">' +
      '<div class="code__bar"><div>' +
      '<span class="code__label">' + label + "</span>" +
      '<span class="code__lang">' + curLang.toLowerCase() + "</span></div>" +
      '<button class="code__copy" type="button">copy</button></div>' +
      '<div class="code__body"><pre>' + highlight(code) + "</pre></div></div>" +
      (d.doc ? '<p><a href="' + d.doc + '" target="_blank" rel="noopener">Official documentation ↗</a></p>' : "");

    var copyBtn = mount.querySelector(".code__copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        if (navigator.clipboard) {
          navigator.clipboard.writeText(code).then(function () {
            copyBtn.textContent = "✓ copied";
            copyBtn.classList.add("is-copied");
            setTimeout(function () {
              copyBtn.textContent = "copy";
              copyBtn.classList.remove("is-copied");
            }, 1600);
          });
        }
      });
    }
  }

  function buildTabs() {
    var langs = Object.keys(DATA);
    if (!langs.length || !langTabs) return;
    curLang = langs[0];
    langTabs.innerHTML = langs.map(function (l) {
      return '<button class="tab" type="button" data-lang="' + l + '">' + l + "</button>";
    }).join("");
    langTabs.querySelectorAll(".tab").forEach(function (b) {
      b.addEventListener("click", function () {
        curLang = b.getAttribute("data-lang"); syncActive(); renderCode();
      });
    });
    if (viewTabs) {
      viewTabs.querySelectorAll(".tab").forEach(function (b) {
        b.addEventListener("click", function () {
          curView = b.getAttribute("data-view"); syncActive(); renderCode();
        });
      });
    }
    syncActive();
    renderCode();
  }

  // ── Flag submission ─────────────────────────────────────────────────────────
  var form = document.getElementById("flag-form");
  var input = document.getElementById("flag-input");
  var result = document.getElementById("flag-result");

  function showResult(ok, msg) {
    if (!result) return;
    result.hidden = false;
    result.className = "alert " + (ok ? "alert--success" : "alert--error");
    result.innerHTML =
      "<div><div class=\"alert__title\">" +
      (ok ? "Correct - flag accepted" : "Incorrect") + "</div>" +
      "<div class=\"alert__body\">" +
      (msg || (ok
        ? "Nice work. Restart the lab to get a fresh flag."
        : "That flag is not valid. Keep going.")) +
      "</div></div>";
  }

  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var flag = input ? input.value : "";
      fetch("/check", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "flag=" + encodeURIComponent(flag)
      })
        .then(function (r) { return r.json(); })
        .then(function (data) { showResult(!!data.correct); })
        .catch(function () { showResult(false, "Could not reach the server."); });
    });
  }

  // ── Vulnerable client-side docs search (DOM-based / client-side reflected) ──
  // THIS is the lab's real vulnerability. The search term is read from the URL
  // fragment (location.hash) - a source the server never receives - and written
  // into the page with innerHTML, a sink that parses HTML. An attacker who
  // controls the fragment controls markup parsed in this origin.
  //
  // Note: a <script> inserted via innerHTML does NOT execute (HTML5), so the
  // exploit uses an event-handler payload such as <img src=x onerror=...>.
  var searchForm = document.getElementById("search-form");
  var searchInput = document.getElementById("search-input");
  var searchResult = document.getElementById("search-result");

  function renderSearch() {
    if (!searchResult) return;
    var raw = location.hash.slice(1);
    if (!raw) { searchResult.hidden = true; searchResult.innerHTML = ""; return; }
    var term;
    // The browser percent-encodes some characters in the fragment; decode to
    // restore the attacker's payload (fall back to the raw value on bad input).
    try { term = decodeURIComponent(raw); } catch (e) { term = raw; }
    searchResult.hidden = false;
    // === VULNERABILITY: untrusted fragment written to an innerHTML sink ========
    searchResult.innerHTML = "Showing results for: <strong>" + term + "</strong>";
    // ==========================================================================
    if (searchInput && document.activeElement !== searchInput) {
      searchInput.value = term;
    }
  }

  if (searchForm) {
    searchForm.addEventListener("submit", function (e) {
      e.preventDefault();
      // Keep the term in the fragment so the result is shareable / bookmarkable.
      location.hash = encodeURIComponent(searchInput ? searchInput.value : "");
      renderSearch();  // hashchange won't fire if the value is unchanged
    });
  }
  window.addEventListener("hashchange", renderSearch);
  renderSearch();  // render on initial load straight from the fragment

  buildTabs();
})();
