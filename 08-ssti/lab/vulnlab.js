/*
 * Shared helpers for the WildWebApps SSTI lab (Node.js port of vulnlab.py).
 *
 * It provides:
 *   - generateFlag():  a fresh random MD5 hex string (call once per process)
 *   - checkFlag():     safe comparison of a submitted answer
 *   - plantBashrc():   write the flag as `export PASSWORD=<flag>` into a .bashrc
 *
 * The flag lives in an environment variable inside the target user's .bashrc,
 * exactly the kind of secret a real server keeps in a shell start-up file.
 */
const crypto = require("crypto");
const fs = require("fs");

// generateFlag returns a fresh random 32-char MD5 hex string.
// A new value is produced on every process start, so the flag rotates.
function generateFlag() {
  const randomBytes = crypto.randomBytes(16);
  return crypto.createHash("md5").update(randomBytes).digest("hex");
}

// checkFlag compares a submitted answer against the expected flag.
// The comparison is case-insensitive, whitespace-trimmed, and length-safe.
function checkFlag(expected, submitted) {
  if (!submitted) {
    return false;
  }
  const candidate = submitted.trim().toLowerCase();
  const target = expected.toLowerCase();
  // Reject on a length mismatch first, because timingSafeEqual throws when the
  // two buffers differ in length.
  if (candidate.length !== target.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(target));
}

// plantBashrc writes a realistic .bashrc that exports the flag as PASSWORD.
// The file is rewritten on every start, so restarting the lab rotates the flag.
// This mimics a server whose service account keeps a secret in a shell rc file.
function plantBashrc(flag, bashrcPath) {
  const content = [
    "# ~/.bashrc: executed by bash(1) for non-login shells.",
    "",
    "# If not running interactively, don't do anything.",
    "case $- in",
    "    *i*) ;;",
    "      *) return;;",
    "esac",
    "",
    "export HISTSIZE=1000",
    "export HISTFILESIZE=2000",
    "export LANG=C.UTF-8",
    "",
    "# Application service credentials (loaded into the environment on login).",
    "export DB_HOST=127.0.0.1",
    "export DB_USER=wildportal",
    "# The lab flag is stored as this account's password:",
    "export PASSWORD=" + flag,
    "",
    'alias ll="ls -alF"',
    "",
  ].join("\n");
  fs.writeFileSync(bashrcPath, content, "utf8");
}

module.exports = { generateFlag, checkFlag, plantBashrc };
