#!/usr/bin/env python3
"""Scan a decompiled/source/extracted tree (or a single file) for an app's
network surface and other analysis anchors.

Built for the "I decompiled it, now where does it talk to the world?" step. Runs
over jadx/apktool output (Java, Kotlin, smali), beautified or minified JS bundles,
an extracted firmware root filesystem, or any source tree, and pulls out:

  - declared endpoints: Retrofit-style annotations (Java/Kotlin and smali),
    HTTP-client calls with literal paths (axios/ktor/okhttp-style .get("/x"),
    fetch("/x"))
  - URLs, WebSocket URLs, and hostnames found inside string literals
  - likely API path templates ("/v1/users/{id}")
  - auth/header markers, networking libraries, crypto markers
  - secret-shaped strings (masked by default; --show-secrets to reveal)

Each hit carries file:line so you can jump straight to it. Files are read as
text and never executed. Treat results as leads to confirm, not conclusions.

Usage:
    python extract_endpoints.py <dir-or-file> [--json] [--show-secrets]
           [--ext .java,.kt,.js] [--all-ext] [--max-bytes N] [--keep-noise]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys

MAX_LOCS = 8

TLDS = (r"com|net|org|io|dev|app|co|ai|cloud|gov|edu|me|xyz|tech|info|biz|us|uk|de|"
        r"cn|ru|jp|in|br|fr|it|nl|es|kr|tv|gg|so|sh|to|ly|internal|local|lan|corp")

URL_RE = re.compile(r"""\b(?:https?|wss?)://[^\s"'`<>\\\]]{3,}""")
HOST_RE = re.compile(r"""(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s))(?![\w-]|\.[a-z])""" % TLDS, re.I)
# A quote right after a backslash never opens a literal. Without that, every \" in an
# unterminated run was a fresh start that rescanned to the end of the line (quadratic on
# one long minified line); with it, at most one start per quote type fails per line.
STRING_LIT = re.compile(r'''(?<!\\)"((?:[^"\\\n]|\\.){3,})"|(?<!\\)'((?:[^'\\\n]|\\.){3,})'|`([^`\n]{3,})`''')

ANNOTATION_RE = re.compile(r"""@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*(?:value\s*=\s*)?"([^"]*)\"""")
HTTP_ANNOT_RE = re.compile(r"""@HTTP\s*\(\s*method\s*=\s*"(\w+)"\s*,\s*path\s*=\s*"([^"]*)\"""")
SMALI_ANNOT_RE = re.compile(r"""Lretrofit2?/http/(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP);""")
SMALI_VALUE_RE = re.compile(r"""^\s*(?:value|path)\s*=\s*"([^"]*)\"""")
CLIENT_CALL_RE = re.compile(r"""\.(get|post|put|delete|patch|head)\s*\(\s*["'`]((?:https?://|/)[^"'`\s]*)["'`]""", re.I)
FETCH_RE = re.compile(r"""\bfetch\s*\(\s*["'`]((?:https?://|/)[^"'`\s]*)["'`]""")

PATTERNS = {
    "api_path": re.compile(r"""["'`](/(?:api|v\d+|rest|graphql|oauth2?|auth|users?|login|logout|token|account|device|session)\b[A-Za-z0-9_\-/{}.:$]*)["'`]"""),
    "auth_header": re.compile(r"""\b(Authorization|Bearer|X-Api-Key|X-Auth-Token|apikey|api_key|access_token|refresh_token|client_secret|X-Signature|HMAC)\b""", re.I),
    # No trailing \b: these names routinely appear inside longer identifiers
    # (OkHttp in OkHttpClient, EVP_ in EVP_EncryptInit).
    "crypto": re.compile(r"""\b(AES|DES|RSA|ECB|CBC|GCM|PBKDF2|HMAC|SHA-?(?:1|256|512)|MD5|SecretKeySpec|Cipher\.getInstance|EVP_|CryptoKit|CommonCrypto|KeyStore|javax\.crypto|BCrypt)"""),
    "net_lib": re.compile(r"""\b(Retrofit|OkHttp|HttpURLConnection|Volley|Ktor|Apollo|URLSession|NSURLSession|Alamofire|axios|XMLHttpRequest|WebSocket|gRPC|grpc|socket\.io|HttpClient)"""),
    # The JWT branch may not start inside a longer [\w-] run: with only \b, every
    # "-eyJ" in one long run was a fresh start that rescanned the whole run.
    "secret_ish": re.compile(r"""\b(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9A-Za-z]{10,}|gh[pousr]_[0-9A-Za-z]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}|(?<![\w-])eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"""),
}

CODE_EXT = {".java", ".kt", ".kts", ".smali", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
            ".swift", ".m", ".mm", ".c", ".cc", ".cpp", ".h", ".hpp", ".go", ".rs", ".py",
            ".rb", ".php", ".cs", ".dart", ".lua", ".gradle", ".vue", ".svelte"}
DEFAULT_EXT = CODE_EXT | {".json", ".xml", ".plist", ".html", ".htm", ".cfg", ".conf", ".ini",
                          ".properties", ".txt", ".yaml", ".yml", ".env", ".sh", ".wat", ".proto",
                          ".graphql", ".gql", ""}  # "" = extensionless config/binaries in firmware roots
SKIP_DIRS = {".git", "node_modules", ".gradle", "build", "__pycache__", ".idea", ".svn"}

# Reverse-DNS package names (com.example.app, android.app, java.net) look like hosts.
# A real hostname essentially never starts with one of these labels.
REVERSE_DNS_FIRST = {"com", "org", "net", "io", "android", "androidx", "java", "javax", "kotlin",
                     "kotlinx", "dalvik", "sun", "edu", "gov", "okhttp3", "retrofit2", "dagger", "jakarta"}
NOISE_HOSTS = {"schemas.android.com", "www.w3.org", "w3.org", "schemas.microsoft.com", "xmlpull.org",
               "java.sun.com", "www.apache.org", "apache.org", "json-schema.org", "purl.org",
               "ns.adobe.com", "www.gnu.org", "gnu.org", "opensource.org", "creativecommons.org",
               "developer.android.com", "developer.apple.com", "www.apple.com", "example.com",
               "www.example.com", "localhost", "schemas.xmlsoap.org", "www.mozilla.org",
               "reactjs.org", "react.dev", "fb.me", "github.com", "raw.githubusercontent.com",
               "npmjs.org", "www.npmjs.com", "registry.npmjs.org", "tc39.es", "goo.gl", "jquery.com"}


VALID_HOST = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}|localhost")


def host_of(url: str) -> str:
    """Hostname of a URL, or "" when it isn't a syntactically real host (pseudo-URLs,
    regex fragments, template placeholders)."""
    m = re.match(r"[a-z]+://([^/:?#]+)", url, re.I)
    h = m.group(1).lower() if m else ""
    return h if VALID_HOST.fullmatch(h) else ""


def clean_url(url: str) -> str:
    # Strip trailing punctuation and unbalanced closing brackets. Counts are taken
    # once and updated as we trim, so a match ending in a long run of ")" stays linear.
    opener = {")": "(", "}": "{", "]": "["}
    counts = {c: url.count(c) for c in "(){}[]"}
    end = len(url)
    while end:
        ch = url[end - 1]
        if ch in ".,;:":
            end -= 1
        elif ch in opener and counts[ch] > counts[opener[ch]]:
            counts[ch] -= 1
            end -= 1
        else:
            break
    return url[:end]


# Generic TLDs are rarely the tail of a dotted identifier; ccTLD-like ones (.de,
# .info, .local, .to ...) constantly are ("editor.language.de", minified "a.info").
STRONG_TLDS = {"com", "net", "org", "io", "dev", "app", "co", "ai", "cloud", "gov", "edu"}


def plausible_host(h: str) -> bool:
    labels = h.lower().split(".")
    return labels[0] not in REVERSE_DNS_FIRST and not all(l.isdigit() for l in labels[:-1])


def host_in_context(chunk: str, start: int, end: int, h: str) -> bool:
    """Accept a bare hostname only when it reads like one, not like a dotted identifier."""
    before, after = chunk[max(0, start - 2):start], chunk[end:end + 1]
    url_context = before.endswith("//") or before.endswith("@") or after in (":", "/")
    if url_context:
        return True
    tld = h.rsplit(".", 1)[-1].lower()
    whole = chunk.strip().lower() == h
    first = h.split(".", 1)[0]
    return tld in STRONG_TLDS and (whole or len(first) > 2)


def mask(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:2] + "…" + " (len %d)" % len(secret)
    return "%s…%s (len %d)" % (secret[:4], secret[-4:], len(secret))


class Results:
    def __init__(self):
        self.data = {k: {} for k in ("endpoint", "url", "host", "api_path", "net_lib", "auth_header", "crypto", "secret_ish")}

    def add(self, cat: str, val: str, loc: str) -> None:
        locs = self.data[cat].setdefault(val, [])
        if len(locs) < MAX_LOCS and loc not in locs:
            locs.append(loc)


def scan_text(text: str, rel: str, is_code: bool, res: Results, keep_noise: bool) -> None:
    pending_smali = None
    for lineno, line in enumerate(text.splitlines(), 1):
        loc = "%s:%d" % (rel, lineno)
        # smali Retrofit annotations span lines: the annotation type, then `value = "..."`
        m = SMALI_ANNOT_RE.search(line)
        if m:
            pending_smali = m.group(1)
        elif pending_smali:
            v = SMALI_VALUE_RE.match(line)
            if v:
                res.add("endpoint", "%s %s" % (pending_smali, v.group(1)), loc)
                pending_smali = None
            elif line.strip().startswith(".end annotation"):
                pending_smali = None
        # Each line is scanned whole, once per regex. (Overlapping fixed-size windows
        # over long minified lines reported matches cut at the window edge as extra,
        # truncated URLs and hosts.) Keep every pattern free of quadratic backtracking on
        # multi-MB lines (see the secret_ish JWT note).
        for m in ANNOTATION_RE.finditer(line):
            res.add("endpoint", "%s %s" % (m.group(1), m.group(2)), loc)
        for m in HTTP_ANNOT_RE.finditer(line):
            res.add("endpoint", "%s %s" % (m.group(1).upper(), m.group(2)), loc)
        for m in CLIENT_CALL_RE.finditer(line):
            res.add("endpoint", "%s %s" % (m.group(1).upper(), m.group(2)), loc)
        for m in FETCH_RE.finditer(line):
            res.add("endpoint", "FETCH %s" % m.group(1), loc)
        for m in URL_RE.finditer(line):
            url = clean_url(m.group(0))
            h = host_of(url)
            if keep_noise or h not in NOISE_HOSTS:
                res.add("url", url, loc)
                if h:
                    res.add("host", h, loc)   # hosts taken from URLs are high-precision
        # Hostnames: only inside string literals in code (identifiers and package
        # names produce endless false positives); anywhere in config/text files.
        if is_code:
            chunks = [next(g for g in sm.groups() if g is not None) for sm in STRING_LIT.finditer(line)]
        else:
            chunks = [line]
        for chunk in chunks:
            for hm in HOST_RE.finditer(chunk):
                h = hm.group(1).lower()
                if (plausible_host(h) and host_in_context(chunk, hm.start(1), hm.end(1), h)
                        and (keep_noise or h not in NOISE_HOSTS)):
                    res.add("host", h, loc)
        for cat, pat in PATTERNS.items():
            for pm in pat.finditer(line):
                res.add(cat, pm.group(1), loc)


def _inside(path: str, root_real: str) -> bool:
    real = os.path.realpath(path)
    return real == root_real or real.startswith(root_real.rstrip(os.sep) + os.sep)


def iter_files(root: str, exts, max_bytes: int, skipped: dict):
    """Yield regular files under root. Never follows a symlink out of the scanned tree
    (extracted firmware roots are full of absolute links into the analyst's own /etc,
    /tmp ...) and never opens FIFOs, sockets or device nodes (open().read() on those
    blocks forever or never ends). Skips are tallied in skipped[reason]."""
    if os.path.isfile(root):
        yield root
        return
    root_real = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if exts is not None and ext not in exts:
                continue
            path = os.path.join(dirpath, fn)
            try:
                st = os.lstat(path)
                if stat.S_ISLNK(st.st_mode):
                    if not _inside(path, root_real):
                        skipped["symlink_out_of_tree"].append(path)
                        continue
                    st = os.stat(path)    # in-tree link: judge what it points at
                if not stat.S_ISREG(st.st_mode):
                    skipped["special"].append(path)
                    continue
                if st.st_size > max_bytes:
                    skipped["large"].append(path)
                    continue
            except OSError:
                continue
            yield path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract an app's network/crypto surface from a source tree.")
    ap.add_argument("path", help="directory (e.g. jadx output) or a single file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ext", help="comma-separated extensions to include (default: a built-in text/code set)")
    ap.add_argument("--all-ext", action="store_true", help="scan every file regardless of extension")
    ap.add_argument("--max-bytes", type=int, default=25_000_000, help="skip files larger than this (default 25MB)")
    ap.add_argument("--show-secrets", action="store_true", help="print secret-shaped strings in full (masked by default)")
    ap.add_argument("--keep-noise", action="store_true", help="keep well-known schema/doc/library hosts")
    ap.add_argument("--top", type=int, default=20, help="entries shown per category in the text report (default 20)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print("error: no such path: %s" % args.path, file=sys.stderr)
        return 2
    if args.all_ext:
        exts = None
    elif args.ext:
        exts = {e if e.startswith(".") else "." + e for e in args.ext.lower().split(",")}
    else:
        exts = DEFAULT_EXT

    base = args.path if os.path.isdir(args.path) else (os.path.dirname(args.path) or ".")
    res, n = Results(), 0
    skipped_all = {"large": [], "special": [], "symlink_out_of_tree": []}
    skipped = skipped_all["large"]
    for path in iter_files(args.path, exts, args.max_bytes, skipped_all):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        n += 1
        rel = os.path.relpath(path, base).replace("\\", "/")
        scan_text(text, rel, os.path.splitext(path)[1].lower() in CODE_EXT, res, args.keep_noise)

    findings = res.data
    if not args.show_secrets:
        findings["secret_ish"] = {mask(k): v for k, v in findings["secret_ish"].items()}

    if args.json:
        print(json.dumps({"files_scanned": n, "skipped_large": len(skipped),
                          "skipped_special": len(skipped_all["special"]),
                          "skipped_symlink_out_of_tree": len(skipped_all["symlink_out_of_tree"]),
                          "findings": findings}, indent=2))
        return 0

    titles = {
        "endpoint": "Declared endpoints (annotations / client calls)", "url": "URLs (http/https/ws)",
        "host": "Hostnames in string literals", "api_path": "API path templates",
        "net_lib": "Networking libraries", "auth_header": "Auth / header markers",
        "crypto": "Crypto markers",
        "secret_ish": "Secret-shaped strings (VERIFY — may be false positives%s)" % ("" if args.show_secrets else "; masked"),
    }
    print("=" * 70)
    print("NETWORK/CRYPTO SURFACE  (%d files scanned%s)" % (n, ", %d skipped as too large" % len(skipped) if skipped else ""))
    print("=" * 70)
    any_hits = False
    for cat, title in titles.items():
        hits = findings.get(cat)
        if not hits:
            continue
        any_hits = True
        print("\n[%s]  %d distinct" % (title, len(hits)))
        # Most-referenced first, capped: this output lands in the agent's context,
        # so show the entries that matter and leave the long tail to --json.
        for val in sorted(hits, key=lambda v: (-len(hits[v]), v))[:args.top]:
            locs = ", ".join(hits[val][:3])
            more = "" if len(hits[val]) <= 3 else " (+%d more)" % (len(hits[val]) - 3)
            shown = val if len(val) <= 100 else val[:97] + "..."
            print("  %s\n      %s%s" % (shown, locs, more))
        if len(hits) > args.top:
            print("  ... %d more (full list: --json > endpoints.json, then grep it)" % (len(hits) - args.top))
    if not any_hits:
        print("\nNo network/crypto markers found. If this was a binary, decompile or extract it "
              "first (see the target's references/ playbook), then re-run on the output directory.")
    if skipped:
        print("\nnote: skipped %d file(s) over --max-bytes, e.g. %s" % (len(skipped), skipped[0]))
    if skipped_all["special"]:
        print("note: skipped %d non-regular file(s) (FIFO/socket/device), e.g. %s"
              % (len(skipped_all["special"]), skipped_all["special"][0]))
    if skipped_all["symlink_out_of_tree"]:
        print("note: skipped %d symlink(s) pointing outside the scanned tree, e.g. %s"
              % (len(skipped_all["symlink_out_of_tree"]), skipped_all["symlink_out_of_tree"][0]))
    print("\n" + "-" * 70)
    print("Leads, not conclusions: confirm each against the code or live traffic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
