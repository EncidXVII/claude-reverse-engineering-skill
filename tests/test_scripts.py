#!/usr/bin/env python3
"""Dependency-free test + structure validator for the reverse-engineering skill.

Runs with plain `python tests/test_scripts.py` (no pytest, no third-party deps)
so it works in any CI runner. Exercises the three runnable scripts on synthesized
fixtures and validates the skill's structure and manifests.

Exit code 0 = all passed, 1 = something failed.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "reverse-engineering")
SCRIPTS = os.path.join(SKILL, "scripts")
PY = sys.executable

_failures = []
_passed = 0


def check(name, cond, detail=""):
    global _passed
    if cond:
        _passed += 1
        print("  ok   " + name)
    else:
        _failures.append(name + ((" — " + detail) if detail else ""))
        print("  FAIL " + name + ((" — " + detail) if detail else ""))


def run(args, **kw):
    """Run a bundled script with -I (isolated) and return (rc, stdout+stderr)."""
    p = subprocess.run([PY, "-I"] + args, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# 1. Every bundled .py compiles (covers the PyGhidra/Jython Ghidra script too, which
#    is written to also be valid CPython 3).
# ---------------------------------------------------------------------------
def test_compile():
    print("\n[compile] all bundled scripts byte-compile under this Python")
    import py_compile
    for dirpath, _dirs, files in os.walk(SCRIPTS):
        for fn in files:
            if fn.endswith(".py"):
                path = os.path.join(dirpath, fn)
                try:
                    py_compile.compile(path, doraise=True)
                    check("compile " + os.path.relpath(path, SKILL), True)
                except py_compile.PyCompileError as e:
                    check("compile " + os.path.relpath(path, SKILL), False, str(e))


# ---------------------------------------------------------------------------
# 2. triage.py: detection, routing, and regressions for audited flaws.
# ---------------------------------------------------------------------------
def make_pe(clr=False, extra=b""):
    """Minimal valid PE32+ with one section; optionally a CLR (.NET) data directory."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0x60000000, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108, 16)
    if clr:
        struct.pack_into("<II", opt, 112 + 14 * 8, 0x2000, 0x48)
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIII", sec, 8, 0x1000, 0x1000, 0x200, 0x200)
    body = bytes(dos) + coff + bytes(opt) + bytes(sec)
    return body + b"\x00" * (0x200 - len(body)) + b"\x90" * 0x200 + extra


def tri(triage, path, *extra):
    rc, out = run([triage, path, "--json", "--no-strings"] + list(extra))
    try:
        return rc, json.loads(out)
    except ValueError:
        return rc, {"_raw": out[:300]}


def fp_names(data):
    return [f["name"] for f in data.get("fingerprints", [])]


def test_triage():
    print("\n[triage] detection, routing, regressions")
    triage = os.path.join(SCRIPTS, "triage.py")
    with tempfile.TemporaryDirectory() as d:
        def write(name, blob):
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(blob)
            return p

        elf = write("a.out", b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 3, 183) + b"\x00" * 100)
        rc, data = tri(triage, elf)
        check("ELF -> native-elf", rc == 0 and data.get("route_key") == "native-elf", data.get("route_key"))
        check("ELF arch parsed (AArch64)", data.get("format_details", {}).get("arch") == "AArch64")
        rc, out = run([triage, elf, "--json"])
        check("emits sha256", len(json.loads(out).get("hashes", {}).get("sha256", "")) == 64)

        rc, data = tri(triage, write("native.exe", make_pe()))
        check("PE -> native-pe, x86-64", data.get("route_key") == "native-pe"
              and data.get("format_details", {}).get("arch") == "x86-64", str(data.get("format_details")))
        rc, data = tri(triage, write("managed.dll", make_pe(clr=True)))
        check(".NET detected from CLR header", data.get("route_key") == "dotnet", data.get("route_key"))
        # regression: a non-Electron PE that merely contains "node_modules"/"electron" strings
        rc, data = tri(triage, write("node.exe", make_pe(extra=b"node_modules electron chrome-devtools")))
        check("no false Electron on plain PE", "Electron app" not in fp_names(data), str(fp_names(data)))
        rc, data = tri(triage, write("app.exe", make_pe(extra=b"ELECTRON_RUN_AS_NODE")))
        check("Electron detected from real marker", "Electron app" in fp_names(data), str(fp_names(data)))
        # regression: markers beyond the analysis window must still be found (whole-file scan)
        pyi = write("pyi.exe", make_pe(extra=b"\x00" * 300000 + b"MEI\x0c\x0b\x0a\x0b\x0e"))
        rc, data = tri(triage, pyi, "--max-read", "4096")
        check("PyInstaller cookie found past --max-read", "PyInstaller bundle (Python)" in fp_names(data), str(fp_names(data)))
        # regression: CAFEBABE disambiguation
        rc, data = tri(triage, write("Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 32))
        check("Java .class (not Mach-O fat)", data.get("route_key") == "java-class", data.get("route_key"))
        fat = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + struct.pack(">IIIII", 0x01000007, 3, 4096, 64, 12)
               + struct.pack(">IIIII", 0x0100000c, 0, 8192, 64, 14) + b"\x00" * 32)
        rc, data = tri(triage, write("uni", fat))
        check("fat Mach-O slices", data.get("format_details", {}).get("slices") == ["x86-64", "ARM64"], str(data.get("format_details")))
        # APK + framework fingerprints
        apk = os.path.join(d, "app.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("AndroidManifest.xml", "x")
            z.writestr("classes.dex", "dex\n035\x00")
            z.writestr("lib/arm64-v8a/libflutter.so", "x")
            z.writestr("assets/index.android.bundle", b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f" + b"\x00" * 8)
        rc, data = tri(triage, apk)
        check("APK -> android", data.get("route_key") == "android", data.get("route_key"))
        check("Flutter + Hermes fingerprinted", "Flutter" in fp_names(data)
              and "React Native (Hermes bytecode)" in fp_names(data), str(fp_names(data)))
        # regression: directory mode (install dirs, macOS .app bundles)
        app = os.path.join(d, "Demo.app", "Contents")
        os.makedirs(os.path.join(app, "MacOS"))
        with open(os.path.join(app, "Info.plist"), "w") as f:
            f.write("<plist/>")
        with open(os.path.join(app, "MacOS", "Demo"), "wb") as f:
            f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
        rc, data = tri(triage, os.path.join(d, "Demo.app"))
        markers = [m["name"] for m in data.get("directory", {}).get("app_markers", [])]
        check("directory mode works on .app bundle", rc == 0 and "Apple app bundle" in markers, str(markers))
        # crypto constants: AES S-box inside .text (file 0x210 -> VA 0x1010), SHA-256 K outside any section
        sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
        pe_bytes = make_pe(extra=bytes.fromhex("982f8a4291443771"))
        pe_bytes = pe_bytes[:0x210] + sbox + pe_bytes[0x210 + len(sbox):]
        rc, data = tri(triage, write("crypto.dll", pe_bytes))
        found = {c["constant"]: c["hits"][0] for c in data.get("crypto", [])}
        aes = found.get("AES S-box", {})
        check("crypto: AES S-box with section VA", aes.get("va") == "0x1010" and aes.get("section") == ".text", str(found))
        check("crypto: SHA-256 constants (file offset)", "SHA-256 round constants" in found, str(found))

        # dependency extraction: Go build info (1.18+ inline layout) and Rust crate paths
        def uv(n):
            out = b""
            while n >= 0x80:
                out += bytes([(n & 0x7F) | 0x80])
                n >>= 7
            return out + bytes([n])
        modinfo = (b"\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6"
                   b"path\texample.com/tool\nmod\texample.com/tool\tv1.4.0\th1:abc=\n"
                   b"dep\tgolang.org/x/sys\tv0.18.0\th1:def=\n"
                   b"\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2")
        ver = b"go1.22.3"
        binf = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16 + uv(len(ver)) + ver + uv(len(modinfo)) + modinfo
        gobin = write("gotool", b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 62) + b"\x00" * 200 + binf)
        rc, data = tri(triage, gobin)
        dep = data.get("dependencies", {})
        check("Go: toolchain + main module + deps", dep.get("toolchain") == "go1.22.3"
              and dep.get("main_module") == "example.com/tool v1.4.0"
              and "golang.org/x/sys v0.18.0" in dep.get("packages", []), str(dep))
        rust = write("rusttool.exe", make_pe(extra=(
            b"/rustc/abc123/library/core/src/panicking.rs\x00"
            b"C:\\Users\\dev\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\serde-1.0.197\\src\\de.rs\x00"
            b"/cargo/registry/src/index.crates.io-6f17d22bba15001f/regex-automata-0.4.6/src/meta.rs\x00")))
        rc, data = tri(triage, rust)
        pk = data.get("dependencies", {}).get("packages", [])
        check("Rust: crates from source paths", "serde 1.0.197" in pk and "regex-automata 0.4.6" in pk, str(pk))

        # malformed input must not crash
        for name, blob in (("trunc_pe", b"MZ\x00\x00"), ("trunc_elf", b"\x7fELF"), ("empty", b"")):
            rc, _ = tri(triage, write(name, blob))
            check("no crash on " + name, rc == 0)


# ---------------------------------------------------------------------------
# 3. check_tools.py runs, emits JSON, and finds Ghidra via --ghidra-dir.
# ---------------------------------------------------------------------------
def test_check_tools():
    print("\n[check_tools] runs, JSON, Ghidra detection")
    ct = os.path.join(SCRIPTS, "check_tools.py")
    rc, out = run([ct, "--json"])
    check("check_tools rc=0", rc == 0, out[:200])
    data = json.loads(out)
    check("check_tools has by_task", "by_task" in data and "triage" in data["by_task"])
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "support"))
        rc, out = run([ct, "--json", "--ghidra-dir", d])
        check("Ghidra found via --ghidra-dir", "ghidra" in json.loads(out)["have"])


# ---------------------------------------------------------------------------
# 4. extract_endpoints.py: surface + regressions for audited flaws.
# ---------------------------------------------------------------------------
def test_extract_endpoints():
    print("\n[extract_endpoints] surface + regressions")
    ee = os.path.join(SCRIPTS, "extract_endpoints.py")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "Api.java"), "w") as f:
            f.write("package com.example.app;\nimport android.app.Activity;\nimport java.net.URL;\n")
            f.write('@GET("v2/users/{id}/profile")\n')
            f.write('String u = "https://api.example.io/v1/items/{itemId}";\n')
            f.write("OkHttpClient c; // Authorization: Bearer x\n")
            f.write('Cipher.getInstance("AES/CBC/PKCS5Padding");\n')
            fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"   # assembled at runtime so no key-shaped literal sits in the repo
            f.write('String k = "%s";\n' % fake_key)
        with open(os.path.join(d, "Api.smali"), "w") as f:
            f.write('    .annotation runtime Lretrofit2/http/POST;\n        value = "auth/v1/login"\n    .end annotation\n')
        with open(os.path.join(d, "bundle.min.js"), "w") as f:
            pad = "var a=function(){return 1};" * 2000
            f.write(pad + 'axios.post("/api/v3/orders",x);' + pad)
        rc, out = run([ee, d, "--json"])
        check("extract_endpoints rc=0", rc == 0, out[:200])
        f = json.loads(out)["findings"]
        check("finds url with template intact", "https://api.example.io/v1/items/{itemId}" in f["url"], str(f["url"]))
        check("finds net_lib OkHttp", "OkHttp" in f["net_lib"])
        check("finds crypto AES", "AES" in f["crypto"])
        check("Retrofit annotation endpoint", "GET v2/users/{id}/profile" in f["endpoint"], str(f["endpoint"]))
        check("smali Retrofit annotation", "POST auth/v1/login" in f["endpoint"], str(f["endpoint"]))
        check("endpoint deep in a long minified line", "POST /api/v3/orders" in f["endpoint"], str(f["endpoint"]))
        bad = [h for h in f["host"] if h in ("android.app", "java.net", "com.example.app")]
        check("package names are not reported as hosts", not bad, str(bad))
        check("secrets masked by default", bool(f["secret_ish"]) and fake_key not in json.dumps(f["secret_ish"]))


# ---------------------------------------------------------------------------
# 5. app_inspect.py: Android manifest, Apple bundle, Windows version info, games.
# ---------------------------------------------------------------------------
def build_axml(events):
    """Minimal Android binary-XML writer. events: ("start", tag, [(attr, kind, value)]) / ("end", tag)."""
    strings = []

    def si(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    for ev in events:
        si(ev[1])
        if ev[0] == "start":
            for name, kind, value in ev[2]:
                si(name)
                if kind == "s":
                    si(value)
    offs, sdata = b"", b""
    for s in strings:
        offs += struct.pack("<I", len(sdata))
        sdata += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(sdata) % 4:
        sdata += b"\x00"
    pool = struct.pack("<HHIIIIII", 0x0001, 28, 28 + len(offs) + len(sdata), len(strings), 0, 0,
                       28 + len(offs), 0) + offs + sdata
    body = b""
    for ev in events:
        if ev[0] == "start":
            attrs = b""
            for name, kind, value in ev[2]:
                if kind == "s":
                    attrs += struct.pack("<IIIHBBI", 0xFFFFFFFF, si(name), si(value), 8, 0, 0x03, si(value))
                elif kind == "b":
                    attrs += struct.pack("<IIIHBBI", 0xFFFFFFFF, si(name), 0xFFFFFFFF, 8, 0, 0x12,
                                         0xFFFFFFFF if value else 0)
                else:
                    attrs += struct.pack("<IIIHBBI", 0xFFFFFFFF, si(name), 0xFFFFFFFF, 8, 0, 0x10, value)
            size = 16 + 20 + len(attrs)
            body += struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF)
            body += struct.pack("<IIHHHHHH", 0xFFFFFFFF, si(ev[1]), 20, 20, len(ev[2]), 0, 0, 0) + attrs
        else:
            body += struct.pack("<HHIII", 0x0103, 16, 24, 1, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, si(ev[1]))
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(body)) + pool + body


def test_app_inspect():
    print("\n[app_inspect] platform metadata extraction")
    ai = os.path.join(SCRIPTS, "app_inspect.py")

    def inspect(path):
        rc, out = run([ai, path, "--json"])
        try:
            return rc, json.loads(out)
        except ValueError:
            return rc, {"_raw": out[:300]}

    with tempfile.TemporaryDirectory() as d:
        # Android
        manifest = build_axml([
            ("start", "manifest", [("package", "s", "com.example.demo"), ("versionName", "s", "1.2.3"),
                                   ("versionCode", "i", 42)]),
            ("start", "uses-sdk", [("minSdkVersion", "i", 24), ("targetSdkVersion", "i", 34)]), ("end", "uses-sdk"),
            ("start", "uses-permission", [("name", "s", "android.permission.INTERNET")]), ("end", "uses-permission"),
            ("start", "application", [("debuggable", "b", True), ("allowBackup", "b", False)]),
            ("start", "activity", [("name", "s", ".MainActivity"), ("exported", "b", True)]),
            ("start", "intent-filter", []),
            ("start", "action", [("name", "s", "android.intent.action.MAIN")]), ("end", "action"),
            ("start", "category", [("name", "s", "android.intent.category.LAUNCHER")]), ("end", "category"),
            ("end", "intent-filter"),
            ("start", "intent-filter", []),
            ("start", "data", [("scheme", "s", "demoapp"), ("host", "s", "open")]), ("end", "data"),
            ("end", "intent-filter"),
            ("end", "activity"),
            ("start", "service", [("name", "s", ".SyncService"), ("exported", "b", False)]), ("end", "service"),
            ("start", "receiver", [("name", "s", "com.example.demo.PushReceiver")]),
            ("start", "intent-filter", []), ("end", "intent-filter"),
            ("end", "receiver"),
            ("end", "application"), ("end", "manifest"),
        ])
        apk = os.path.join(d, "demo.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("AndroidManifest.xml", manifest)
            z.writestr("classes.dex", "dex\n035\x00")
            z.writestr("lib/arm64-v8a/libnative.so", "x")
        rc, r = inspect(apk)
        check("android: package/version", r.get("package") == "com.example.demo" and r.get("version") == "1.2.3"
              and r.get("version_code") == 42 and r.get("target_sdk") == 34, str(r)[:200])
        check("android: launcher + permission", r.get("launcher") == "com.example.demo.MainActivity"
              and "android.permission.INTERNET" in r.get("permissions", []), str(r.get("launcher")))
        check("android: deep link", any(l["url"] == "demoapp://open" for l in r.get("deep_links", [])), str(r.get("deep_links")))
        exp = {e["name"]: e["exported"] for e in r.get("exported", [])}
        check("android: exported (explicit + implicit, not false)", exp.get("com.example.demo.MainActivity") is True
              and str(exp.get("com.example.demo.PushReceiver", "")).startswith("implicit")
              and "com.example.demo.SyncService" not in exp, str(exp))
        check("android: debuggable flag", r.get("app", {}).get("debuggable") is True, str(r.get("app")))

        # Apple (IPA): Info.plist, encrypted arm64 slice, entitlements in the code signature
        ents = plistlib.dumps({"application-identifier": "TEAM.com.example.demo", "get-task-allow": True})
        ent_blob = struct.pack(">II", 0xFADE7171, 8 + len(ents)) + ents
        superblob = struct.pack(">III", 0xFADE0CC0, 20 + len(ent_blob), 1) + struct.pack(">II", 5, 20) + ent_blob
        macho = (struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, 40, 0, 0)
                 + struct.pack("<IIIIII", 0x2C, 24, 0, 0, 1, 0)
                 + struct.pack("<IIII", 0x1D, 16, 72, len(superblob)) + superblob)
        info = plistlib.dumps({"CFBundleIdentifier": "com.example.demo", "CFBundleShortVersionString": "2.0",
                               "CFBundleExecutable": "Demo", "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demo"]}],
                               "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                               "NSCameraUsageDescription": "scan codes"}, fmt=plistlib.FMT_BINARY)
        ipa = os.path.join(d, "demo.ipa")
        with zipfile.ZipFile(ipa, "w") as z:
            z.writestr("Payload/Demo.app/Info.plist", info)
            z.writestr("Payload/Demo.app/Demo", macho)
            z.writestr("Payload/Demo.app/Frameworks/Foo.framework/Foo", "x")
        rc, r = inspect(ipa)
        check("apple: plist fields", r.get("bundle_id") == "com.example.demo" and r.get("url_schemes") == ["demo"]
              and r.get("ats_allows_arbitrary_loads") is True
              and "NSCameraUsageDescription" in r.get("privacy_permissions", []), str(r)[:200])
        sl = (r.get("slices") or [{}])[0]
        check("apple: arm64 slice marked encrypted", sl.get("arch") == "arm64" and sl.get("encrypted") is True, str(sl))
        check("apple: entitlements from code signature", (sl.get("entitlements") or {}).get("get-task-allow") is True, str(sl))
        check("apple: frameworks", r.get("frameworks") == ["Foo.framework"], str(r.get("frameworks")))

        # Windows: version resource + manifest execution level
        def vs_string(key, val):
            body = struct.pack("<HHH", 0, len(val) + 1, 1) + key.encode("utf-16-le") + b"\x00\x00"
            body += b"\x00" * (-len(body) % 4) + val.encode("utf-16-le") + b"\x00\x00"
            body += b"\x00" * (-len(body) % 4)
            return struct.pack("<H", len(body)) + body[2:]
        vs = struct.pack("<HHH", 0, 0, 1) + "VS_VERSION_INFO".encode("utf-16-le") + b"\x00\x00"
        vs += b"\x00" * (-len(vs) % 4)
        for k, v in (("CompanyName", "Example Corp"), ("ProductName", "Demo App"), ("FileVersion", "1.2.3.4")):
            vs += vs_string(k, v)
        vs = struct.pack("<H", len(vs)) + vs[2:]
        pe = os.path.join(d, "demo.exe")
        with open(pe, "wb") as f:
            f.write(make_pe(extra=b"\x00" * 4 + vs + b'<requestedExecutionLevel level="asInvoker"/>'))
        rc, r = inspect(pe)
        vi = r.get("version_info", {})
        check("windows: version resource", vi.get("CompanyName") == "Example Corp"
              and vi.get("ProductName") == "Demo App" and vi.get("FileVersion") == "1.2.3.4", str(vi))
        check("windows: execution level + unsigned", r.get("execution_level") == "asInvoker"
              and r.get("signed") is False, str(r)[:200])

        # Games: Unity IL2CPP and Godot
        unity = os.path.join(d, "UnityGame")
        os.makedirs(os.path.join(unity, "Demo_Data", "il2cpp_data", "Metadata"))
        with open(os.path.join(unity, "Demo_Data", "globalgamemanagers"), "wb") as f:
            f.write(b"\x00" * 20 + b"2022.3.10f1" + b"\x00" * 20)
        with open(os.path.join(unity, "GameAssembly.dll"), "wb") as f:
            f.write(b"MZ")
        with open(os.path.join(unity, "Demo_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), "wb") as f:
            f.write(struct.pack("<Ii", 0xFAB11BAF, 29))
        rc, r = inspect(unity)
        check("game: Unity IL2CPP + version + metadata", r.get("engine") == "Unity" and r.get("backend") == "IL2CPP"
              and r.get("version") == "2022.3.10f1" and r.get("il2cpp_metadata_version") == 29, str(r)[:200])
        godot = os.path.join(d, "GodotGame")
        os.makedirs(godot)
        with open(os.path.join(godot, "game.pck"), "wb") as f:
            f.write(b"GDPC" + struct.pack("<IIII", 2, 4, 2, 1))
        rc, r = inspect(godot)
        check("game: Godot version", r.get("engine") == "Godot" and r.get("version") == "4.2.1", str(r)[:200])

        # malformed input must not crash
        bad = os.path.join(d, "bad.apk")
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00garbage")
        rc, r = inspect(bad)
        check("no crash on malformed manifest", rc == 0, str(r)[:200])

# ---------------------------------------------------------------------------
# 6. Structure: SKILL.md frontmatter, referenced paths, manifests.
# ---------------------------------------------------------------------------
def _parse_frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    fm = {}
    # tiny YAML-ish reader good enough for top-level scalar keys we need
    for line in m.group(1).splitlines():
        mm = re.match(r"^([a-zA-Z_-]+):\s*(.*)$", line)
        if mm and mm.group(2) not in (">-", "|", ">", ""):
            fm[mm.group(1)] = mm.group(2).strip()
        elif mm:
            fm.setdefault(mm.group(1), "")
    return fm


def test_structure():
    print("\n[structure] SKILL.md, references, manifests")
    skill_md = os.path.join(SKILL, "SKILL.md")
    check("SKILL.md exists", os.path.isfile(skill_md))
    text = open(skill_md, encoding="utf-8").read()
    fm = _parse_frontmatter(text)
    check("frontmatter present on line 1", fm is not None)
    check("name == reverse-engineering", fm and fm.get("name") == "reverse-engineering", fm and fm.get("name"))
    check("SKILL.md under 500 lines", text.count("\n") + 1 < 500, str(text.count("\n") + 1))

    # description length (spec cap 1024)
    dm = re.search(r"description:\s*>-\n((?:  .*\n)+)", text)
    desc_len = len(re.sub(r"\s+", " ", dm.group(1))) if dm else 0
    check("description within 1024 chars", 0 < desc_len <= 1024, str(desc_len))

    # every markdown-linked relative path resolves
    links = set(re.findall(r"\]\((references/[\w\-]+\.md|assets/[\w\-]+\.md)\)", text))
    missing = [l for l in links if not os.path.isfile(os.path.join(SKILL, l))]
    check("all SKILL.md reference links resolve", not missing, ",".join(missing))

    # every references/*.md is linked from SKILL.md
    on_disk = {"references/" + fn for fn in os.listdir(os.path.join(SKILL, "references")) if fn.endswith(".md")}
    unlinked = on_disk - links
    check("no orphan reference files", not unlinked, ",".join(sorted(unlinked)))

    # script paths named in SKILL.md exist
    spaths = set(re.findall(r"scripts/[\w./\-]+\.py", text))
    smissing = [s for s in spaths if not os.path.isfile(os.path.join(SKILL, s))]
    check("all SKILL.md script paths exist", not smissing, ",".join(smissing))

    # playbooks and scripts named inside the bundled scripts (e.g. triage routes) exist
    dangling = set()
    for dirpath, _dirs, files in os.walk(SCRIPTS):
        for fn in files:
            if fn.endswith(".py"):
                src = open(os.path.join(dirpath, fn), encoding="utf-8").read()
                for ref in re.findall(r"references/[\w\-]+\.md|scripts/[\w/\-]+\.(?:py|java)", src):
                    if not os.path.isfile(os.path.join(SKILL, ref)):
                        dangling.add(ref)
    check("no dangling references inside scripts", not dangling, ",".join(sorted(dangling)))

    # manifests are valid JSON with matching plugin names
    mp = json.load(open(os.path.join(ROOT, ".claude-plugin", "marketplace.json")))
    pj = json.load(open(os.path.join(ROOT, ".claude-plugin", "plugin.json")))
    check("marketplace.json valid + has plugins", bool(mp.get("plugins")))
    check("plugin.json name matches skill", pj.get("name") == "reverse-engineering", pj.get("name"))
    entry_names = {p["name"] for p in mp.get("plugins", [])}
    check("marketplace lists the plugin", "reverse-engineering" in entry_names, ",".join(entry_names))


def main():
    print("Testing reverse-engineering skill at:\n  " + SKILL)
    for t in (test_compile, test_triage, test_check_tools, test_extract_endpoints, test_app_inspect, test_structure):
        t()
    print("\n" + "=" * 60)
    if _failures:
        print("FAILED ({} ok, {} failed):".format(_passed, len(_failures)))
        for f in _failures:
            print("  - " + f)
        return 1
    print("ALL PASSED ({} checks)".format(_passed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
