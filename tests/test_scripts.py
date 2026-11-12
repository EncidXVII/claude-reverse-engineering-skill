#!/usr/bin/env python3
"""Dependency-free test + structure validator for the reverse-engineering skill.

Runs with plain `python tests/test_scripts.py` (no pytest, no third-party deps)
so it works in any CI runner. Exercises the three runnable scripts on synthesized
fixtures and validates the skill's structure and manifests.

Exit code 0 = all passed, 1 = something failed.
"""
from __future__ import annotations

import ast
import json
import os
import plistlib
import random
import re
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "reverse-engineering")
SCRIPTS = os.path.join(SKILL, "scripts")
EVALS = os.path.join(ROOT, "evals")
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


TIMEOUT_RC = 124


def run(args, timeout=120, **kw):
    """Run a bundled script with -I (isolated) and return (rc, stdout+stderr).

    A hang becomes a failure result (rc TIMEOUT_RC) instead of stalling or crashing the suite."""
    try:
        p = subprocess.run([PY, "-I"] + args, capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return TIMEOUT_RC, "TIMEOUT after {}s".format(timeout)
    return p.returncode, p.stdout + p.stderr


def jload(out):
    """Parse script JSON output; on garbage, return a dict that fails checks instead of raising."""
    try:
        data = json.loads(out)
    except ValueError:
        return {"_raw": out[:300]}
    return data if isinstance(data, dict) else {"_raw": out[:300]}


# ---------------------------------------------------------------------------
# 1. Every bundled .py compiles (covers the PyGhidra/Jython Ghidra script too, which
#    is written to also be valid CPython 3).
# ---------------------------------------------------------------------------
def test_compile():
    print("\n[compile] all bundled scripts byte-compile under this Python")
    import py_compile
    # bytecode goes to a temp dir, so no __pycache__ lands in the skill folder
    with tempfile.TemporaryDirectory() as out:
        for dirpath, _dirs, files in os.walk(SCRIPTS):
            for fn in files:
                if fn.endswith(".py"):
                    path = os.path.join(dirpath, fn)
                    try:
                        py_compile.compile(path, cfile=os.path.join(out, fn + "c"), doraise=True)
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
    return rc, jload(out)


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
        check("emits sha256", len(jload(out).get("hashes", {}).get("sha256", "")) == 64)

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
        check("fat Mach-O slices", data.get("format_details", {}).get("slices") == ["x86_64", "arm64"], str(data.get("format_details")))
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


def test_triage_robustness():
    print("\n[triage] special files, symlinks, fat64/arm64e, UPX on ELF")
    triage = os.path.join(SCRIPTS, "triage.py")

    def elf64(body=b""):
        return b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 62) + b"\x00" * 100 + body

    with tempfile.TemporaryDirectory() as d:
        def write(name, blob):
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(blob)
            return p

        # 1.1: FIFOs and out-of-tree symlinks
        if hasattr(os, "mkfifo"):
            fd_dir = os.path.join(d, "fifo_dir")
            os.mkdir(fd_dir)
            with open(os.path.join(fd_dir, "a.out"), "wb") as f:
                f.write(elf64())
            fifo = os.path.join(fd_dir, "pipe")
            os.mkfifo(fifo)
            rc, out = run([triage, fd_dir, "--json", "--no-strings"], timeout=30)
            dd = jload(out).get("directory", {})
            check("triage: FIFO in directory skipped, no hang",
                  rc == 0 and dd.get("skipped_special") == 1 and dd.get("files_scanned") == 1, "rc=%s %s" % (rc, dd))
            rc, out = run([triage, fifo, "--json"], timeout=30)
            check("triage: FIFO as single path exits 2", rc == 2, "rc=%s %s" % (rc, out[-200:]))
        else:
            print("  skip FIFO tests (no os.mkfifo on this platform)")

        if hasattr(os, "symlink"):
            outside = write("host_secret.bin", elf64(b"HOST"))
            ld = os.path.join(d, "link_dir")
            os.mkdir(ld)
            with open(os.path.join(ld, "inside.bin"), "wb") as f:
                f.write(elf64())
            try:
                os.symlink(outside, os.path.join(ld, "escape"))
                os.symlink(os.path.join(ld, "inside.bin"), os.path.join(ld, "internal"))
                made = True
            except (OSError, NotImplementedError):
                made = False
            if made:
                rc, data = tri(triage, ld)
                dd = data.get("directory", {})
                paths = [n.get("path") for n in dd.get("notable_files", [])]
                check("triage: out-of-tree symlink skipped and counted",
                      rc == 0 and dd.get("skipped_symlink_out_of_tree") == 1 and "escape" not in paths
                      and dd.get("files_scanned") == 1, "rc=%s %s" % (rc, dd))
            else:
                print("  skip symlink test (symlinks not permitted here)")

        # 1.5: fat / fat64 / arm64e / lipo step
        fat = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
               + struct.pack(">IIIII", 0x01000007, 3, 4096, 64, 12)
               + struct.pack(">IIIII", 0x0100000c, 0x80000002, 8192, 64, 14) + b"\x00" * 64)
        rc, data = tri(triage, write("uni_arm64e", fat))
        fd = data.get("format_details", {})
        check("triage: arm64e slice (0x80000002) named arm64e", fd.get("slices") == ["x86_64", "arm64e"], str(fd))
        step = (data.get("next_steps") or [""])[0]
        check("triage: lipo step uses a present slice", "lipo -thin x86_64 " in step, step)

        fat64 = (b"\xca\xfe\xba\xbf" + struct.pack(">I", 2)
                 + struct.pack(">IIQQII", 0x0100000c, 0, 1 << 33, 64, 14, 0)
                 + struct.pack(">IIQQII", 0x01000007, 8, 1 << 34, 64, 14, 0) + b"\x00" * 64)
        rc, data = tri(triage, write("uni64", fat64))
        fd = data.get("format_details", {})
        check("triage: fat64 parsed (32-byte fat_arch_64)", rc == 0 and data.get("route_key") == "macho-fat"
              and fd.get("slices") == ["arm64", "x86_64h"], str(data)[:300])

        # an unnamed subtype is shown but never used for lipo -thin
        odd = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
               + struct.pack(">IIIII", 0x0100000c, 0x8000000c, 4096, 64, 14)
               + struct.pack(">IIIII", 0x0100000c, 0x80000002, 8192, 64, 14) + b"\x00" * 64)
        rc, data = tri(triage, write("uni_odd", odd))
        step = (data.get("next_steps") or [""])[0]
        check("triage: lipo step skips slices lipo cannot name", "lipo -thin arm64e " in step, step)

        rc, data = tri(triage, write("short_cafe", b"\xca\xfe\xba\xbe"))
        check("triage: 4-byte CAFEBABE routes to unknown with note", rc == 0 and data.get("route_key") == "unknown"
              and any("truncated header" in n for n in data.get("notes", [])), str(data.get("route_key")))

        rc, data = tri(triage, sys.executable)
        check("triage: smoke test on sys.executable", rc == 0 and bool(data.get("route_key")), "rc=%s" % rc)

        # 1.6: UPX on ELF, and no bare-UPX! false positive
        rnd = random.Random(1234)
        noise = bytes(rnd.getrandbits(8) for _ in range(200 * 1024))
        upx = elf64(b"\x00" * 100 + b"UPX!" + b"\x00" * 16 + noise
                    + b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $\n")
        rc, data = tri(triage, write("upx_elf.bin", upx))
        check("triage: UPX ELF gets packer hint", "UPX-packed" in fp_names(data), str(fp_names(data)))
        check("triage: high-entropy native file gets likely-packed note",
              any("likely packed" in n for n in data.get("notes", [])), str(data.get("notes")))

        info_only = elf64(b"\x00" * 8192 + b"$Info: This file is packed with the UPX executable packer $"
                          + b"\x00" * 8192)
        rc, data = tri(triage, write("upx_info_elf.bin", info_only))
        check("triage: UPX $Info string anywhere gives packer hint", "UPX-packed" in fp_names(data),
              str(fp_names(data)))

        plain = elf64(b"\x00" * 8192 + b"some code UPX! not a header" + b"\x00" * 8192)
        rc, data = tri(triage, write("plain_elf.bin", plain))
        check("triage: bare UPX! mid-file gives no packer hint", rc == 0 and "UPX-packed" not in fp_names(data)
              and not any("likely packed" in n for n in data.get("notes", [])), str(fp_names(data)))


# ---------------------------------------------------------------------------
# 3. check_tools.py runs, emits JSON, and finds Ghidra via --ghidra-dir.
# ---------------------------------------------------------------------------
def test_check_tools():
    print("\n[check_tools] runs, JSON, Ghidra detection")
    ct = os.path.join(SCRIPTS, "check_tools.py")
    rc, out = run([ct, "--json"])
    check("check_tools rc=0", rc == 0, out[:200])
    data = jload(out)
    check("check_tools has by_task", "by_task" in data and "triage" in data["by_task"])
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "support"))
        open(os.path.join(d, "support", "analyzeHeadless"), "w").close()
        rc, out = run([ct, "--json", "--ghidra-dir", d])
        check("Ghidra found via --ghidra-dir", "ghidra" in jload(out).get("have", []))


def test_check_tools_discovery():
    print("\n[check_tools] Ghidra discovery, qemu-user aliases, JDK row")
    ct = os.path.join(SCRIPTS, "check_tools.py")
    with tempfile.TemporaryDirectory() as d:
        # a PATH we control, so real tools on this machine don't leak into the results
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir)
        env = dict(os.environ, PATH=bindir)

        def ct_run(args):
            return run([ct] + args, env=env, timeout=60)

        def ct_json(args):
            rc, out = ct_run(["--json"] + args)
            return rc, jload(out)

        def mkfile(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(path, 0o755)

        # 1.7: a real-looking install (support/analyzeHeadless) is found and its path reported
        g = os.path.join(d, "ghidra_11.4_PUBLIC")
        mkfile(os.path.join(g, "support", "analyzeHeadless"))
        rc, data = ct_json(["--ghidra-dir", g])
        check("ct: Ghidra found via --ghidra-dir", rc == 0 and "ghidra" in data.get("have", []), str(data)[:300])
        check("ct: analyzeHeadless present", "analyzeHeadless" in data.get("have", []))
        check("ct: JSON ghidra_dir is the folder", data.get("ghidra_dir") == g, str(data.get("ghidra_dir")))
        check("ct: pyghidraRun absent without support/pyghidraRun", "pyghidraRun" not in data.get("have", []))
        rc, out = ct_run(["--ghidra-dir", g])
        check("ct: text prints 'ghidra dir: <path>'", rc == 0 and ("ghidra dir: " + g) in out, out[-400:])
        mkfile(os.path.join(g, "support", "pyghidraRun"))
        rc, data = ct_json(["--ghidra-dir", g])
        check("ct: pyghidraRun present with support/pyghidraRun", "pyghidraRun" in data.get("have", []))

        # 1.7: an empty support/ folder is not Ghidra
        e = os.path.join(d, "ghidra_empty")
        os.makedirs(os.path.join(e, "support"))
        rc, data = ct_json(["--ghidra-dir", e])
        check("ct: empty support/ is not Ghidra", rc == 0 and data.get("ghidra_dir") != e, str(data.get("ghidra_dir")))

        # 1.7: version sort picks 11.10 over 11.9 (and over 9.2)
        vroot = os.path.join(d, "versions")
        for ver in ("9.2", "11.9", "11.10", "11.4.2"):
            mkfile(os.path.join(vroot, "ghidra_%s_PUBLIC" % ver, "support", "analyzeHeadless"))
        sys.dont_write_bytecode = True        # no __pycache__ in the skill folder
        sys.path.insert(0, SCRIPTS)
        try:
            import check_tools as c
            real_which, c.shutil.which = c.shutil.which, lambda _n: None   # ignore a real ghidraRun
            try:
                picked = c.ghidra_dir(patterns=[os.path.join(vroot, "ghidra_*")])
            finally:
                c.shutil.which = real_which
        finally:
            sys.path.remove(SCRIPTS)
        check("ct: version sort picks 11.10 over 11.9",
              picked == os.path.join(vroot, "ghidra_11.10_PUBLIC"), str(picked))

        if os.name == "nt":
            print("  skip qemu/JDK PATH tests on Windows")
            return
        # 1.8: qemu-user is detected through a per-arch binary name
        rc, data = ct_json([])
        check("ct: qemu-user missing with nothing on PATH", rc == 0 and "qemu-user" in data.get("missing", []))
        mkfile(os.path.join(bindir, "qemu-aarch64-static"))
        rc, data = ct_json([])
        check("ct: qemu-user found via qemu-aarch64-static", "qemu-user" in data.get("have", []), str(data)[:300])
        check("ct: no stale qemu-user-static entry",
              "qemu-user-static" not in data.get("have", []) + data.get("missing", []))

        # 1.8: no JDK on PATH -> jdk row says not found, java/android note it, javap stub not counted
        mkfile(os.path.join(bindir, "javap"))   # a stub, like macOS /usr/bin/javap, with no java
        rc, out = ct_run([])
        check("ct: JDK row renamed to 'jdk'", rc == 0 and "  jdk        not found" in out, out[-500:])
        check("ct: java/android tasks note a missing JDK", out.count("needs a JDK") >= 2, out[-500:])
        rc, data = ct_json([])
        check("ct: java_major null without java", rc == 0 and data.get("java_major") is None)


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
        f = jload(out).get("findings", {})
        f = {k: f.get(k, []) for k in ("url", "net_lib", "crypto", "endpoint", "host", "secret_ish")}
        check("finds url with template intact", "https://api.example.io/v1/items/{itemId}" in f["url"], str(f["url"]))
        check("finds net_lib OkHttp", "OkHttp" in f["net_lib"])
        check("finds crypto AES", "AES" in f["crypto"])
        check("Retrofit annotation endpoint", "GET v2/users/{id}/profile" in f["endpoint"], str(f["endpoint"]))
        check("smali Retrofit annotation", "POST auth/v1/login" in f["endpoint"], str(f["endpoint"]))
        check("endpoint deep in a long minified line", "POST /api/v3/orders" in f["endpoint"], str(f["endpoint"]))
        bad = [h for h in f["host"] if h in ("android.app", "java.net", "com.example.app")]
        check("package names are not reported as hosts", not bad, str(bad))
        check("secrets masked by default", bool(f["secret_ish"]) and fake_key not in json.dumps(f["secret_ish"]))


def test_extract_endpoints_robustness():
    print("\n[extract_endpoints] FIFOs, symlinks, long lines")
    ee = os.path.join(SCRIPTS, "extract_endpoints.py")

    def scan(path, timeout):
        rc, out = run([ee, path, "--json"], timeout=timeout)
        j = jload(out)
        j.setdefault("findings", {})
        for k in ("url", "host"):
            j["findings"].setdefault(k, [])
        return rc, j, out

    with tempfile.TemporaryDirectory() as tmp:
        # 1.1: a FIFO inside the tree is skipped (and counted), not opened
        if hasattr(os, "mkfifo"):
            d = os.path.join(tmp, "fifo_tree")
            os.makedirs(os.path.join(d, "etc"))
            os.mkfifo(os.path.join(d, "etc", "pipe.conf"))
            with open(os.path.join(d, "etc", "app.conf"), "w") as f:
                f.write("server=https://fw.fifo-test-host.com/api\n")
            rc, j, out = scan(d, 30)
            check("ee: FIFO in tree does not hang", rc != TIMEOUT_RC, out[:200])
            check("ee: FIFO skipped, counted, rest scanned", rc == 0 and j.get("skipped_special") == 1
                  and "https://fw.fifo-test-host.com/api" in j["findings"]["url"], out[:300])
        else:
            print("  skip FIFO test (no os.mkfifo on this platform)")

        # 1.1: a symlink leaving the scanned root is not followed; an in-tree one is
        if hasattr(os, "symlink"):
            outside = os.path.join(tmp, "outside.txt")
            with open(outside, "w") as f:
                f.write("https://leak.outside-host-x.com/a\n")
            d = os.path.join(tmp, "fw")
            os.makedirs(os.path.join(d, "etc"))
            with open(os.path.join(d, "etc", "real.conf"), "w") as f:
                f.write("https://inside.tree-host-x.com/b\n")
            try:
                os.symlink(outside, os.path.join(d, "etc", "resolv.conf"))
                os.symlink(os.path.join(d, "etc", "real.conf"), os.path.join(d, "etc", "alias.conf"))
                made = True
            except (OSError, NotImplementedError):
                made = False   # e.g. Windows without symlink privilege
            if made:
                rc, j, out = scan(d, 60)
                check("ee: out-of-tree symlink not followed (and counted)", rc == 0
                      and "https://leak.outside-host-x.com/a" not in j["findings"]["url"]
                      and "https://inside.tree-host-x.com/b" in j["findings"]["url"]
                      and j.get("skipped_symlink_out_of_tree") == 1, out[:300])
            else:
                print("  skip symlink test (cannot create symlinks here)")

        # 1.4: a URL straddling the old 4000-char window boundary is reported once, whole
        d = os.path.join(tmp, "window")
        os.makedirs(d)
        with open(os.path.join(d, "a.js"), "w") as f:
            f.write("x" * 4280 + ' "https://api.realhost-example.com/v1" ' + "y" * 5000 + "\n")
        rc, j, out = scan(d, 60)
        urls = [u for u in j["findings"]["url"] if "realh" in u]
        hosts = [h for h in j["findings"]["host"] if "realh" in h]
        check("ee: window-boundary URL reported once, untruncated",
              rc == 0 and urls == ["https://api.realhost-example.com/v1"], repr(urls) + " " + out[:200])
        check("ee: window-boundary host not truncated", hosts == ["api.realhost-example.com"], repr(hosts))

        # 1.4: a ~5 MB single minified-like line (plus hostile runs) stays fast
        d = os.path.join(tmp, "long")
        os.makedirs(d)
        pieces = ['function a%d(b,c){return b.c+c.d*%d}e.get("/api/v1/i/%d");'
                  'fetch("https://svc%d.example-api.com/v2/x?q=%d");t.p="editor.language.de";'
                  % (i, i, i, i % 50, i) for i in range(40000)]
        body = "".join(pieces)
        with open(os.path.join(d, "bundle.min.js"), "w") as f:
            f.write(body[:4500000] + ("eyJ" + "a" * 20 + "-") * 20000 + "a." * 50000 + "\n")
        t0 = time.time()
        rc, j, out = scan(d, 60)
        dt = time.time() - t0
        check("ee: 5 MB single line under 10 s", rc == 0 and dt < 10, "rc=%s %.1fs" % (rc, dt))
        check("ee: long line still finds URLs", "https://svc7.example-api.com/v2/x?q=7" in j["findings"]["url"])

        # 1.4: unterminated string literals full of escaped quotes stay linear (each \" used to
        # restart a scan to the end of the line) and literals after them are still found
        d = os.path.join(tmp, "quotes")
        os.makedirs(d)
        with open(os.path.join(d, "q.js"), "w") as f:
            f.write('var s="' + '\\"a' * 350000 + "\n" + "var t='" + "\\'" * 500000 + "\n"
                    + 'var u="' + '\\"' * 500000 + "\n" + 'h="cdn.quote-test-host.com";\n')
        t0 = time.time()
        rc, j, out = scan(d, 60)
        dt = time.time() - t0
        check("ee: 1 MB lines of escaped quotes under 10 s", rc == 0 and dt < 10, "rc=%s %.1fs" % (rc, dt))
        check("ee: literal after escaped-quote lines still scanned",
              "cdn.quote-test-host.com" in j["findings"]["host"], repr(list(j["findings"]["host"])[:5]))


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
        return rc, jload(out)

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


def test_app_inspect_robustness():
    print("\n[app_inspect] hostile AXML, size caps, partial reports, fat64, FIFOs")
    with tempfile.TemporaryDirectory() as tmp:
        ai = os.path.join(SCRIPTS, "app_inspect.py")

        def inspect(path, timeout=30):
            t0 = time.time()
            rc, out = run([ai, path, "--json"], timeout=timeout)
            return rc, jload(out), time.time() - t0

        def thin(cpu, sub, cmds=b"", ncmds=0):
            return struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, sub, 2, ncmds, len(cmds), 0, 0) + cmds

        # 1.2: string pool claims 50,000,000 strings inside a 28-byte chunk (the 172-byte hang.apk shape)
        pool = struct.pack("<HHIIIIII", 0x0001, 28, 28, 50000000, 0, 0, 28, 0)
        axml = struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool
        hang = os.path.join(tmp, "hang.apk")
        with zipfile.ZipFile(hang, "w") as z:
            z.writestr("AndroidManifest.xml", axml)
        rc, r, dt = inspect(hang, timeout=10)
        check("app_inspect: oversized AXML string count finishes fast", rc == 0 and dt < 10
              and r.get("platform") == "android", "rc=%s dt=%.1f %s" % (rc, dt, str(r)[:200]))

        # same, plus an element whose attribute count overruns its chunk, then a resource
        # map (last chunk) that declares 4000 bytes but has only 8: both must be clamped
        elem = struct.pack("<HHIII", 0x0102, 16, 36, 1, 0xFFFFFFFF) + struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20,
                                                                                  65535, 0, 0, 0)
        resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4000) + struct.pack("<II", 0x01010003, 0x01010006)
        axml2 = struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(elem) + len(resmap)) + pool + elem + resmap
        hang2 = os.path.join(tmp, "hang2.apk")
        with zipfile.ZipFile(hang2, "w") as z:
            z.writestr("AndroidManifest.xml", axml2)
        rc, r, dt = inspect(hang2, timeout=10)
        check("app_inspect: oversized resmap/attribute counts are clamped", rc == 0 and "_raw" not in r
              and "manifest parse failed" not in str(r.get("error", "")), "rc=%s %s" % (rc, str(r)[:200]))

        # 1.2: 8000 32-byte string pools, each with one UTF-16 string claiming ~2^31 chars that
        # points at its own header (stringsStart=12 lands on styles=0xFFFFFFFF, read as a
        # 0x7FFFFFFF-char length). The decode budget is global, so memory stays bounded.
        chunk = struct.pack("<HHIIIIII", 0x0001, 28, 32, 1, 0xFFFFFFFF, 0, 12, 0) + struct.pack("<I", 0)
        selfref = b"".join([chunk] * 8000)
        axml3 = struct.pack("<HHI", 0x0003, 8, 8 + len(selfref)) + selfref
        bomb = os.path.join(tmp, "selfref.apk")
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", axml3)
        code = "\n".join([
            "import resource, sys, zipfile",
            "sys.path.insert(0, sys.argv[1])",
            "import app_inspect",
            "d = zipfile.ZipFile(sys.argv[2]).read('AndroidManifest.xml')",
            "try:",
            "    for _ in app_inspect.parse_axml(d): pass",
            "except Exception: pass",
            "rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss",
            "print(rss >> 20 if sys.platform == 'darwin' else rss >> 10)"])
        try:
            import resource  # noqa: F401  (POSIX only)
            have_resource = True
        except ImportError:
            have_resource = False
        if have_resource:
            rc, out = run(["-B", "-c", code, SCRIPTS, bomb], timeout=30)
            last = (out.strip().splitlines() or [""])[-1]
            mb = int(last) if rc == 0 and last.isdigit() else -1
            check("app_inspect: self-referencing string pools stay under 200 MB", rc == 0 and 0 <= mb < 200,
                  "rc=%s rss=%sMB %s" % (rc, mb, out[-200:]))
        else:
            print("  skip AXML memory test (no resource module on this platform)")

        # 1.3: a manifest declaring 17 MB (deflates to a few KB) is refused by size, not decompressed
        big = os.path.join(tmp, "bomb.apk")
        with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * (17 << 20))
            z.writestr("classes.dex", "dex\n035\x00")
        rc, r, dt = inspect(big, timeout=30)
        check("app_inspect: oversized zip member flagged, not read", rc == 0 and "limit" in str(r.get("manifest_error"))
              and r.get("dex_files") == 1, str(r)[:300])

        big_ipa = os.path.join(tmp, "bomb.ipa")
        with zipfile.ZipFile(big_ipa, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("Payload/A.app/Info.plist", b"\x00" * (17 << 20))
        rc, r, dt = inspect(big_ipa, timeout=30)
        check("app_inspect: oversized Info.plist flagged, not parsed", rc == 0 and "limit" in str(r.get("error")),
              str(r)[:300])

        # 1.3: malformed plist value types keep the rest of the report
        info = plistlib.dumps({"CFBundleIdentifier": "com.good.app", "CFBundleShortVersionString": "9.9",
                               "CFBundleExecutable": "Good", "CFBundleURLTypes": ["oops", {"CFBundleURLSchemes": "x"},
                                                                                 {"CFBundleURLSchemes": ["good", 7]}],
                               "NSAppTransportSecurity": "yes", "UIBackgroundModes": 5})
        # truncated code-signature superblob (claims 5 entries in 12 bytes), then a load command cut short:
        # LC_ENCRYPTION_INFO_64 whose body is missing because the file ends right after its 8-byte header
        sig = struct.pack(">III", 0xFADE0CC0, 12, 5)
        cs = struct.pack("<IIII", 0x1D, 16, 32 + 16 + 8 + 8, len(sig))
        cut = struct.pack("<II", 0x2C, 24)
        macho = thin(0x0100000C, 0, cs + cut, ncmds=2) + b"\x00" * 8 + sig
        macho = macho[:32 + 16 + 8 + 4]                       # 4 bytes into the missing body
        bad = os.path.join(tmp, "bad.ipa")
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("Payload/Good.app/Info.plist", info)
            z.writestr("Payload/Good.app/Good", macho)
        rc, r, dt = inspect(bad)
        check("app_inspect: malformed plist values give a partial report", rc == 0 and r.get("bundle_id") == "com.good.app"
              and r.get("version") == "9.9" and r.get("url_schemes") == ["good"] and r.get("background_modes") == []
              and "Traceback" not in str(r), str(r)[:300])
        sl = (r.get("slices") or [{}])[0]
        check("app_inspect: truncated Mach-O load command recorded as *_error", sl.get("arch") == "arm64"
              and any(k.endswith("_error") for k in sl), str(sl))

        root_plist = os.path.join(tmp, "list.ipa")
        with zipfile.ZipFile(root_plist, "w") as z:
            z.writestr("Payload/L.app/Info.plist", plistlib.dumps(["not", "a", "dict"]))
        rc, r, dt = inspect(root_plist)
        check("app_inspect: non-dict Info.plist root is a clean error", rc == 0 and "dictionary" in str(r.get("error")),
              str(r)[:300])

        # 1.5: arm64e (subtype 0x80000002) named arm64e; fat64 (0xCAFEBABF) recognized
        s1, s2 = thin(0x01000007, 3), thin(0x0100000C, 0x80000002)
        fat = struct.pack(">II", 0xCAFEBABE, 2) + struct.pack(">IIIII", 0x01000007, 3, 4096, len(s1), 12) \
            + struct.pack(">IIIII", 0x0100000C, 0x80000002, 8192, len(s2), 14)
        fat = fat.ljust(4096, b"\x00") + s1.ljust(4096, b"\x00") + s2
        p = os.path.join(tmp, "fat.bin")
        with open(p, "wb") as f:
            f.write(fat)
        rc, r, dt = inspect(p)
        archs = [s.get("arch") for s in r.get("slices", [])]
        check("app_inspect: fat arm64e slice named arm64e", archs == ["x86_64", "arm64e"], str(r)[:300])
        fat64 = struct.pack(">II", 0xCAFEBABF, 2) + struct.pack(">IIQQII", 0x01000007, 8, 4096, len(s1), 12, 0) \
            + struct.pack(">IIQQII", 0x0100000C, 0x80000002, 8192, len(s2), 14, 0)
        fat64 = fat64.ljust(4096, b"\x00") + thin(0x01000007, 8).ljust(4096, b"\x00") + s2
        p = os.path.join(tmp, "fat64.bin")
        with open(p, "wb") as f:
            f.write(fat64)
        rc, r, dt = inspect(p)
        archs = [s.get("arch") for s in r.get("slices", [])]
        check("app_inspect: fat64 (0xCAFEBABF) parsed, x86_64h named", archs == ["x86_64h", "arm64e"], str(r)[:300])

        # 1.1: FIFOs and out-of-tree symlinks in walked folders (POSIX only)
        if not hasattr(os, "mkfifo"):
            print("  skip FIFO/symlink tests (no os.mkfifo on this platform)")
            return
        unity = os.path.join(tmp, "FifoGame")
        os.makedirs(os.path.join(unity, "Demo_Data"))
        os.mkfifo(os.path.join(unity, "Demo_Data", "globalgamemanagers"))
        with open(os.path.join(unity, "GameAssembly.dll"), "wb") as f:
            f.write(b"MZ")
        rc, r, dt = inspect(unity, timeout=10)
        check("app_inspect: FIFO in game folder skipped, no hang", rc == 0 and r.get("engine") == "Unity"
              and r.get("skipped_special", 0) >= 1, "rc=%s %s" % (rc, str(r)[:200]))

        fifo = os.path.join(tmp, "pipe.apk")
        os.mkfifo(fifo)
        rc, r, dt = inspect(fifo, timeout=10)
        check("app_inspect: FIFO as the target exits 2, no hang", rc == 2, "rc=%s %s" % (rc, str(r)[:200]))

        outside = os.path.join(tmp, "outside.pck")
        with open(outside, "wb") as f:
            f.write(b"GDPC" + struct.pack("<IIII", 2, 4, 2, 1))
        leak = os.path.join(tmp, "LeakGame")
        os.makedirs(leak)
        os.symlink(outside, os.path.join(leak, "game.pck"))
        rc, r, dt = inspect(leak, timeout=10)
        check("app_inspect: out-of-tree symlink not followed", rc == 0 and "_raw" not in r
              and r.get("engine") != "Godot", str(r)[:200])


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
    with open(os.path.join(ROOT, ".claude-plugin", "marketplace.json"), encoding="utf-8") as fh:
        mp = jload(fh.read())
    with open(os.path.join(ROOT, ".claude-plugin", "plugin.json"), encoding="utf-8") as fh:
        pj = jload(fh.read())
    check("marketplace.json valid + has plugins", bool(mp.get("plugins")))
    check("plugin.json name matches skill", pj.get("name") == "reverse-engineering", pj.get("name"))
    entry_names = {p["name"] for p in mp.get("plugins", [])}
    check("marketplace lists the plugin", "reverse-engineering" in entry_names, ",".join(entry_names))


# ---------------------------------------------------------------------------
# 7. Repo metadata: eval schemas, version agreement, Ghidra export sync.
# ---------------------------------------------------------------------------
def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), ""
    except (OSError, ValueError) as e:
        return None, str(e)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# 1. Trigger evals: bare array of {query, should_trigger}, no dupes, balanced.
# ---------------------------------------------------------------------------
def test_trigger_evals():
    print("\n[evals] trigger-evals.json schema and balance")
    data, err = load_json(os.path.join(EVALS, "trigger-evals.json"))
    check("trigger-evals.json is valid JSON", data is not None, err)
    if data is None:
        return
    check("trigger-evals is a JSON array", isinstance(data, list))
    if not isinstance(data, list):
        return
    bad = [i for i, e in enumerate(data)
           if not (isinstance(e, dict) and set(e) == {"query", "should_trigger"}
                   and isinstance(e["query"], str) and e["query"].strip()
                   and isinstance(e["should_trigger"], bool))]
    check("every entry is exactly {query: str, should_trigger: bool}", not bad, "indexes %s" % bad)
    if bad:
        return
    queries = [e["query"].strip().lower() for e in data]
    dupes = sorted(set(q for q in queries if queries.count(q) > 1))
    check("no duplicate queries", not dupes, "; ".join(dupes))
    pos = sum(e["should_trigger"] for e in data)
    neg = len(data) - pos
    check("at least 16 positives and 16 negatives", pos >= 16 and neg >= 16, "%d/%d" % (pos, neg))
    check("positives and negatives within 25% of each other",
          min(pos, neg) * 4 >= max(pos, neg) * 3, "%d/%d" % (pos, neg))


# ---------------------------------------------------------------------------
# 2. Behavioral evals: skill-creator evals.json format plus a category.
# ---------------------------------------------------------------------------
def test_behavior_evals():
    print("\n[evals] evals.json schema")
    data, err = load_json(os.path.join(EVALS, "evals.json"))
    check("evals.json is valid JSON", data is not None, err)
    if not isinstance(data, dict):
        return
    check("skill_name matches the skill", data.get("skill_name") == "reverse-engineering", str(data.get("skill_name")))
    cases = data.get("evals")
    check("evals is a non-empty list", isinstance(cases, list) and bool(cases))
    if not isinstance(cases, list):
        return
    categories = {"proceed", "decline-part", "ambiguous"}
    ids = []
    for i, c in enumerate(cases):
        label = "case %s" % (c.get("id", i) if isinstance(c, dict) else i)
        ok = (isinstance(c, dict) and isinstance(c.get("id"), int)
              and isinstance(c.get("prompt"), str) and c["prompt"].strip()
              and isinstance(c.get("expected_output"), str) and c["expected_output"].strip()
              and isinstance(c.get("files", []), list)
              and isinstance(c.get("expectations"), list) and c["expectations"]
              and all(isinstance(x, str) and x.strip() for x in c["expectations"])
              and c.get("category") in categories)
        check(label + " has id, prompt, expected_output, expectations, category", ok)
        if isinstance(c, dict):
            ids.append(c.get("id"))
            for f in c.get("files") or []:
                ext = os.path.splitext(str(f))[1].lower()
                check(label + " ships no prebuilt binary (" + str(f) + ")",
                      ext not in (".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".apk", ".o"))
                check(label + " file exists (" + str(f) + ")", os.path.isfile(os.path.join(ROOT, str(f))))
    check("eval ids are unique", len(ids) == len(set(ids)), str(ids))
    seen = {c.get("category") for c in cases if isinstance(c, dict)}
    check("covers proceed, decline-part and ambiguous", categories <= seen, ",".join(sorted(map(str, seen))))


# ---------------------------------------------------------------------------
# 3. plugin.json, marketplace.json and SKILL.md agree on one semver version.
# ---------------------------------------------------------------------------
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def skill_md_version():
    text = read(os.path.join(SKILL, "SKILL.md"))
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    # metadata:\n  version: "x" (quoted or bare), without needing PyYAML
    v = re.search(r"^metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+version:\s*[\"']?([^\"'\s]+)", m.group(1) + "\n", re.M)
    return v.group(1) if v else None


def test_versions():
    print("\n[meta] version consistency")
    pj, err = load_json(os.path.join(ROOT, ".claude-plugin", "plugin.json"))
    check("plugin.json is valid JSON", pj is not None, err)
    versions = {"plugin.json": (pj or {}).get("version"), "SKILL.md metadata.version": skill_md_version()}
    mp, _ = load_json(os.path.join(ROOT, ".claude-plugin", "marketplace.json"))
    if "version" in (mp or {}).get("metadata", {}):
        versions["marketplace.json metadata.version"] = mp["metadata"]["version"]
    for p in (mp or {}).get("plugins", []):
        if p.get("name") == "reverse-engineering" and "version" in p:
            versions["marketplace.json plugin entry"] = p["version"]
    for where, v in versions.items():
        check(where + " is semver", isinstance(v, str) and bool(SEMVER.fullmatch(v)), repr(v))
    distinct = set(versions.values())
    check("all versions match", len(distinct) == 1,
          ", ".join("%s=%s" % kv for kv in versions.items()))


# ---------------------------------------------------------------------------
# 4. The Java and Python Ghidra exports flag the same API families.
# ---------------------------------------------------------------------------
def java_api_groups(src):
    m = re.search(r"API_GROUPS\s*=\s*\{(.*?)\n\s*\};", src, re.S)
    if not m:
        return None
    lit = r'"((?:[^"\\]|\\.)*)"'

    def unescape(s):
        return re.sub(r"\\(.)", lambda e: {"n": "\n", "t": "\t"}.get(e.group(1), e.group(1)), s)

    return [(unescape(a), unescape(b))
            for a, b in re.findall(r"\{\s*" + lit + r"\s*,\s*" + lit + r"\s*\}", m.group(1))]


def python_api_groups(src):
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "API_GROUPS"):
            return [tuple(g) for g in ast.literal_eval(node.value)]
    return None


def test_api_groups_sync():
    print("\n[ghidra] DecompileExport.java and decompile_export.py API_GROUPS match")
    gdir = os.path.join(SKILL, "scripts", "ghidra")
    java = java_api_groups(read(os.path.join(gdir, "DecompileExport.java")))
    py = python_api_groups(read(os.path.join(gdir, "decompile_export.py")))
    check("found API_GROUPS in the Java export", bool(java))
    check("found API_GROUPS in the Python export", bool(py))
    if java and py:
        diff = [("java", g) for g in java if g not in py] + [("python", g) for g in py if g not in java]
        check("API_GROUPS identical (names, regexes, order)", java == py,
              "; ".join("only in %s: %s" % (side, g[0]) for side, g in diff) or "order differs")


def main():
    print("Testing reverse-engineering skill at:\n  " + SKILL)
    for t in (test_compile, test_triage, test_triage_robustness, test_check_tools, test_check_tools_discovery,
              test_extract_endpoints, test_extract_endpoints_robustness, test_app_inspect,
              test_app_inspect_robustness, test_structure, test_trigger_evals,
              test_behavior_evals, test_versions, test_api_groups_sync):
        try:
            t()
        except Exception:
            # one crashing group records a failure; the remaining groups still run
            check(t.__name__ + " crashed", False, traceback.format_exc().strip().splitlines()[-1])
            traceback.print_exc()
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
