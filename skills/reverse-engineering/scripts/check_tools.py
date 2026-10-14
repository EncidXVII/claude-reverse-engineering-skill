#!/usr/bin/env python3
"""Report which reverse-engineering tools are installed, grouped by task.

The point is to pick tools that actually exist on this machine before planning a
workflow, and to show the one install command for anything missing that the
current target needs. Stdlib only; runs anywhere Python 3.8+ does.

Run it WITHOUT `-I` so it can see user-site Python packages (pip install --user);
it never touches a sample, so isolation isn't needed here.

Usage:
    python check_tools.py                 # full report, grouped by task
    python check_tools.py --task android  # only the tools for one task
    python check_tools.py --json          # machine-readable
    python check_tools.py --have          # just the names that are present

Tasks: triage, native, debug, android, ios, dotnet, java, js, wasm, dynamic,
       network, firmware, emulation, diffing, malware
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

# Python libraries agents commonly script against: (import name, pip name, use).
PY_LIBS = [
    ("frida", "frida", "Frida bindings for scripted hooking"),
    ("capstone", "capstone", "disassemble byte ranges from Python"),
    ("lief", "lief", "parse/modify ELF, PE, Mach-O"),
    ("pefile", "pefile", "PE parsing"),
    ("elftools", "pyelftools", "ELF/DWARF parsing"),
    ("rzpipe", "rzpipe", "script rizin from Python"),
    ("r2pipe", "r2pipe", "script radare2 from Python"),
    ("angr", "angr", "symbolic execution"),
    ("unicorn", "unicorn", "CPU emulation of code snippets"),
    ("z3", "z3-solver", "constraint solving (CTF input checks)"),
    ("yara", "yara-python", "YARA rule matching"),
]


def java_version():
    """Return the JVM's major version (e.g. 21), or None when java isn't usable."""
    if not shutil.which("java"):
        return None
    try:
        p = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r'version "(\d+)(?:\.(\d+))?', p.stderr + p.stdout)
    if not m:
        return None
    major = int(m.group(1))
    return int(m.group(2)) if major == 1 and m.group(2) else major  # "1.8" -> 8


def python_libs():
    return {name: importlib.util.find_spec(name) is not None for name, _pip, _use in PY_LIBS}

# name -> (what it's for, install hint). Hints are deliberately short; versions
# move, so when one looks wrong, check the tool's site rather than trusting this.
TOOLS = {
    # triage / basics
    "file":      ("triage: identify file type", "apt install file / preinstalled on macOS/Linux"),
    "xxd":       ("triage: hex dump", "part of vim-common / busybox"),
    "strings":   ("triage: extract strings", "binutils (apt install binutils)"),
    # native disassembly / decompilation
    "ghidra":    ("native: decompiler+disassembler (GUI)", "download from github.com/NationalSecurityAgency/ghidra (needs JDK 21)"),
    "analyzeHeadless": ("native: Ghidra headless (scripting/batch)", "ships in Ghidra support/ ; add it to PATH"),
    "pyghidraRun": ("native: Ghidra with CPython 3 (PyGhidra)", "ships in Ghidra 12+ ; run once to install the Python module"),
    "rizin":     ("native: CLI disasm engine (scriptable)", "apt install rizin / brew install rizin"),
    "r2":        ("native: radare2 CLI", "github.com/radareorg/radare2 (sys/install.sh)"),
    "cutter":    ("native: rizin GUI", "download from cutter.re"),
    "objdump":   ("native: disassemble (binutils)", "apt install binutils"),
    "readelf":   ("native: ELF headers/sections", "apt install binutils"),
    "nm":        ("native: symbol table", "apt install binutils"),
    "c++filt":   ("native: demangle C++ names", "apt install binutils"),
    "dumpbin":   ("native: PE headers/imports (MSVC)", "ships with Visual Studio / Build Tools"),
    "otool":     ("native/macho: headers, libs, disasm", "Xcode command line tools"),
    "lipo":      ("native/macho: split fat binaries", "Xcode command line tools"),
    # debuggers
    "gdb":       ("debug: Linux debugger (add GEF/pwndbg)", "apt install gdb ; then install GEF or pwndbg"),
    "lldb":      ("debug: LLVM debugger (macOS/Linux)", "Xcode CLT / apt install lldb"),
    "x64dbg":    ("debug: Windows user-mode debugger", "download from x64dbg.com"),
    "windbg":    ("debug: Windows kernel/crash dumps", "Windows SDK / Store"),
    # android
    "jadx":      ("android/java: DEX/JAR -> Java (CLI)", "brew install jadx / github.com/skylot/jadx"),
    "jadx-gui":  ("android/java: DEX/JAR -> Java (GUI)", "github.com/skylot/jadx releases"),
    "apktool":   ("android: decode resources + smali", "brew install apktool / apktool.org"),
    "baksmali":  ("android: DEX -> smali", "github.com/google/smali"),
    "bundletool": ("android: AAB -> installable APKs", "github.com/google/bundletool"),
    "adb":       ("android: device bridge (dynamic)", "Android platform-tools"),
    # ios / apple
    "class-dump": ("ios: Obj-C class/method headers", "github.com/nygard/class-dump (or a maintained fork)"),
    "plutil":    ("ios: inspect Info.plist", "preinstalled on macOS"),
    "codesign":  ("ios: entitlements / signature", "preinstalled on macOS"),
    # .NET
    "ilspycmd":  (".net: decompile to C# (CLI)", "dotnet tool install -g ilspycmd"),
    "dotnet":    (".net: SDK (ildasm/monodis helpers)", "dotnet.microsoft.com"),
    "monodis":   (".net: Mono IL disassembler", "apt install mono-devel"),
    # java
    "cfr":       ("java: decompiler", "download cfr.jar from benf.org/other/cfr"),
    "procyon":   ("java: decompiler", "github.com/mstrobel/procyon"),
    "javap":     ("java: official bytecode disassembler", "ships with the JDK"),
    # js / wasm
    "node":      ("js: run/inspect bundles, npx tools", "nodejs.org"),
    "npx":       ("js: run @electron/asar, prettier, etc.", "ships with Node.js"),
    "wasm2wat":  ("wasm: bytecode -> text (wabt)", "apt install wabt / brew install wabt"),
    "wasm-objdump": ("wasm: sections/imports/exports", "apt install wabt"),
    "wasm-decompile": ("wasm: higher-level pseudocode", "apt install wabt"),
    # dynamic instrumentation
    "frida":     ("dynamic: hook native/Android/iOS (CLI)", "pip install frida-tools"),
    "frida-trace": ("dynamic: auto-hook matching functions", "pip install frida-tools"),
    "objection": ("dynamic: Frida recipes for mobile", "pip install objection"),
    "strace":    ("dynamic: trace syscalls (Linux)", "apt install strace"),
    "ltrace":    ("dynamic: trace library calls (Linux)", "apt install ltrace"),
    "dtruss":    ("dynamic: trace syscalls (macOS)", "preinstalled (needs SIP considerations)"),
    # network
    "mitmproxy": ("network: TLS intercepting proxy (scriptable)", "pip install mitmproxy"),
    "mitmweb":   ("network: mitmproxy web UI", "pip install mitmproxy"),
    "wireshark": ("network: packet capture/analysis", "wireshark.org"),
    "tshark":    ("network: Wireshark CLI", "apt install tshark"),
    "grpcurl":   ("network: call/enumerate gRPC", "github.com/fullstorydev/grpcurl"),
    "curl":      ("network: replay requests", "preinstalled nearly everywhere"),
    # firmware
    "binwalk":   ("firmware: carve/extract (v3 = Rust)", "apt install binwalk3 / cargo install binwalk"),
    "unblob":    ("firmware: robust extractor", "pip install unblob (needs extractors)"),
    "unsquashfs": ("firmware: extract SquashFS", "apt install squashfs-tools"),
    "7z":        ("firmware/archives: many formats", "apt install p7zip-full"),
    # emulation / symbolic
    "qemu-user-static": ("emulation: run foreign-arch binaries", "apt install qemu-user-static"),
    "qemu-system-arm": ("emulation: boot ARM firmware", "apt install qemu-system-arm"),
    # diffing
    "rz-diff":   ("diffing: binary diff (rizin)", "ships with rizin"),
    "radiff2":   ("diffing: binary diff (radare2)", "ships with radare2"),
    "bindiff":   ("diffing: function-level diff (with Ghidra/IDA)", "github.com/google/bindiff releases"),
    # malware analysis (defensive)
    "capa":      ("malware: capabilities mapped to ATT&CK", "github.com/mandiant/capa releases (or pip install flare-capa)"),
    "floss":     ("malware: obfuscated/stack string recovery", "github.com/mandiant/flare-floss releases"),
    "yara":      ("malware: rule-based matching", "apt/brew install yara"),
    "diec":      ("malware: packer/compiler identification (Detect It Easy)", "github.com/horsicq/Detect-It-Easy releases"),
    "olevba":    ("malware: Office macro extraction (oletools)", "pip install oletools"),
}

TASKS = {
    "triage":    ["file", "xxd", "strings"],
    "native":    ["ghidra", "analyzeHeadless", "pyghidraRun", "rizin", "r2",
                  "cutter", "objdump", "readelf", "nm", "c++filt", "dumpbin", "otool", "lipo"],
    "debug":     ["gdb", "lldb", "x64dbg", "windbg"],
    "android":   ["jadx", "jadx-gui", "apktool", "baksmali", "bundletool", "adb"],
    "ios":       ["class-dump", "plutil", "codesign", "otool", "lipo"],
    "dotnet":    ["ilspycmd", "dotnet", "monodis"],
    "java":      ["jadx", "cfr", "procyon", "javap"],
    "js":        ["node", "npx"],
    "wasm":      ["wasm2wat", "wasm-objdump", "wasm-decompile"],
    "dynamic":   ["frida", "frida-trace", "objection", "strace", "ltrace", "dtruss"],
    "network":   ["mitmproxy", "mitmweb", "wireshark", "tshark", "grpcurl", "curl"],
    "firmware":  ["binwalk", "unblob", "unsquashfs", "7z"],
    "emulation": ["qemu-user-static", "qemu-system-arm"],
    "diffing":   ["rz-diff", "radiff2", "bindiff"],
    "malware":   ["capa", "floss", "yara", "diec", "olevba"],
}


GHIDRA_GLOBS = ("C:/ghidra*", "C:/Program Files/ghidra*", "C:/tools/ghidra*", "~/ghidra*",
                "~/tools/ghidra*", "/opt/ghidra*", "/usr/share/ghidra*", "/Applications/ghidra*")


def ghidra_dir(explicit=None):
    """Ghidra isn't put on PATH by its installer: use --ghidra-dir, else common install folders.

    Deliberately reads no environment variables; pass --ghidra-dir for a custom location.
    """
    candidates = [explicit] if explicit else []
    for pattern in GHIDRA_GLOBS:
        candidates += sorted(glob.glob(os.path.expanduser(pattern)), reverse=True)
    for d in candidates:
        if d and os.path.isdir(os.path.join(d, "support")):
            return d
    return None


GHIDRA_FOUND = None   # set from main() so present() can use the --ghidra-dir result


def present(name: str) -> bool:
    if name in ("ghidra", "analyzeHeadless", "pyghidraRun") and GHIDRA_FOUND:
        return True
    # Also probe a couple of common Windows aliases.
    if shutil.which(name) or (name == "ghidra" and shutil.which("ghidraRun")):
        return True
    if os.name == "nt":
        for alt in (name + ".exe", name + ".bat", name + ".cmd"):
            if shutil.which(alt):
                return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Report installed reverse-engineering tools.")
    ap.add_argument("--task", choices=sorted(TASKS), help="only show one task group")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--have", action="store_true", help="print only installed tool names")
    ap.add_argument("--verbose", action="store_true", help="every task in detail, with install hints")
    ap.add_argument("--ghidra-dir", help="Ghidra install folder, if not in a standard location")
    args = ap.parse_args(argv)

    global GHIDRA_FOUND
    GHIDRA_FOUND = ghidra_dir(args.ghidra_dir)

    status = {name: present(name) for name in TOOLS}

    if args.have:
        for name in sorted(n for n, ok in status.items() if ok):
            print(name)
        return 0

    tasks = {args.task: TASKS[args.task]} if args.task else TASKS

    jver = java_version()
    libs = python_libs()

    if args.json:
        out = {
            "have": sorted(n for n, ok in status.items() if ok),
            "missing": sorted(n for n, ok in status.items() if not ok),
            "by_task": {t: {n: status.get(n, False) for n in names} for t, names in tasks.items()},
            "java_major": jver,
            "python_libs": libs,
        }
        print(json.dumps(out, indent=2))
        return 0

    have_count = sum(1 for ok in status.values() if ok)
    print("REVERSE-ENGINEERING TOOLBOX  ({} of {} known tools present)".format(have_count, len(TOOLS)))

    # Default: one compact line per task. Install hints only when asked
    # (--task/--verbose), because this runs every session and its output stays in
    # the agent's context.
    if not args.task and not args.verbose:
        for task, names in tasks.items():
            have = [n for n in names if status.get(n)]
            miss = [n for n in names if not status.get(n)]
            print("  {:<10} have: {:<34} missing: {}".format(
                task, ", ".join(have) or "-", ", ".join(miss) or "-"))
        libs_have = [n for n, ok in libs.items() if ok]
        print("  {:<10} {}".format("java", "JDK %d" % jver if jver else "not found")
              + ("  (Ghidra 12 needs 21+)" if jver and jver < 21 else ""))
        print("  {:<10} have: {}".format("py-libs", ", ".join(libs_have) or "-"))
        print("Install commands for one target type: check_tools.py --task <name>  (all: --verbose)")
        return 0

    for task, names in tasks.items():
        shown = [n for n in names if n in TOOLS]
        present_here = [n for n in shown if status.get(n)]
        print("\n[{}]  {}/{} present".format(task, len(present_here), len(shown)))
        for n in shown:
            mark = "OK  " if status.get(n) else "--  "
            purpose, hint = TOOLS[n]
            line = "  {}{:<16} {}".format(mark, n, purpose)
            if not status.get(n):
                line += "\n        install: {}".format(hint)
            print(line)
    if args.verbose:
        print("\n[java]  " + ("JDK %d" % jver if jver else "not found"))
        if jver and jver < 21:
            print("        note: Ghidra 12 needs JDK 21+; jadx/apktool run on older JDKs")
        print("\n[python libraries]  %d/%d importable" % (sum(libs.values()), len(libs)))
        for name, pip_name, use in PY_LIBS:
            mark = "OK  " if libs[name] else "--  "
            line = "  {}{:<16} {}".format(mark, name, use)
            if not libs[name]:
                line += "\n        install: pip install {}".format(pip_name)
            print(line)
    print("\n" + "-" * 70)
    print("Tip: install only what the current target needs, not everything.")
    if not any(status.values()):
        print("Nothing detected. A free baseline: Ghidra, rizin, Frida, jadx, "
              "ilspycmd, mitmproxy, binwalk, Python 3. See references/tools.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
