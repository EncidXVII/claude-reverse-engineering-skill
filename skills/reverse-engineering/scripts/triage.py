#!/usr/bin/env python3
"""Triage an unknown artifact (file or directory) before choosing RE tools.

One pass that answers "what is this and where do I start?":
  - file type from magic bytes (not the extension, which lies)
  - header facts: PE (arch, DLL/EXE, subsystem, sections, real .NET check via the
    CLR header), ELF (class, endianness, arch, type), Mach-O (arch, fat slices),
    Java .class vs Mach-O fat disambiguation
  - framework / packer / installer fingerprints (Electron, Go, Rust, PyInstaller,
    Node SEA, .NET single-file, UPX, NSIS, Inno Setup, Flutter, React Native,
    Unity, Xamarin/MAUI, Qt, ...)
  - hashes, overall + per-section entropy (packing/encryption hint)
  - printable strings (ASCII + UTF-16LE) with interesting ones surfaced
  - container contents for ZIP-based formats (APK/AAB/IPA/JAR/MSIX/extensions)
  - directory mode: summarize an install dir, an extracted archive, or a macOS
    .app bundle and point at the files worth analyzing first
  - a "Suggested next steps" line that routes to the right SKILL reference

Stdlib only (Python 3.8+). It only reads bytes and never executes the artifact.
When the artifact lives in an untrusted directory, run with -I:

    python -I triage.py /path/to/sample
    python -I triage.py /path/to/App.app          # directory mode
    python -I triage.py sample --json             # machine-readable
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import os
import re
import stat
import struct
import sys
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Magic-byte signatures, checked at offset 0 in order (more specific first).
# (signature, label, route key)
# ---------------------------------------------------------------------------
SIGNATURES = [
    (b"\x7fELF", "ELF executable/shared object", "native-elf"),
    (b"MZ", "PE (Windows .exe/.dll/.sys)", "native-pe"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (big-endian)", "macho"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (big-endian)", "macho"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit", "macho"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit", "macho"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary or Java class", "cafebabe"),
    (b"\xca\xfe\xba\xbf", "Mach-O fat binary (64-bit offsets)", "cafebabe"),
    (b"dex\n", "Android DEX bytecode", "android"),
    (b"Cr24", "Chrome extension (CRX)", "zip"),
    (b"PK\x03\x04", "ZIP container", "zip"),
    (b"PK\x05\x06", "ZIP (empty archive)", "zip"),
    (b"\x1f\x8b", "gzip compressed", "compressed"),
    (b"BZh", "bzip2 compressed", "compressed"),
    (b"\xfd7zXZ\x00", "xz compressed", "compressed"),
    (b"\x28\xb5\x2f\xfd", "zstandard compressed", "compressed"),
    (b"\x04\x22\x4d\x18", "lz4 frame compressed", "compressed"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "archive"),
    (b"Rar!\x1a\x07", "RAR archive", "archive"),
    (b"!<arch>\n", "ar archive (.deb package or static library)", "archive"),
    (b"\xed\xab\xee\xdb", "RPM package", "archive"),
    (b"\x00asm", "WebAssembly module (.wasm)", "wasm"),
    (b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f", "Hermes bytecode (React Native)", "frameworks"),
    (b"\x27\x05\x19\x56", "U-Boot legacy uImage (firmware)", "firmware"),
    (b"\xd0\x0d\xfe\xed", "Flattened device tree / FIT image (firmware)", "firmware"),
    (b"UBI#", "UBI firmware volume", "firmware"),
    (b"hsqs", "SquashFS filesystem (little-endian)", "firmware"),
    (b"sqsh", "SquashFS filesystem (big-endian)", "firmware"),
    (b"\x85\x19", "JFFS2 filesystem (little-endian)", "firmware"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound file (MSI installer or legacy Office doc)", "ole"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "resource"),
    (b"\xff\xd8\xff", "JPEG image", "resource"),
    (b"GIF8", "GIF image", "resource"),
    (b"%PDF", "PDF document", "resource"),
    (b"SQLite format 3\x00", "SQLite database", "resource"),
    (b"bplist00", "binary property list (Apple)", "resource"),
]

ROUTES = {
    "native-elf": "references/native-binaries.md — `rz-bin -I` / `readelf -h`, then decompile headless with scripts/ghidra/DecompileExport.java (SKILL.md step 6)",
    "native-pe": "references/native-binaries.md — `rz-bin -I` / `rz-bin -i` (imports), then decompile headless with scripts/ghidra/DecompileExport.java (SKILL.md step 6)",
    "macho": "references/ios.md (Apple) + references/native-binaries.md — `otool -l` / `rz-bin -I`, then Ghidra",
    "macho-fat": "Fat Mach-O — thin one slice first (`lipo -thin arm64 in -output out`), then references/ios.md",
    "java-class": "references/managed-bytecode.md (Java) — `javap -p -c`, or `jadx -d out/ <file>` / CFR",
    "dotnet": "references/managed-bytecode.md (.NET) — `ilspycmd <file> -o out/` (or -p for a project)",
    "android": "references/android.md — `jadx -d out/ <apk>` then scripts/extract_endpoints.py out/; `apktool d` for resources",
    "ios": "references/ios.md — unzip, find Payload/*.app, check LC_ENCRYPTION_INFO, then analyze the Mach-O",
    "java": "references/managed-bytecode.md (Java) — `jadx -d out/ <jar>` or CFR, then grep/extract_endpoints",
    "asar": "references/js-electron-wasm.md — `npx @electron/asar extract app.asar out/`, then read the JS",
    "wasm": "references/js-electron-wasm.md — `wasm2wat`, `wasm-objdump -x`, `wasm-decompile`",
    "compressed": "Decompress a copy into a fresh dir (gunzip/xz -d/zstd -d), then re-triage the output",
    "archive": "Extract into a fresh empty dir (7z x / tar -xf / ar x), then triage the directory",
    "firmware": "references/firmware-embedded.md — `binwalk` scan, then extract with binwalk -e / unblob into a fresh dir",
    "ole": "OLE2: an .msi installer (extract with `msiextract`/`lessmsi`/`7z x`) or a legacy Office doc (`olevba` for macros)",
    "frameworks": "references/frameworks-packagers.md — find the framework's code container (hint below) and use its decompiler",
    "installer": "references/frameworks-packagers.md (installers) — extract a copy WITHOUT running it into a fresh dir, then triage that dir",
    "browser-ext": "references/js-electron-wasm.md — a browser extension: read manifest.json, then the background/content scripts",
    "windows-pkg": "references/frameworks-packagers.md — MSIX/APPX: unzip into a fresh dir, read AppxManifest.xml, triage the dir",
    "python": "references/frameworks-packagers.md (Python) — extract the archive, then decompile .pyc with a version-matched tool",
    "office": "OOXML document — if it has vbaProject.bin, inspect macros with `olevba` (oletools); treat as untrusted",
    "zip": "ZIP container — `unzip -l`, then route by contents (APK -> android, IPA -> ios, JAR -> java, .asar -> js-electron-wasm)",
    "resource": "A data/resource file, not code. Inspect with a format-specific tool; it may be embedded in a larger target",
    "directory": "See the per-file routing above; start with the largest executable or the app's code container",
    "unknown": "references/workflow.md — unknown format. Use entropy + strings + `binwalk` to find embedded structure",
}

# Binary fingerprints: (label, route-or-None, hint, any-of marker tuples).
# Each entry matches if ALL bytes in any one of its marker tuples are present.
FINGERPRINTS = [
    ("Electron app", "asar",
     "app code lives in resources/app.asar beside the executable — extract and read the JS",
     [(b"ELECTRON_RUN_AS_NODE",), (b"electron.asar", b"Electron")]),
    ("Node.js single-executable app (SEA)", "frameworks",
     "the app's JS is an embedded blob (NODE_SEA_BLOB resource/section) — carve it and read the JS",
     [(b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:1",)]),
    ("Node.js packaged with pkg", "frameworks",
     "a virtual filesystem payload is appended to the launcher — carve it rather than disassembling node",
     [(b"PAYLOAD_POSITION", b"PAYLOAD_SIZE")]),
    ("PyInstaller bundle (Python)", "python",
     "extract with pyinstxtractor(-ng), then decompile the .pyc with a version-matched decompiler",
     [(b"MEI\x0c\x0b\x0a\x0b\x0e",), (b"_MEIPASS", b"pyi-")]),
    ("Nuitka-compiled Python", "frameworks",
     "Python compiled to C — analyze as native code; constants and module names still leak in strings",
     [(b"NUITKA_ONEFILE_PARENT",), (b"__nuitka_",)]),
    ("Go binary", None,
     "Ghidra 11+ recovers Go symbols/types; GoReSym also extracts function names and build info",
     [(b"Go build ID: \"",), (b"\xff Go buildinf:",)]),
    ("Rust binary", None,
     "demangle names (rustfilt), expect heavy inlining; panic strings leak source paths",
     [(b"/rustc/",)]),
    ("GraalVM native image (Java compiled ahead-of-time)", None,
     "Java compiled to native — no bytecode to decompile; analyze as native, class names survive in strings",
     [(b"com.oracle.svm",)]),
    ("Qt application", None,
     "QML/resources are compiled into the binary (.qrc); signal/slot names survive in strings",
     [(b"Qt6Core",), (b"Qt5Core",), (b"QtCore.framework",)]),
    ("Unity player", "frameworks",
     "game code is in *_Data/Managed (Mono) or GameAssembly + global-metadata.dat (IL2CPP)",
     [(b"UnityPlayer",)]),
    ("Delphi / C++Builder", None,
     "use IDR or Ghidra Delphi scripts to recover class/RTTI names",
     [(b"Borland\\Delphi",), (b"Embarcadero", b"TObject")]),
    ("AutoIt compiled script", "frameworks",
     "the AutoIt script is embedded as a resource — extract it rather than disassembling the interpreter",
     [(b"AU3!EA06",)]),
    ("NSIS installer", "installer",
     "extract with `7z x` (never run it to unpack)",
     [(b"Nullsoft Install System",), (b"NullsoftInst",)]),
    ("Inno Setup installer", "installer",
     "extract with `innoextract` (never run it to unpack)",
     [(b"Inno Setup Setup Data",)]),
    ("InstallShield installer", "installer",
     "try `7z x`; InstallShield cabinets may need unshield",
     [(b"InstallShield",)]),
    ("Godot engine game", "frameworks",
     "the game pack (.pck) holds scripts/assets; GDRE Tools can recover GDScript",
     [(b"GDPC", b"Godot Engine")]),
]

# .NET single-file bundle: apphosts carry an 8-byte header-offset placeholder
# followed by this 32-byte signature; the offset is non-zero only when bundled.
DOTNET_BUNDLE_SIG = bytes([
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
])

PE_MACHINES = {0x14c: "x86", 0x8664: "x86-64", 0xaa64: "ARM64", 0xa641: "ARM64EC",
               0x1c0: "ARM", 0x1c4: "ARM Thumb-2", 0x200: "IA-64", 0x5064: "RISC-V 64"}
PE_SUBSYSTEMS = {1: "native (driver)", 2: "Windows GUI", 3: "Windows console", 9: "Windows CE",
                 10: "EFI application", 11: "EFI boot driver", 12: "EFI runtime driver", 14: "Xbox"}
ELF_MACHINES = {2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM",
                43: "SPARC V9", 62: "x86-64", 83: "AVR", 94: "Xtensa", 105: "MSP430",
                183: "AArch64", 243: "RISC-V", 247: "eBPF", 258: "LoongArch"}
ELF_TYPES = {1: "relocatable object", 2: "executable", 3: "shared object / PIE executable", 4: "core dump"}
MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000c: "ARM64",
              0x0200000c: "ARM64_32", 18: "PowerPC", 0x01000012: "PowerPC64"}
# lipo-style names for fat slices: cputype -> (base name, {cpusubtype & 0x00FFFFFF: name}).
# The high byte of cpusubtype carries capability bits (e.g. arm64e pointer-auth ABI version).
LIPO_ARCHS = {7: ("i386", {}), 0x01000007: ("x86_64", {3: "x86_64", 8: "x86_64h"}),
              12: ("arm", {5: "armv4t", 6: "armv6", 7: "armv5", 9: "armv7", 11: "armv7s", 12: "armv7k",
                           14: "armv6m", 15: "armv7m", 16: "armv7em"}),
              0x0100000c: ("arm64", {0: "arm64", 1: "arm64v8", 2: "arm64e"}),
              0x0200000c: ("arm64_32", {0: "arm64_32", 1: "arm64_32"}),
              18: ("ppc", {}), 0x01000012: ("ppc64", {})}
MACHO_FILETYPES = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 9: "dylib stub", 0xb: "kext bundle"}

# (regex, category, prefilter). The prefilter is a cheap literal a string must
# contain before the regex runs on it — patterns like the email one backtrack
# across long strings, so skipping strings that can't match is a large speedup.
INTERESTING_PATTERNS = [
    (re.compile(rb"https?://[^\s\"'<>)\]\\]{4,}"), "url", b"://"),
    (re.compile(rb"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"), "ipv4", b"."),
    (re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}"), "email", b"@"),
    (re.compile(rb"-----BEGIN [A-Z ]+-----"), "pem-key/cert", b"-----BEGIN"),
    (re.compile(rb"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b|AKIA[0-9A-Z]{16}"), "secret-ish", None),
    (re.compile(rb"(?:/usr/|/bin/|/etc/|/data/data/|C:\\\\|\\\\Windows\\\\|\\\\Program Files)"), "path", None),
    (re.compile(rb"(?:GCC: \(|clang version|rustc |go1\.\d+|Microsoft \(R\)|\.NETFramework|\.NETCoreApp|mono)"), "toolchain", None),
    (re.compile(rb"(?:CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|URLDownloadToFile|WinHttpOpen|"
                rb"InternetOpen|RegSetValueEx|CryptEncrypt|BCryptEncrypt|IsDebuggerPresent|ptrace|dlopen|execve|"
                rb"LoadLibrary|GetProcAddress)"), "api-of-interest", None),
]

MAX_STRINGS_SHOWN = 15


@dataclass
class TriageResult:
    path: str
    kind: str = "file"
    size_bytes: int = 0
    file_label: str = "unknown"
    route_key: str = "unknown"
    format_details: dict = field(default_factory=dict)
    sections: list = field(default_factory=list)
    fingerprints: list = field(default_factory=list)
    dependencies: dict = field(default_factory=dict)
    crypto: list = field(default_factory=list)
    hashes: dict = field(default_factory=dict)
    entropy: float = 0.0
    entropy_note: str = ""
    container: dict = field(default_factory=dict)
    directory: dict = field(default_factory=dict)
    interesting: dict = field(default_factory=dict)
    sample_strings: list = field(default_factory=list)
    next_steps: list = field(default_factory=list)
    notes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def shannon_entropy(buf: bytes, cap: int = 8 * 1024 * 1024) -> float:
    """Shannon entropy in bits/byte. Large buffers are sampled evenly (C-speed Counter)."""
    n = len(buf)
    if n == 0:
        return 0.0
    if n > cap:
        slices, step = 128, n // 128
        width = cap // slices
        buf = b"".join(buf[i * step:i * step + width] for i in range(slices))
        n = len(buf)
    ent = 0.0
    for c in Counter(buf).values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)


def entropy_note(ent: float) -> str:
    if ent >= 7.5:
        return "very high — likely packed, encrypted, or compressed"
    if ent >= 6.8:
        return "high — compressed data or packed/encrypted regions"
    if ent >= 5.0:
        return "moderate — typical of native code with data"
    return "low — plaintext, structured data, or lots of padding"


def _hashers():
    out = {}
    for name in ("md5", "sha1", "sha256"):
        try:  # FIPS builds refuse md5/sha1 unless flagged as non-security use
            out[name] = hashlib.new(name, usedforsecurity=False)
        except TypeError:  # Python < 3.9
            out[name] = hashlib.new(name)
        except ValueError:
            continue
    return out


def u16(data, off, e="<"):
    return struct.unpack_from(e + "H", data, off)[0]


def u32(data, off, e="<"):
    return struct.unpack_from(e + "I", data, off)[0]


def detect_magic(head: bytes):
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar archive", "archive"
    for sig, label, key in SIGNATURES:
        if head.startswith(sig):
            return label, key
    if head[:2] == b"#!":
        line = head.split(b"\n", 1)[0].decode("latin-1", "replace")
        return "script with shebang: " + line[:60], "resource"
    return "unknown (no known magic bytes)", "unknown"


# ---------------------------------------------------------------------------
# format parsers (all bounds-checked; malformed input yields notes, not crashes)
# ---------------------------------------------------------------------------
UPX_HINT = "decompress a copy with `upx -d -o unpacked.bin <file>`, then triage that"
UPX_INFO = b"$Info: This file is packed with the UPX"
NATIVE_ROUTES = ("native-pe", "native-elf", "macho", "macho-fat", "dotnet")


def upx_marker_near_ends(path: str, data: bytes, size: int) -> bool:
    """UPX! only in the first or last 4 KiB (where UPX puts its headers), never anywhere in the file."""
    if b"UPX!" in data[:4096]:
        return True
    try:
        with open(path, "rb") as f:
            f.seek(max(0, size - 4096))
            return b"UPX!" in f.read(4096)
    except OSError:
        return False


def parse_pe(data: bytes, r: TriageResult) -> None:
    try:
        e_lfanew = u32(data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            r.notes.append("MZ header but no PE signature (DOS stub or truncated file)")
            return
        machine, nsec, tstamp = struct.unpack_from("<HHI", data, e_lfanew + 4)
        opt_size, chars = struct.unpack_from("<HH", data, e_lfanew + 20)
        opt = e_lfanew + 24
        pe32plus = u16(data, opt) == 0x20B
        subsystem = u16(data, opt + 68)
        n_rva = u32(data, opt + (108 if pe32plus else 92))
        dd = opt + (112 if pe32plus else 96)
        clr_rva = clr_size = 0
        if n_rva > 14:
            clr_rva, clr_size = struct.unpack_from("<II", data, dd + 14 * 8)
        if n_rva > 4:   # certificate table (file offset, size): lets crypto scan skip the code signature
            r._cert_range = struct.unpack_from("<II", data, dd + 4 * 8)
        r._image_base = struct.unpack_from("<Q", data, opt + 24)[0] if pe32plus else u32(data, opt + 28)
        sec_off = opt + opt_size
        for i in range(min(nsec, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
            sec = {"name": name, "virtual_size": vsize, "raw_size": rsize, "vaddr": vaddr, "raw_ptr": rptr}
            if rsize and rptr + rsize <= len(data):
                sec["entropy"] = shannon_entropy(data[rptr:rptr + rsize])
            r.sections.append(sec)
    except struct.error:
        r.notes.append("PE headers truncated or malformed")
        return

    when = ""
    if 631152000 <= tstamp <= 2208988800:  # 1990..2040 => plausibly a real date
        when = datetime.fromtimestamp(tstamp, timezone.utc).strftime("%Y-%m-%d")
    r.format_details.update({
        "format": "PE32+" if pe32plus else "PE32",
        "arch": PE_MACHINES.get(machine, hex(machine)),
        "image": "DLL" if chars & 0x2000 else "EXE",
        "subsystem": PE_SUBSYSTEMS.get(subsystem, str(subsystem)),
        "timestamp": when or "0x%08x (not a date; often a reproducible-build hash)" % tstamp,
        "dotnet": bool(clr_rva and clr_size),
    })
    if clr_rva and clr_size:
        r.route_key = "dotnet"
        r.file_label += "  ->  .NET managed assembly (CLR header present)"
    names = {s["name"] for s in r.sections}
    if {"UPX0", "UPX1"} & names or b"UPX!" in data[:4096]:
        r.fingerprints.append({"name": "UPX-packed", "hint": UPX_HINT})
    packed = [s["name"] for s in r.sections if s.get("entropy", 0) >= 7.2 and s["raw_size"] > 4096]
    if packed:
        r.notes.append("high-entropy section(s) %s — packed/encrypted code or embedded compressed data" % ", ".join(packed))


def parse_elf(data: bytes, r: TriageResult) -> None:
    try:
        ei_class, ei_data = data[4], data[5]
        e = "<" if ei_data == 1 else ">"
        e_type, e_machine = struct.unpack_from(e + "HH", data, 16)
    except (IndexError, struct.error):
        r.notes.append("ELF header truncated")
        return
    r.format_details.update({
        "format": "ELF64" if ei_class == 2 else "ELF32",
        "endianness": "little" if ei_data == 1 else "big",
        "arch": ELF_MACHINES.get(e_machine, str(e_machine)),
        "type": ELF_TYPES.get(e_type, str(e_type)),
    })
    if r.format_details["arch"] not in ("x86", "x86-64", "AArch64"):
        r.notes.append("non-PC architecture — common in firmware; Ghidra supports it, run it under qemu-user if dynamic analysis is needed")


def parse_macho(data: bytes, r: TriageResult) -> None:
    e = "<" if data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    try:
        cpu, _sub, ftype = struct.unpack_from(e + "iiI", data, 4)
    except struct.error:
        r.notes.append("Mach-O header truncated")
        return
    r.format_details.update({
        "arch": MACHO_CPUS.get(cpu & 0xFFFFFFFF, hex(cpu & 0xFFFFFFFF)),
        "type": MACHO_FILETYPES.get(ftype, str(ftype)),
    })
    if b"__swift5_" in data:
        r.fingerprints.append({"name": "Swift code", "hint": "demangle with `swift demangle`; class/protocol metadata recoverable"})
    if b"__objc_classname" in data or b"__objc_methname" in data:
        r.fingerprints.append({"name": "Objective-C metadata", "hint": "class-dump / `ipsw class-dump` recovers class and method names"})


def lipo_name(cpu: int, sub: int) -> str:
    base, subs = LIPO_ARCHS.get(cpu, (None, {}))
    if base is None:
        return MACHO_CPUS.get(cpu, hex(cpu))
    if not subs:
        return base
    name = subs.get(sub & 0x00FFFFFF)
    return name or "%s (subtype %d)" % (base, sub & 0x00FFFFFF)   # lipo has no name for it


def parse_cafebabe(data: bytes, r: TriageResult) -> None:
    """CA FE BA BE is both Java class magic and Mach-O fat magic. Disambiguate.
    CA FE BA BF is fat64 (64-bit offsets/sizes, 32-byte fat_arch_64 entries)."""
    if len(data) < 8:
        r.file_label, r.route_key = "unknown (truncated CAFEBABE header)", "unknown"
        r.notes.append("truncated header: CAFEBABE magic but fewer than 8 bytes, so neither a fat Mach-O nor a Java class")
        return
    fat64 = data[3] == 0xbf
    word = u32(data, 4, ">")
    if fat64 or word < 45:  # nfat_arch is tiny; a Java class has major version >= 45 here
        r.file_label, r.route_key = "Mach-O universal (fat%s) binary" % ("64" if fat64 else ""), "macho-fat"
        stride = 32 if fat64 else 20
        arches = []
        for i in range(min(word, 16)):
            try:
                cpu, sub = struct.unpack_from(">II", data, 8 + i * stride)
            except struct.error:
                break
            arches.append(lipo_name(cpu, sub))
        r.format_details["slices"] = arches
    else:
        major = u16(data, 6, ">")
        java = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7", 52: "8"}
        r.file_label, r.route_key = "Java class file", "java-class"
        r.format_details["class_version"] = "%d (Java %s)" % (major, java.get(major, str(major - 44)))


GO_BUILDINF = b"\xff Go buildinf:"
GO_MODLINE = re.compile(rb"(?<![A-Za-z0-9_])(path|mod|dep)\t([^\t\n]+)(?:\t([^\t\n]*))?")
RUST_CRATE = re.compile(rb"[/\\](?:registry[/\\]src[/\\][^/\\]+|vendor)[/\\]([A-Za-z0-9_\-]+?)-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)[/\\]")


def _uvarint(buf: bytes, i: int):
    x = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        x |= (b & 0x7F) << shift
        if b < 0x80:
            return x, i
        shift += 7
    raise ValueError("truncated varint")


def _find_in_file(path: str, marker: bytes, chunk: int = 4 * 1024 * 1024) -> int:
    """Offset of the first occurrence of marker anywhere in the file, or -1."""
    with open(path, "rb") as f:
        pos, tail = 0, b""
        while True:
            block = f.read(chunk)
            if not block:
                return -1
            window = tail + block
            i = window.find(marker)
            if i != -1:
                return pos - len(tail) + i
            tail = window[-(len(marker) - 1):]
            pos += len(block)


def go_dependencies(path: str, data: bytes):
    """Go version, main module, and dependency list from the embedded build info."""
    i = data.find(GO_BUILDINF)
    if i != -1:
        block = data[i:i + 65536]
    else:
        off = _find_in_file(path, GO_BUILDINF)
        if off < 0:
            return None
        with open(path, "rb") as f:
            f.seek(off)
            block = f.read(65536)
    info = {"language": "Go"}
    if len(block) > 33 and block[15] & 0x2:          # Go 1.18+: strings stored inline after the header
        try:
            n, j = _uvarint(block, 32)
            info["toolchain"] = block[j:j + n].decode("utf-8", "replace")
        except ValueError:
            pass
    if "toolchain" not in info:
        m = re.search(rb"go1\.\d+(?:\.\d+)?", block) or re.search(rb"go1\.\d+(?:\.\d+)?", data)
        if m:
            info["toolchain"] = m.group(0).decode()
    lines = GO_MODLINE.findall(block) or GO_MODLINE.findall(data)   # older layouts keep modinfo elsewhere
    deps = []
    for kind, mod_path, ver in lines:
        entry = (mod_path + (b" " + ver if ver else b"")).decode("utf-8", "replace")
        if kind == b"path":
            info.setdefault("main_package", entry)
        elif kind == b"mod":
            info.setdefault("main_module", entry)
        elif entry not in deps:
            deps.append(entry)
    info["packages"] = deps
    return info


def rust_dependencies(data: bytes):
    """Crate names and versions leaked through panic/source paths."""
    crates = {}
    for m in RUST_CRATE.finditer(data):
        crates[m.group(1).decode()] = m.group(2).decode()
    if not crates:
        return None
    info = {"language": "Rust", "packages": sorted("%s %s" % kv for kv in crates.items())}
    m = re.search(rb"rustc version (\d+\.\d+\.\d+)", data)
    if m:
        info["toolchain"] = "rustc " + m.group(1).decode()
    return info


ALL_MARKERS = sorted({m for _n, _r, _h, alts in FINGERPRINTS for alt in alts for m in alt} | {DOTNET_BUNDLE_SIG, UPX_INFO})
_OVERLAP = max(len(m) for m in ALL_MARKERS) + 8


class MarkerScanner:
    """Streams the WHOLE file for fingerprint markers.

    Markers often sit far from the start (Electron strings near the end of a
    200+ MB binary, PyInstaller's cookie in the last bytes), so scanning only the
    analysis window would miss them. Chunks overlap so a marker spanning a chunk
    boundary is still found.
    """

    def __init__(self):
        self.found = {}    # marker -> the 8 bytes preceding it (needed for the .NET bundle check)
        self._tail = b""

    def feed(self, chunk: bytes) -> None:
        window = self._tail + chunk
        for m in ALL_MARKERS:
            if m not in self.found:
                i = window.find(m)
                if i != -1:
                    self.found[m] = window[max(0, i - 8):i]
        self._tail = window[-_OVERLAP:]


# Well-known constant tables (the findcrypt idea). Multi-word patterns only, so
# chance matches in 64 MB of data stay negligible. 32-bit tables are listed in
# little-endian (x86/ARM) byte order, with a big-endian variant where common.
CRYPTO_CONSTANTS = [
    ("AES S-box", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("AES inverse S-box", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("AES T-table", bytes.fromhex("a56363c6847c7cf8")),
    ("AES T-table (big-endian)", bytes.fromhex("c66363a5f87c7c84")),
    ("SHA-256 round constants", bytes.fromhex("982f8a4291443771")),
    ("SHA-256 round constants (big-endian)", bytes.fromhex("428a2f9871374491")),
    ("SHA-256 initial hash", bytes.fromhex("67e6096a85ae67bb")),
    ("SHA-512 round constants", bytes.fromhex("22ae28d7982f8a42")),
    ("SHA-512 initial hash", bytes.fromhex("08c9bcf367e6096a")),
    ("MD5 round constants", bytes.fromhex("78a46ad756b7c7e8")),
    ("MD5 / SHA-1 initial hash", bytes.fromhex("0123456789abcdeffedcba9876543210")),
    ("CRC-32 table", bytes.fromhex("963007772c610eee")),
    ("Blowfish P-array (pi digits)", bytes.fromhex("886a3f24d308a385")),
    ("ChaCha20 / Salsa20 constant", b"expand 32-byte k"),
    ("DES permutation table", bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52])),
    ("RSA key or certificate (rsaEncryption OID)", bytes.fromhex("06092a864886f70d010101")),
    ("NIST P-256 curve prime", bytes.fromhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")),
    ("Base64 alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
]


def find_crypto(data: bytes, r: TriageResult) -> None:
    """Locate known crypto/encoding tables; give PE virtual addresses for jumping in Ghidra."""
    cert = getattr(r, "_cert_range", (0, 0))
    base = getattr(r, "_image_base", None)
    for name, pat in CRYPTO_CONSTANTS:
        hits, start = [], 0
        while len(hits) < 3:
            i = data.find(pat, start)
            if i < 0:
                break
            start = i + 1
            if cert[1] and cert[0] <= i < cert[0] + cert[1]:
                continue                                  # inside the Authenticode signature, not the program
            hit = {"offset": "0x%x" % i}
            if base is not None:
                for s in r.sections:
                    if s.get("raw_ptr", 0) <= i < s.get("raw_ptr", 0) + s.get("raw_size", 0):
                        hit["va"] = "0x%x" % (base + s["vaddr"] + i - s["raw_ptr"])
                        hit["section"] = s["name"]
                        break
            hits.append(hit)
        if hits:
            r.crypto.append({"constant": name, "hits": hits})


def run_fingerprints(found: dict, r: TriageResult) -> None:
    seen = {f["name"] for f in r.fingerprints}
    for name, route, hint, alternatives in FINGERPRINTS:
        if name in seen:
            continue
        if any(all(m in found for m in alt) for alt in alternatives):
            r.fingerprints.append({"name": name, "hint": hint})
            if route and r.route_key in ("native-pe", "native-elf", "macho", "unknown"):
                r.route_key = route
    prefix = found.get(DOTNET_BUNDLE_SIG, b"")
    if len(prefix) == 8 and struct.unpack("<q", prefix)[0] > 0:
        r.fingerprints.append({"name": ".NET single-file bundle",
                               "hint": "assemblies are embedded in the apphost — open it in ILSpy (supports bundles) and decompile"})
        r.route_key = "dotnet"


# ---------------------------------------------------------------------------
# containers
# ---------------------------------------------------------------------------
def classify_zip(path: str, r: TriageResult) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            hermes = False
            if "assets/index.android.bundle" in names:
                with zf.open("assets/index.android.bundle") as fh:
                    hermes = fh.read(8) == b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
            ipa_bundle = next((n for n in names if n.startswith("Payload/") and n.endswith(".app/main.jsbundle")), None)
            if ipa_bundle:
                with zf.open(ipa_bundle) as fh:
                    hermes = hermes or fh.read(8) == b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
    except (zipfile.BadZipFile, OSError, RuntimeError, KeyError) as e:
        r.notes.append("ZIP open failed: %s" % e)
        return

    s = set(names)
    low = [n.lower() for n in names]
    kind, route = "generic ZIP", "zip"
    if "AndroidManifest.xml" in s and any(n.startswith("classes") and n.endswith(".dex") for n in names):
        kind, route = "Android APK", "android"
    elif "AndroidManifest.xml" in s and "classes.jar" in s:
        kind, route = "Android library (AAR)", "android"
    elif "base/manifest/AndroidManifest.xml" in s:
        kind, route = "Android App Bundle (AAB)", "android"
    elif any(n.endswith(".apk") for n in names) and ("manifest.json" in s or "info.json" in s):
        kind, route = "split-APK bundle (XAPK/APKM/APKS) — triage base.apk inside", "android"
    elif any(n.startswith("Payload/") and ".app/" in n for n in names):
        kind, route = "iOS app (IPA)", "ios"
    elif "AppxManifest.xml" in s or "AppxMetadata/AppxBundleManifest.xml" in s:
        kind, route = "Windows app package (MSIX/APPX)", "windows-pkg"
    elif "[Content_Types].xml" in s:
        kind, route = "Office Open XML document", "office"
        if any(n.endswith("vbaProject.bin") for n in names):
            r.fingerprints.append({"name": "VBA macros present", "hint": "inspect with `olevba` (oletools) before anything else"})
    elif "META-INF/MANIFEST.MF" in s or any(n.endswith(".class") for n in names):
        kind, route = ("Java WAR" if any(n.startswith("WEB-INF/") for n in names) else "Java JAR"), "java"
    elif any(n.endswith(".dist-info/WHEEL") for n in names):
        kind, route = "Python wheel", "python"
    elif "manifest.json" in s and any(n.endswith(".js") for n in names):
        kind, route = "browser extension (CRX/XPI/zip)", "browser-ext"
    elif any(n.endswith(".asar") for n in names):
        kind, route = "archive containing an Electron app (.asar)", "asar"

    # framework fingerprints from member names (mobile + desktop)
    def has(pred):
        return any(pred(n) for n in low)
    fw = []
    if has(lambda n: n.endswith("libflutter.so") or "flutter.framework/" in n or n.startswith("assets/flutter_assets/")):
        fw.append(("Flutter", "Dart AOT code is in libapp.so / App.framework — use blutter; Java/Kotlin layer is thin"))
    if "assets/index.android.bundle" in s or ipa_bundle:
        fw.append(("React Native" + (" (Hermes bytecode)" if hermes else " (plain JS bundle)"),
                   "the app logic is the JS bundle — " + ("decompile Hermes bytecode with hermes-dec" if hermes else "beautify and read it")))
    if has(lambda n: n.endswith("libil2cpp.so") or n.endswith("global-metadata.dat") or "unityframework.framework/" in n):
        fw.append(("Unity (IL2CPP)", "C# compiled to native — recover types/method names with Il2CppDumper or Cpp2IL, then Ghidra"))
    elif has(lambda n: n.endswith("managed/assembly-csharp.dll")):
        fw.append(("Unity (Mono)", "game code is Assembly-CSharp.dll — decompile with ILSpy"))
    if has(lambda n: n.endswith("libmonodroid.so") or n.startswith("assemblies/") or "libxamarin-app.so" in n or "libassemblies." in n):
        fw.append(("Xamarin / .NET MAUI", "managed .NET assemblies are packed in the APK — extract them (assembly store) then ILSpy"))
    if has(lambda n: n.endswith("cordova.js") or n.endswith("capacitor.config.json")):
        fw.append(("Cordova / Capacitor (web app)", "the app is HTML/JS under assets/www or assets/public — read it directly"))
    if has(lambda n: n.startswith("kotlin/") or n.endswith(".kotlin_module")):
        fw.append(("Kotlin", "Kotlin metadata survives R8 and can restore class names"))
    for name, hint in fw:
        r.fingerprints.append({"name": name, "hint": hint})
    if fw and route in ("android", "ios"):
        r.notes.append("cross-platform framework detected — app logic lives in its container; see references/frameworks-packagers.md")

    abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2 and n.endswith(".so")})
    dex = sum(1 for n in names if n.startswith("classes") and n.endswith(".dex"))
    r.container = {"type": kind, "entry_count": len(names), "sample_entries": names[:40]}
    if abis:
        r.container["native_abis"] = abis
    if dex:
        r.container["dex_files"] = dex
    r.route_key = route
    r.file_label += "  ->  " + kind


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------
def extract_strings(data: bytes, min_len: int):
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    out = [m.group(0) for m in ascii_re.finditer(data)]
    out += [m.group(0)[::2] for m in utf16_re.finditer(data)]
    return out


def valid_ipv4(s: bytes) -> bool:
    parts = s.split(b".")
    return all(p.isdigit() and int(p) <= 255 for p in parts) and parts[0] not in (b"0",)


def surface_strings(data: bytes, r: TriageResult, min_len: int, top_n: int) -> None:
    strings = extract_strings(data, min_len)
    joined_all = b"\n".join(strings)
    interesting = {}
    for pat, name, pre in INTERESTING_PATTERNS:
        joined = joined_all if pre is None else b"\n".join(s for s in strings if pre in s)
        found, seen = [], set()
        for m in pat.finditer(joined):
            s = m.group(0)
            if name == "ipv4" and not valid_ipv4(s):
                continue
            if s not in seen:
                seen.add(s)
                found.append(s.decode("latin-1", "replace"))
            if len(found) >= 15:
                break
        if found:
            interesting[name] = found
    r.interesting = interesting
    r.sample_strings = [s.decode("latin-1", "replace")[:160] for s in heapq.nlargest(top_n, strings, key=len)]


# ---------------------------------------------------------------------------
# directory mode
# ---------------------------------------------------------------------------
DIR_APP_MARKERS = [
    # Electron ships either resources/app.asar or an unpacked resources/app/ (VS Code
    # does the latter, plus node_modules.asar), so match any of those.
    ("Electron app", lambda p: p.endswith(".asar") or p.endswith("/resources/app/package.json")
     or "electron framework.framework/" in p),
    ("Chromium Embedded Framework (CEF) app", lambda p: p.endswith("/libcef.dll") or p.endswith("/libcef.so")),
    ("NW.js app", lambda p: p.endswith("/nw.dll") or p.endswith("/package.nw")),
    ("Flutter app", lambda p: p.endswith("/flutter_windows.dll") or "/flutter_assets/" in p or "flutter.framework/" in p or p.endswith("/libflutter.so")),
    ("Unity (IL2CPP)", lambda p: p.endswith("/gameassembly.dll") or p.endswith("/global-metadata.dat") or p.endswith("/libil2cpp.so")),
    ("Unity (Mono)", lambda p: p.endswith("/managed/assembly-csharp.dll")),
    ("Godot game", lambda p: p.endswith(".pck")),
    ("Qt app", lambda p: re.search(r"/qt[56]core\.dll$|/libqt[56]core\.so|qtcore\.framework/", p) is not None),
    (".NET app", lambda p: p.endswith(".runtimeconfig.json") or p.endswith(".deps.json")),
    ("PyInstaller one-dir app", lambda p: p.endswith("/base_library.zip")),
    ("embedded Python runtime", lambda p: re.search(r"/python3\d*\.dll$|/libpython3[\d.]*\.(so|dylib)", p) is not None),
    ("Java app (bundled JRE/JARs)", lambda p: p.endswith(".jar") or "/lib/jvm" in p),
    ("Apple app bundle", lambda p: p.endswith("/contents/info.plist") or re.search(r"\.app/info\.plist$", p) is not None),
]
NOTABLE_ROUTES = {"native-pe", "native-elf", "macho", "macho-fat", "dotnet", "android", "zip", "wasm",
                  "java-class", "archive", "firmware", "compressed", "ole", "frameworks"}


def _is_regular(path: str, follow: bool = False) -> bool:
    """True only for a regular file. FIFOs, sockets and device nodes block or never end on read.
    lstat by default, so a symlink is never regular; follow=True stats the link target."""
    try:
        st = os.stat(path) if follow else os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def _inside(path: str, root_real: str) -> bool:
    real = os.path.realpath(path)
    return real == root_real or real.startswith(root_real.rstrip(os.sep) + os.sep)


def triage_directory(root: str, r: TriageResult, max_files: int) -> None:
    r.kind = "directory"
    counts, notable, apps, total, scanned = Counter(), [], {}, 0, 0
    truncated = False
    skipped_special = skipped_out_of_tree = 0
    root_real = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
        for fn in filenames:
            if scanned >= max_files:
                truncated = True
                break
            path = os.path.join(dirpath, fn)
            if os.path.islink(path):
                # in-tree links duplicate files already walked; out-of-tree ones would pull in host files
                if not _inside(path, root_real):
                    skipped_out_of_tree += 1
                continue
            if not _is_regular(path):
                skipped_special += 1     # FIFO, socket or device node: open()/read() would block
                continue
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    head = f.read(4096)
            except OSError:
                continue
            scanned += 1
            total += size
            label, route = detect_magic(head)
            if route == "native-pe" and b"PE\x00\x00" in head:
                tmp = TriageResult(path=path)
                parse_pe(head, tmp)
                if tmp.format_details.get("dotnet"):
                    label, route = ".NET assembly", "dotnet"
            if fn.endswith(".asar"):
                label, route = "Electron archive (.asar)", "asar"
            counts["text/other" if route == "unknown" else route] += 1
            rel = os.path.relpath(path, root).replace("\\", "/")
            relp = "/" + rel.lower()
            for name, pred in DIR_APP_MARKERS:
                if name not in apps and pred(relp):
                    apps[name] = rel
            if route in NOTABLE_ROUTES or route == "asar":
                notable.append((size, rel, label))
        if truncated:
            break
    r.size_bytes = total
    r.file_label = "directory (%d files scanned%s)" % (scanned, ", truncated" if truncated else "")
    r.route_key = "directory"
    r.directory = {
        "files_scanned": scanned,
        "by_route": dict(counts.most_common()),
        "app_markers": [{"name": k, "evidence": v} for k, v in apps.items()],
        "notable_files": [{"size": s, "path": p, "type": l} for s, p, l in heapq.nlargest(20, notable)],
        "skipped_special": skipped_special,
        "skipped_symlink_out_of_tree": skipped_out_of_tree,
    }
    steps = []
    for name in apps:
        if name.startswith("Electron"):
            steps.append(ROUTES["asar"] + " (if the app ships an unpacked resources/app/ folder, read it directly)")
        elif name in ("Flutter app", "Unity (IL2CPP)", "Unity (Mono)", "Godot game", "PyInstaller one-dir app", "embedded Python runtime"):
            steps.append(ROUTES["frameworks"])
        elif name == ".NET app":
            steps.append(ROUTES["dotnet"])
        elif name == "Apple app bundle":
            steps.append(ROUTES["macho"])
    steps.append("Triage the top notable files individually: python -I triage.py <dir>/<file>")
    r.next_steps = list(dict.fromkeys(steps))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def triage_file(path: str, r: TriageResult, args) -> None:
    r.size_bytes = os.path.getsize(path)
    hashers = _hashers()
    scanner = MarkerScanner()
    buf = bytearray()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
            scanner.feed(chunk)
            if len(buf) < args.max_read:
                buf.extend(chunk[: args.max_read - len(buf)])
    data = bytes(buf)
    r.hashes = {k: h.hexdigest() for k, h in hashers.items()}
    if r.size_bytes > len(data):
        r.notes.append("analyzed the first %d MiB only (raise --max-read for more)" % (len(data) // (1024 * 1024)))

    r.entropy = shannon_entropy(data)
    r.entropy_note = entropy_note(r.entropy)
    r.file_label, r.route_key = detect_magic(data[:4096])

    if r.route_key == "native-pe":
        parse_pe(data, r)
    elif r.route_key == "native-elf":
        parse_elf(data, r)
    elif r.route_key == "macho":
        parse_macho(data, r)
    elif r.route_key == "cafebabe":
        parse_cafebabe(data, r)
    elif r.route_key == "zip":
        classify_zip(path, r)

    native = r.route_key in NATIVE_ROUTES
    if r.route_key in ("native-pe", "native-elf", "macho", "macho-fat", "dotnet", "unknown"):
        run_fingerprints(scanner.found, r)
        names = {fp["name"] for fp in r.fingerprints}
        if native and "UPX-packed" not in names and (
                UPX_INFO in scanner.found or upx_marker_near_ends(path, data, r.size_bytes)):
            r.fingerprints.append({"name": "UPX-packed", "hint": UPX_HINT})
        deps = (go_dependencies(path, data) if "Go binary" in names else None) or \
               (rust_dependencies(data) if "Rust binary" in names else None)
        if deps:
            r.dependencies = deps
    if native and r.entropy >= 7.2 and not any("entropy" in s for s in r.sections):
        r.notes.append("whole-file entropy %.2f with no section data — likely packed or encrypted; "
                       "look for a packer stub before decompiling" % r.entropy)
    if r.route_key not in ("zip", "archive", "compressed", "resource", "asar"):
        find_crypto(data, r)

    if not args.no_strings:
        surface_strings(data, r, args.min_len, args.strings)

    r.next_steps = [ROUTES.get(r.route_key, ROUTES["unknown"])]
    if r.route_key == "macho-fat":
        present = [a for a in r.format_details.get("slices", []) if " " not in a and not a.startswith("0x")]
        if present:
            r.next_steps[0] = ("Fat Mach-O — thin one slice first (`lipo -thin %s <file> -output out`), "
                               "then references/ios.md" % present[0])
        else:
            r.next_steps[0] = ("Fat Mach-O — list the slices with `lipo -archs <file>`, thin one with "
                               "`lipo -thin <arch> <file> -output out`, then references/ios.md")
    for fp in r.fingerprints:
        r.next_steps.append("%s: %s" % (fp["name"], fp["hint"]))
    if r.crypto:
        r.next_steps.append("Crypto constants found: jump to each address in Ghidra (or search memory for the "
                            "bytes) and follow xrefs to the routine that uses it")
    if r.dependencies.get("packages"):
        r.next_steps.append("Check the dependency versions for known vulnerabilities "
                            "(osv-scanner, govulncheck for Go, cargo-audit data for Rust)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Triage a file or directory for reverse engineering.")
    ap.add_argument("path", help="file or directory to triage")
    ap.add_argument("--strings", type=int, default=25, help="how many longest strings to keep (default 25)")
    ap.add_argument("--min-len", type=int, default=5, help="minimum string length (default 5)")
    ap.add_argument("--no-strings", action="store_true", help="skip string extraction")
    ap.add_argument("--max-read", type=int, default=64 * 1024 * 1024,
                    help="max bytes analyzed for strings/entropy/fingerprints (default 64 MiB; hashes always cover the whole file)")
    ap.add_argument("--max-files", type=int, default=20000, help="directory mode: max files to scan (default 20000)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print("error: no such file or directory: %s" % args.path, file=sys.stderr)
        return 2

    if not os.path.isdir(args.path) and not _is_regular(args.path, follow=True):
        print("error: not a regular file or directory (FIFO, socket or device?): %s" % args.path, file=sys.stderr)
        return 2

    r = TriageResult(path=os.path.abspath(args.path))
    if os.path.isdir(args.path):
        triage_directory(args.path, r, args.max_files)
    else:
        triage_file(args.path, r, args)

    if args.json:
        print(json.dumps(asdict(r), indent=2))
    else:
        print_report(r)
    return 0


def print_report(r: TriageResult) -> None:
    line = "=" * 72
    print(line)
    print("TRIAGE  " + r.path)
    print(line)
    print("type        : " + r.file_label)
    print("size        : {:,} bytes".format(r.size_bytes))
    for k, v in r.format_details.items():
        print("{:<12}: {}".format(k, v))
    if r.kind == "file":
        print("entropy     : %s/8.0  (%s)" % (r.entropy, r.entropy_note))
        for k, v in r.hashes.items():
            print("{:<12}: {}".format(k, v))
    if r.sections:
        print("-" * 72)
        print("SECTIONS")
        for s in r.sections[:24]:
            ent = "  entropy %.2f" % s["entropy"] if "entropy" in s else ""
            print("  {:<10} raw {:>10,}{}".format(s["name"], s["raw_size"], ent))
    if r.fingerprints:
        print("-" * 72)
        print("FINGERPRINTS")
        for fp in r.fingerprints:
            print("  * %s — %s" % (fp["name"], fp["hint"]))
    if r.crypto:
        print("-" * 72)
        print("CRYPTO / ENCODING CONSTANTS")
        for c in r.crypto:
            where = ", ".join(
                (h["va"] + " (" + h.get("section", "") + ")") if "va" in h else "file " + h["offset"]
                for h in c["hits"])
            print("  * %-44s %s" % (c["constant"], where))
    if r.dependencies:
        d = r.dependencies
        pk = d.get("packages", [])
        print("-" * 72)
        print("DEPENDENCIES  (%s, %d packages)" % (d["language"], len(pk)))
        for k in ("toolchain", "main_module", "main_package"):
            if d.get(k):
                print("  {:<13} {}".format(k + ":", d[k]))
        for p in pk[:20]:
            print("    " + p)
        if len(pk) > 20:
            print("    ... %d more (use --json)" % (len(pk) - 20))
    if r.container:
        c = r.container
        print("-" * 72)
        print("CONTAINER   : %s (%d entries)" % (c["type"], c["entry_count"]))
        if c.get("native_abis"):
            print("native ABIs : " + ", ".join(c["native_abis"]))
        if c.get("dex_files"):
            print("dex files   : %d" % c["dex_files"])
        for name in c["sample_entries"][:12]:
            print("              - " + name)
        if c["entry_count"] > 12:
            print("              ... and %d more" % (c["entry_count"] - 12))
    if r.directory:
        d = r.directory
        print("-" * 72)
        print("BY TYPE     : " + ", ".join("%s=%d" % kv for kv in d["by_route"].items()))
        if d.get("skipped_special") or d.get("skipped_symlink_out_of_tree"):
            print("SKIPPED     : %d special (FIFO/socket/device), %d symlinks leaving the tree"
                  % (d.get("skipped_special", 0), d.get("skipped_symlink_out_of_tree", 0)))
        if d["app_markers"]:
            print("APP MARKERS :")
            for m in d["app_markers"]:
                print("  * %s  (%s)" % (m["name"], m["evidence"]))
        if d["notable_files"]:
            print("NOTABLE FILES (largest code/containers):")
            for nf in d["notable_files"][:15]:
                print("  {:>12,}  {}  [{}]".format(nf["size"], nf["path"], nf["type"]))
    if r.interesting:
        print("-" * 72)
        print("INTERESTING STRINGS")
        for cat, items in r.interesting.items():
            print("  [%s]" % cat)
            for it in items[:10]:
                print("      " + it)
    if r.sample_strings:
        print("-" * 72)
        print("LONGEST STRINGS (sample)")
        for s in r.sample_strings[:MAX_STRINGS_SHOWN]:
            print("  " + s)
    if r.notes:
        print("-" * 72)
        for n in r.notes:
            print("note: " + n)
    print(line)
    print("SUGGESTED NEXT STEPS")
    for s in r.next_steps:
        print("  - " + s)
    print(line)


if __name__ == "__main__":
    raise SystemExit(main())
