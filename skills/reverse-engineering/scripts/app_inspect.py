#!/usr/bin/env python3
"""Pull the platform facts that matter out of an app, automatically.

Point it at an APK, an IPA, an iOS/macOS .app folder, a Windows .exe/.dll, or a
game folder. It reads the platform's own metadata (no external tools) and prints
a compact summary:

  Android  package, version, SDK levels, permissions, exported components,
           deep links, debuggable/backup/cleartext flags (binary manifest)
  Apple    bundle id, version, URL schemes, ATS exceptions, privacy keys,
           entitlements, App Store encryption per architecture, frameworks
  Windows  product, company, version, signing-certificate names, privilege level
  Games    engine and version, scripting backend, where the game code lives
           (Unity Mono / IL2CPP, Unreal, Godot)

Stdlib only (Python 3.8+). Reads bytes; never executes anything. Run with -I.

Usage: python -I app_inspect.py <file-or-dir> [--json]
"""
from __future__ import annotations

import argparse
import json
import mmap
import os
import plistlib
import re
import stat
import struct
import sys
import zipfile

# --------------------------------------------------------------------------
# Android binary XML (AXML)
# --------------------------------------------------------------------------
# Fallback names for attributes whose name string was stripped (resource IDs).
ANDROID_ATTR_IDS = {
    0x01010003: "name", 0x01010006: "permission", 0x0101000f: "debuggable",
    0x01010010: "exported", 0x01010027: "scheme", 0x01010028: "host",
    0x0101020c: "minSdkVersion", 0x0101021b: "versionCode", 0x0101021c: "versionName",
    0x01010270: "targetSdkVersion", 0x01010280: "allowBackup",
    0x010104ec: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
}
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
MAX_AXML_STRINGS = 500000
MAX_META_BYTES = 16 << 20          # manifests and Info.plist: real ones are kilobytes
MAX_EXE_BYTES = 256 << 20          # Mach-O inside an IPA: read at most this much, flag truncation


def _err(e):
    return "%s: %s" % (type(e).__name__, e)


def _read_member(z, name, limit, truncate=False):
    """Read a zip member without trusting it to be small. Returns (bytes or None, note or None)."""
    size = z.getinfo(name).file_size
    if size > limit and not truncate:
        return None, "%s is %d bytes (declared), over the %d-byte limit; not read" % (name, size, limit)
    with z.open(name) as f:
        data = f.read(limit)
    if size > limit:
        return data, "%s is %d bytes; only the first %d were read" % (name, size, limit)
    return data, None


def _map_file(f):
    """Map an open file read-only (no full read into memory); empty files give b""."""
    try:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    except ValueError:                                     # empty file
        return b""


def _regular_in_tree(paths, root, skipped):
    """Keep regular files; drop FIFOs/devices/sockets and symlinks that leave root (counted in skipped)."""
    real_root = os.path.realpath(root)
    out = []
    for p in paths:
        try:
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                rp = os.path.realpath(p)
                if os.path.commonpath([real_root, rp]) != real_root:
                    skipped["skipped_symlink_out_of_tree"] = skipped.get("skipped_symlink_out_of_tree", 0) + 1
                    continue
                st = os.stat(p)
        except (OSError, ValueError):
            skipped["skipped_special"] = skipped.get("skipped_special", 0) + 1
            continue
        if not stat.S_ISREG(st.st_mode):
            skipped["skipped_special"] = skipped.get("skipped_special", 0) + 1
            continue
        out.append(p)
    return out


def _axml_str(data, offsets, base, i, utf8, limit):
    """Decode string i of a pool, at most `limit` characters long."""
    off = base + struct.unpack_from("<I", data, offsets + i * 4)[0]
    if utf8:
        off += 2 if data[off] & 0x80 else 1               # skip UTF-16 length
        n = data[off]
        if n & 0x80:
            n, off = ((n & 0x7F) << 8) | data[off + 1], off + 2
        else:
            off += 1
        return data[off:off + min(n, limit)].decode("utf-8", "replace")
    n = struct.unpack_from("<H", data, off)[0]
    off += 2
    if n & 0x8000:
        n, off = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, off)[0], off + 2
    return data[off:off + min(n, limit) * 2].decode("utf-16-le", "replace")


def parse_axml(data):
    """Yield ("start", tag, attrs) and ("end", tag, None) events."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("not Android binary XML")
    pos = struct.unpack_from("<H", data, 2)[0]
    strings, resmap = [], []
    # Decoded characters across ALL string pools: a real manifest decodes to at most
    # len(data) characters, so overlapping or self-referencing strings (or many tiny
    # pools) cannot blow up memory. Each string is cut to what is left of the budget.
    budget = 2 * len(data) + 4096
    while pos + 8 <= len(data):
        ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
        if csize < 8:
            break
        # Header counts are attacker-controlled: clamp them to the bytes the chunk really has.
        body = max(0, min(csize, len(data) - pos) - hsize)
        if ctype == 0x0001:                                # string pool
            count, _styles, flags, sstart = struct.unpack_from("<IIII", data, pos + 8)
            count = min(count, body // 4, MAX_AXML_STRINGS - len(strings))   # total, not per pool
            for i in range(count):
                try:
                    s = _axml_str(data, pos + hsize, pos + sstart, i, bool(flags & 0x100), budget) if budget > 0 else ""
                except (struct.error, IndexError):
                    s = ""
                budget -= len(s)
                strings.append(s)
        elif ctype == 0x0180:                              # resource id map
            resmap = list(struct.unpack_from("<%dI" % (body // 4), data, pos + hsize))
        elif ctype == 0x0102:                              # start element
            ext = pos + hsize
            _ns, name_i, astart, asize, acount = struct.unpack_from("<IIHHH", data, ext)
            avail = body - astart
            acount = min(acount, max(0, avail) // asize) if asize else min(acount, 1)
            attrs = {}
            for a in range(acount):
                _ans, ai, raw, _sz, _r0, dtype, d = struct.unpack_from("<IIIHBBI", data, ext + astart + a * asize)
                key = strings[ai] if ai < len(strings) and strings[ai] else \
                    ANDROID_ATTR_IDS.get(resmap[ai] if ai < len(resmap) else 0, "attr%d" % ai)
                if raw != 0xFFFFFFFF and raw < len(strings):
                    val = strings[raw]
                elif dtype == 0x03 and d < len(strings):
                    val = strings[d]
                elif dtype == 0x12:
                    val = d != 0
                elif dtype in (0x10, 0x11):
                    val = d - (1 << 32) if d >= 1 << 31 else d
                elif dtype == 0x01:
                    val = "@0x%08x" % d
                else:
                    val = d
                attrs[key] = val
            yield "start", (strings[name_i] if name_i < len(strings) else "?"), attrs
        elif ctype == 0x0103:                              # end element
            name_i = struct.unpack_from("<I", data, pos + hsize + 4)[0]
            yield "end", (strings[name_i] if name_i < len(strings) else "?"), None
        pos += csize


def inspect_apk(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "AndroidManifest.xml" not in names:
            return {"platform": "android", "error": "no AndroidManifest.xml (an .aab stores it as protobuf; "
                                                    "convert with bundletool build-apks first)"}
        manifest, too_big = _read_member(z, "AndroidManifest.xml", MAX_META_BYTES)
    r = {"platform": "android", "permissions": [], "exported": [], "deep_links": [], "app": {}}
    if too_big:
        r["manifest_error"] = too_big
        manifest = b""
    comp, filt = None, None
    try:
        for ev, tag, a in parse_axml(manifest) if manifest else ():
            if ev == "end":
                if tag == "intent-filter" and filt is not None and comp is not None:
                    for s in sorted(filt["schemes"]) or []:
                        for h in sorted(filt["hosts"]) or [""]:
                            r["deep_links"].append({"url": "%s://%s" % (s, h), "component": comp["name"]})
                    filt = None
                elif tag in COMPONENTS:
                    comp = None
                continue
            if tag == "manifest":
                r.update(package=a.get("package"), version=a.get("versionName"), version_code=a.get("versionCode"))
            elif tag == "uses-sdk":
                r.update(min_sdk=a.get("minSdkVersion"), target_sdk=a.get("targetSdkVersion"))
            elif tag.startswith("uses-permission"):
                r["permissions"].append(a.get("name"))
            elif tag == "application":
                r["app"] = {k: a[k] for k in ("name", "debuggable", "allowBackup", "usesCleartextTraffic",
                                              "networkSecurityConfig") if k in a}
            elif tag in COMPONENTS:
                name = str(a.get("name") or "?")
                if name.startswith(".") and r.get("package"):
                    name = r["package"] + name
                comp = {"type": tag, "name": name, "exported": a.get("exported"),
                        "permission": a.get("permission"), "filters": 0, "launcher": False}
                r.setdefault("_components", []).append(comp)
            elif tag == "intent-filter" and comp is not None:
                comp["filters"] += 1
                filt = {"schemes": set(), "hosts": set()}
            elif tag == "category" and comp is not None and a.get("name") == "android.intent.category.LAUNCHER":
                comp["launcher"] = True
            elif tag == "data" and filt is not None:
                if a.get("scheme"):
                    filt["schemes"].add(str(a["scheme"]))
                if a.get("host"):
                    filt["hosts"].add(str(a["host"]))
    except (ValueError, struct.error, IndexError, TypeError, AttributeError) as e:
        r["error"] = "manifest parse failed: %s" % e
    for c in r.pop("_components", []):
        if c["launcher"]:
            r["launcher"] = c["name"]
        exported = c["exported"]
        if exported is None and c["filters"]:
            exported = "implicit (intent-filter; only on targetSdk < 31)"
        if exported:
            r["exported"].append({"type": c["type"], "name": c["name"], "exported": exported,
                                  "permission": c["permission"]})
    r["dex_files"] = sum(1 for n in names if re.match(r"classes\d*\.dex$", n))
    r["native_abis"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
    return r


# --------------------------------------------------------------------------
# Apple: Info.plist, Mach-O encryption + entitlements
# --------------------------------------------------------------------------
CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32"}
ARM_SUB = {5: "armv4t", 6: "armv6", 7: "armv5", 9: "armv7", 11: "armv7s", 12: "armv7k", 14: "armv6m",
           15: "armv7m", 16: "armv7em"}
ENT_KEYS = ("application-identifier", "com.apple.developer.team-identifier", "get-task-allow",
            "keychain-access-groups", "com.apple.security.application-groups",
            "com.apple.developer.associated-domains", "aps-environment",
            "com.apple.security.app-sandbox", "com.apple.security.network.client")


def arch_name(cpu, sub):
    """lipo-style architecture name (arm64e, x86_64h, armv7s, ...) from cputype + cpusubtype."""
    sub &= 0x00FFFFFF                                      # drop capability bits (arm64e sets 0x80000000)
    if cpu == 0x0100000C:
        return {1: "arm64v8", 2: "arm64e"}.get(sub, "arm64")
    if cpu == 0x01000007:
        return "x86_64h" if sub == 8 else "x86_64"
    if cpu == 12:
        return ARM_SUB.get(sub, "arm")
    return CPU.get(cpu, hex(cpu))


def _entitlements(blob):
    if len(blob) < 12 or struct.unpack_from(">I", blob, 0)[0] != 0xFADE0CC0:
        return None
    for i in range(min(struct.unpack_from(">I", blob, 8)[0], 64, (len(blob) - 12) // 8)):
        _t, off = struct.unpack_from(">II", blob, 12 + i * 8)
        if off + 8 <= len(blob) and struct.unpack_from(">I", blob, off)[0] == 0xFADE7171:
            try:
                ents = plistlib.loads(blob[off + 8:off + struct.unpack_from(">I", blob, off + 4)[0]])
            except Exception:
                return None
            if not isinstance(ents, dict):
                return None
            return {k: ents[k] if isinstance(ents[k], (bool, int)) else str(ents[k]) for k in ENT_KEYS if k in ents}
    return None


def _thin(data):
    m = data[:4]
    fmt = {b"\xcf\xfa\xed\xfe": ("<", 32), b"\xce\xfa\xed\xfe": ("<", 28),
           b"\xfe\xed\xfa\xcf": (">", 32), b"\xfe\xed\xfa\xce": (">", 28)}.get(m)
    if not fmt:
        return []
    e, off = fmt
    if len(data) < off:
        return [{"arch": None, "error": "Mach-O header truncated"}]
    cpu, sub, _ft, ncmds = struct.unpack_from(e + "IIII", data, 4)
    s = {"arch": arch_name(cpu, sub), "encrypted": None, "entitlements": None}
    try:
        for _ in range(min(ncmds, 4096)):
            if off + 8 > len(data):
                break
            cmd, size = struct.unpack_from(e + "II", data, off)
            if cmd in (0x21, 0x2C):                        # LC_ENCRYPTION_INFO(_64)
                s["encrypted"] = struct.unpack_from(e + "I", data, off + 16)[0] != 0
            elif cmd == 0x1D:                              # LC_CODE_SIGNATURE
                doff, dsize = struct.unpack_from(e + "II", data, off + 8)
                try:
                    s["entitlements"] = _entitlements(data[doff:doff + dsize])
                except Exception as ex:
                    s["entitlements_error"] = _err(ex)
            if size < 8:
                break
            off += size
    except Exception as ex:
        s["load_commands_error"] = _err(ex)
    return [s]


def macho_slices(data):
    m = data[:4]
    fat64 = m == b"\xca\xfe\xba\xbf"
    if fat64 or (m == b"\xca\xfe\xba\xbe" and len(data) >= 8 and struct.unpack_from(">I", data, 4)[0] < 45):
        fmt, stride = (">IIQQI", 32) if fat64 else (">IIIII", 20)
        out = []
        for i in range(min(struct.unpack_from(">I", data, 4)[0], 16)):
            try:
                cpu, sub, off, size, _al = struct.unpack_from(fmt, data, 8 + i * stride)
                sl = _thin(data[off:off + size]) or [{"arch": arch_name(cpu, sub), "error": "no Mach-O at slice offset"}]
            except Exception as ex:
                sl = [{"arch": None, "error": _err(ex)}]
            out.extend(sl)
        return out
    return _thin(data)


def _plist_dict(pb):
    pl = plistlib.loads(pb)
    if not isinstance(pl, dict):
        raise ValueError("Info.plist root is %s, not a dictionary" % type(pl).__name__)
    return pl


def _url_schemes(pl):
    types = pl.get("CFBundleURLTypes") or []
    return sorted({s for t in (types if isinstance(types, list) else []) if isinstance(t, dict)
                   for s in (t.get("CFBundleURLSchemes") if isinstance(t.get("CFBundleURLSchemes"), list) else [])
                   if isinstance(s, str)})


def apple_summary(plist_bytes, exe_bytes, frameworks, kind):
    pl = _plist_dict(plist_bytes)
    r = {
        "platform": kind,
        "bundle_id": pl.get("CFBundleIdentifier"),
        "name": pl.get("CFBundleDisplayName") or pl.get("CFBundleName"),
        "version": pl.get("CFBundleShortVersionString"), "build": pl.get("CFBundleVersion"),
        "min_os": pl.get("MinimumOSVersion") or pl.get("LSMinimumSystemVersion"),
        "executable": pl.get("CFBundleExecutable"),
    }

    def field(key, fn, default):
        # one malformed value (or truncated binary) costs only its own field, never the report
        try:
            r[key] = fn()
        except Exception as e:
            r[key] = default
            r[key + "_error"] = _err(e)

    ats = pl.get("NSAppTransportSecurity")
    ats = ats if isinstance(ats, dict) else {}
    exc = ats.get("NSExceptionDomains")
    field("url_schemes", lambda: _url_schemes(pl), [])
    field("ats_allows_arbitrary_loads", lambda: ats.get("NSAllowsArbitraryLoads"), None)
    field("ats_exception_domains", lambda: sorted(str(k) for k in (exc if isinstance(exc, dict) else {})), [])
    bg = pl.get("UIBackgroundModes")
    field("background_modes", lambda: [str(x) for x in bg] if isinstance(bg, list) else [], [])
    field("privacy_permissions", lambda: sorted(k for k in pl if isinstance(k, str) and k.startswith("NS")
                                                and k.endswith("UsageDescription")), [])
    field("frameworks", lambda: sorted(frameworks), [])
    field("slices", lambda: macho_slices(exe_bytes) if exe_bytes else [], [])
    if any(s.get("encrypted") for s in r["slices"]):
        r["note"] = ("App Store encrypted: the code is not readable statically; the metadata here still is. "
                     "Analyze a decrypted build you are authorized to use (see references/ios.md).")
    return r


def _exe_name(pl):
    v = pl.get("CFBundleExecutable")
    return v if isinstance(v, str) and "/" not in v and v not in ("", ".", "..") else ""


def inspect_ipa(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        plist = next((n for n in names if re.match(r"Payload/[^/]+\.app/Info\.plist$", n)), None)
        if not plist:
            return {"platform": "ios", "error": "no Payload/*.app/Info.plist"}
        app = plist[:-len("Info.plist")]
        pb, too_big = _read_member(z, plist, MAX_META_BYTES)
        if too_big:
            return {"platform": "ios", "error": too_big}
        exe = app + _exe_name(_plist_dict(pb))
        eb, truncated = _read_member(z, exe, MAX_EXE_BYTES, truncate=True) if exe != app and exe in names else (b"", None)
        fws = {n[len(app) + 11:].split("/")[0] for n in names if n.startswith(app + "Frameworks/") and ".framework/" in n}
    r = apple_summary(pb, eb, fws, "ios")
    if truncated:
        r["executable_truncated"] = truncated
    return r


def inspect_app_dir(root):
    mac = os.path.isfile(os.path.join(root, "Contents", "Info.plist"))
    base = os.path.join(root, "Contents") if mac else root
    with open(os.path.join(base, "Info.plist"), "rb") as f:
        pb = f.read(MAX_META_BYTES + 1)
    if len(pb) > MAX_META_BYTES:
        return {"platform": "macos" if mac else "ios", "error": "Info.plist over the %d-byte limit" % MAX_META_BYTES}
    exe_name = _exe_name(_plist_dict(pb))
    exe = os.path.join(base, "MacOS", exe_name) if mac else os.path.join(base, exe_name)
    fdir = os.path.join(base, "Frameworks")
    fws = [d for d in os.listdir(fdir) if d.endswith(".framework")] if os.path.isdir(fdir) else []
    if exe_name and os.path.isfile(exe):
        with open(exe, "rb") as f:
            eb = _map_file(f)
            try:
                return apple_summary(pb, eb, fws, "macos" if mac else "ios")
            finally:
                if isinstance(eb, mmap.mmap):
                    eb.close()
    return apple_summary(pb, b"", fws, "macos" if mac else "ios")


# --------------------------------------------------------------------------
# Windows PE: version resource, signing certificate names, manifest
# --------------------------------------------------------------------------
VS_KEYS = ("ProductName", "CompanyName", "FileDescription", "FileVersion", "ProductVersion",
           "OriginalFilename", "LegalCopyright")


def _vs_value(blob, key):
    k = key.encode("utf-16-le") + b"\x00\x00"
    i = blob.find(k)
    if i < 0:
        return None
    j = (i + len(k) + 3) & ~3                              # values are DWORD-aligned
    end = j
    while end + 1 < len(blob) and blob[end:end + 2] != b"\x00\x00":
        end += 2
    return blob[j:end].decode("utf-16-le", "replace").strip() or None


def inspect_pe(path):
    with open(path, "rb") as f:
        data = _map_file(f)                                # mapped, not read: game executables are huge
        try:
            return _pe_summary(data, path)
        finally:
            if isinstance(data, mmap.mmap):
                data.close()


def _pe_summary(data, path):
    r = {"platform": "windows", "file": os.path.basename(path)}
    try:
        i = data.find("VS_VERSION_INFO".encode("utf-16-le"))
        if i >= 6:
            blob = data[i - 6:i - 6 + struct.unpack_from("<H", data, i - 6)[0]]
            r["version_info"] = {k: v for k in VS_KEYS for v in [_vs_value(blob, k)] if v}
    except Exception as e:
        r["version_info_error"] = _err(e)
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        opt = pe + 24
        dd = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B else 96)
        sec_off, sec_size = struct.unpack_from("<II", data, dd + 4 * 8)   # security directory
        clr = struct.unpack_from("<II", data, dd + 14 * 8)
        r["dotnet"] = bool(clr[0] and clr[1])
        r["signed"] = bool(sec_off and sec_size)
        if r["signed"]:
            cert = data[sec_off:sec_off + sec_size]
            names = []
            for m in re.finditer(rb"\x06\x03\x55\x04\x03([\x0c\x13\x14\x16\x1e])([\x01-\x7f])", cert):
                v = cert[m.end():m.end() + m.group(2)[0]]
                v = v.decode("utf-16-be" if m.group(1) == b"\x1e" else "utf-8", "replace")
                if v not in names:
                    names.append(v)
            r["certificate_names"] = names[:6]
    except struct.error:
        r["error"] = "PE headers truncated"
    except Exception as e:
        r["signature_error"] = _err(e)
    m = re.search(rb"requestedExecutionLevel\s+level=[\"'](\w+)[\"']", data)
    if m:
        r["execution_level"] = m.group(1).decode()
    return r


# --------------------------------------------------------------------------
# Games: Unity, Unreal, Godot
# --------------------------------------------------------------------------
def inspect_game_dir(root, skipped=None):
    found, files = {}, []
    for dp, dn, fn in os.walk(root, followlinks=False):
        if dp[len(root):].count(os.sep) > 4:
            dn[:] = []
            continue
        files.extend(os.path.join(dp, f) for f in fn)
    skipped = {} if skipped is None else skipped
    files = _regular_in_tree(files, root, skipped)
    rel = {os.path.relpath(p, root).replace("\\", "/"): p for p in files}
    low = {k.lower(): v for k, v in rel.items()}

    unity_ggm = next((p for k, p in low.items() if k.endswith("_data/globalgamemanagers") or k.endswith("_data/data.unity3d")), None)
    il2cpp = [k for k in low if k.endswith("gameassembly.dll") or k.endswith("libil2cpp.so") or k.endswith("global-metadata.dat")]
    mono = [k for k in rel if k.lower().endswith("_data/managed/assembly-csharp.dll")]
    if unity_ggm or il2cpp or mono:
        g = {"engine": "Unity", "backend": "IL2CPP" if il2cpp else "Mono"}
        if unity_ggm:
            with open(unity_ggm, "rb") as f:
                v = re.search(rb"\b\d{1,4}\.\d+\.\d+[abfpx]\d+", f.read(4096))
            g["version"] = v.group(0).decode() if v else None
        meta = next((p for k, p in low.items() if k.endswith("global-metadata.dat")), None)
        if meta:
            with open(meta, "rb") as f:
                head = f.read(8)
            if len(head) == 8 and struct.unpack_from("<I", head)[0] == 0xFAB11BAF:
                g["il2cpp_metadata_version"] = struct.unpack_from("<i", head, 4)[0]
        g["code"] = mono or [k for k in rel if k.lower().endswith(("gameassembly.dll", "libil2cpp.so", "global-metadata.dat"))]
        g["next"] = ("decompile Assembly-CSharp.dll with ILSpy" if not il2cpp else
                     "recover types/method names with Il2CppDumper or Cpp2IL (metadata version above), then Ghidra")
        found = g
    paks = [k for k in rel if k.lower().endswith(".pak") and "/content/paks/" in "/" + k.lower()]
    if paks and not found:
        g = {"engine": "Unreal", "paks": paks[:5]}
        with open(rel[paks[0]], "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 1024))
            tail = f.read()
        i = tail.rfind(b"\xe1\x12\x6f\x5a")
        if i >= 0 and i + 8 <= len(tail):
            g["pak_format_version"] = struct.unpack_from("<I", tail, i + 4)[0]
        g["code"] = [k for k in rel if k.lower().endswith("-shipping.exe")][:3]
        g["next"] = "game code is native in the *-Shipping binary (Ghidra); assets are in the .pak files"
        found = g
    pck = next((p for k, p in low.items() if k.endswith(".pck")), None)
    if pck and not found:
        with open(pck, "rb") as f:
            head = f.read(20)
        if head[:4] == b"GDPC":
            _fmt, major, minor, patch = struct.unpack_from("<IIII", head, 4)
            found = {"engine": "Godot", "version": "%d.%d.%d" % (major, minor, patch),
                     "code": [os.path.relpath(pck, root)],
                     "next": "unpack the .pck and recover GDScript with GDRE Tools"}
    if found:
        found["platform"] = "game"
        found.update(skipped)
    return found


# --------------------------------------------------------------------------
# dispatch + output
# --------------------------------------------------------------------------
def inspect(path):
    if os.path.isdir(path):
        if os.path.isfile(os.path.join(path, "Contents", "Info.plist")) or \
                os.path.isfile(os.path.join(path, "Info.plist")):
            return inspect_app_dir(path)
        skipped = {}
        game = inspect_game_dir(path, skipped)
        if game:
            return game
        exes = []
        for dp, dn, fn in os.walk(path, followlinks=False):
            if dp[len(path):].count(os.sep) > 2:
                dn[:] = []
            exes.extend(os.path.join(dp, f) for f in fn if f.lower().endswith(".exe"))
        exes = _regular_in_tree(exes, path, {})            # same files the game walk already counted
        if exes:
            main = max(exes, key=os.path.getsize)
            r = inspect_pe(main)
            r["note"] = "inspected the largest .exe in the folder; run triage.py on the folder for the rest"
            r.update(skipped)
            return r
        return {"error": "no app bundle, game, or executable recognized; run triage.py on it"}
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"MZ":
        return inspect_pe(path)
    if head[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
        if "AndroidManifest.xml" in names or "base/manifest/AndroidManifest.xml" in names:
            return inspect_apk(path)
        if any(n.startswith("Payload/") for n in names):
            return inspect_ipa(path)
    if head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        r = {"platform": "macho"}
        with open(path, "rb") as f:
            data = _map_file(f)
            try:
                r["slices"] = macho_slices(data)
            except Exception as e:
                r["slices"], r["slices_error"] = [], _err(e)
            finally:
                if isinstance(data, mmap.mmap):
                    data.close()
        return r
    return {"error": "not an APK, IPA, .app, PE, Mach-O, or game folder; run triage.py on it"}


def print_report(r):
    for k, v in r.items():
        if v in (None, [], {}, ""):
            continue
        if isinstance(v, list) and v and isinstance(v[0], dict):
            print("%s:" % k)
            for item in v[:25]:
                print("  - " + ", ".join("%s=%s" % (a, b) for a, b in item.items() if b not in (None, [], {})))
            if len(v) > 25:
                print("  ... %d more (use --json)" % (len(v) - 25))
        elif isinstance(v, list):
            print("%s: %s" % (k, ", ".join(map(str, v[:40])) + (" ... +%d" % (len(v) - 40) if len(v) > 40 else "")))
        elif isinstance(v, dict):
            print("%s: %s" % (k, ", ".join("%s=%s" % (a, b) for a, b in v.items())))
        else:
            print("%s: %s" % (k, v))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Extract platform metadata from an app, APK/IPA, PE, or game folder.")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.exists(args.path):
        print("error: no such path: %s" % args.path, file=sys.stderr)
        return 2
    if not os.path.isdir(args.path) and not stat.S_ISREG(os.stat(args.path).st_mode):
        print("error: not a regular file or directory (FIFO, device or socket): %s" % args.path, file=sys.stderr)
        return 2
    try:
        r = inspect(args.path)
    except (zipfile.BadZipFile, plistlib.InvalidFileException, OSError, ValueError, struct.error) as e:
        r = {"error": "%s: %s" % (type(e).__name__, e)}
    except Exception as e:                                 # last resort: still emit a report, never a traceback
        r = {"error": "internal error (partial input not reported): %s: %s" % (type(e).__name__, e)}
    if args.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print_report(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
