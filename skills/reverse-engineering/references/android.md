# Android — APK, AAB, DEX, native libs

Android apps bundle Dalvik/ART bytecode (`classes*.dex`, decompiles close to Java),
resources, a manifest, and often native `.so` libraries. Analyze both the managed
layer and the native layer.

## Table of contents
- Unpack the APK/AAB
- Decompile to Java (jadx) — the main event
- Smali-level (apktool / baksmali) for patching and detail
- The manifest and resources
- Native libraries
- Dynamic analysis with Frida
- Common recipes

## Unpack

An APK is a ZIP. An AAB (App Bundle) is a ZIP of modules; convert it to an
installable APK set with Google's `bundletool` if you need to run it.

```bash
unzip -l app.apk                    # peek without extracting
unzip app.apk -d app_apk/           # into a fresh empty dir
# contents: AndroidManifest.xml (binary), classes*.dex, resources.arsc,
#           res/, assets/, lib/<abi>/*.so, META-INF/ (signatures)
```

Multi-dex apps have `classes.dex`, `classes2.dex`, … — analyze all of them.

## Decompile to Java with jadx (primary tool)

`jadx` turns DEX into readable Java. Agents use the CLI and search the output
tree; `jadx-gui` is the same engine for a human at the keyboard.

```bash
jadx -d out/ --show-bad-code app.apk          # decompile everything to out/
python3 -I <skill-dir>/scripts/extract_endpoints.py out/   # endpoints, hosts, crypto
grep -rn "loginUrl\|/api/" out/sources | head -50          # jump to relevant code
grep -rln "class .*LoginRepository" out/sources            # find a class by name
```

- Search for a UI string, URL, or API name to land on relevant code fast, then
  read callers with `grep -rn "methodName(" out/sources`.
- `--show-bad-code` keeps output for methods jadx couldn't fully decompile;
  fall back to smali (below) for those.
- `--deobf` renames obfuscated short names consistently, which makes grep usable
  on R8-minified apps.
- A human in `jadx-gui` gets full-text search, "Find Usage" xrefs, and renames
  that persist in a project file. If a jadx MCP server is connected, an agent gets
  the same live view (see `mcp-servers.md`).

If decompilation looks mangled, the app is likely obfuscated (ProGuard/R8/
DexGuard — short meaningless names like `a.a.a`). Work behaviorally: anchor on
strings, resources, and Android framework calls (`findViewById`, `onClick`,
`Retrofit`, `OkHttp`), which can't be renamed away.

## Smali level — apktool and baksmali

For exact instruction-level detail, resource decoding, or when you need to
rebuild, use smali (human-readable Dalvik assembly).

```bash
apktool d app.apk -o app_src/       # decode: smali/ + decoded manifest + res/
# ... inspect or modify app_src/smali/...
apktool b app_src/ -o rebuilt.apk   # rebuild (then it must be re-signed to install)
```

`apktool` also decodes the **binary** `AndroidManifest.xml` and `resources.arsc`
into readable XML — worth running just for that. `baksmali`/`smali` are the
lower-level DEX ⇄ smali assembler/disassembler if you want them directly.

Rebuilt APKs must be re-signed (`apksigner`) before a device will install them —
relevant when you're testing a patched build of *your own* app or a CTF target.

## Manifest and resources

Fastest route: `python3 -I <skill-dir>/scripts/app_inspect.py app.apk` reads the binary
manifest directly (package, SDK levels, permissions, exported components, deep links,
debuggable/backup/cleartext flags) without apktool.

The manifest is the app's blueprint — read it first:
```bash
# after apktool d, just open app_src/AndroidManifest.xml
```
Note: `package`, `minSdk`/`targetSdk`, exported components (`android:exported=
"true"` on activities/services/receivers/providers = attack surface and entry
points), permissions requested, `android:debuggable`, `networkSecurityConfig`
(cleartext/pinning), deep-link intent filters, and declared native libs.

`strings.xml` and other resources often hold URLs, feature flags, and sometimes
secrets developers assumed were hidden.

## Native libraries (`lib/<abi>/*.so`)

These are ELF shared objects — route them to `references/native-binaries.md`
(Ghidra/rizin). The managed↔native boundary is JNI: look for `JNI_OnLoad` and
`Java_<pkg>_<Class>_<method>` export names, which map native functions back to the
Java methods that call them. Security-sensitive logic (crypto, licensing, anti-
tamper) is frequently pushed into native code precisely because it's harder to
read — budget accordingly.

## Dynamic analysis with Frida

Frida instruments a running app: hook methods, log arguments/returns, and read
runtime values that never appear statically (decrypted strings, derived keys,
server responses). Requires a rooted device/emulator or a repackaged app with the
Frida gadget, on a target you're authorized to instrument.

```bash
frida-ps -Uai                       # list installed/running apps on USB device
frida -U -f com.example.app -l hook.js              # spawned app resumes once the script loads
frida -U -f com.example.app -l hook.js -q -t 30 > hook.log   # agent mode: no REPL, exit after 30s
```

Typical hook (log a method's I/O):
```javascript
Java.perform(function () {
  var C = Java.use('com.example.Crypto');
  C.decrypt.overload('[B').implementation = function (buf) {
    var out = this.decrypt(buf);
    console.log('[decrypt] ->', out);     // observe the plaintext
    return out;
  };
});
```

`objection` (built on Frida) gives ready-made commands for common tasks
(enumerate classes, dump keystore, inspect SQLite/preferences). For HTTPS traffic
and certificate pinning, see `references/web-apis-protocols.md`.

## Common recipes

- **"What server does it talk to?"** Search decompiled code/resources for `http`,
  `Retrofit`, base-URL constants; confirm live with an intercepting proxy
  (`web-apis-protocols.md`).
- **"Where's the key/secret?"** Search strings and `strings.xml`; if derived at
  runtime, hook the crypto class with Frida and log inputs/outputs.
- **"Is this component reachable?"** Exported components in the manifest define the
  external entry surface; trace their `onCreate`/`onReceive`/`onStartCommand`.
- **"Obfuscated — where do I start?"** Framework callbacks and library classes
  keep their real names; anchor there and on UI strings, then expand outward.
