# iOS / Apple — IPA, Mach-O apps, frameworks

iOS apps are Mach-O binaries (Objective-C and/or Swift) packaged in an IPA. Apple
platforms expose rich runtime metadata, so class and method names often come back
for free — but App Store binaries are **encrypted** (FairPlay) until decrypted
from memory on a real device.

## Table of contents
- Unpack the IPA
- The encryption problem (and when it applies)
- Static analysis (class-dump, Hopper/Ghidra, Objective-C vs Swift)
- Entitlements, Info.plist, embedded data
- Dynamic analysis (Frida / LLDB)
- Common recipes

## Unpack

An IPA is a ZIP:
```bash
unzip app.ipa -d app_ipa/
# Payload/<App>.app/  contains:
#   <App>            the Mach-O executable
#   Info.plist       app metadata
#   embedded.mobileprovision / *.entitlements
#   Frameworks/      bundled .dylib/.framework (analyze these too)
#   assets, nibs, etc.
```

Analyze the main executable *and* anything in `Frameworks/` — third-party SDKs and
the app's own split-out code live there.

## The encryption problem

App Store apps ship with an encrypted `__TEXT` (FairPlay DRM). Check the load
command:
```bash
otool -l "Payload/App.app/App" | grep -A4 LC_ENCRYPTION_INFO
# cryptid 1 => still encrypted ; cryptid 0 => already decrypted / never encrypted
```

If `cryptid 1`, static tools see ciphertext. Decryption happens legitimately in
memory when the app runs on a device the user controls; research tooling dumps the
decrypted image from a **jailbroken device** you own (e.g. via a Frida-based
dumper). Enterprise/ad-hoc, developer, and your-own-build binaries are typically
*not* encrypted and analyze directly. Only decrypt apps you are authorized to
study.

## Static analysis

Once you have a decrypted (or never-encrypted) Mach-O:

- **Metadata for free.** Objective-C keeps class/method names in `__objc_*`
  sections. Recover them:
  ```bash
  class-dump "Payload/App.app/App"        # Obj-C headers: classes, methods, ivars
  ```
  Ghidra and rizin also parse this metadata; rizin: `rz-bin -I`, then `rz-bin -c` for
  classes. Hopper is a popular commercial choice on macOS with good Obj-C/Swift
  support.
- **Swift** mangles names but still embeds type metadata. Demangle with
  `swift demangle` (or tool built-ins). Swift's heavy generics/inlining make the
  decompile noisier than Obj-C; lean on the metadata and dynamic analysis.
- **Mach-O mechanics** (segments, linked dylibs, fat slices) are in
  `references/native-binaries.md`.

## Entitlements, Info.plist, embedded data

Fastest route: `python3 -I <skill-dir>/scripts/app_inspect.py app.ipa` (or a `.app` folder)
prints the Info.plist essentials, entitlements from the code signature, frameworks, and
whether each architecture slice is App Store encrypted, on any OS.

```bash
plutil -p "Payload/App.app/Info.plist"          # bundle id, URL schemes, ATS config
codesign -d --entitlements :- "Payload/App.app" # capabilities the app is granted
```

`Info.plist` reveals URL schemes (deep links), background modes, and App Transport
Security exceptions (cleartext allowances). Entitlements show keychain groups,
app groups, and special capabilities — useful for mapping data flow and attack
surface.

## Dynamic analysis

On a device/simulator you control:

- **Frida** — same model as Android (`references/android.md`): hook Obj-C/Swift
  methods, log arguments and return values, read runtime-only values. Obj-C hooks
  are especially clean:
  ```javascript
  var m = ObjC.classes.LoginManager['- validateToken:'];
  Interceptor.attach(m.implementation, {
    onEnter: function (args) { console.log('token =', new ObjC.Object(args[2]).toString()); }
  });
  ```
  `objection` provides canned iOS commands (keychain dump, pasteboard, class
  enumeration, pinning bypass helpers).
- **LLDB** — attach for instruction-level work; mind SIP, code signing, and
  entitlement/`get-task-allow` constraints on attaching to a process.
- HTTPS interception and pinning are covered in
  `references/web-apis-protocols.md`.

## Common recipes

- **"List the app's classes and methods."** `class-dump` (Obj-C) or the tool's
  class view; for Swift, demangle the metadata symbols.
- **"Find the networking / endpoints."** Strings for `http`/host names; classes
  named `*API`/`*Client`/`*Service`; confirm live with a proxy.
- **"Read a value computed at runtime."** Hook the producing method with Frida and
  log it — the fastest route on iOS given how much is dynamic dispatch.
- **"It's encrypted (cryptid 1)."** You need a decrypted dump from a device you
  own; otherwise work from `Info.plist`, entitlements, strings in unencrypted
  segments, and the frameworks.
