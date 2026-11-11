# Frameworks, packagers, and installers

Many apps aren't "a binary" in the usual sense: the executable is a generic
runtime (Electron, Flutter engine, Unity player, Python interpreter) and the
app's real logic sits in a separate container next to it or inside it.
Disassembling the runtime wastes hours. Find the container, then use the tool
that reads that format. `scripts/triage.py` fingerprints most of these and
prints the matching hint; this page explains each one.

## Table of contents
- Mobile cross-platform (Flutter, React Native, Xamarin/MAUI, Cordova/Capacitor)
- Game engines (Unity, Godot, Unreal)
- Packaged scripting runtimes (Python, Node.js, AutoIt)
- Compiled languages with special structure (Go, Rust, Delphi, GraalVM)
- Installers and OS packages
- How to confirm what you're looking at

## Mobile cross-platform

| Framework | Where the app logic lives | Read it with |
| --- | --- | --- |
| **Flutter** | Dart AOT snapshot in `lib/<abi>/libapp.so` (Android) or `App.framework/App` (iOS); `libflutter.so` is just the engine | `blutter` (recovers Dart classes/functions for the matching Dart version), then Ghidra on `libapp.so` with its output |
| **React Native** | JS bundle: `assets/index.android.bundle` (Android) or `main.jsbundle` (iOS) | Plain JS: beautify and read. Hermes bytecode (magic `c6 1f bc 03`): `hermes-dec` to disassemble/decompile |
| **Xamarin / .NET MAUI** | .NET assemblies packed into the APK (`assemblies/`, an assembly store `.blob`, or `libassemblies.*.blob.so`) | Extract the assemblies (assembly-store unpackers), then ILSpy — see `managed-bytecode.md` |
| **Cordova / Capacitor / Ionic** | HTML/JS under `assets/www/` or `assets/public/` | Read directly; it's a web app (see `js-electron-wasm.md`) |
| **Kotlin Multiplatform / Compose** | Regular DEX (Android) or native framework (iOS) | Normal Android/iOS flow; Kotlin metadata helps restore names |

The Java/Kotlin (or Obj-C/Swift) layer of these apps is usually a thin shell.
Note it, then move to the container.

## Game engines

`python3 -I <skill-dir>/scripts/app_inspect.py <game-folder>` reports the engine, version,
Unity scripting backend (Mono or IL2CPP, with the IL2CPP metadata version), Unreal pak
format, or Godot version, plus where the game code lives.

Typical legitimate goals: modding a single-player game you own, reading a save or
asset format for a tool, or interoperability. (Cheats for online multiplayer are
out of scope — see the skill's scope section.)

| Engine | Where the logic lives | Read it with |
| --- | --- | --- |
| **Unity (Mono)** | `*_Data/Managed/Assembly-CSharp.dll` (+ other game DLLs) | ILSpy — near-source C# |
| **Unity (IL2CPP)** | C# compiled to native: `GameAssembly.dll` / `libil2cpp.so` plus `global-metadata.dat` | Il2CppDumper or Cpp2IL to recover type and method names from the metadata, then Ghidra with the generated symbols |
| **Godot** | Game pack `.pck` (separate or embedded in the exe) | GDRE Tools to unpack the pack and recover GDScript |
| **Unreal** | Native code in the game exe; assets in `.pak`/`.utoc` containers | Ghidra for code (UE reflection names survive in strings); FModel/UE Viewer for asset formats |

Asset extraction for Unity is done with AssetRipper/AssetStudio — useful for
format work, not needed for code.

## Packaged scripting runtimes

- **PyInstaller** — the exe (or `_internal/` folder) is a bootloader plus an
  archive of `.pyc` files. Extract with `pyinstxtractor-ng`, find the entry
  script, then decompile `.pyc` with a tool that supports that Python version
  (`pycdc` for broad coverage; disassemble with `python3 -m dis` under the same
  Python version when decompilers fail on new bytecode).
- **Nuitka** — Python compiled to C. There's no bytecode to decompile; analyze
  as native code. Module and constant names still leak in strings.
- **py2exe / cx_Freeze** — a `library.zip` of `.pyc` beside the exe; unzip and
  decompile as above.
- **Node.js SEA / pkg / nexe** — JS embedded in a Node launcher. SEA stores it in
  a `NODE_SEA_BLOB` resource/section; pkg appends a virtual filesystem. Carve the
  payload and read the JS. If it was compiled to a V8 snapshot or bytecode
  (`bytenode`, `.jsc`), static recovery is limited — observe it dynamically.
- **AutoIt** — the script is an embedded resource; extract it with an AutoIt
  script extractor instead of disassembling the interpreter.

## Compiled languages with special structure

- **Go** — large static binaries with full runtime metadata. Ghidra 11+ recovers
  Go function names and types; `GoReSym` extracts symbols and build info
  (Go version, module paths) when the binary is stripped.
- **Rust** — demangle with `rustfilt`; expect heavy inlining and monomorphized
  generics. Panic messages leak source paths (`/rustc/<hash>/…`, crate paths).
- **Delphi / C++Builder** — RTTI and form resources (`.dfm`) carry class and
  event-handler names; IDR or Ghidra Delphi scripts recover them.
- **GraalVM native-image** — Java compiled ahead of time; no bytecode exists.
  Analyze as native; class and method names survive in strings/metadata.
- **.NET single-file / ReadyToRun** — single-file bundles embed the assemblies in
  the apphost (ILSpy opens them). ReadyToRun assemblies still contain IL, so
  ILSpy works; Native AOT does not — treat it as native.

## Installers and OS packages

Extract installers **without running them** — running one executes its scripts.
Unpack into a fresh empty directory, then run `triage.py` on that directory.

| Format | Extract with |
| --- | --- |
| NSIS (`Nullsoft`) | `7z x setup.exe -oout/` |
| Inno Setup | `innoextract -d out/ setup.exe` |
| MSI | `msiextract` (msitools), `lessmsi`, or `7z x` |
| InstallShield | `7z x`; cabinets may need `unshield` |
| MSIX / APPX | it's a ZIP: unzip, read `AppxManifest.xml` |
| Squirrel (Electron updaters) | `7z x` → `.nupkg` (also a ZIP) → app files |
| `.deb` | `ar x pkg.deb` then extract `data.tar.*` |
| `.rpm` | `rpm2cpio pkg.rpm \| cpio -idmv` (or `7z x`) |
| AppImage | ELF runtime + SquashFS: find the SquashFS offset (`binwalk`) and `unsquashfs -o <offset>`; avoid `--appimage-extract` on untrusted files since it runs the binary |
| macOS `.dmg` / `.pkg` | `7z x` (dmg); `pkgutil --expand-full` (pkg, macOS) or `xar -xf` + extract `Payload` |
| Browser extension (`.crx`, `.xpi`) | ZIP (CRX adds a small header that `7z x`/`unzip` skip): read `manifest.json`, then the scripts |

Installer scripts are worth reading too: NSIS and Inno scripts show what gets
installed, registered, and launched.

## How to confirm what you're looking at

1. `triage.py` on the file — check the FINGERPRINTS block.
2. `triage.py` on the install directory — check APP MARKERS and the largest files.
3. Strings: framework names, version banners, and bundle/asset file names are
   strong signals (`flutter`, `UnityPlayer`, `hermes`, `_MEIPASS`, `Go build ID`).
4. If two signals disagree, trust file structure (sections, containers, magic
   bytes) over strings.
