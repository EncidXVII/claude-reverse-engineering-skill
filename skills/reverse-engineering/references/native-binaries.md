# Native binaries — ELF, PE, Mach-O

For compiled machine code: Linux/Unix ELF executables and `.so` libraries,
Windows PE (`.exe`/`.dll`/`.sys`), and Apple Mach-O. (Managed PEs — .NET — go to
`references/managed-bytecode.md`; the triage script flags those.)

## Table of contents
- Fast facts pass (format, imports, symbols)
- Choosing a disassembler/decompiler
- Ghidra workflow
- rizin / radare2 workflow
- Debugging (gdb/lldb/x64dbg/WinDbg)
- Format-specific notes (ELF / PE / Mach-O)
- Common analysis recipes

## Fast facts pass (do this before opening a disassembler)

Identify architecture, bitness, linkage, and the import/symbol vocabulary — it
often answers the question or tells you exactly where to look.

```bash
file target                       # arch, bitness, static/dynamic, stripped?
rz-bin -I target                  # rizin: one-screen summary (arch, bits, canary, nx, pic, stripped)
rz-bin -z target                  # strings in data sections (cleaner than raw strings)
rz-bin -i target                  # imports  (what external APIs it calls)
rz-bin -E target                  # exports  (what it offers to others)
rz-bin -s target                  # symbols
# radare2 users: the same flags work with `rabin2`

# Toolchain-native equivalents:
readelf -a target                 # ELF: everything (headers, sections, dynsym, relocs)
nm -D target ; objdump -d target  # ELF/Mach-O symbols + disassembly
dumpbin /headers /imports target.dll     # PE (MSVC toolchain)
otool -hV -L target ; otool -tv target   # Mach-O headers, linked libs, disassembly
```

Read the imports like a table of contents: crypto (`EVP_`, `AES`, `BCrypt`),
network (`connect`, `send`, `WSAStartup`, `getaddrinfo`), process/injection
(`CreateRemoteThread`, `VirtualAllocEx`, `ptrace`), filesystem, registry.

## Choosing a disassembler/decompiler

- **Ghidra** (free, NSA, open source) — the default recommendation. Excellent
  decompiler, all major architectures, scriptable (Python/Java), great xrefs. Best
  all-rounder and what to suggest when the user has nothing installed.
- **rizin + Cutter** (free, open source) — rizin is the CLI/scriptable engine,
  Cutter its Qt GUI (with an optional decompiler). Superb for scripting and
  headless/batch work; pairs well with Frida.
- **radare2** — the older project rizin forked from; same spirit, different
  governance. Either is fine.
- **IDA Pro / Binary Ninja / Hopper** — commercial, excellent, use if available.
  IDA's decompiler (Hex-Rays) and Binary Ninja's IL are best-in-class. Hopper is a
  good affordable macOS/Linux option.

Default to **Ghidra for understanding** and **rizin for scripting/automation**.

## Ghidra workflow

**Agents:** use the headless export in SKILL.md step 6 (`DecompileExport.java`),
then grep the output and read slices. Details for that recipe:

- **Requirements.** Ghidra 12 needs JDK 21. Use the `.java` script: Ghidra 12+
  runs `.py` scripts only when launched through PyGhidra, and
  `decompile_export.py` is the variant for that.
- **Script args** after the output path: a case-insensitive function-name filter,
  then a max function count.
- **What the export holds.** Before the decompiled code, a map: entry points,
  imports, strings, the most-called functions (name those first), and which
  functions call network, crypto, file, process, registry, and dynamic-loading
  APIs (start reading there).
- **Large targets** (game executables, Electron/Chromium apps, anything over
  ~50 MB) can take a very long time. Analyze the one DLL or module that matters
  instead of the whole app, cap analysis with `-analysisTimeoutPerFile 900`
  (seconds) and `-max-cpu <n>`, pass the name filter and function cap, and run it
  in the background. The timeout stops auto-analysis only; the export script then
  runs with no overall limit, so an outer `timeout` is the backstop (GNU
  coreutils; `gtimeout` on macOS via Homebrew). A killed run leaves no footer,
  so treat its output as partial.
- **Re-export without re-analyzing** (new filter or output): leave
  `-deleteProject` off every run while you still want the project, and swap
  `-import <target>` for `-process <target-filename> -noanalysis`; `rm -rf "$P"`
  when done. `-import` into an existing project needs `-overwrite`.
- **Parallel runs.** One project per `mktemp -d` folder; two runs sharing a
  project collide on its lock and output file.

The GUI steps below are for a human.

1. New project → Import File → let it auto-detect format/arch → analyze with
   defaults (plus "Decompiler Parameter ID" for better signatures).
2. Go to `main`/entry (Symbol Tree → Functions, or the entry point in the Symbol
   Tree). For stripped binaries, start from exports or from the string xref.
3. Use the **Decompiler** pane (not just the listing) — read C-like output, not
   raw asm, unless you need instruction-level detail.
4. **Rename and retype** as you understand things (`L` to rename, `Ctrl+L` to
   change type). Define structs for recurring data layouts.
5. **Xrefs**: right-click a symbol → References. `Ctrl+Shift+G` jumps to an
   address. The string window (Window → Defined Strings) → double-click → xref is
   the fastest path to relevant code.

## rizin / radare2 workflow

An agent must run rizin **non-interactively**: plain `rizin target` opens a REPL
that waits for input and hangs the shell. Use `-q` (quit after) with `-c`
(commands), and write large output to a file:

```bash
rizin -q -c 'aaa; afl' target > funcs.txt          # analyze, list functions
rizin -q -c 'aaa; s main; pdf' target              # disassemble main
rizin -q -c 'aaa; axt @ sym.imp.strcmp' target     # xrefs TO a symbol (who calls it)
rizin -q -c 'iz' target                            # strings in data sections
rizin -q -c 'aaa; s main; pdg' target              # decompile (needs the rz-ghidra plugin)
# radare2: same commands with `r2 -q -c '...' target`
```

Useful commands inside those `-c` strings: `afl` (functions), `pdf` (disassemble
function), `axt`/`axf` (xrefs to/from), `iz`/`izz` (strings), `ii`/`iE`
(imports/exports). Interactive-only views like `V`/`VV` are for humans at a
terminal. Install the `rz-ghidra` (or `r2ghidra`) plugin to get Ghidra's
decompiler via `pdg`. For repeated queries, script it with `rzpipe`/`r2pipe`
from Python instead of re-running the CLI.

## Debugging

- **Linux**: `gdb` (with GEF or pwndbg for a far better UI — breakpoints, hexdump,
  heap view, patterns). `lldb` also works.
- **Windows**: `x64dbg` (free, the community standard for user-mode), WinDbg
  (kernel/driver and crash dumps), or a debugger inside IDA/x64dbg.
- **macOS**: `lldb`. Note SIP and code-signing/entitlement constraints when
  attaching.

Core moves: break at a function, inspect registers/args per the platform calling
convention, step over/into, watch a memory address, patch an instruction or flag
to test a hypothesis. Use breakpoints on imported APIs (e.g. break on `recv` to
catch inbound data) to anchor dynamically.

## Format-specific notes

**ELF (Linux/Unix)**
- Sections vs segments: `readelf -S` (sections, link-time view) vs `-l` (segments,
  load-time). `.text` code, `.rodata` constants/strings, `.data`/`.bss` globals,
  `.plt`/`.got` dynamic-call machinery.
- Stripped binaries lose `.symtab` but keep `.dynsym` (exported/imported). Recover
  more with signatures (FLIRT-like) or by matching known library code.
- Mitigations from `rz-bin -I`: NX, PIE, RELRO, stack canary, Fortify.

**PE (Windows)**
- Import Address Table (IAT) names the APIs; the delay-load and bound-import
  tables matter too. Rich header fingerprints the compiler/linker.
- Resources (`.rsrc`) hold icons, manifests, version info, and sometimes embedded
  payloads — carve them out. TLS callbacks run *before* the entry point (a classic
  anti-debug/unpack trick) — don't miss them.
- Authenticode signature: check whether it's signed and by whom.

**Mach-O (Apple)**
- Load commands describe segments (`__TEXT`, `__DATA`) and linked dylibs
  (`otool -l`). Objective-C/Swift metadata lives in `__objc_*`/`__swift5_*` and
  gives up class/method names cheaply (see `references/ios.md`).
- "Fat"/universal binaries contain multiple architectures — slice the one you want
  with `lipo -thin arm64 in -output out`.

## Common analysis recipes

- **"What does this do on startup?"** Find entry → `main` → trace the first dozen
  calls; name them as you go. Watch for config loads, network setup, and
  persistence.
- **"Where's the crypto/key?"** Import search for crypto APIs; xref to the call
  sites; if the key is derived at runtime, break on the crypto API and read the
  key buffer in the debugger.
- **"Parse this file format."** Find the parser (xref from `fopen`/`CreateFile`/
  `read`), map the struct it reads into, and define that struct in your tool.
  Confirm offsets by diffing two sample files.
- **"Patch to test a hypothesis."** In a debugger, flip a branch or return value to
  see the effect — a fast, non-destructive way to confirm what a check gates.
  (Keep patches in your analysis copy; this is for understanding, not distributing
  a modified binary.)
