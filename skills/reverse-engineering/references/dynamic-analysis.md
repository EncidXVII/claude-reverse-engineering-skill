# Dynamic analysis and safe handling of untrusted samples

Dynamic analysis means running the target while observing it — debuggers,
tracers, hooks, and monitors. It's the fastest way past packing, obfuscation, and
runtime-computed values. It's also where you can hurt yourself if the target is
malicious, so isolation comes first.

## Table of contents
- Isolation rules (do this before running anything)
- Choosing an instrument
- Frida (cross-platform hooking)
- System-call / API tracing
- Behavioral monitoring (malware triage)
- Anti-analysis and how to handle it
- Emulation

## Isolation rules

If you did not build the target yourself, treat running it as potentially
destructive. A single wrong double-click can encrypt your drive or exfiltrate your
credentials.

- **Malware gets a full VM, not a container.** Run samples in a throwaway VM with
  a clean snapshot you revert after each run: REMnux (Linux distro/OVA) or
  FLARE-VM (install script for a Windows VM you provide). Containers share the host kernel, so use them
  only for CTF binaries or your own builds. Never on your host OS, never on a
  machine with data or credentials you care about.
- **Close the VM's side doors.** No shared folders, shared clipboard, or
  drag-and-drop, and no USB passthrough. Use host-only or internal networking,
  with FakeNet-NG inside the guest or an INetSim/REMnux gateway VM; never bridged
  or NAT.
- **No credentials, no sync.** The analysis environment has no logged-in accounts,
  no password manager, no mounted cloud drives, no SSH keys, no access to your
  file shares.
- **Control the network.** Default to no network, or a simulated one (a fake
  internet like `INetSim`/`FakeNet-NG`) so the sample reveals its C2 behavior
  without reaching real victims or phoning home from your IP. Only allow real
  egress deliberately, through a monitored, attributable channel, and never for
  malware that could attack third parties.
- **One sample per fresh, empty directory.** Your analysis scripts and notes live
  in a *different* directory. Pass the sample path as an argument; don't `cd` into
  its directory to run tools.
- **Guard interpreter imports.** Run Python that touches a sample with `python3 -I`
  so a planted `json.py`/`os.py`/`sitecustomize.py` beside the sample can't hijack
  an `import`. The same risk applies to any tool that loads plugins/config from the
  current directory.
- **Snapshot before, revert after.** Take the VM snapshot before detonation so you
  can diff filesystem/registry/network and then roll back clean.

These rules are non-negotiable for malware. For your own app or a CTF binary the
risk is low, but the "sample in its own dir, scripts elsewhere, `-I` for Python"
hygiene is cheap and worth keeping.

## Choosing an instrument

| You want to…                                   | Reach for…                                  |
| ---------------------------------------------- | ------------------------------------------- |
| Read/modify args & returns of specific funcs   | Frida (any), dnSpyEx (.NET), JVM agent (Java) |
| Step instruction-by-instruction                | gdb+GEF/pwndbg, lldb, x64dbg, WinDbg         |
| See every syscall / library call               | strace/ltrace (Linux), dtruss (macOS), API Monitor / Procmon (Windows) |
| Watch files/registry/processes/network         | Procmon + Procmon-style tools, `sysdig`, Sysmon |
| Catch network behavior                          | mitmproxy/Wireshark + FakeNet/INetSim (see web-apis-protocols.md) |
| Let packed code unpack itself, then dump        | debugger to OEP + process dumper            |

## Frida

Frida injects a JavaScript engine into a target process so you can hook functions
across native, Android, iOS, and more from one toolkit. It's the most versatile
single instrument in RE.

```bash
frida-ps -U                                         # processes (USB device); -R for remote
frida -f ./target -l hook.js -q -t 30 > hook.log    # spawn, run script, exit after 30s
frida -U -n AppName -l hook.js -q -t 60 > hook.log  # attach to a running app by name
frida-trace -i 'recv*' -f ./target                  # auto-generate+attach stubs (stop with a timeout)
```

Without `-q` (quiet, no prompt) the `frida` CLI drops into an interactive REPL
and waits for input, which hangs an agent's shell. `-t` sets how many seconds to
keep running in quiet mode before exiting (`-t inf` to run until killed — then
start it in the background and stop it yourself). Redirect output to a file and
read it afterwards.

Hook template (native):
```javascript
// Frida 17+ API. Resolve the export, then attach.
Interceptor.attach(Module.getGlobalExportByName('strcmp'), {
  onEnter(args) { this.a = args[0].readUtf8String(); this.b = args[1].readUtf8String(); },
  onLeave(ret)  { console.log('strcmp(', this.a, ',', this.b, ') =', ret); }
});
```
Hooking `strcmp`/`memcmp`/`strncmp` is a classic way to watch comparisons (e.g. a
CTF input check) without reading any disassembly. Language-specific hooking lives
in the Android/iOS/managed reference files.

### Frida 17 API notes (important)

Frida 17 (2025) removed the old static `Module`/`Memory` helpers. Using the
pre-17 names throws at runtime, so write hooks the new way:

- `Module.getExportByName(null, 'open')` → `Module.getGlobalExportByName('open')`
- `Module.getExportByName('libc.so', 'open')` → `Process.getModuleByName('libc.so').getExportByName('open')`
  (`findExportByName` returns `null` instead of throwing when absent)
- `Module.getBaseAddress('libc.so')` → `Process.getModuleByName('libc.so').base`
- `Memory.readU32(ptr)` / `Memory.writeU32(ptr, v)` → `ptr.readU32()` / `ptr.writeU32(v)`
- Callback enumeration (`{ onMatch, onComplete }`) is gone — the unsuffixed
  methods now return arrays: `for (const m of Process.enumerateModules()) { … }`.

The Java/ObjC/Swift bridges are no longer bundled into the GumJS runtime. They're
baked into the `frida` REPL and `frida-trace` agents (frida-tools 14+), so
one-off scripts there still work; a custom standalone agent must bundle them with
`frida-compile`.

## System-call / API tracing

Often the quickest "what does it actually do" answer:

```bash
strace -f -e trace=file,network ./target    # Linux: files + sockets, follow children
ltrace ./target                              # Linux: library calls (if not static)
dtruss ./target                              # macOS (needs SIP considerations)
```
On Windows, **Procmon** (file/registry/process/thread events) and **API Monitor**
cover the same ground; **Sysmon** logs persistently for later review.

## Behavioral monitoring (malware triage)

In a reverted-snapshot VM with simulated network, detonate and record what
changes:

- Files created/modified/deleted; new persistence (autoruns, services, scheduled
  tasks, cron, launch agents).
- Processes spawned, injection into other processes.
- Network: DNS lookups, connection attempts, C2 beacons (captured by FakeNet/
  INetSim).
- Registry/config changes.

This yields IOCs (indicators of compromise) and a behavior summary fast, and tells
you where to focus static analysis. Automated sandboxes (CAPE/Cuckoo-style) do
this systematically; a manual Procmon+Wireshark run is a fine start.

## Anti-analysis and how to handle it

Targets (especially malware and protected software) detect and resist analysis.
Recognize the technique, then neutralize it *in your environment* so you can keep
working:

- **Anti-debug**: `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`, `ptrace(PTRACE_
  TRACEME)`, `PEB.BeingDebugged`, timing checks (RDTSC deltas), `int 3` scanning.
  Counter: debugger plugins (ScyllaHide, GEF's anti-anti-debug), or hook the
  detection API to return the "safe" value.
- **Anti-VM / anti-sandbox**: checks for VM artifacts (MAC prefixes, drivers,
  registry keys), low core/RAM counts, user-activity heuristics, or long sleeps to
  outlast a sandbox timeout. Counter: harden the VM to look real, patch/skip the
  checks, or patch out the sleeps.
- **Anti-tamper / integrity checks**: the code hashes itself and refuses to run if
  modified. Counter: patch in memory after the check, or hook the check — don't
  modify the on-disk bytes it verifies.

Neutralizing these to *analyze* a sample is standard practice. Doing it to help
malware evade defenders' detection in the wild is out of scope (see the skill's
scope note).

## Emulation

When you can't or shouldn't run the target natively:

- **QEMU** — run foreign-architecture binaries (`qemu-user` for a single ELF,
  full-system to boot a firmware image). Essential for MIPS/ARM embedded work.
- **Unicorn** — a CPU emulator (QEMU-derived) you drive from Python to execute a
  slice of code (e.g. a decryption routine) in isolation and read the result.
- **Qiling** — a higher-level framework on Unicorn that emulates OS APIs, so you
  can run a function or a whole binary with fine-grained hooks and no real OS.
- **angr** — symbolic execution: explore many paths at once, solve for an input
  that reaches a target state (great for CTF "find the key" problems and for
  mapping complex branching without manual stepping).
