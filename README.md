<div align="center">

<img src=".github/assets/social-preview.png" alt="Claude Reverse Engineering Skill: understand any app with your AI coding agent. Works with Claude Code, Codex, Cursor, Gemini CLI and GitHub Copilot." width="100%">

Binary analysis · APK & IPA decompilation · .NET / Java · Electron & WASM · firmware · malware triage · API & protocol recovery · Ghidra / IDA / radare2 / jadx via MCP

[![Validate](https://github.com/EncidXVII/claude-reverse-engineering-skill/actions/workflows/validate.yml/badge.svg)](https://github.com/EncidXVII/claude-reverse-engineering-skill/actions/workflows/validate.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-open%20standard-8A2BE2)](https://agentskills.io)
[![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-D97757)](#claude-code-recommended)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB)](#requirements)
[![skills.sh](https://img.shields.io/badge/skills.sh-listed-111111)](https://www.skills.sh/encidxvii/claude-reverse-engineering-skill/reverse-engineering)

</div>

---

# Claude Reverse Engineering Skill

An [Agent Skill](https://agentskills.io) that gives your AI agent a professional reverse-engineering workflow: **identify** what a file really is, **pick tools that are actually installed**, **decompile and export** code headlessly, **map the network surface**, and **report findings** that point to real addresses — while handling untrusted samples safely.

It covers native executables (ELF, PE, Mach-O), Android (APK, AAB, DEX), iOS and macOS apps, .NET and Java bytecode, JavaScript/Electron/WebAssembly, cross-platform frameworks (Flutter, React Native, Xamarin/MAUI, Unity), installers, firmware images, and network protocols.

Built for authorized work: security research, CTFs, malware analysis, interoperability, and debugging.

## Contents

- [Why this skill](#why-this-skill)
- [What it can analyze](#what-it-can-analyze)
- [Works with](#works-with)
- [Install](#install)
- [Usage](#usage)
- [Bundled tools](#bundled-tools)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [What the skill runs](#what-the-skill-runs)
- [FAQ](#faq)
- [Responsible use](#responsible-use)
- [Contributing](#contributing)
- [License](#license)

## Why this skill

- **One command to install, nothing to configure.** A standard Agent Skill: install it as a Claude Code plugin or with `npx skills add`, and it works. No cloning, no index scripts, no per-client adapters, no extra runtimes — just Python 3.8+.
- **Scripts that do the analysis.** The bundled tools read the files themselves — triage, app/platform metadata, endpoint extraction, decompiled-code export — instead of only routing the agent to someone else's tool.
- **Triage first, not guesswork.** A zero-dependency triage script reads magic bytes and real headers (PE, ELF, Mach-O, CLR), fingerprints 25+ frameworks, packers, and installers, and tells the agent exactly which playbook to open next.
- **Headless by design.** Agents can't click through a GUI. The skill ships a Ghidra post-script that exports decompiled C, imports, and strings to a text file — tested against Ghidra 12.1.4, with a CI job that re-runs it on every push — plus non-interactive commands for rizin, jadx, Frida, gdb, and lldb.
- **Drives real RE tools over MCP.** When rea, GhidraMCP, IDA Pro MCP, radare2-mcp, or jadx MCP is connected, the agent decompiles, renames, and follows cross-references directly — the skill supplies the method, the server does the calls.
- **Finds the network surface fast.** Pulls Retrofit annotations, HTTP client calls, URLs, hosts, auth headers, and crypto usage out of decompiled code and minified JS, each with `file:line`.
- **Safe with untrusted samples.** Isolation rules for malware, `python -I` against import hijacking, and an explicit rule that text inside a binary is data — never instructions — so analyzed files can't prompt-inject the agent.
- **Grounded output.** Every finding must cite an address, offset, symbol, or request the tools actually showed, say how it's known (decompiler, assembly, runtime, or inferred), and name what wasn't verified.
- **Tested on real tools, not just docs.** 63 automated checks covering every script and the skill's structure, run in CI on Linux, macOS, and Windows, plus a CI job that runs the Ghidra export against a real Ghidra release on every push.
- **Light on context.** One short `SKILL.md`; the 14 playbooks load only when a task needs them, so the skill costs almost nothing until it's used.
- **One permissive license.** Everything is Apache-2.0 — safe to use at work, fork, and ship.

## What it can analyze

| Target | Examples | Playbook |
| --- | --- | --- |
| Native binaries | `.exe` `.dll` `.sys` · ELF `.so` · Mach-O `.dylib` | [native-binaries.md](skills/reverse-engineering/references/native-binaries.md) |
| Android | `.apk` `.aab` `.dex` · native libs · smali | [android.md](skills/reverse-engineering/references/android.md) |
| iOS / Apple | `.ipa` · Mach-O apps · frameworks · `.app` bundles | [ios.md](skills/reverse-engineering/references/ios.md) |
| .NET & Java | managed `.dll`/`.exe` · `.jar` `.class` `.war` | [managed-bytecode.md](skills/reverse-engineering/references/managed-bytecode.md) |
| JS, Electron, WASM | bundles · source maps · `.asar` · `.wasm` · browser extensions | [js-electron-wasm.md](skills/reverse-engineering/references/js-electron-wasm.md) |
| Frameworks & packagers | Flutter · React Native/Hermes · Xamarin/MAUI · Unity · Godot · PyInstaller · Node SEA · Go · Rust | [frameworks-packagers.md](skills/reverse-engineering/references/frameworks-packagers.md) |
| Installers & packages | NSIS · Inno Setup · MSI · MSIX · `.deb` · `.rpm` · AppImage · `.dmg` | [frameworks-packagers.md](skills/reverse-engineering/references/frameworks-packagers.md#installers-and-os-packages) |
| Firmware & IoT | router/camera images · SquashFS/JFFS2/UBI · bare-metal blobs | [firmware-embedded.md](skills/reverse-engineering/references/firmware-embedded.md) |
| Network & APIs | HTTPS APIs · WebSockets · gRPC · custom binary protocols | [web-apis-protocols.md](skills/reverse-engineering/references/web-apis-protocols.md) |
| Running processes | Frida hooks · tracing · sandboxed malware behavior | [dynamic-analysis.md](skills/reverse-engineering/references/dynamic-analysis.md) |
| Malware | capability triage · obfuscated strings · config extraction · IOCs · YARA rules · reports | [malware-analysis.md](skills/reverse-engineering/references/malware-analysis.md) |
| Version changes | what a security update fixed · regressions · format/protocol changes between builds | [diffing.md](skills/reverse-engineering/references/diffing.md) |

## Works with

| Agent | Status | Install via |
| --- | --- | --- |
| **Claude Code** | First-class (script paths resolve automatically) | Plugin marketplace or skills folder |
| **Claude.ai / Claude Desktop** | Supported | Upload as a skill |
| OpenAI Codex CLI | Supported | `npx skills add` |
| Cursor | Supported | `npx skills add` |
| Gemini CLI | Supported | `npx skills add` |
| GitHub Copilot | Supported | `npx skills add` |
| OpenCode, Windsurf, Kiro, and other Agent Skills clients | Supported | `npx skills add` or manual copy |

Any agent that can read a `SKILL.md` and run shell commands can use the full workflow. Chat-only assistants without a shell can still follow the playbooks, but can't run the bundled scripts.

## Install

### Claude Code (recommended)

Install as a plugin — updates arrive automatically. Inside Claude Code, run:

```text
/plugin marketplace add EncidXVII/claude-reverse-engineering-skill
/plugin install reverse-engineering@reverse-engineering-skill
```

Or from your terminal:

```bash
claude plugin marketplace add EncidXVII/claude-reverse-engineering-skill
claude plugin install reverse-engineering@reverse-engineering-skill
```

Or copy the skill folder (personal = all projects, project = this repo only):

```bash
git clone https://github.com/EncidXVII/claude-reverse-engineering-skill
cp -r claude-reverse-engineering-skill/skills/reverse-engineering ~/.claude/skills/        # personal
cp -r claude-reverse-engineering-skill/skills/reverse-engineering .claude/skills/          # project
```

### Claude.ai and Claude Desktop

Download the repository, zip the `skills/reverse-engineering` folder, and upload it under **Settings → Capabilities → Skills**.

### Codex, Cursor, Gemini CLI, GitHub Copilot, OpenCode, Windsurf, Kiro

Use the open-source [`skills`](https://github.com/vercel-labs/skills) installer (the skill is listed on [skills.sh](https://www.skills.sh/encidxvii/claude-reverse-engineering-skill/reverse-engineering)):

```bash
npx skills add EncidXVII/claude-reverse-engineering-skill --skill reverse-engineering
npx skills add EncidXVII/claude-reverse-engineering-skill --skill reverse-engineering -a codex -a cursor   # pick agents
npx skills add EncidXVII/claude-reverse-engineering-skill --skill reverse-engineering -g                   # user-wide
```

<details>
<summary>Manual install paths</summary>

Copy `skills/reverse-engineering` into the agent's skills directory:

| Agent | Project | User-wide |
| --- | --- | --- |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` |
| Codex | `.agents/skills/` | `~/.agents/skills/` |
| Cursor | `.agents/skills/` | `~/.cursor/skills/` |
| Gemini CLI | `.agents/skills/` | `~/.gemini/skills/` |
| GitHub Copilot | `.agents/skills/` | `~/.copilot/skills/` |
| OpenCode | `.agents/skills/` | `~/.config/opencode/skills/` |
| Windsurf | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` |
| Kiro | `.kiro/skills/` | `~/.kiro/skills/` |

</details>

## Usage

Just describe the task — the skill loads automatically. No special syntax needed.

```text
I have a stripped ELF from a CTF (./crackme). What does the password check do?

Decompile base.apk and list every API endpoint it calls, with the auth headers.

What is this installer from our vendor actually going to drop on the machine?

Unpack this router firmware and find the web admin backend.

Here's a malware sample in my analysis VM — summarize its behavior and IOCs.

How does this Electron app talk to its native addon?
```

In Claude Code you can also invoke it directly with `/reverse-engineering` (or `/reverse-engineering:reverse-engineering` when installed as a plugin).

## Bundled tools

All scripts are standard-library Python — nothing to `pip install`.

| Script | What it does |
| --- | --- |
| [`triage.py`](skills/reverse-engineering/scripts/triage.py) | Identify a file **or a whole folder** (install dir, extracted archive, macOS `.app`): format, architecture, real .NET check, framework/packer/installer fingerprints, Go and Rust dependency lists with versions, crypto constants (AES, SHA, ChaCha, RSA…) with addresses, hashes, per-section entropy, interesting strings, container contents, and next steps. |
| [`app_inspect.py`](skills/reverse-engineering/scripts/app_inspect.py) | Platform facts in one call: Android manifest (permissions, exported components, deep links, debug/backup flags), iOS/macOS Info.plist, entitlements and App Store encryption per architecture, Windows version info and signer, game engine/version/backend and where the code lives (Unity, Unreal, Godot). |
| [`check_tools.py`](skills/reverse-engineering/scripts/check_tools.py) | Which RE tools, JDK version, and Python RE libraries are installed, grouped by task, with install hints for what's missing. |
| [`extract_endpoints.py`](skills/reverse-engineering/scripts/extract_endpoints.py) | Network and crypto surface of a decompiled tree: Retrofit/smali annotations, client calls, URLs, hosts, auth headers, crypto APIs. Handles minified one-line bundles; masks secrets by default. |
| [`DecompileExport.java`](skills/reverse-engineering/scripts/ghidra/DecompileExport.java) | Ghidra headless post-script: one UTF-8 file with a program map first (entry points, imports with DLL names, strings, most-called functions, and which functions call network, crypto, file, process, registry and loading APIs), then decompiled C for every function. `decompile_export.py` is the PyGhidra variant. |

Real `triage.py` output for a Rust executable (trimmed):

```text
type        : PE (Windows .exe/.dll/.sys)
format      : PE32+
arch        : x86-64
subsystem   : Windows console
dotnet      : False
entropy     : 6.428/8.0  (moderate — typical of native code with data)
SECTIONS
  .text      raw  9,209,856  entropy 6.31
  .rdata     raw  3,086,336  entropy 6.03
FINGERPRINTS
  * Rust binary — demangle names (rustfilt), expect heavy inlining; panic strings leak source paths
SUGGESTED NEXT STEPS
  - references/native-binaries.md — `rz-bin -I` / `rz-bin -i` (imports), then decompile
    headless with scripts/ghidra/DecompileExport.java (SKILL.md step 6)
```

Run them yourself:

```bash
python skills/reverse-engineering/scripts/check_tools.py
python -I skills/reverse-engineering/scripts/triage.py path/to/file-or-folder
python -I skills/reverse-engineering/scripts/extract_endpoints.py path/to/decompiled-output
```

## How it works

1. **Toolbox check** — find out what's installed before planning.
2. **Triage** — identify the artifact from its bytes, not its extension.
3. **Safe workspace** — one sample per empty folder; nothing untrusted runs on the host.
4. **MCP first** — drive Ghidra/IDA/radare2/jadx directly when a server is connected.
5. **Route** — open the playbook for the target type.
6. **Static first, dynamic to confirm** — headless decompilation, then hooks or a debugger in isolation when values only exist at runtime.
7. **Record** — findings with addresses and offsets, using the [report template](skills/reverse-engineering/assets/findings-template.md).

## Requirements

- **Required:** Python 3.8+ and an agent with shell access.
- **Optional, detected at runtime:** Ghidra 12+ with JDK 21, rizin or radare2, jadx, apktool, ILSpy (`ilspycmd`), Frida, mitmproxy, binwalk, Node.js. Install only what your target needs — `check_tools.py` prints the exact command for anything missing.

## What the skill runs

Transparency for anyone reviewing it before install:

- **No network access, no telemetry.** None of the bundled scripts open a network connection or send data anywhere.
- **Never executes the file being analyzed.** `triage.py`, `app_inspect.py` and `extract_endpoints.py` only read bytes; the Ghidra scripts run inside your own Ghidra.
- **`check_tools.py`** looks up tool names on your `PATH` and in common install folders (or a `--ghidra-dir` you pass), checks whether a few Python libraries are importable, and runs `java -version`.
- **Everything else is guidance.** The playbooks tell the agent which tools to run (for example Ghidra, jadx, or Frida) when you have them installed; your agent's permission settings decide whether it asks before running them.

## FAQ

**Can Claude reverse engineer an APK?**
Yes. The skill has Claude decompile the APK with jadx, detect frameworks like Flutter or React Native, and extract the app's API endpoints with `extract_endpoints.py`.

**Does it work with Ghidra MCP or IDA Pro MCP?**
Yes. If an RE MCP server is connected, the skill tells the agent to use it for decompiling, renaming, and cross-references. Without one, it uses the bundled headless Ghidra export.

**Does it work without Claude?**
Yes. It follows the open Agent Skills standard and installs into Codex, Cursor, Gemini CLI, GitHub Copilot, OpenCode, and others with `npx skills add`.

**Can it decompile any program?**
It can analyze nearly any format, but results depend on the installed tools and on the target's protections: strong encryption without the key, or heavy virtualization-based obfuscation, can't be undone by any tool.

**Is it safe to point at malware?**
The skill never executes samples itself and enforces isolation rules for any dynamic step — but run malware analysis inside a disposable VM with no credentials, as you would without an AI agent.

**Is reverse engineering legal?**
It's widely legal for security research, interoperability, and analyzing software you own or are authorized to test, but laws and license terms vary by country. See [Responsible use](#responsible-use).

## Responsible use

This project is for analyzing software you **own, are authorized to test, or are permitted to study**: CTF challenges, lab malware samples, your own products, and scoped security engagements. The skill declines to help with piracy, license or DRM removal to avoid paying, cheats for online multiplayer games, and making malware evade detection. You are responsible for following applicable laws and license agreements.

## Contributing

Issues and pull requests are welcome — new target types, better tool recommendations, and fixes as tools evolve.

- Keep `SKILL.md` short (routing and principles); put depth in `references/`.
- Bundled scripts stay standard-library only and cross-platform.
- Every command in a playbook must be non-interactive.
- Run the test suite before opening a PR:

```bash
python tests/test_scripts.py
```

```text
.
├── .claude-plugin/          Claude Code plugin + marketplace manifests
├── .github/workflows/       CI: tests on Linux/macOS/Windows, frontmatter lint, real-Ghidra export
├── evals/                   trigger evals for tuning the skill description
├── skills/reverse-engineering/
│   ├── SKILL.md             entry point: workflow, routing, safety rules
│   ├── references/          14 playbooks, loaded on demand
│   ├── scripts/             triage, tool check, endpoint extraction, Ghidra export
│   └── assets/              findings report template
└── tests/                   dependency-free test suite
```

## License

[Apache 2.0](LICENSE)

---

<sub>Independent project, not affiliated with or endorsed by Anthropic, OpenAI, Google, GitHub, or the NSA. Claude, Ghidra, IDA Pro, and other product names are trademarks of their respective owners.</sub>
