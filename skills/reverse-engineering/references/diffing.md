# Comparing versions (diffing)

When you have two builds of the same program, comparing them is usually faster
than analyzing either one from scratch: the difference isolates exactly what
changed. Typical reasons — understanding what a vendor's security update fixed so
you can verify and prioritize it, finding the cause of a regression, tracking how
a file format or protocol changed for an interoperable tool, or seeing what a new
malware variant added.

## Table of contents
- Pick the right level
- Native binaries
- Managed code, apps, and scripts
- Firmware and packages
- Reading the result

## Pick the right level

Start at the cheapest level that can answer the question, and only go deeper for
the parts that changed:

1. **Files** — which files in the package or install changed at all (hashes).
2. **Metadata** — version info, imports/exports, strings, sections.
3. **Functions** — which functions changed, were added, or were removed.
4. **Code** — the instruction or decompiled-C difference inside a changed function.

```bash
# 1-2: what changed at the file and metadata level
python3 -I <skill-dir>/scripts/triage.py old/ --json > old.json
python3 -I <skill-dir>/scripts/triage.py new/ --json > new.json
rz-diff -t imports old.bin new.bin                  # imports added/removed
rz-diff -t strings old.bin new.bin                  # strings added/removed
```

## Native binaries

Function-level matching is the core step: tools pair up functions between the two
builds (by call graph, constants, and structure, since addresses shift between
builds) and score how similar each pair is.

- **BinDiff** (free) — with Ghidra (BinExport plugin) or IDA. Gives matched,
  changed, and unmatched functions with similarity scores and a side-by-side
  graph view.
- **Diaphora** (free) — IDA or Ghidra plugin; strong at matching and at showing
  pseudocode diffs.
- **Ghidra Version Tracking** — built in; ports your names and comments from an
  analyzed old build onto the new one, which saves re-doing the work.
- **rz-diff** (rizin) / **radiff2** (radare2) — command line; fine for quick
  byte-level and function-level comparisons:
  ```bash
  rz-diff -t functions old.bin new.bin   # function-level comparison
  ```

Headless option without a GUI: export both builds with
`scripts/ghidra/DecompileExport.java` (see SKILL.md step 6) and diff the two text
files. Function names like `FUN_1400123a0` change between builds, so match by
imported calls and strings inside each function rather than by name.

Watch for noise: compiler and linker changes reorder code and change register
allocation without any real change in behavior. Look at the functions with
partial similarity (roughly 0.5–0.95) first — identical ones didn't change and
very low scores are usually unrelated code.

## Managed code, apps, and scripts

Decompile both versions to source and use ordinary text diffing — far easier than
native code:

```bash
jadx -d old_src old.apk && jadx -d new_src new.apk
git diff --no-index --stat old_src new_src        # which classes changed
git diff --no-index old_src/sources/com/example new_src/sources/com/example
```

The same works for .NET (`ilspycmd -p -o old_src old.dll`), Java (`jadx`/CFR), and
JS bundles (beautify both first). Obfuscated apps rename classes between builds,
so match by strings and API calls, not by class names.

## Firmware and packages

Extract both images into separate fresh directories, then:

```bash
diff -rq old_root new_root                 # files added, removed, or changed
```

Then triage and diff only the binaries that changed — usually a handful out of
thousands. Configuration files and startup scripts often explain the change
before you open a disassembler.

## Reading the result

- Write down each meaningful change as old behavior → new behavior, with the
  function addresses in both builds.
- For a security fix, the typical signature is a new bounds or length check, a
  changed comparison, or input validation added before an existing call — confirm
  your reading by checking what inputs the new code now rejects.
- Carry your names and notes forward (Version Tracking, or by hand) so the next
  version's diff starts from an analyzed baseline.
