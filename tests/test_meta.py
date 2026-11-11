#!/usr/bin/env python3
"""Dependency-free consistency checks for the repo's metadata and evals.

Runs with plain `python tests/test_meta.py`. Covers what test_scripts.py doesn't:
eval file schemas and balance, version agreement across manifests, and the Java
and Python Ghidra exports staying in sync.

Exit code 0 = all passed, 1 = something failed.
"""
from __future__ import annotations

import ast
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "reverse-engineering")
EVALS = os.path.join(ROOT, "evals")

_failures = []
_passed = 0


def check(name, cond, detail=""):
    global _passed
    if cond:
        _passed += 1
        print("  ok   " + name)
    else:
        _failures.append(name + ((" — " + detail) if detail else ""))
        print("  FAIL " + name + ((" — " + detail) if detail else ""))


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), ""
    except (OSError, ValueError) as e:
        return None, str(e)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# 1. Trigger evals: bare array of {query, should_trigger}, no dupes, balanced.
# ---------------------------------------------------------------------------
def test_trigger_evals():
    print("\n[evals] trigger-evals.json schema and balance")
    data, err = load_json(os.path.join(EVALS, "trigger-evals.json"))
    check("trigger-evals.json is valid JSON", data is not None, err)
    if data is None:
        return
    check("trigger-evals is a JSON array", isinstance(data, list))
    if not isinstance(data, list):
        return
    bad = [i for i, e in enumerate(data)
           if not (isinstance(e, dict) and set(e) == {"query", "should_trigger"}
                   and isinstance(e["query"], str) and e["query"].strip()
                   and isinstance(e["should_trigger"], bool))]
    check("every entry is exactly {query: str, should_trigger: bool}", not bad, "indexes %s" % bad)
    if bad:
        return
    queries = [e["query"].strip().lower() for e in data]
    dupes = sorted(set(q for q in queries if queries.count(q) > 1))
    check("no duplicate queries", not dupes, "; ".join(dupes))
    pos = sum(e["should_trigger"] for e in data)
    neg = len(data) - pos
    check("at least 16 positives and 16 negatives", pos >= 16 and neg >= 16, "%d/%d" % (pos, neg))
    check("positives and negatives within 25% of each other",
          min(pos, neg) * 4 >= max(pos, neg) * 3, "%d/%d" % (pos, neg))


# ---------------------------------------------------------------------------
# 2. Behavioral evals: skill-creator evals.json format plus a category.
# ---------------------------------------------------------------------------
def test_behavior_evals():
    print("\n[evals] evals.json schema")
    data, err = load_json(os.path.join(EVALS, "evals.json"))
    check("evals.json is valid JSON", data is not None, err)
    if not isinstance(data, dict):
        return
    check("skill_name matches the skill", data.get("skill_name") == "reverse-engineering", str(data.get("skill_name")))
    cases = data.get("evals")
    check("evals is a non-empty list", isinstance(cases, list) and bool(cases))
    if not isinstance(cases, list):
        return
    categories = {"proceed", "decline-part", "ambiguous"}
    ids = []
    for i, c in enumerate(cases):
        label = "case %s" % (c.get("id", i) if isinstance(c, dict) else i)
        ok = (isinstance(c, dict) and isinstance(c.get("id"), int)
              and isinstance(c.get("prompt"), str) and c["prompt"].strip()
              and isinstance(c.get("expected_output"), str) and c["expected_output"].strip()
              and isinstance(c.get("files", []), list)
              and isinstance(c.get("expectations"), list) and c["expectations"]
              and all(isinstance(x, str) and x.strip() for x in c["expectations"])
              and c.get("category") in categories)
        check(label + " has id, prompt, expected_output, expectations, category", ok)
        if isinstance(c, dict):
            ids.append(c.get("id"))
            for f in c.get("files") or []:
                ext = os.path.splitext(str(f))[1].lower()
                check(label + " ships no prebuilt binary (" + str(f) + ")",
                      ext not in (".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".apk", ".o"))
                check(label + " file exists (" + str(f) + ")", os.path.isfile(os.path.join(ROOT, str(f))))
    check("eval ids are unique", len(ids) == len(set(ids)), str(ids))
    seen = {c.get("category") for c in cases if isinstance(c, dict)}
    check("covers proceed, decline-part and ambiguous", categories <= seen, ",".join(sorted(map(str, seen))))


# ---------------------------------------------------------------------------
# 3. plugin.json, marketplace.json and SKILL.md agree on one semver version.
# ---------------------------------------------------------------------------
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def skill_md_version():
    text = read(os.path.join(SKILL, "SKILL.md"))
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    # metadata:\n  version: "x" (quoted or bare), without needing PyYAML
    v = re.search(r"^metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+version:\s*[\"']?([^\"'\s]+)", m.group(1) + "\n", re.M)
    return v.group(1) if v else None


def test_versions():
    print("\n[meta] version consistency")
    pj, err = load_json(os.path.join(ROOT, ".claude-plugin", "plugin.json"))
    check("plugin.json is valid JSON", pj is not None, err)
    versions = {"plugin.json": (pj or {}).get("version"), "SKILL.md metadata.version": skill_md_version()}
    mp, _ = load_json(os.path.join(ROOT, ".claude-plugin", "marketplace.json"))
    if "version" in (mp or {}).get("metadata", {}):
        versions["marketplace.json metadata.version"] = mp["metadata"]["version"]
    for p in (mp or {}).get("plugins", []):
        if p.get("name") == "reverse-engineering" and "version" in p:
            versions["marketplace.json plugin entry"] = p["version"]
    for where, v in versions.items():
        check(where + " is semver", isinstance(v, str) and bool(SEMVER.fullmatch(v)), repr(v))
    distinct = set(versions.values())
    check("all versions match", len(distinct) == 1,
          ", ".join("%s=%s" % kv for kv in versions.items()))


# ---------------------------------------------------------------------------
# 4. The Java and Python Ghidra exports flag the same API families.
# ---------------------------------------------------------------------------
def java_api_groups(src):
    m = re.search(r"API_GROUPS\s*=\s*\{(.*?)\n\s*\};", src, re.S)
    if not m:
        return None
    lit = r'"((?:[^"\\]|\\.)*)"'

    def unescape(s):
        return re.sub(r"\\(.)", lambda e: {"n": "\n", "t": "\t"}.get(e.group(1), e.group(1)), s)

    return [(unescape(a), unescape(b))
            for a, b in re.findall(r"\{\s*" + lit + r"\s*,\s*" + lit + r"\s*\}", m.group(1))]


def python_api_groups(src):
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "API_GROUPS"):
            return [tuple(g) for g in ast.literal_eval(node.value)]
    return None


def test_api_groups_sync():
    print("\n[ghidra] DecompileExport.java and decompile_export.py API_GROUPS match")
    gdir = os.path.join(SKILL, "scripts", "ghidra")
    java = java_api_groups(read(os.path.join(gdir, "DecompileExport.java")))
    py = python_api_groups(read(os.path.join(gdir, "decompile_export.py")))
    check("found API_GROUPS in the Java export", bool(java))
    check("found API_GROUPS in the Python export", bool(py))
    if java and py:
        diff = [("java", g) for g in java if g not in py] + [("python", g) for g in py if g not in java]
        check("API_GROUPS identical (names, regexes, order)", java == py,
              "; ".join("only in %s: %s" % (side, g[0]) for side, g in diff) or "order differs")


def main():
    print("Checking repo metadata at:\n  " + ROOT)
    for t in (test_trigger_evals, test_behavior_evals, test_versions, test_api_groups_sync):
        try:
            t()
        except Exception as e:  # one broken group shouldn't hide the others
            check(t.__name__ + " ran", False, "%s: %s" % (type(e).__name__, e))
    print("\n" + "=" * 60)
    if _failures:
        print("FAILED ({} ok, {} failed):".format(_passed, len(_failures)))
        for f in _failures:
            print("  - " + f)
        return 1
    print("ALL PASSED ({} checks)".format(_passed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
