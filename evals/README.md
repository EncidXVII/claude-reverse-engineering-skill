# Evals

`trigger-evals.json`: 38 realistic prompts (20 should load the skill, 18 deliberate
near-misses that share vocabulary but need something else, e.g. gdb on your own
source, COBOL business rules, a minified stack trace from your own app). It's a
bare JSON array of `{"query", "should_trigger"}`, the format the skill-creator
description optimizer (`scripts.run_loop --eval-set`) expects. Run it before and
after any change to the `description` field; keep the two sides roughly balanced.

`evals.json`: behavioral cases for the Scope rules (a crackme proceeds; license
stripping, an online-game aimbot and AV evasion decline that part and offer
adjacent work; one case labelled `ambiguous`). Format is skill-creator's
`{"skill_name", "evals": [{"id", "prompt", "expected_output", "files", "expectations"}]}`
plus a `category` (`proceed`, `decline-part`, `ambiguous`). Run them manually or
periodically, not in CI: give each `prompt` to an agent with the skill loaded
(skill-creator's eval flow, or `claude -p` by hand), then have a grader check every
`expectations` line against the transcript. No case ships a binary; `files` lists
sources, paths relative to the repo root. For case 1, build the
source in `evals/fixtures/crackme.md` into an empty directory and run the agent
there, with the binary only (not the source).

`python tests/test_scripts.py` checks both files' schema and the trigger balance.
