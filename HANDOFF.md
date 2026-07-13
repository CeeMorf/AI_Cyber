# HANDOFF

Status of the mcp-hayabusa MCP server as of 2026-07-12. This is a working demo/practice
build, not a production SOC deployment — see "What's left to do" before treating any of
this as real.

## What we built

Everything lives in `server.py` (single-file FastMCP server). It exposes **4 tools** and
**13 resources**, all detailed in `CLAUDE.md`'s Architecture section (read that for the
"how it's implemented" level of detail — this doc is the "what and why" level).

### Tools

| Tool | Purpose |
|---|---|
| `scan_evtx` | Run Hayabusa against an EVTX file, return findings as JSON (filter by severity/title) |
| `get_hayabusa_rules` | Search/list all ~4,964 detection rules (builtin + custom) by keyword |
| `analyze_coverage` | Coverage report (`covered`/`partial`/`gap`) for an ATT&CK technique ID *or* tactic name, against our custom rules |
| `suggest_rule` | For a technique that isn't covered: suggest a detection approach (grounded in matching builtin rules, or a keyword-based guess) and optionally scaffold a draft rule file |

### Resources

Everything under the `detection://` scheme, all custom-content-only (not the vendored
builtin rule set):

- **Rules** — `detection://rules`, `.../{rule_name}`, `.../by-technique/{id}`
- **ATT&CK coverage** — `detection://attack/techniques/{id}` (name/description + coverage assessment)
- **Playbooks** — `detection://playbooks`, `.../{playbook_name}`, `.../by-alert/{alert_name}`
- **Environment** — `detection://environment/hosts`, `.../services`, `.../baselines`
- **Investigations** — `detection://investigations`, `.../{case_id}`, `.../by-technique/{id}`

### Content on disk

| Directory | Contents | Status |
|---|---|---|
| `rules/` | 6 custom Sigma rules (LSASS access/dump, DCSync, Kerberoasting, 2x Pass-the-Hash) | Real detection logic, all `status: test` |
| `playbooks/` | 4 IR playbooks (credential-theft, pass-the-hash, dcsync, kerberoasting) | Real, generic IR content — usable as-is |
| `environment/` | hosts.yml, services.yml, baselines.yml | **Placeholder** (`example_data: true`) — see below |
| `investigations/` | 4 past-case files (INV-2026-009/014/021/033) | **Placeholder** (`example_data: true`) — see below |

The rules and playbooks are real, reusable security content. The environment and
investigations data is explicitly fake — see "Decisions & why" for why we didn't try to
make it look real.

## How to use it

**Run it:** `python3 server.py` (already wired into `.mcp.json` for MCP clients). Install
deps first with `pip3 install -r requirements.txt`.

**Scan a log:**
```
scan_evtx(file_path="samples/UACME_59_Sysmon.evtx", min_severity="high")
```

**Check coverage before/after adding a detection:**
```
analyze_coverage("credential-access")          # whole tactic
analyze_coverage("T1003")                      # one technique + its sub-techniques
```

**Fill a gap found above:**
```
suggest_rule("T1003.002")                      # suggestion only
suggest_rule("T1003.002", create_rule_file=True)  # writes a draft into rules/
```
Note: for a parent technique (has sub-techniques) `suggest_rule` won't guess — it tells
you which sub-techniques are uncovered and asks you to re-call with one of those.

**During an actual (or drill) investigation**, the intended flow is:
1. An alert fires → `detection://playbooks/by-alert/{alert title or rule name}` to find the relevant playbook.
2. Check `detection://environment/baselines` for whether the observed behavior matches a known-benign pattern before escalating.
3. `detection://investigations/by-technique/{id}` to see if this technique has fired before and how it was handled.
4. Work the playbook's triage/investigation/containment/eradication/recovery steps.

**Before using this for real:** replace the placeholder content in `environment/` and
`investigations/` with your actual inventory and case history (same YAML schema, same
`example_data`/`note` convention — just set `example_data: false` or drop the field once
it's real data, and update/remove the `note`).

## What's left to do

Roughly in priority order:

1. **Replace `environment/` and `investigations/` placeholder data with real content.**
   Nothing in these resources should inform an actual decision until this happens — see
   the "Decisions" section for why we didn't fake this convincingly instead.
2. **Promote custom rules past `status: test`.** All 6 custom rules are still `test`,
   which is why `analyze_coverage`/`detection://attack/techniques/{id}` report them as
   `partial` rather than `covered` even though a rule exists. Promote to `stable` once
   validated against real telemetry (false-positive rate checked, etc.).
3. **Close real coverage gaps.** `analyze_coverage("credential-access")` currently shows
   0/17 top-level techniques fully `covered`, 15/17 `gap` for custom rules (the vendored
   builtin set covers much more — this is specifically about our custom layer). Use
   `suggest_rule` to scaffold rules for the highest-value gaps, starting with the
   uncovered `T1003.*` sub-techniques (SAM, NTDS, LSA Secrets, cached domain creds).
4. **No automated test suite.** `test_server.py` is a manual smoke script for `scan_evtx`
   only — none of the newer tools/resources have any test coverage beyond the manual
   verification done while building them. Worth a real pytest suite, especially for the
   YAML-parsing edge cases below.
5. **Real MCP-client integration testing.** Everything so far has been verified by calling
   the Python functions directly and via `mcp.list_tools()`/`mcp.read_resource()` in a
   script — not through an actual MCP client (Claude Desktop, etc.) end to end.
6. **Decide what to do about the `attack.defense-evasion` tag vs. live MITRE data.**
   MITRE's current ATT&CK data has split "Defense Evasion" into `stealth` and
   `defense-impairment` tactics (see Decisions below); our rule tags (and the wider Sigma
   corpus) still use the old `attack.defense-evasion` label. `analyze_coverage` handles
   the query-time mismatch with a hint, but if you want tactic-based tooling to be fully
   consistent, the tags themselves would need auditing at some point.
7. **Optional:** playbooks/investigations only have a `by-alert`/`by-technique` lookup,
   no other filter axes (e.g. investigations by host, by status, by date range). Add if
   the workflow calls for it — didn't build these speculatively.

## Decisions & why

- **Custom rules are additive to, and tracked separately from, the vendored builtin
  Hayabusa rule set.** `scan_evtx`/`get_hayabusa_rules` read both; all `detection://`
  resources scope to custom content only. This predates this session but shapes
  everything built on top of it.

- **`analyze_coverage`/`suggest_rule` reuse the exact same coverage-assessment logic as
  the pre-existing `detection://attack/techniques/{id}` resource** (extracted into
  `_assess_technique_coverage`), rather than reimplementing it. Its existing
  parent-vs-leaf asymmetry — a parent technique counts as `covered` if *any* rule matches
  each sub-technique, while a leaf technique requires a `stable`-status rule — was
  preserved as-is when refactoring, since it was already documented, intentional
  behavior, not something to "fix" incidentally while adding new tools.

- **`suggest_rule` never invents detection logic for a parent (multi-sub-technique)
  ATT&CK ID.** It reports which sub-techniques are uncovered and asks you to pick one.
  A rule tagged with just a broad parent technique isn't a meaningful detection target,
  and guessing which sub-behavior you meant would be worse than asking.

- **`suggest_rule`'s suggestions are grounded in real data, not invented expertise.** It
  looks at how the vendored builtin corpus (~5,000 rules) already detects a technique and
  bases its logsource suggestion on that. Only when *nothing* in the entire vendored
  corpus covers a technique does it fall back to a keyword-based guess — and the response
  explicitly says so, rather than presenting a guess with false confidence.

- **MITRE's live ATT&CK data no longer has a `defense-evasion` tactic** — current STIX
  data has it split into `stealth` and `defense-impairment`. Discovered this while
  building tactic-name support for `analyze_coverage`; added `LEGACY_TACTIC_HINTS` so a
  query for the old name gets a helpful pointer instead of a bare "not found." Rule tags
  in this repo (and the wider Sigma ecosystem) still use the old name — this doesn't
  break technique-ID-based rule matching (keyed off stable `T\d+` IDs), only tactic-name
  lookups.

- **Environment and investigation data ship as explicitly-labeled placeholder content
  (`example_data: true` + a `note` field), not fabricated-to-look-real data.** Unlike
  rules/playbooks (generic security domain knowledge, safe to write directly), hosts,
  services, baselines, and case history are facts about a *specific real deployment* that
  can't be derived from this codebase. Inventing something plausible-looking risked it
  being mistaken for real infrastructure or a real incident later. Asked before building
  either; the choice both times was clearly-marked illustrative placeholder data over
  either empty scaffolding or blocking on real input.

- **The placeholder environment/investigation/playbook content is a deliberately
  cross-referenced worked example, not four disconnected demos.** Same fictional
  environment (`CORP.LOCAL`, hosts `DC01`/`DC02`/`SQL01`/`FS01`/`JMP01`/`WKS-*`) runs
  through all of it — e.g. the `svc_backup` NTLM baseline explains a false-positive
  investigation case *and* the pass-the-hash playbook's false-positives section; the
  JMP01-only LSASS-tooling baseline is what let a placeholder investigation escalate
  quickly. Point of this: to show how the four resource types are meant to be used
  together, not just that each one works in isolation.

- **File-per-item (`rules/`, `playbooks/`, `investigations/`) vs. one-file-per-category
  (`environment/`).** The first three are open-ended namespaces of many independently
  named things, so each gets its own file and the filename *is* the canonical ID used in
  the resource URI (no separate "name" field duplicated inside the YAML, to avoid two
  names for one thing drifting apart). `environment/` is exactly three fixed categories
  (hosts, services, baselines) requested up front, not a namespace — so each is one file,
  loaded and returned whole.

- **Two real bugs caught during testing, both YAML gotchas worth knowing if you're
  hand-writing more playbook/investigation files:**
  - A plain-scalar YAML list item containing `": "` (colon + space) — e.g. `- Pull the
    process tree: parent, command line...` — silently parses as a single-key mapping
    instead of a string. Hit this in 3 of the first 4 playbook files; fixed by quoting.
    Documented in `CLAUDE.md`.
  - YAML parses unquoted dates (`opened: 2026-03-04`) into Python `datetime.date`
    objects, which aren't JSON-serializable on their own — broke a plain `json.dumps` on
    the raw dict during testing (FastMCP's own resource-response encoding handled it
    fine). Fixed with `_iso_date` normalization in `_parse_investigation`.
