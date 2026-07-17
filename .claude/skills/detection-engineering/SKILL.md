---
name: detection-engineering
description: |
  Detection rule development standards. Activate when:
  - Writing, creating, or modifying Sigma rules
  - Reviewing detection rules for quality or completeness
  - Discussing detection coverage, gaps, or improvements
  - Working with any YAML file under rules/ (or hayabusa/rules/)
  - Asked to validate, check, or audit detection rules
  Enforces this project's rule-quality standards before a rule is considered done.
version: 0.1.0
---

# Detection Engineering Standards

## Overview

This project's custom rules (`rules/`) are hand-written Sigma-style YAML consumed by Hayabusa. Every rule added or edited here — and every review of one — must satisfy the five standards below. These are stricter than bare Sigma validity: a rule can be syntactically valid Sigma and still fail these checks.

Ground truth for existing conventions: read a couple of files in `rules/` (e.g. `security_dcsync_replication_rights.yml`, `proc_creation_pth_mimikatz_command_line.yml`) before writing a new one, to match field ordering and style.

## The five standards

### 1. ATT&CK technique mapping is required

Every rule's `tags` list must include at least one `attack.tXXXX` (or `attack.tXXXX.YYY` for a sub-technique) entry, lowercase.

- Prefer the most specific sub-technique available (`attack.t1003.006`, not just `attack.t1003`) when the detection logic is specific to that sub-technique.
- Also tag the relevant tactic(s), e.g. `attack.credential-access` — technique tags and tactic tags are both expected, matching the existing rules in this repo.
- A rule with zero `attack.t\d+` tags is incomplete. Do not write or approve one.
- If you're targeting a gap, check coverage first with `analyze_coverage` or `detection://attack/techniques/{id}` rather than guessing the ID.

### 2. Severity must be justified

Sigma's `level` field (not a field literally named `severity`) must be one of exactly: `low`, `medium`, `high`, `critical`. No other values, no abbreviations in the rule file itself.

Every rule must also carry a one-line justification for the chosen level. This project's rules don't have a dedicated YAML field for this — put it in the `description` block (as prose) since `description` is already free text and every existing rule uses it that way. Example reasoning to include:

- `critical` — the technique has no legitimate business use and directly indicates compromise (e.g. Pass-the-Hash command-line syntax).
- `high` — strong indicator but with a narrow, explainable false-positive path (e.g. DCSync rights used by non-DC accounts).
- `medium` / `low` — legitimate administrative activity can produce the same signal; severity reflects how much correlation/context is needed to act on it.

When reviewing a rule, reject a `level` that isn't argued for, and reject `critical` used as a default rather than a conclusion.

### 3. False positive conditions must be documented

Every rule must have a non-empty `falsepositives` list (Sigma's native field — this project already uses it consistently). Each entry must be a concrete, specific scenario, not a hedge.

- Bad: `- Unknown` / `- False positives are possible`
- Good: `- Azure AD Connect / Entra Connect sync accounts (should be reviewed and allow-listed explicitly)`

If you genuinely believe there are no plausible false positives, say so explicitly and explain why (e.g. "Unlikely; these argument combinations are not used by legitimate administrative tools" — see `proc_creation_pth_mimikatz_command_line.yml`), rather than leaving the field empty or omitting it.

### 4. At least one test case is required

Sigma has no standard field for this, so this project uses a custom top-level `test_cases` list (unknown keys are harmless — Hayabusa and Sigma tooling ignore fields they don't recognize). Add it after `falsepositives`:

```yaml
test_cases:
    - description: Mimikatz sekurlsa::pth invocation with all three required args
      should_match: true
      sample_fields:
          EventID: 4688
          Channel: Security
          CommandLine: 'mimikatz.exe "sekurlsa::pth /user:admin /ntlm:<hash> /run:cmd.exe"'
    - description: Benign process creation with none of the pth argument markers
      should_match: false
      sample_fields:
          EventID: 4688
          Channel: Security
          CommandLine: 'powershell.exe -Command Get-Process'
```

- At minimum, include one `should_match: true` case that a reader can trace through the `detection:` block by hand and confirm it matches.
- A `should_match: false` case (near-miss) is strongly preferred whenever the rule has filters/exclusions, to prove the filter logic actually excludes something plausible.
- A rule with no `test_cases` is incomplete — don't write or approve one without it, even though nothing in the Hayabusa toolchain enforces this mechanically today.

### 5. Rule filenames must be lowercase with underscores

The filename stem (used as `rule_name` in the `detection://rules/{rule_name}` URI, via `_custom_rule_name`) must be `lowercase_with_underscores`, no spaces, no hyphens, no mixed case. Follow the existing prefix convention seen in `rules/`:

- `security_*` — rules keyed on Windows Security-channel events
- `proc_creation_*` — process-creation rules
- `proc_access_*` — process-access rules

Pick the prefix that matches `logsource.category`/`logsource.service`, then a short slug of what's detected, e.g. `security_kerberoasting_rc4_ticket.yml`. This mirrors `_LOGSOURCE_FILE_PREFIXES` used by the `suggest_rule` tool for auto-generated drafts — stay consistent with it even when writing a rule by hand.

## Review checklist

When reviewing any Sigma rule (new or edited) in this repo, check all five, in this order, and call out every failure — don't stop at the first one:

1. [ ] `tags` contains at least one `attack.tXXXX[.YYY]` entry
2. [ ] `level` is exactly `low`/`medium`/`high`/`critical`, and the `description` explains why that level
3. [ ] `falsepositives` is non-empty and each entry is a specific scenario, not a hedge
4. [ ] `test_cases` exists with at least one `should_match: true` entry that traces through `detection:` correctly
5. [ ] filename is `lowercase_with_underscores.yml` matching the existing prefix convention

Also sanity-check anything the checklist doesn't cover but would break the rule at scan time: `detection.condition` references every selection/filter block actually defined, and `logsource` matches an existing prefix pattern rather than inventing a new one without reason.

## Validation

After creating or modifying a rule, validate it:

```
python .claude/skills/detection-engineering/scripts/validate-rule.py path/to/rule.yml
```

This checks standards 1-5 above (ATT&CK tags, severity level, falsepositives, test_cases, filename convention) and prints a JSON report with a `valid` boolean and an `issues` list of anything that failed. Exit code is 0 if all checks pass, 1 if any fail, 2 on a file/parse error.

## Reference material

- `references/example-rules/lsass_memory_access.yml` — a fully worked, standards-compliant rule with inline comments pointing at where each of the five standards lives in the file. Start here when writing a new rule from scratch.
- `references/severity-guide.md` — expands Standard 2: decision heuristics and worked examples (drawn from this repo's actual rules) for choosing between `low`/`medium`/`high`/`critical`.
- `references/false-positive-patterns.md` — expands Standard 3: the recurring shapes false positives take (EDR/security products, infrastructure accounts, legacy protocols, help-desk workflows, migration tooling) plus a checklist for writing a specific entry instead of a hedge.
