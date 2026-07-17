# Severity Guide

Expands on Standard 2 in `SKILL.md`. Sigma's `level` field must be exactly one of
`low`, `medium`, `high`, `critical` — no abbreviations, no other values — and every
rule must justify its chosen level in prose inside `description`.

The question to ask is not "how bad would this be if real?" but **"how much does
this specific signal, by itself, distinguish attack from normal administration?"**
A rule that only fires on unambiguous attacker behavior earns a high level even if
the technique itself is low-impact; a rule that also fires on routine admin work
earns a lower level even if the technique is severe when it *is* an attack.

## critical

The technique has no legitimate business use in this environment, or the specific
pattern matched is not something legitimate tooling produces. A `critical` alert
should be actionable on its own, without needing to correlate against other events
or check an allowlist first.

- Ask: "Is there any plausible, non-contrived reason a legitimate admin, script, or
  product would produce exactly this signal?" If the honest answer is no, `critical`
  is justified.
- Example from this repo: `proc_creation_pth_mimikatz_command_line.yml` — the
  `sekurlsa::pth /user: /ntlm: /run:` argument combination is Mimikatz syntax; no
  legitimate administrative tool constructs a command line that way.
- Example: `proc_creation_lsass_dump_comsvcs.yml` — invoking comsvcs.dll's MiniDump
  export via rundll32 against LSASS is a known LOLBin credential-dumping technique
  with no everyday administrative workflow behind it.
- Don't default here. `critical` used as a starting point rather than a conclusion
  is exactly what the review checklist rejects — see SKILL.md's note on this.

## high

A strong indicator with a narrow, explainable false-positive path — the kind of
thing you can name specifically (a product, a job function, a migration script),
not a vague "could be anything."

- Ask: "Can I name the specific legitimate scenario that would trip this, and is
  that scenario rare/identifiable enough that seeing it still deserves a look?"
- Example: `security_dcsync_replication_rights.yml` — DCSync rights exercised by a
  non-DC, non-system account is high because the *only* narrow legitimate cases are
  a newly promoted DC or a known sync account (Entra Connect), both nameable and
  allowlistable.
- Example: `proc_creation_vaultcmd_credential_manager_list.yml` — VaultCmd has no
  everyday admin workflow, but a help-desk credential-troubleshooting session or a
  profile-migration script could plausibly invoke it, so it's high rather than
  critical.
- Example: `security_pass_the_hash_ntlm_anomaly.yml` — NTLM logon with zero Key
  Length is a strong PtH indicator, but some legacy appliances authenticate this way
  by design, hence high rather than critical and a note to baseline first.

## medium

Legitimate administrative or business activity can produce the same signal without
being especially rare — the alert needs correlation (time, account, source, volume)
before it's actionable, not just a glance.

- Ask: "Would a security-aware admin, on seeing this alert alone, need to go check
  something else before deciding if it's bad?" If yes, that's medium territory.
- Example: `security_kerberoasting_rc4_ticket.yml` — RC4-HMAC service ticket
  requests happen legitimately whenever a service account or legacy app hasn't been
  migrated to AES, which is common enough in real environments that this needs
  volume/targeting context, not just a single hit.
- Example: `signinlogs_ropc_authentication_flow.yml` — ROPC is discouraged but still
  a supported, intentionally-used OAuth flow for specific legacy/test applications.

## low

Informational or hygiene-oriented signal: worth recording for an investigation
timeline or a baseline drift report, but not something that should page anyone or
sit in a triage queue on its own. No rule in this repo currently uses `low` — if you
find yourself reaching for it, double check whether the signal is detection-grade at
all, or whether it belongs in `environment/baselines.yml` instead.

## Quick decision heuristic

1. Would literally any legitimate process produce this exact signal? If no → `critical`.
2. Can you name the *specific* legitimate scenario(s), and are they rare/identifiable? → `high`.
3. Is the legitimate scenario common enough that you need extra context to act? → `medium`.
4. Is this closer to a baseline/audit fact than a suspicious event? → `low`.

Whatever you land on, the `description` block must spell out which of these
reasonings applied — see the `## The five standards` → `### 2. Severity must be
justified` section of `SKILL.md` for the exact convention.
