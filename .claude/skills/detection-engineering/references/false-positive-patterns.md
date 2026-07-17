# False Positive Patterns

Expands on Standard 3 in `SKILL.md`. Every rule's `falsepositives` list must be
non-empty, and every entry must name a concrete, specific scenario — never a hedge
like `- Unknown` or `- False positives are possible`. A good entry lets a future
analyst decide, without guessing, whether a specific alert matches a known-benign
pattern and should be allowlisted or tuned.

The categories below are the recurring shapes false positives take in this repo and
in Windows/AD detection generally. Use them as a checklist when writing
`falsepositives` for a new rule: which of these apply to *this specific* detection?

## 1. Security/EDR products doing their job

Antivirus, EDR agents, and system utilities often need the same access or behavior
an attacker would use, because their job is to inspect the same things attackers
target.

- `proc_access_lsass_memory_read.yml`: "Endpoint security products and system
  utilities that legitimately inspect LSASS" — and the rule backs this with an
  actual `filter_known_tools` exclusion listing `MsMpEng.exe`, `procexp64.exe`, etc.,
  not just a documented hope.
- When this applies: name the *specific products/processes* if you know your
  environment, not just "security software" in the abstract.

## 2. Infrastructure accounts that legitimately need elevated rights

Service accounts, sync agents, and infrastructure components that require
privileges normal user accounts don't, where the privilege itself is expected but
the *account* exercising it needs to be verified against a known list.

- `security_dcsync_replication_rights.yml`: "Azure AD Connect / Entra Connect sync
  accounts (should be reviewed and allow-listed explicitly)" and "Legitimate
  replication traffic from a newly promoted Domain Controller."
- The parenthetical instruction ("should be reviewed and allow-listed explicitly")
  is doing real work here — it tells the analyst what to *do* with a confirmed FP,
  not just that one might occur.

## 3. Legacy protocols/applications that can't use modern alternatives

Older software or appliances that were built before a more secure alternative
existed, and that can't be trivially upgraded.

- `security_kerberoasting_rc4_ticket.yml`: "Legacy applications or service accounts
  that do not support AES encryption."
- `security_pass_the_hash_ntlm_anomaly.yml`: "Some legacy applications and
  appliances authenticate this way by design; baseline before alerting."
- `signinlogs_ropc_authentication_flow.yml` / `adfs_legacy_auth_usernamemixed.yml`:
  legacy OAuth/WS-Trust flows still deliberately used by specific old apps or hybrid
  connectors.
- When this applies: if you can name the specific legacy system class (not just
  "legacy stuff"), do so — it's what makes the entry actionable instead of a hedge.

## 4. Help desk / support workflows

Interactive troubleshooting that happens to touch the same surface as an attacker
technique, usually identifiable because it's tied to a ticket or a specific support
process.

- `proc_creation_vaultcmd_credential_manager_list.yml`: "Help-desk troubleshooting
  of a user's saved RDP/network credentials via vaultcmd (should be tied to a known
  support ticket)."
- The "should be tied to a known support ticket" clause is the pattern to copy: it
  gives the analyst a concrete thing to check (does a ticket exist?) rather than
  just a plausible-sounding excuse.

## 5. Migration / provisioning / automation tooling

One-time or scheduled processes (profile migrations, backups, imaging, CI/CD) that
run unattended and can trip detections built around "no one does this by hand."

- `proc_creation_vaultcmd_credential_manager_list.yml`: "User-profile migration or
  backup tooling that enumerates vault entries prior to a profile transfer."
- When this applies: note whether the activity is expected to be a one-time event
  (easy to explain away once) or recurring (worth a permanent exclusion).

## 6. Genuinely unlikely — say so explicitly

Sometimes there really isn't a plausible legitimate path. Standard 3 still requires
an entry in this case — write the absence-of-FP reasoning out instead of leaving the
field empty.

- `proc_creation_pth_mimikatz_command_line.yml`: "Unlikely; these argument
  combinations are not used by legitimate administrative tools."
- `proc_creation_lsass_dump_comsvcs.yml`: "Unlikely; comsvcs.dll MiniDump is rarely
  invoked for legitimate administrative purposes."
- This differs from a hedge because it states a *reason* ("these argument
  combinations are not used by...") rather than just asserting uncertainty.

## Writing a good entry: the test

Before adding a `falsepositives` entry, check it against this: **could a new analyst
use this sentence to decide, without asking you, whether a specific alert is the
documented FP or not?**

- Bad: `- False positives are possible` — gives the analyst nothing to check against.
- Bad: `- Unknown` — same problem, plus it undercuts the rule's credibility.
- Good: `- <specific process/account/workflow> doing <specific specific thing>
  (<what to do about it, if anything>)`.

If a rule has a `filter_*` block in `detection:`, its corresponding
`falsepositives` entry should describe exactly what that filter excludes — the
filter is the enforcement, the `falsepositives` entry is the documentation of why it
exists. See `proc_access_lsass_memory_read.yml` for the pairing (`filter_known_tools`
↔ the EDR/utilities entry).
