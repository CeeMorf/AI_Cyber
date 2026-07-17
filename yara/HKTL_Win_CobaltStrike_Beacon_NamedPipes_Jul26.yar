/*
    Cobalt Strike is a commercially licensed, dual-use adversary-simulation
    platform. Its Beacon payload is used both by authorized red teams/pentesters
    and by real threat actors (it is one of the most widely abused post-exploitation
    frameworks in criminal and APT intrusions alike). Category is HKTL_, not MAL_,
    for that reason -- a match here means "Cobalt Strike Beacon," not "malicious,"
    and should be triaged against known-authorized engagements before escalation.

    Scope and limitations (read before deploying):
    - Beacon's network behavior (URIs, headers, User-Agent, jitter/sleep) is
      fully reconfigurable via Malleable C2 profiles, and operators routinely
      customize these specifically to evade default-value signatures. This rule
      does NOT rely on any profile-dependent network indicator for that reason.
    - It targets named-pipe format strings that Beacon's post-exploitation
      modules (execute-assembly, psexec-family lateral movement, SSH client)
      construct internally with sprintf-style substitution. These are far more
      stable across Malleable C2 customization than network indicators, but they
      can still change between Cobalt Strike major versions -- treat this rule
      as one detection layer, not a complete one, and pair it with a maintained,
      continuously-updated ruleset (see references) plus network/behavioral
      detection.
    - Not tested against a goodware corpus in this environment (no VirusTotal
      goodware access here) -- run `yr scan` against a local clean-file set
      before production deployment, per the skill's Quality Checklist.
*/

rule HKTL_Win_CobaltStrike_Beacon_NamedPipes_Jul26 {
  meta:
    description  = "Detects Cobalt Strike Beacon via default named-pipe format strings used by its post-exploitation modules (execute-assembly, psexec-family lateral movement, SSH client)"
    author       = "mcp-hayabusa sample rules"
    reference    = "https://attack.mitre.org/software/S0154/"
    reference2   = "https://github.com/elastic/protections-artifacts"
    date         = "2026-07-16"
    score        = 70
    tags         = "hktl, cobaltstrike, beacon, c2, post-exploitation, named-pipe"
    mitre_attack = "S0154"
    note         = "Dual-use tool: matches include authorized red-team/pentest engagements. Confirm against known-authorized activity before treating as an incident."

  strings:
    // Default named-pipe format strings Beacon constructs for post-ex modules.
    // Individually distinctive (not generic pipe-naming patterns seen in
    // legitimate software); required as a group of 2+ to reduce single-string risk.
    $pipe1 = "\\pipe\\MSSE-%d-server" ascii
    $pipe2 = "\\pipe\\status_%d" ascii
    $pipe3 = "\\pipe\\postex_ssh_%d" ascii
    $pipe4 = "\\pipe\\postex_%d" ascii

  condition:
    // Cheap checks first: size bound, then PE magic bytes.
    filesize < 20MB and
    uint16(0) == 0x5A4D and

    // Require 2 of 4 -- a single hit could plausibly be a naming coincidence,
    // two independent Beacon-specific pipe formats together is not.
    2 of ($pipe*)
}
