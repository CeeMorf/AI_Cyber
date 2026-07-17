/*
    Targets the Cobalt Strike Beacon configuration block itself, rather than a
    behavioral artifact of one Beacon feature (see
    HKTL_Win_CobaltStrike_Beacon_NamedPipes_Jul26.yar for the pipe-based rule).

    Why this is a stronger, more canonical indicator:
    Every Beacon config is serialized as a sequence of [2B field id][2B data
    type][2B length][value] TLV entries, XOR-encoded with a single-byte key.
    The first entry is always field 0x0001 (BeaconType), data type 0x0001
    (2-byte short) -- i.e. the fixed 6-byte header 00 01 00 01 00 02 before
    XOR. This structure is required by the format itself, so it survives
    Malleable C2 profile customization (which only changes field *values*,
    not the serialization format or default keys) and Artifact Kit
    customization (which touches the stager/loader, not Beacon's config
    encoder). This is the same header Didier Stevens' 1768.py and other
    public Beacon config parsers search for -- see references.

    Two literal strings below are that 6-byte header pre-XORed with Cobalt
    Strike's two known default single-byte keys:
      - 0x69 ('i'): used by Cobalt Strike versions before 4.x
      - 0x2e ('.'): used by Cobalt Strike 4.x and later
    Verified independently against 1768.py's documented key/header constants,
    not written from memory alone.

    Scope and limitations:
    - Does not require a PE/MZ header. The config blob appears in many
      container forms -- full Beacon DLLs, raw shellcode stagers, memory
      dumps, and even non-PE loaders (e.g. MSBuild-script-embedded configs,
      per SANS ISC) -- so gating on uint16(0) == 0x5A4D like the named-pipe
      rule would reduce recall for no real specificity gain here.
    - Only covers the two *default* keys. An operator who sets a custom XOR
      key (rare but possible in some tooling/forks) will not match; a
      brute-force xor(0x00-0xff) scan would catch that case too but at real
      performance cost -- not included here, consistent with the skill's
      "don't speculate on modifiers" and "bound loops"/"avoid unbounded
      scans" guidance.
    - Not tested against a goodware corpus in this environment -- run before
      production deployment, per the skill's Quality Checklist.
*/

rule HKTL_Win_CobaltStrike_Beacon_Config_Jul26 {
  meta:
    description  = "Detects a Cobalt Strike Beacon configuration block via its fixed TLV header (BeaconType field), XOR-encoded with either of Cobalt Strike's two default single-byte keys"
    author       = "mcp-hayabusa sample rules"
    reference    = "https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.py"
    reference2   = "https://isc.sans.edu/diary/30426"
    date         = "2026-07-16"
    score        = 85
    tags         = "hktl, cobaltstrike, beacon, c2, config, tlv"
    mitre_attack = "S0154"
    note         = "Dual-use tool: matches include authorized red-team/pentest engagements. Header/key values verified against Didier Stevens' 1768.py source, a primary tool in this space -- not asserted from memory alone."

  strings:
    // Raw header 00 01 00 01 00 02, pre-XORed with each of Beacon's two default keys.
    $config_key69 = "ihihik" ascii  // XOR key 0x69 ('i'), Cobalt Strike < 4
    $config_key2e = "././.," ascii  // XOR key 0x2e ('.'), Cobalt Strike 4.x+

  condition:
    filesize < 50MB and
    any of them
}
