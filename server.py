import json
import os
import platform
import re
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import date
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

mcp = FastMCP("hayabusa")

REPO_ROOT = Path(__file__).resolve().parent
HAYABUSA_DIR = REPO_ROOT / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / ("hayabusa.exe" if platform.system() == "Windows" else "hayabusa")
BUILTIN_RULES_DIR = HAYABUSA_DIR / "rules"
RULES_CONFIG_DIR = BUILTIN_RULES_DIR / "config"
CUSTOM_RULES_DIR = REPO_ROOT / "rules"

# Compact technique index built by scripts/download_attack_data.py from the
# MITRE ATT&CK Enterprise STIX bundle (~50MB raw; this keeps just id, name,
# description, and sub-technique relationships for the ~700 techniques).
ATTACK_TECHNIQUES_FILE = REPO_ROOT / "attack" / "enterprise-attack-techniques.json"

# Rule sources merged for both scanning and listing. Each entry is
# (label, root dir, subdirectory to exclude from that root, if any).
# The builtin tree's "config" subdirectory holds field-mapping data, not
# detection rules, so it's excluded there; the custom tree has no such subdir.
RULE_SOURCES = (
    ("builtin", BUILTIN_RULES_DIR, RULES_CONFIG_DIR),
    ("custom", CUSTOM_RULES_DIR, None),
)

# Ordered from least to most severe. Hayabusa abbreviates some of these
# ("informational" -> "info", "medium" -> "med", "critical" -> "crit") in its
# output, so both the full name and the abbreviation map to the same rank.
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
SEVERITY_ALIASES = {
    "informational": "informational",
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "high": "high",
    "critical": "critical",
    "crit": "critical",
}
SCAN_TIMEOUT_SECONDS = 300


OUTPUT_FORMATS = ("summary", "full")
# Fields dropped from each finding in "summary" output_format. These hold
# bulky secondary detail (call stacks, file hashes, version info, etc.)
# that's rarely needed to triage a result.
SUMMARY_DROP_FIELDS = ("ExtraFieldInfo",)

# libyaml bindings if available; ~10x faster than the pure-Python loader,
# which matters when parsing several thousand rule files per call.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _normalize_severity(value: str) -> str:
    canonical = SEVERITY_ALIASES.get(value.strip().lower())
    if canonical is None:
        raise ToolError(
            f"Invalid min_severity {value!r}. Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )
    return canonical


def _normalize_output_format(value: str) -> str:
    canonical = value.strip().lower()
    if canonical not in OUTPUT_FORMATS:
        raise ToolError(
            f"Invalid output_format {value!r}. Must be one of: {', '.join(OUTPUT_FORMATS)}"
        )
    return canonical


def _merge_rule_sources(dest_dir: Path) -> Path:
    """Combine all RULE_SOURCES into one real directory tree for Hayabusa's -r flag.

    Hayabusa's rule loader walks -r's directory but doesn't follow symlinked
    subdirectories it finds along the way, so a symlink-based merge silently
    drops everything past the first level. Hardlinking instead gives it an
    ordinary directory tree to walk, at effectively no cost since no file data
    is copied.
    """
    for label, root, exclude_dir in RULE_SOURCES:
        if not root.exists():
            continue
        for path in root.rglob("*.yml"):
            if ".git" in path.parts:
                continue
            if exclude_dir is not None and exclude_dir in path.parents:
                continue
            target = dest_dir / label / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(path, target)
    return dest_dir


@mcp.tool()
def scan_evtx(
    file_path: str,
    min_severity: str = "informational",
    rule_filter: str = "",
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan an EVTX file with Hayabusa and return findings as structured JSON.

    Args:
        file_path: Path to the EVTX file to scan.
        min_severity: Minimum severity level to include (informational, low, medium, high, critical).
        rule_filter: Only include findings whose rule title contains this string (case-insensitive), e.g. "lateral" or "mimikatz".
        output_format: "summary" (default) drops bulky auxiliary detail from each finding; "full" returns everything Hayabusa reports.
        max_results: If set, return at most this many findings.
    """
    evtx_path = Path(file_path).expanduser()
    if not evtx_path.exists():
        raise ToolError(f"EVTX file not found: {evtx_path}")
    if not evtx_path.is_file():
        raise ToolError(f"Not a file: {evtx_path}")

    if not HAYABUSA_BIN.exists():
        raise ToolError(
            f"Hayabusa binary not found at {HAYABUSA_BIN}. "
            "Run scripts/download_hayabusa.sh to install it."
        )

    min_severity = _normalize_severity(min_severity)
    output_format = _normalize_output_format(output_format)
    if max_results is not None and max_results < 1:
        raise ToolError(f"Invalid max_results {max_results!r}. Must be a positive integer.")

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        merged_rules_dir = _merge_rule_sources(Path(tmp_dir) / "rules")
        command = [
            str(HAYABUSA_BIN),
            "json-timeline",
            "-f", str(evtx_path),
            "-o", str(output_path),
            "-r", str(merged_rules_dir),
            "-c", str(RULES_CONFIG_DIR),
            "-m", min_severity,
            "-L",  # JSONL output: one compact JSON object per line
            "-w",  # no-wizard: scan everything, don't prompt
            "-C",  # clobber: overwrite the output file
            "-q",  # quiet: suppress the launch banner
            "-Q",  # quiet-errors: don't write a separate error log file
            "-K",  # no-color: keep output free of ANSI escape codes
            "-N",  # no-summary: skip the results summary table
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            raise ToolError(f"Failed to execute Hayabusa binary at {HAYABUSA_BIN}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS} seconds"
            ) from exc

        if result.returncode != 0 or not output_path.exists():
            details = (result.stderr or result.stdout or "no output").strip()
            raise ToolError(f"Hayabusa scan failed: {details[-2000:]}")

        findings = []
        with output_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if rule_filter:
        needle = rule_filter.strip().lower()
        findings = [f for f in findings if needle in f.get("RuleTitle", "").lower()]

    total_event_count = len(findings)
    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [
            {k: v for k, v in finding.items() if k not in SUMMARY_DROP_FIELDS}
            for finding in findings
        ]

    return {
        "file": str(evtx_path),
        "min_severity": min_severity,
        "rule_filter": rule_filter or None,
        "output_format": output_format,
        "total_event_count": total_event_count,
        "event_count": len(findings),
        "truncated": max_results is not None and total_event_count > max_results,
        "findings": findings,
    }


def _iter_rule_files():
    for _label, root, exclude_dir in RULE_SOURCES:
        if not root.exists():
            continue
        for path in root.rglob("*.yml"):
            if ".git" in path.parts:
                continue
            if exclude_dir is not None and exclude_dir in path.parents:
                continue
            yield path


def _parse_rule_metadata(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.load(f, Loader=_YAML_LOADER)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict) or "title" not in data:
        return None

    logsource = data.get("logsource") or {}
    tags = data.get("tags") or []
    return {
        "title": data.get("title"),
        "id": data.get("id"),
        "level": data.get("level"),
        "status": data.get("status"),
        "description": data.get("description"),
        "tags": tags,
        "logsource": {
            "category": logsource.get("category"),
            "product": logsource.get("product"),
            "service": logsource.get("service"),
        },
        "rule_path": str(path.relative_to(REPO_ROOT)),
    }


@mcp.tool()
def get_hayabusa_rules(keyword: str = "", max_results: int | None = None) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Args:
        keyword: Only include rules whose title, description, tags, or ID contain this string (case-insensitive), e.g. "lateral" or "mimikatz".
        max_results: If set, return at most this many rules.
    """
    if not BUILTIN_RULES_DIR.exists():
        raise ToolError(
            f"Hayabusa rules directory not found at {BUILTIN_RULES_DIR}. "
            "Run scripts/download_hayabusa.sh to install it."
        )
    if max_results is not None and max_results < 1:
        raise ToolError(f"Invalid max_results {max_results!r}. Must be a positive integer.")

    needle = keyword.strip().lower()
    rules = []
    for path in _iter_rule_files():
        rule = _parse_rule_metadata(path)
        if rule is None:
            continue

        if needle:
            haystack = " ".join(
                str(v) for v in (rule["title"], rule["id"], rule["description"], *rule["tags"]) if v
            ).lower()
            if needle not in haystack:
                continue

        rules.append(rule)

    total_rule_count = len(rules)
    if max_results is not None:
        rules = rules[:max_results]

    return {
        "keyword": keyword or None,
        "total_rule_count": total_rule_count,
        "returned_count": len(rules),
        "truncated": max_results is not None and total_rule_count > max_results,
        "rules": rules,
    }


def _iter_custom_rule_files():
    if not CUSTOM_RULES_DIR.exists():
        return
    for path in sorted(CUSTOM_RULES_DIR.rglob("*.yml")):
        if ".git" in path.parts:
            continue
        yield path


def _custom_rule_name(path: Path) -> str:
    return path.relative_to(CUSTOM_RULES_DIR).with_suffix("").as_posix()


def _normalize_technique_id(value: str) -> str:
    """Turn "T1003.001", "t1003.001", "1003.001", or "attack.t1003.001" into "t1003.001"."""
    canonical = value.strip().lower()
    if canonical.startswith("attack."):
        canonical = canonical[len("attack."):]
    if not canonical.startswith("t"):
        canonical = f"t{canonical}"
    return canonical


def _rule_matches_technique(tags: list, technique: str) -> bool:
    for tag in tags:
        tag = str(tag).lower()
        if not tag.startswith("attack.t"):
            continue
        tag_technique = tag[len("attack."):]
        if tag_technique == technique:
            return True
        # A parent technique query (no sub-technique suffix, e.g. "t1003")
        # also matches any of its sub-techniques (e.g. "t1003.001").
        if "." not in technique and tag_technique.startswith(f"{technique}."):
            return True
    return False


def _find_custom_rules_by_technique(technique: str) -> list:
    rules = []
    for path in _iter_custom_rule_files():
        rule = _parse_rule_metadata(path)
        if rule is None or not _rule_matches_technique(rule["tags"], technique):
            continue
        rules.append({"rule_name": _custom_rule_name(path), **rule})
    return rules


_ATTACK_TECHNIQUES_CACHE = None


def _load_attack_techniques() -> dict:
    global _ATTACK_TECHNIQUES_CACHE
    if _ATTACK_TECHNIQUES_CACHE is None:
        if not ATTACK_TECHNIQUES_FILE.exists():
            raise ValueError(
                f"ATT&CK technique data not found at {ATTACK_TECHNIQUES_FILE}. "
                "Run scripts/download_attack_data.py to fetch it."
            )
        with ATTACK_TECHNIQUES_FILE.open(encoding="utf-8") as f:
            _ATTACK_TECHNIQUES_CACHE = json.load(f)["techniques"]
    return _ATTACK_TECHNIQUES_CACHE


@mcp.resource("detection://rules", mime_type="application/json")
def list_detection_rules() -> dict:
    """List all custom Sigma detection rules available under rules/."""
    rules = []
    for path in _iter_custom_rule_files():
        rule = _parse_rule_metadata(path)
        if rule is None:
            continue
        rules.append({"rule_name": _custom_rule_name(path), **rule})

    return {
        "total_rule_count": len(rules),
        "rules": rules,
    }


@mcp.resource("detection://rules/{rule_name}", mime_type="text/yaml")
def get_detection_rule(rule_name: str) -> str:
    """Get a specific custom Sigma rule's raw YAML content by rule name."""
    for path in _iter_custom_rule_files():
        if _custom_rule_name(path) == rule_name:
            return path.read_text(encoding="utf-8")
    raise ValueError(f"Rule not found: {rule_name!r}")


@mcp.resource("detection://rules/by-technique/{technique_id}", mime_type="application/json")
def get_rules_by_technique(technique_id: str) -> dict:
    """List custom Sigma rules tagged with a given ATT&CK technique ID (e.g. "T1003.001" or "T1003")."""
    technique = _normalize_technique_id(technique_id)
    rules = _find_custom_rules_by_technique(technique)

    return {
        "technique_id": technique_id,
        "normalized_technique_id": technique,
        "total_rule_count": len(rules),
        "rules": rules,
    }


def _assess_technique_coverage(technique_id: str) -> dict:
    """Look up an ATT&CK technique's name/description and assess our Sigma rule coverage for it.

    Coverage is "gap" (no matching rules), "covered", or "partial". For a
    technique with sub-techniques (e.g. T1003), coverage reflects how many of
    its sub-techniques have at least one matching rule; for a leaf technique,
    it's "covered" only if a matching rule has reached status "stable" (an
    only-"test"-status match is "partial"). Raises ValueError if the technique
    ID is unknown.
    """
    technique = _normalize_technique_id(technique_id)
    attack_id = technique.upper()

    techniques = _load_attack_techniques()
    entry = techniques.get(attack_id)
    if entry is None:
        raise ValueError(f"Unknown ATT&CK technique: {technique_id!r}")

    matching_rules = _find_custom_rules_by_technique(technique)
    sub_techniques = entry["sub_techniques"]

    sub_technique_coverage = None
    if sub_techniques:
        sub_technique_coverage = {
            sub_id: "covered" if _find_custom_rules_by_technique(sub_id.lower()) else "gap"
            for sub_id in sub_techniques
        }
        covered_count = sum(1 for v in sub_technique_coverage.values() if v == "covered")
        if covered_count == 0:
            coverage = "gap"
        elif covered_count == len(sub_techniques):
            coverage = "covered"
        else:
            coverage = "partial"
    elif not matching_rules:
        coverage = "gap"
    elif any(rule.get("status") == "stable" for rule in matching_rules):
        coverage = "covered"
    else:
        coverage = "partial"

    return {
        "technique_id": technique_id,
        "attack_id": attack_id,
        "name": entry["name"],
        "description": entry["description"],
        "url": entry["url"],
        "is_subtechnique": entry["is_subtechnique"],
        "parent_technique": entry["parent_technique"],
        "sub_techniques": sub_techniques,
        "tactics": entry.get("tactics", []),
        "matching_rules": matching_rules,
        "coverage": coverage,
        "sub_technique_coverage": sub_technique_coverage,
    }


@mcp.resource("detection://attack/techniques/{technique_id}", mime_type="application/json")
def get_attack_technique_coverage(technique_id: str) -> dict:
    """Look up an ATT&CK technique's name/description and assess our Sigma rule coverage for it.

    Coverage is "gap" (no matching rules), "covered", or "partial". For a
    technique with sub-techniques (e.g. T1003), coverage reflects how many of
    its sub-techniques have at least one matching rule; for a leaf technique,
    it's "covered" only if a matching rule has reached status "stable" (an
    only-"test"-status match is "partial").
    """
    return _assess_technique_coverage(technique_id)


# MITRE renamed the "Defense Evasion" tactic, splitting it into "stealth" and
# "defense-impairment" in the ATT&CK data this index is built from. Rules in
# this repo (and the wider Sigma corpus) still use the old "defense-evasion"
# tag for tactic labeling, so a bare lookup of that name would otherwise fail
# with no explanation.
LEGACY_TACTIC_HINTS = {
    "defense-evasion": (
        "MITRE ATT&CK split the 'Defense Evasion' tactic into 'stealth' and "
        "'defense-impairment' -- try one of those instead."
    ),
}

_KNOWN_TACTICS_CACHE = None


def _load_known_tactics() -> set:
    global _KNOWN_TACTICS_CACHE
    if _KNOWN_TACTICS_CACHE is None:
        techniques = _load_attack_techniques()
        _KNOWN_TACTICS_CACHE = {
            tactic for entry in techniques.values() for tactic in entry.get("tactics", [])
        }
    return _KNOWN_TACTICS_CACHE


def _normalize_tactic_slug(value: str) -> str:
    return value.strip().lower().replace(" ", "-").replace("_", "-")


def _coverage_report(query: str, query_type: str, technique_reports: list, **extra) -> dict:
    covered = [r for r in technique_reports if r["coverage"] == "covered"]
    partial = [r for r in technique_reports if r["coverage"] == "partial"]
    gap = [r for r in technique_reports if r["coverage"] == "gap"]
    total = len(technique_reports)

    report = {
        "query": query,
        "query_type": query_type,
        "summary": {
            "total_techniques": total,
            "covered": len(covered),
            "partial": len(partial),
            "gap": len(gap),
            "coverage_percent": round(len(covered) / total * 100, 1) if total else 0.0,
        },
        "covered_techniques": covered,
        "partial_techniques": partial,
        "gap_techniques": gap,
    }
    report.update(extra)
    return report


@mcp.tool()
def analyze_coverage(identifier: str) -> dict:
    """Analyze Sigma rule coverage for an ATT&CK technique ID or tactic name.

    For a technique ID (e.g. "T1003" or "T1003.001"), reports coverage for
    that technique and, if it has sub-techniques, each sub-technique. For a
    tactic name (e.g. "credential-access" or "Lateral Movement"), reports
    coverage for every technique under that tactic. Coverage per technique is
    "covered", "partial", or "gap" -- see detection://attack/techniques/{id}
    for the exact rules. Rule matching only considers custom rules under
    rules/, not the vendored builtin Hayabusa rule set.

    Args:
        identifier: An ATT&CK technique ID or a tactic name/slug.
    """
    identifier = identifier.strip()
    if not identifier:
        raise ToolError("identifier must not be empty.")

    techniques = _load_attack_techniques()
    normalized_technique = _normalize_technique_id(identifier).upper()

    if normalized_technique in techniques:
        try:
            assessment = _assess_technique_coverage(identifier)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

        if assessment["sub_techniques"]:
            technique_reports = [
                {
                    "technique_id": sub_id,
                    "name": techniques[sub_id]["name"],
                    "coverage": assessment["sub_technique_coverage"][sub_id],
                    "matching_rules": sorted(
                        rule["rule_name"]
                        for rule in _find_custom_rules_by_technique(sub_id.lower())
                    ),
                }
                for sub_id in assessment["sub_techniques"]
            ]
        else:
            technique_reports = [
                {
                    "technique_id": assessment["attack_id"],
                    "name": assessment["name"],
                    "coverage": assessment["coverage"],
                    "matching_rules": sorted(
                        rule["rule_name"] for rule in assessment["matching_rules"]
                    ),
                }
            ]

        return _coverage_report(
            identifier, "technique", technique_reports, technique=assessment
        )

    slug = _normalize_tactic_slug(identifier)
    known_tactics = _load_known_tactics()
    if slug not in known_tactics:
        message = (
            f"{identifier!r} is not a recognized ATT&CK technique ID or tactic name. "
            f"Known tactics: {', '.join(sorted(known_tactics))}."
        )
        hint = LEGACY_TACTIC_HINTS.get(slug)
        if hint:
            message += f" {hint}"
        raise ToolError(message)

    technique_reports = []
    for attack_id, entry in techniques.items():
        if slug not in entry.get("tactics", []):
            continue
        parent = entry.get("parent_technique")
        if entry["is_subtechnique"] and parent in techniques and slug in techniques[parent].get("tactics", []):
            # Counted via its parent's roll-up below instead, to avoid double-counting.
            continue

        if entry["sub_techniques"]:
            matches = sorted({
                rule["rule_name"]
                for sub_id in entry["sub_techniques"]
                for rule in _find_custom_rules_by_technique(sub_id.lower())
            })
        else:
            matches = sorted(
                rule["rule_name"] for rule in _find_custom_rules_by_technique(attack_id.lower())
            )

        assessment = _assess_technique_coverage(attack_id)
        technique_reports.append({
            "technique_id": attack_id,
            "name": entry["name"],
            "coverage": assessment["coverage"],
            "matching_rules": matches,
        })

    technique_reports.sort(key=lambda r: r["technique_id"])
    return _coverage_report(identifier, "tactic", technique_reports, tactic=slug)


def _iter_builtin_rule_files():
    if not BUILTIN_RULES_DIR.exists():
        return
    for path in BUILTIN_RULES_DIR.rglob("*.yml"):
        if ".git" in path.parts:
            continue
        if RULES_CONFIG_DIR in path.parents:
            continue
        yield path


def _find_builtin_rules_by_technique(technique: str) -> list:
    rules = []
    for path in _iter_builtin_rule_files():
        rule = _parse_rule_metadata(path)
        if rule is None or not _rule_matches_technique(rule["tags"], technique):
            continue
        rules.append(rule)
    return rules


# Heuristic fallback used only when neither our custom rules nor the entire
# vendored builtin set (~5000 rules) have anything tagged for a technique --
# a real gap in the wider Sigma corpus, not just our project. These are
# rough keyword guesses at a plausible logsource, not a researched detection
# engineering recommendation; the response always says so explicitly.
_LOGSOURCE_KEYWORD_HINTS = [
    (("registry",), {"category": "registry_event", "product": "windows", "service": None}),
    (("scheduled task", "task scheduler"), {"category": None, "product": "windows", "service": "taskscheduler"}),
    (("powershell",), {"category": "ps_script", "product": "windows", "service": None}),
    (("dns",), {"category": "dns_query", "product": "windows", "service": None}),
    (("network", "traffic", "connection"), {"category": "network_connection", "product": "windows", "service": None}),
    (("file", "wrote", "written", "dropped"), {"category": "file_event", "product": "windows", "service": None}),
    (("process", "execute", "execution", "command"), {"category": "process_creation", "product": "windows", "service": None}),
]


def _keyword_logsource_guess(description: str) -> dict:
    text = (description or "").lower()
    for keywords, logsource in _LOGSOURCE_KEYWORD_HINTS:
        if any(keyword in text for keyword in keywords):
            return logsource
    return {"category": None, "product": "windows", "service": None}


# Maps a logsource category to the filename prefix convention already used
# by hand-written rules in rules/ (mirrors the vendored Sigma corpus's own
# naming, e.g. proc_creation_win_*.yml, registry_event_*.yml).
_LOGSOURCE_FILE_PREFIXES = {
    "process_creation": "proc_creation",
    "process_access": "proc_access",
    "registry_event": "registry",
    "registry_set": "registry",
    "network_connection": "net_conn",
    "file_event": "file_event",
    "image_load": "image_load",
    "pipe_created": "pipe_created",
    "dns_query": "dns_query",
    "ps_script": "posh_ps",
    "create_remote_thread": "create_remote_thread",
}


def _rule_template_filename(attack_id: str, name: str, logsource: dict) -> Path:
    prefix = _LOGSOURCE_FILE_PREFIXES.get(logsource.get("category")) or logsource.get(
        "category"
    ) or logsource.get("service") or "custom"
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:60]
    base = f"{prefix}_{slug}"
    candidate = CUSTOM_RULES_DIR / f"{base}.yml"
    suffix = 2
    while candidate.exists():
        candidate = CUSTOM_RULES_DIR / f"{base}_{suffix}.yml"
        suffix += 1
    return candidate


def _build_rule_template(assessment: dict, logsource: dict) -> dict:
    attack_id = assessment["attack_id"]
    tags = sorted(
        {f"attack.{tactic}" for tactic in assessment.get("tactics", [])}
        | {f"attack.{attack_id.lower()}"}
    )
    return {
        "title": f"TODO - {assessment['name']} Detection ({attack_id})",
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": (
            f"TODO: describe the specific behavior detected. Drafted as a starting "
            f"point for ATT&CK {attack_id} ({assessment['name']})."
        ),
        "references": [assessment["url"]],
        "author": "suggest_rule tool (auto-generated draft -- review before use)",
        "date": date.today().isoformat(),
        "modified": date.today().isoformat(),
        "tags": tags,
        "logsource": {k: v for k, v in logsource.items() if v is not None},
        "detection": {
            "selection": {"TODO_add_selection_fields": "TODO_add_values"},
            "condition": "selection",
        },
        "falsepositives": ["Unknown -- refine after testing against real data"],
        "level": "medium",
        "ruletype": "Sigma",
    }


@mcp.tool()
def suggest_rule(technique_id: str, create_rule_file: bool = False) -> dict:
    """Check custom-rule coverage for an ATT&CK technique and suggest a detection approach for any gap.

    For a technique with sub-techniques (e.g. "T1003"), reports which
    sub-techniques are uncovered and asks you to re-call with one of those
    specific sub-technique IDs -- suggestions and rule templates are only
    generated for a single leaf technique, since a rule tagged only with a
    broad parent technique isn't a meaningful detection target.

    For a leaf technique that isn't already "covered", looks at how the
    vendored builtin Hayabusa/Sigma rules (if any) detect it to suggest a
    logsource and point at reference rules; falls back to a rough
    keyword-based logsource guess if no builtin rule covers it either. If
    create_rule_file is True, writes a draft Sigma rule (status
    "experimental", placeholder detection logic) into rules/ for a human to
    refine and promote to "test"/"stable" -- it is never written for an
    already-"covered" technique or a parent technique query.

    Args:
        technique_id: An ATT&CK technique ID, e.g. "T1003.001" or "T1003".
        create_rule_file: If True, write a draft rule template into rules/ (see above for when this is skipped).
    """
    try:
        assessment = _assess_technique_coverage(technique_id)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    coverage = assessment["coverage"]
    attack_id = assessment["attack_id"]
    existing_custom_rules = sorted(rule["rule_name"] for rule in assessment["matching_rules"])

    result = {
        "technique_id": assessment["technique_id"],
        "attack_id": attack_id,
        "name": assessment["name"],
        "url": assessment["url"],
        "tactics": assessment["tactics"],
        "coverage": coverage,
        "already_covered": coverage == "covered",
        "existing_custom_rules": existing_custom_rules,
        "reference_builtin_rules": [],
        "suggested_logsource": None,
        "suggestion": None,
        "rule_template": None,
        "rule_file_created": None,
    }

    if assessment["sub_techniques"]:
        uncovered = sorted(
            sub_id
            for sub_id, sub_coverage in assessment["sub_technique_coverage"].items()
            if sub_coverage == "gap"
        )
        result["uncovered_sub_techniques"] = uncovered
        if coverage == "covered":
            result["suggestion"] = (
                f"{attack_id} is fully covered ({len(assessment['sub_techniques'])} of "
                f"{len(assessment['sub_techniques'])} sub-techniques have a matching rule). No action needed."
            )
        else:
            result["suggestion"] = (
                f"{attack_id} is a parent technique with {len(assessment['sub_techniques'])} "
                f"sub-techniques; {len(uncovered)} are uncovered: {', '.join(uncovered) or 'none'}. "
                "Call suggest_rule again with one specific uncovered sub-technique ID for a concrete "
                "detection suggestion and optional rule template."
            )
        if create_rule_file:
            result["suggestion"] += " (create_rule_file was ignored: not applicable to a parent technique query.)"
        return result

    if coverage == "covered":
        result["suggestion"] = (
            f"{attack_id} is already covered by a stable custom rule "
            f"({', '.join(existing_custom_rules)}). No action needed."
        )
        if create_rule_file:
            result["suggestion"] += " (create_rule_file was ignored: coverage is already 'covered'.)"
        return result

    builtin_refs = _find_builtin_rules_by_technique(_normalize_technique_id(technique_id))
    top_refs = sorted(
        builtin_refs, key=lambda r: (r.get("status") != "stable", r.get("level") != "critical")
    )[:5]
    result["reference_builtin_rules"] = [
        {"title": r["title"], "level": r["level"], "status": r["status"], "rule_path": r["rule_path"]}
        for r in top_refs
    ]

    if builtin_refs:
        logsource_counts = Counter(
            (r["logsource"]["category"], r["logsource"]["product"], r["logsource"]["service"])
            for r in builtin_refs
        )
        (category, product, service), _count = logsource_counts.most_common(1)[0]
        suggested_logsource = {"category": category, "product": product, "service": service}
        result["suggestion"] = (
            f"{len(builtin_refs)} builtin Hayabusa rule(s) already detect {attack_id} "
            f"(e.g. \"{top_refs[0]['title']}\" at {top_refs[0]['rule_path']}). Most target "
            f"logsource category={category!r} product={product!r} service={service!r} -- "
            "review one of those rules' detection block as a starting point for a custom variant."
        )
    else:
        suggested_logsource = _keyword_logsource_guess(assessment["description"])
        result["suggestion"] = (
            f"No builtin or custom rule currently tags {attack_id} -- this looks like a real gap, "
            f"not just a missing custom rule. Based on the technique description, a plausible "
            f"starting logsource is {suggested_logsource!r}, but this is a rough heuristic guess: "
            f"read {assessment['url']} and confirm against real telemetry before writing detection logic."
        )

    result["suggested_logsource"] = suggested_logsource
    template = _build_rule_template(assessment, suggested_logsource)
    result["rule_template"] = template

    if create_rule_file:
        target_path = _rule_template_filename(attack_id, assessment["name"], suggested_logsource)
        target_path.write_text(
            yaml.dump(template, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
        result["rule_file_created"] = str(target_path.relative_to(REPO_ROOT))
        result["suggestion"] += f" Draft written to {result['rule_file_created']}."

    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
