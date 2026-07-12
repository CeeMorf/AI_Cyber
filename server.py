import json
import os
import platform
import subprocess
import tempfile
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
    rules = []
    for path in _iter_custom_rule_files():
        rule = _parse_rule_metadata(path)
        if rule is None or not _rule_matches_technique(rule["tags"], technique):
            continue
        rules.append({"rule_name": _custom_rule_name(path), **rule})

    return {
        "technique_id": technique_id,
        "normalized_technique_id": technique,
        "total_rule_count": len(rules),
        "rules": rules,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
