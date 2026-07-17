#!/usr/bin/env python3
"""Validate a custom Sigma rule against this project's detection-engineering standards.

Usage: validate-rule.py <path-to-rule.yml>

Checks (see ../SKILL.md for full rationale):
  1. tags contains at least one attack.tXXXX[.YYY] entry
  2. level is exactly low/medium/high/critical
  3. falsepositives is a non-empty list
  4. test_cases is a non-empty list, with at least one should_match: true entry
  5. filename is lowercase_with_underscores and prefixed per logsource
     (mirrors _LOGSOURCE_FILE_PREFIXES in server.py)

Prints a JSON report to stdout and exits 0 if all checks pass, 1 if any
check fails, 2 on a file/parse error.
"""

import json
import re
import sys
from pathlib import Path

import yaml

ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
VALID_LEVELS = {"low", "medium", "high", "critical"}
FILENAME_RE = re.compile(r"^[a-z0-9_]+$")

# Mirrors _LOGSOURCE_FILE_PREFIXES in server.py, used by the suggest_rule tool
# to name auto-generated rule drafts. Hand-written rules should follow suit.
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


def check_attack_tags(rule: dict) -> dict:
    tags = rule.get("tags") or []
    matches = [t for t in tags if isinstance(t, str) and ATTACK_TAG_RE.match(t)]
    if matches:
        return {"passed": True, "message": f"Found technique tag(s): {', '.join(matches)}"}
    return {"passed": False, "message": "No attack.tXXXX[.YYY] tag found in 'tags'"}


def check_severity(rule: dict) -> dict:
    level = rule.get("level")
    if level in VALID_LEVELS:
        return {"passed": True, "message": f"level is '{level}'"}
    if level is None:
        return {"passed": False, "message": "'level' field is missing"}
    return {
        "passed": False,
        "message": f"'level' is '{level}', must be one of {sorted(VALID_LEVELS)}",
    }


def check_falsepositives(rule: dict) -> dict:
    fps = rule.get("falsepositives")
    if isinstance(fps, list) and len(fps) > 0:
        return {"passed": True, "message": f"{len(fps)} falsepositives entr(y/ies) present"}
    return {"passed": False, "message": "'falsepositives' is missing or empty"}


def check_test_cases(rule: dict) -> dict:
    cases = rule.get("test_cases")
    if not isinstance(cases, list) or len(cases) == 0:
        return {"passed": False, "message": "'test_cases' is missing or empty"}
    has_positive = any(
        isinstance(c, dict) and c.get("should_match") is True for c in cases
    )
    if not has_positive:
        return {
            "passed": False,
            "message": f"{len(cases)} test_cases present, but none has should_match: true",
        }
    return {"passed": True, "message": f"{len(cases)} test_cases present, including a should_match: true case"}


def check_filename(path: str, rule: dict) -> dict:
    stem = Path(path).stem
    if not FILENAME_RE.match(stem):
        return {
            "passed": False,
            "message": f"filename stem '{stem}' is not lowercase_with_underscores",
        }

    logsource = rule.get("logsource") or {}
    category = logsource.get("category")
    service = logsource.get("service")
    expected_prefix = _LOGSOURCE_FILE_PREFIXES.get(category) or category or service

    if expected_prefix and not stem.startswith(f"{expected_prefix}_"):
        return {
            "passed": False,
            "message": (
                f"filename stem '{stem}' does not start with expected prefix "
                f"'{expected_prefix}_' for logsource {logsource}"
            ),
        }

    return {
        "passed": True,
        "message": f"filename '{Path(path).name}' is lowercase_with_underscores"
        + (f" with expected prefix '{expected_prefix}_'" if expected_prefix else ""),
    }


def validate(path: str, rule: dict) -> dict:
    checks = {
        "attack_tags": check_attack_tags(rule),
        "severity": check_severity(rule),
        "falsepositives": check_falsepositives(rule),
        "test_cases": check_test_cases(rule),
        "filename": check_filename(path, rule),
    }
    issues = [c["message"] for c in checks.values() if not c["passed"]]
    return {
        "valid": len(issues) == 0,
        "checks": checks,
        "issues": issues,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: validate-rule.py <path-to-rule.yml>"}))
        return 2

    path = sys.argv[1]

    try:
        with open(path, "r") as f:
            rule = yaml.safe_load(f)
    except FileNotFoundError:
        print(json.dumps({"file": path, "error": f"file not found: {path}"}))
        return 2
    except yaml.YAMLError as e:
        print(json.dumps({"file": path, "error": f"YAML parse error: {e}"}))
        return 2

    if not isinstance(rule, dict):
        print(json.dumps({"file": path, "error": "rule file does not parse to a YAML mapping"}))
        return 2

    result = validate(path, rule)
    result["file"] = path
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
