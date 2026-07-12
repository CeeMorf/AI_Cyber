# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This project is an MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis. It exposes two MCP tools:

- `scan_evtx` — runs Hayabusa's `json-timeline` command against an EVTX file and returns findings as structured JSON, with filtering by severity and rule title.
- `get_hayabusa_rules` — lists/searches the bundled Sigma-style detection rules (title, ATT&CK tags, severity, description) without running a scan.

It also exposes MCP resources over the project's own custom rules in `rules/` (not the vendored builtin set):

- `detection://rules` — list all custom rules (metadata only).
- `detection://rules/{rule_name}` — raw YAML content of one rule, keyed by filename stem (e.g. `security_dcsync_replication_rights`).
- `detection://rules/by-technique/{technique_id}` — rules tagged with a given ATT&CK technique; accepts a sub-technique (`T1003.001`) for an exact match or a parent technique (`T1003`) to match all its sub-techniques.

## Commands

- Run the server (used by MCP clients via `.mcp.json`): `python3 server.py`
- Manual smoke test against the bundled sample EVTX: `python3 test_server.py`
- Install/upgrade the Hayabusa binary + rules into `./hayabusa/`: `scripts/download_hayabusa.sh` (detects OS/arch, pulls the latest GitHub release, safe to re-run)
- Install Python deps: `pip3 install -r requirements.txt`

There is no formal test suite (no pytest) — `test_server.py` is a standalone script that calls `scan_evtx` directly and prints results for manual inspection.

## Architecture

Everything lives in `server.py`, a single-file FastMCP server. Key structure:

- **`HAYABUSA_DIR` / `HAYABUSA_BIN` / `BUILTIN_RULES_DIR`**: paths into the vendored `hayabusa/` directory, which contains the downloaded Hayabusa binary (`hayabusa/hayabusa`, symlinked to the versioned executable), its `rules/` (Sigma-style YAML detection rules) and `rules/config/` (field mappings, channel abbreviations, etc. needed by Hayabusa at scan time). This directory is populated by `scripts/download_hayabusa.sh` and is not meant to be hand-edited.
- **`rules/` (repo root, `CUSTOM_RULES_DIR`)**: hand-written project-specific Sigma rules, additive to the vendored set. `RULE_SOURCES` lists both roots (`builtin`, `custom`) and is the single place both tools read from.
- **`scan_evtx` tool**: shells out to the Hayabusa binary (`json-timeline` subcommand) with a fixed set of flags (JSONL output, no wizard/color/banner/summary, clobber output file), writes results to a temp file, then parses each JSONL line back into Python. Post-processing (rule-title filtering, `max_results` truncation, dropping bulky fields for `output_format="summary"`) happens in Python after Hayabusa runs, not via Hayabusa CLI flags — `min_severity` is the one filter passed through to Hayabusa itself (`-m`). Since Hayabusa's `-r` flag only accepts a single directory and its rule loader doesn't follow symlinked subdirectories while walking it, `_merge_rule_sources` hardlinks both `RULE_SOURCES` into a fresh temp directory before each scan (hardlinks are effectively free — no file data is copied) so a single `-r` covers builtin + custom rules together.
- **`get_hayabusa_rules` tool**: reads rule YAML files directly from both `RULE_SOURCES` roots (not via the Hayabusa binary, via `_iter_rule_files`) using `yaml.CSafeLoader` when available for speed, since there are several thousand rule files. Skips `rules/config/` under the builtin root (data-mapping files, not detection rules) and any path containing `.git`. Each rule's `rule_path` in the response is relative to the repo root, so builtin and custom rules are distinguishable (e.g. `hayabusa/rules/sigma/...` vs `rules/...`).
- **Severity handling**: `SEVERITY_LEVELS` / `SEVERITY_ALIASES` normalize both full names (`informational`, `critical`) and Hayabusa's abbreviated forms (`info`, `crit`, `med`) to a canonical value before passing to the CLI.
- All user-facing errors (missing file, missing binary, invalid severity, scan timeout/failure) are raised as `mcp.server.fastmcp.exceptions.ToolError` so the MCP client gets a clean error message rather than a stack trace.
- **`detection://` resources**: scoped to `CUSTOM_RULES_DIR` only (`_iter_custom_rule_files`), separate from the tools' merged `RULE_SOURCES` view. `_parse_rule_metadata` is shared with `get_hayabusa_rules` so both surfaces describe a rule the same way. A rule's `rule_name` (used in the URI) is its path relative to `rules/` with the extension stripped, via `_custom_rule_name`. Errors (unknown rule name) are raised as plain exceptions — FastMCP's resource dispatch wraps any exception from a resource function into a client-facing error itself, so there's no resource-specific error type to use (unlike `ToolError` for tools).

`credential_access_rules.json` at the repo root is a saved example output of `get_hayabusa_rules` (keyword `attack.credential-access`), not source code.
