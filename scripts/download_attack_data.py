#!/usr/bin/env python3
"""Downloads the MITRE ATT&CK Enterprise STIX bundle and extracts a compact
technique index (id, name, description, sub-technique relationships) to
./attack/enterprise-attack-techniques.json. Safe to re-run to refresh.

The raw STIX bundle is ~50MB and includes malware, tools, mitigations, and
thousands of relationship objects we don't need; only the ~850 attack-pattern
objects (techniques/sub-techniques) are kept, so the server never has to hold
or re-parse the full bundle at request time.
"""
import json
import urllib.request
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
SCRIPT_DIR = Path(__file__).resolve().parent
DEST_DIR = SCRIPT_DIR.parent / "attack"
DEST_FILE = DEST_DIR / "enterprise-attack-techniques.json"


def extract_techniques(stix_objects: list) -> dict:
    techniques = {}
    for obj in stix_objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not attack_id or not attack_id.startswith("T"):
            continue

        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique"))
        techniques[attack_id] = {
            "name": obj.get("name"),
            "description": obj.get("description"),
            "url": url,
            "is_subtechnique": is_subtechnique,
            "parent_technique": attack_id.split(".")[0] if is_subtechnique else None,
            "sub_techniques": [],
        }

    for attack_id, entry in techniques.items():
        parent = entry["parent_technique"]
        if parent and parent in techniques:
            techniques[parent]["sub_techniques"].append(attack_id)
    for entry in techniques.values():
        entry["sub_techniques"].sort()

    return techniques


def main() -> None:
    print(f"Downloading ATT&CK Enterprise STIX bundle from {SOURCE_URL} ...")
    with urllib.request.urlopen(SOURCE_URL) as response:
        bundle = json.load(response)

    techniques = extract_techniques(bundle["objects"])
    print(f"Extracted {len(techniques)} non-deprecated/non-revoked techniques.")

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    with DEST_FILE.open("w", encoding="utf-8") as f:
        json.dump({"techniques": techniques}, f, indent=2)
    print(f"Wrote {DEST_FILE}")


if __name__ == "__main__":
    main()
