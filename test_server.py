"""Simple manual test: calls the scan_evtx tool directly against a sample EVTX file.

Sample source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
"""

import json
from pathlib import Path

import server

SAMPLE_EVTX = Path(__file__).resolve().parent / "samples" / "UACME_59_Sysmon.evtx"


def main() -> None:
    if not SAMPLE_EVTX.exists():
        raise SystemExit(f"Sample EVTX not found: {SAMPLE_EVTX}")

    for min_severity in ("informational", "high"):
        print(f"=== scan_evtx(min_severity={min_severity!r}) ===")
        result = server.scan_evtx(str(SAMPLE_EVTX), min_severity)
        print(f"event_count: {result['event_count']}")
        if result["findings"]:
            print("first finding:")
            print(json.dumps(result["findings"][0], indent=2))
        print()


if __name__ == "__main__":
    main()
