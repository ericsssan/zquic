#!/usr/bin/env python3
"""Compare two bench --json results and fail if any transfer scenario regresses.

Usage: bench_compare.py <baseline.json> <current.json>

Exit 0 if no regressions exceed the threshold; exit 1 otherwise.
"""
import json
import sys

THRESHOLD = 0.10  # 10% regression threshold


def load(path):
    with open(path) as f:
        return json.load(f)


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} baseline.json current.json", file=sys.stderr)
        sys.exit(2)

    baseline = load(sys.argv[1])
    current = load(sys.argv[2])

    regressions = []
    improvements = []

    for name, cur in current["scenarios"].items():
        cur_kbps = cur.get("goodput_kbps", 0.0)
        if cur_kbps == 0.0:
            continue  # handshake-only scenario — skip

        base = baseline["scenarios"].get(name)
        if base is None:
            continue  # new scenario not in baseline — skip

        base_kbps = base.get("goodput_kbps", 0.0)
        if base_kbps <= 0:
            continue

        delta = (cur_kbps - base_kbps) / base_kbps
        pct = delta * 100.0

        if delta < -THRESHOLD:
            regressions.append(
                f"  REGRESS  {name}: {cur_kbps:.0f} kbps  (was {base_kbps:.0f}, {pct:+.1f}%)"
            )
        elif delta > THRESHOLD:
            improvements.append(
                f"  IMPROVE  {name}: {cur_kbps:.0f} kbps  (was {base_kbps:.0f}, {pct:+.1f}%)"
            )

    if improvements:
        print(f"Improvements ({len(improvements)}):")
        for line in improvements:
            print(line)

    if regressions:
        print(f"\nFAIL: {len(regressions)} goodput regression(s) > {THRESHOLD*100:.0f}% threshold:")
        for line in regressions:
            print(line)
        sys.exit(1)
    else:
        print(f"PASS: no regressions > {THRESHOLD*100:.0f}% threshold")


if __name__ == "__main__":
    main()
