"""Runs one batch of tmNIDS tests for the Pi Script Manager and reports a PIMGR_RESULT line.

Uses ids_test_runner's own functions (integrity check, random selection, test runner) with the
job's PARAM_* values. tmNIDS comes from the Manager's traffic-gen profile at the pinned hash.
"""
import json
import logging
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ids_test_runner as r  # noqa: E402


def param(name, default):
    return os.environ.get(f"PARAM_{name.upper()}", default)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S",
                        stream=sys.stdout)
    try:
        pool = [t for t in r.parse_test_list(param("tests", "1-15")) if t in r.TESTS]
    except ValueError:
        print("tests must look like 1-15 or 1,3,5-8", file=sys.stderr)
        return 2
    if not pool:
        print(f"no valid test ids in '{param('tests', '')}' (valid: 1-15)", file=sys.stderr)
        return 2
    lo, hi = int(param("min_tests", 1)), int(param("max_tests", 5))
    gap_lo, gap_hi = int(param("min_gap_s", 2)), int(param("max_gap_s", 45))
    if gap_hi < gap_lo:
        gap_lo, gap_hi = gap_hi, gap_lo
    timeout = int(param("test_timeout_s", 60))

    # Verify only. Never download here: the profile owns this file (root, pinned), and a mismatch
    # means the profile and TMNIDS_SHA256 disagree, which an admin should look at.
    tmnids = Path(sys.argv[1])
    try:
        r._verify_sha256(tmnids.read_bytes(), r.TMNIDS_SHA256)
    except (OSError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        return 2

    rng = random.Random()
    selection = r.choose_tests(pool, lo, max(lo, hi), rng)
    print(f"Running {len(selection)} test(s): {', '.join(map(str, selection))}", flush=True)
    results = {}
    for i, tid in enumerate(selection):
        rc, status = r.run_test(tmnids, tid, timeout, dry_run=False)
        results[str(tid)] = {"test": r.TESTS[tid], "status": status}
        if i < len(selection) - 1 and gap_hi > 0:
            time.sleep(rng.randint(gap_lo, gap_hi))
    # A test "failing" locally (blocked by an IPS, say) is still a valid run: the point is the alerts.
    print("PIMGR_RESULT " + json.dumps({"tests_run": len(selection), "tests": results}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
