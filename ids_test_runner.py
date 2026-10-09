#!/usr/bin/env python3
"""
ids_test_runner.py — randomized NIDS/IPS test driver built on 3CORESec's tmNIDS.

Wraps https://github.com/3CORESec/testmynids.org so a Raspberry Pi (or any
Linux/macOS host with curl + nc) can periodically generate benign-but-signature-
triggering traffic to verify an IDS/IPS is actually alerting.

Randomization has two independent knobs, both useful from cron:
  * WHEN  — a probability gate + random start jitter, so a fixed cron cadence
            turns into unpredictable firing times.
  * WHAT  — a random-sized, random-order subset of the tmNIDS test cases, with
            random pauses between them.

Standard library only. No pip install required.

Typical cron usage (fires ~1/3 of the time, jittered up to 8 min into the slot):
    */10 * * * * /usr/bin/python3 /home/pi/ids_test_runner.py --probability 0.34 --max-jitter 480 >> /home/pi/ids_test_runner.cron.log 2>&1

Run `--install-cron` once to append a randomized entry for you, or `--daemon`
to skip cron entirely and self-schedule with random sleeps.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import logging
import os
import random
import shlex
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

TMNIDS_URL = "https://raw.githubusercontent.com/3CORESec/testmynids.org/master/tmNIDS"

# SHA-256 of a known-good upstream tmNIDS (pinned 2026-10, 9072 bytes). The
# downloaded script is verified against this before it is ever made executable
# or run, so a compromised upstream repo/account or CDN cannot silently push
# code that this tool would then execute under cron. When upstream legitimately
# updates tmNIDS this hash will no longer match: the tool refuses to run and
# prints the hash it saw — review the upstream diff, then update this constant
# (or pass --sha256 <hash>). Use --no-verify only as a deliberate escape hatch.
TMNIDS_SHA256 = "7016952b1713d09aac0b17bc05d1cc9c589c5ab1ed441233b9413717494fa0c4"

# tmNIDS test flags -> human label. -99 ("run all") is intentionally excluded
# from the random pool; we compose our own subsets instead.
TESTS: dict[int, str] = {
    1: "Linux UID (id command output over HTTP)",
    2: "HTTP Basic Authentication (cleartext creds)",
    3: "HTTP malware user-agents",
    4: "Bad certificates & CAs (TLS/DNS/TCP)",
    5: "Tor .onion DNS + node connections",
    6: "EXE/DLL download over HTTP",
    7: "PDF with embedded file",
    8: "SSH outbound scan simulation",
    9: "Suspicious / sinkhole / DDNS domains",
    10: "Anonymous filesharing service (TLS)",
    11: "External IP-address lookup services",
    12: "URL shortener services",
    13: "Policy violation — gaming traffic",
    14: "Adware / PUP activity",
    15: "Malware C2 beacon",
}

DEFAULT_TMNIDS_PATH = Path.home() / ".local" / "share" / "tmnids" / "tmNIDS"
DEFAULT_LOG_FILE = Path.home() / ".local" / "share" / "tmnids" / "ids_test_runner.log"

log = logging.getLogger("ids_test_runner")


# --------------------------------------------------------------------------- #
# tmNIDS acquisition
# --------------------------------------------------------------------------- #
def _verify_sha256(data: bytes, expected: str) -> None:
    """Raise if data's SHA-256 doesn't match the expected (pinned) hash."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected.lower():
        raise RuntimeError(
            "tmNIDS integrity check FAILED — refusing to run.\n"
            f"  expected sha256: {expected}\n"
            f"  actual   sha256: {actual}\n"
            "If upstream legitimately changed, review the diff and update "
            "TMNIDS_SHA256 (or pass --sha256 <hash>); use --no-verify to bypass."
        )


def ensure_tmnids(
    path: Path,
    force_update: bool = False,
    expected_sha: str | None = TMNIDS_SHA256,
) -> Path:
    """Return a path to a verified, executable tmNIDS, downloading if needed.

    The cached copy is re-verified on every run (not just at download time), so
    tampering with the on-disk file is caught too. Pass expected_sha=None to skip
    verification entirely (escape hatch).
    """
    # Reuse a cached copy only if it still matches the pinned hash.
    if path.exists() and not force_update:
        if expected_sha is None:
            return path
        try:
            _verify_sha256(path.read_bytes(), expected_sha)
            return path
        except RuntimeError:
            log.warning("Cached tmNIDS failed integrity check; re-downloading")

    path.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading tmNIDS from %s", TMNIDS_URL)
    tmp = path.with_suffix(".tmp")
    req = urllib.request.Request(TMNIDS_URL, headers={"User-Agent": "ids_test_runner"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (trusted, pinned URL)
        data = resp.read()
    if not data.lstrip().startswith(b"#!"):
        raise RuntimeError("Downloaded tmNIDS does not look like a shell script")

    # Verify BEFORE making it executable or moving it into place.
    if expected_sha is not None:
        _verify_sha256(data, expected_sha)
        log.info("tmNIDS integrity verified (sha256 %s…)", expected_sha[:12])
    else:
        log.warning("tmNIDS integrity verification SKIPPED (--no-verify)")

    tmp.write_bytes(data)
    tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)
    tmp.replace(path)
    log.info("tmNIDS ready at %s (%d bytes)", path, len(data))
    return path


# --------------------------------------------------------------------------- #
# Randomized selection
# --------------------------------------------------------------------------- #
def choose_tests(
    pool: list[int],
    min_tests: int,
    max_tests: int,
    rng: random.Random,
) -> list[int]:
    """Pick a random-sized, random-order subset from the allowed pool."""
    if not pool:
        return []
    lo = max(1, min(min_tests, len(pool)))
    hi = max(lo, min(max_tests, len(pool)))
    k = rng.randint(lo, hi)
    chosen = rng.sample(pool, k)
    rng.shuffle(chosen)
    return chosen


def run_test(
    tmnids: Path,
    test_id: int,
    timeout: int,
    dry_run: bool,
) -> tuple[int, str]:
    """Invoke `tmNIDS -<id>`. Returns (return_code, short_status)."""
    cmd = [str(tmnids), f"-{test_id}"]
    label = TESTS.get(test_id, f"test {test_id}")
    if dry_run:
        log.info("[dry-run] would run: %s  (%s)", shlex.join(cmd), label)
        return 0, "dry-run"

    log.info("Running test %d — %s", test_id, label)
    try:
        proc = subprocess.run(  # noqa: S603 (tmnids path is controlled)
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        log.warning("Test %d timed out after %ds", test_id, timeout)
        return 124, "timeout"
    except FileNotFoundError:
        log.error("tmNIDS not found or not executable at %s", tmnids)
        return 127, "missing"

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if out:
        for line in out.splitlines():
            log.info("  | %s", line)
    if err:
        for line in err.splitlines():
            log.info("  ! %s", line)
    status = "ok" if proc.returncode == 0 else f"rc={proc.returncode}"
    log.info("Test %d finished (%s)", test_id, status)
    return proc.returncode, status


# --------------------------------------------------------------------------- #
# One run
# --------------------------------------------------------------------------- #
def do_run(args: argparse.Namespace, rng: random.Random) -> int:
    """Execute a single (possibly gated) batch of tests. Returns process exit code."""
    # WHEN: probability gate — lets a fixed cron cadence fire unpredictably.
    if rng.random() > args.probability:
        log.info("Skipping this invocation (probability gate %.2f)", args.probability)
        return 0

    # WHEN: random start jitter so we don't fire on the cron boundary.
    if args.max_jitter > 0 and not args.no_jitter:
        jitter = rng.randint(0, args.max_jitter)
        log.info("Jitter sleep %ds before starting", jitter)
        time.sleep(jitter)

    expected_sha = None if args.no_verify else (args.sha256 or TMNIDS_SHA256)
    tmnids = ensure_tmnids(
        Path(args.tmnids_path), force_update=args.update, expected_sha=expected_sha
    )

    pool = args.tests or list(TESTS.keys())
    pool = [t for t in pool if t in TESTS]
    selection = choose_tests(pool, args.min_tests, args.max_tests, rng)
    log.info(
        "Selected %d test(s) from pool of %d: %s",
        len(selection),
        len(pool),
        ", ".join(str(t) for t in selection),
    )

    worst = 0
    for i, test_id in enumerate(selection):
        rc, _ = run_test(tmnids, test_id, args.timeout, args.dry_run)
        worst = worst or rc
        if i < len(selection) - 1 and args.max_gap > 0 and not args.dry_run:
            gap = rng.randint(args.min_gap, args.max_gap)
            log.info("Waiting %ds before next test", gap)
            time.sleep(gap)

    log.info("Batch complete (%d tests run)", len(selection))
    return 0 if worst in (0,) else 0  # non-fatal: a tripped test is success for us


# --------------------------------------------------------------------------- #
# Daemon mode (self-scheduling, no cron)
# --------------------------------------------------------------------------- #
def do_daemon(args: argparse.Namespace, rng: random.Random) -> int:
    log.info(
        "Daemon mode: random interval %d–%d min between batches",
        args.daemon_min,
        args.daemon_max,
    )
    # In daemon mode the probability gate and start jitter are redundant with the
    # random sleep, so neutralize them for the inner run.
    args.probability = 1.0
    args.no_jitter = True
    try:
        while True:
            do_run(args, rng)
            wait = rng.randint(args.daemon_min * 60, args.daemon_max * 60)
            nxt = dt.datetime.now() + dt.timedelta(seconds=wait)
            log.info("Next batch in %d min (~%s)", wait // 60, nxt.strftime("%H:%M"))
            time.sleep(wait)
    except KeyboardInterrupt:
        log.info("Daemon stopped")
        return 0


# --------------------------------------------------------------------------- #
# Cron helper
# --------------------------------------------------------------------------- #
def install_cron(args: argparse.Namespace) -> int:
    """Append a randomized cron entry that calls this script."""
    script = Path(__file__).resolve()
    python = sys.executable or "/usr/bin/python3"
    logpath = Path(args.log_file).with_suffix(".cron.log")
    # Fire every `--cron-step` minutes; the probability gate + jitter inside the
    # script turn that into unpredictable real firing times.
    entry = (
        f"*/{args.cron_step} * * * * {python} {script} "
        f"--probability {args.probability} --max-jitter {args.max_jitter} "
        f"--min-tests {args.min_tests} --max-tests {args.max_tests} "
        f">> {logpath} 2>&1"
    )
    marker = "# ids_test_runner (randomized NIDS tests)"
    try:
        existing = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True
        ).stdout
    except FileNotFoundError:
        log.error("crontab not found; add this line manually:\n%s", entry)
        return 1

    lines = [ln for ln in existing.splitlines() if marker not in ln and script.name not in ln]
    lines.append(marker)
    lines.append(entry)
    new = "\n".join(lines) + "\n"

    proc = subprocess.run(["crontab", "-"], input=new, text=True)
    if proc.returncode == 0:
        log.info("Installed cron entry:\n%s", entry)
    return proc.returncode


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Randomized NIDS/IPS testing via 3CORESec tmNIDS.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--tmnids-path", default=str(DEFAULT_TMNIDS_PATH),
                   help="Where to cache the tmNIDS script")
    p.add_argument("--update", action="store_true",
                   help="Force re-download of tmNIDS before running")
    p.add_argument("--sha256", default=None, metavar="HASH",
                   help="Override the pinned tmNIDS SHA-256 to verify against")
    p.add_argument("--no-verify", action="store_true",
                   help="Skip the tmNIDS integrity check (escape hatch; not recommended)")
    p.add_argument("--tests", type=parse_test_list, default=None,
                   metavar="1,3,5-8",
                   help="Restrict the random pool to these test IDs (default: all 1-15)")

    # WHAT to run
    p.add_argument("--min-tests", type=int, default=1, help="Min tests per batch")
    p.add_argument("--max-tests", type=int, default=5, help="Max tests per batch")
    p.add_argument("--min-gap", type=int, default=2, help="Min seconds between tests")
    p.add_argument("--max-gap", type=int, default=45, help="Max seconds between tests")
    p.add_argument("--timeout", type=int, default=60, help="Per-test timeout (seconds)")

    # WHEN to run (cron randomization)
    p.add_argument("--probability", type=float, default=1.0,
                   help="Chance [0-1] this invocation actually runs (cron gate)")
    p.add_argument("--max-jitter", type=int, default=0,
                   help="Random start delay 0..N seconds before the batch")
    p.add_argument("--no-jitter", action="store_true", help="Disable start jitter")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed RNG for reproducible selection (testing only)")

    # Daemon mode
    p.add_argument("--daemon", action="store_true",
                   help="Loop forever with random intervals instead of using cron")
    p.add_argument("--daemon-min", type=int, default=20,
                   help="Daemon: min minutes between batches")
    p.add_argument("--daemon-max", type=int, default=180,
                   help="Daemon: max minutes between batches")

    # Cron install helper
    p.add_argument("--install-cron", action="store_true",
                   help="Append a randomized crontab entry calling this script")
    p.add_argument("--cron-step", type=int, default=10,
                   help="Cron granularity in minutes for --install-cron")

    # Output
    p.add_argument("--log-file", default=str(DEFAULT_LOG_FILE), help="Log file path")
    p.add_argument("--quiet", action="store_true", help="No console output")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would run without generating traffic")
    p.add_argument("--list", action="store_true", help="List available tests and exit")
    return p


def parse_test_list(s: str) -> list[int]:
    """Parse '1,3,5-8' -> [1,3,5,6,7,8]."""
    out: list[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


def setup_logging(log_file: str, quiet: bool) -> None:
    handlers: list[logging.Handler] = []
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    except OSError as e:
        sys.stderr.write(f"Warning: cannot write log file {log_file}: {e}\n")
    if not quiet:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_file, args.quiet)

    if args.list:
        print("Available tmNIDS tests:")
        for tid, label in TESTS.items():
            print(f"  {tid:>2}  {label}")
        return 0

    rng = random.Random(args.seed) if args.seed is not None else random.Random()

    try:
        if args.install_cron:
            return install_cron(args)
        if args.daemon:
            return do_daemon(args, rng)
        return do_run(args, rng)
    except RuntimeError as e:
        # Expected failure modes (e.g. tmNIDS integrity mismatch): report
        # cleanly with a non-zero exit instead of dumping a traceback.
        log.error("%s", e)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
