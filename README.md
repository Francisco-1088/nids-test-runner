# nids-test-runner

Randomized NIDS/IPS test driver built on [3CORESec's tmNIDS](https://github.com/3CORESec/testmynids.org).

It periodically generates **benign traffic that trips IDS/IPS signatures** (the ET Open ruleset and similar), so you can continuously verify that your sensor is actually seeing and alerting on traffic — not silently failing. Designed to run unattended on a Raspberry Pi 4 (or any Linux/macOS host) from cron, with randomized timing and randomized test selection so the checks don't fall into a predictable pattern.

> ⚠️ **Use only on networks you own or are authorized to test.** This tool intentionally emits traffic that security tooling is designed to flag. It does **not** exploit anything or attack third parties — it fetches signature-triggering content from `testmynids.org` and simulates outbound patterns — but you should still expect it to generate alerts.

## What it does

- **Auto-installs tmNIDS** — downloads and caches the upstream script on first run (to `~/.local/share/tmnids/tmNIDS`), and **verifies it against a pinned SHA-256** before ever making it executable (see [Integrity](#integrity-of-the-downloaded-tmnids)).
- **Randomizes _what_ runs** — each batch runs a random-sized, random-order subset of the 15 tmNIDS test cases, with random pauses between them.
- **Randomizes _when_ it runs** — a probability gate plus random start jitter turn a fixed cron cadence into unpredictable real firing times.
- **Logs everything** — timestamped output per test to `~/.local/share/tmnids/ids_test_runner.log`.
- **No dependencies** — pure Python 3 standard library.

## Requirements

- Python 3.9+
- tmNIDS's own dependencies on the host: `curl`, `nc` (netcat), and `openssl`

On Raspberry Pi OS / Debian / Ubuntu:

```bash
sudo apt update && sudo apt install -y curl netcat-openbsd openssl python3
```

## Quick start

```bash
git clone https://github.com/Francisco-1088/nids-test-runner.git
cd nids-test-runner

python3 ids_test_runner.py --list          # show the 15 available tests
python3 ids_test_runner.py --dry-run       # preview a batch, generate no traffic
python3 ids_test_runner.py                 # run one batch now
```

## Running it periodically

### Option A — randomized cron (recommended)

Let the script append a crontab entry for you:

```bash
python3 ids_test_runner.py --install-cron --probability 0.34 --max-jitter 480
```

This installs a `*/10 * * * *` job, but the `0.34` probability gate and up-to-8-minute
jitter mean it actually fires a handful of unpredictable times per day. Or add it by hand:

```cron
*/10 * * * * /usr/bin/python3 /home/pi/nids-test-runner/ids_test_runner.py \
  --probability 0.34 --max-jitter 480 --min-tests 1 --max-tests 5 \
  >> /home/pi/ids_test_runner.cron.log 2>&1
```

### Option B — self-scheduling daemon (no cron)

```bash
python3 ids_test_runner.py --daemon --daemon-min 20 --daemon-max 180
```

Loops forever, sleeping a random 20–180 minutes between batches. See
[`systemd/nids-test-runner.service`](systemd/nids-test-runner.service) for running it
under systemd on boot.

## Key options

| Flag | Default | Purpose |
|------|---------|---------|
| `--tests 1,3,5-8` | all 1–15 | Restrict the random pool to specific test IDs |
| `--min-tests` / `--max-tests` | 1 / 5 | Batch size range |
| `--min-gap` / `--max-gap` | 2 / 45 | Random seconds between tests |
| `--probability` | 1.0 | Chance `[0-1]` a given invocation actually runs (cron gate) |
| `--max-jitter` | 0 | Random start delay, 0..N seconds |
| `--timeout` | 60 | Per-test timeout |
| `--daemon` | off | Self-schedule instead of using cron |
| `--seed` | — | Seed the RNG for reproducible selection (testing only) |
| `--dry-run` | off | Show what would run without emitting traffic |
| `--update` | off | Force re-download of tmNIDS |
| `--sha256 HASH` | pinned | Override the tmNIDS SHA-256 to verify against |
| `--no-verify` | off | Skip the integrity check (escape hatch; not recommended) |

Run `python3 ids_test_runner.py --help` for the full list.

## Integrity of the downloaded tmNIDS

The runner never blindly executes what it fetches. The downloaded `tmNIDS` is
checked against a **pinned SHA-256** (`TMNIDS_SHA256` in the script) *before* it
is made executable or run, and the cached copy on disk is re-verified on every
invocation — so neither a compromised upstream repo/account or CDN, nor local
tampering with the cache, can get unreviewed code to run under cron.

When 3CORESec legitimately updates `tmNIDS`, the pinned hash will no longer
match and the tool will **refuse to run**, printing the hash it saw:

```
tmNIDS integrity check FAILED — refusing to run.
  expected sha256: 7016952b...
  actual   sha256: <new hash>
```

To adopt the update: review the upstream diff, confirm the new hash
(`curl -fsSL <url> | shasum -a 256`), then update `TMNIDS_SHA256` (or pass
`--sha256 <hash>`). `--no-verify` bypasses the check entirely and is intended
only as a deliberate escape hatch.

## The tests

| # | Test |
|---|------|
| 1 | Linux UID (id command output over HTTP) |
| 2 | HTTP Basic Authentication (cleartext creds) |
| 3 | HTTP malware user-agents |
| 4 | Bad certificates & CAs (TLS/DNS/TCP) |
| 5 | Tor .onion DNS + node connections |
| 6 | EXE/DLL download over HTTP |
| 7 | PDF with embedded file |
| 8 | SSH outbound scan simulation |
| 9 | Suspicious / sinkhole / DDNS domains |
| 10 | Anonymous filesharing service (TLS) |
| 11 | External IP-address lookup services |
| 12 | URL shortener services |
| 13 | Policy violation — gaming traffic |
| 14 | Adware / PUP activity |
| 15 | Malware C2 beacon |

Test definitions come from upstream tmNIDS; this project only orchestrates *which* run *when*.

## Credits

Built on [3CORESec/testmynids.org](https://github.com/3CORESec/testmynids.org). All the
actual detection test logic is theirs; this repo is a randomizing scheduler around it.

## License

[MIT](LICENSE)

## Pi Script Manager

This repo is also a single-script *source* for the Pi Script Manager (`manifest.json` at the
root, script `nids-tests`, category *traffic*). Each job runs **one** batch right away (no
probability gate or jitter: the Manager decides when) and reports which tests ran.

- `pimgr_run.sh` is the entrypoint; `pimgr_nids.py` reuses this runner's selection and test code.
- tmNIDS is installed by the Manager's `traffic-gen` profile from the upstream commit whose hash
  matches `TMNIDS_SHA256`. The wrapper only verifies it; it never downloads (a mismatch fails the job).
- eth0 only for now: tmNIDS calls `curl`/`nc`/`dig` itself, so its traffic follows the default route.
- When you bump `TMNIDS_SHA256`, update the commit and sha256 in the Manager's `traffic-gen` profile too.
