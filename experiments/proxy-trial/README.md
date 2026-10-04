# Isolated public-proxy feasibility trial

This is a diagnostic experiment, separate from the subscription publisher. It
does not write, regenerate, or deploy any subscription. The workflow is manual
only, has `contents: read`, does not persist checkout credentials, and contains
no publish job. Do not dispatch the existing production checker for this test.

## Files to add after authorized review

- `experiment.yml` → `.github/workflows/experiment.yml`
- `trial.py`, `prepare_inputs.py`, `test_trial.py`, `feeds.json`, this README →
  `experiments/proxy-trial/`
- Do not commit local `inputs/`, `selected-private.json`, downloaded core,
  temporary files, or measurement results.

## Method and scope

Six allowlisted public subscription feeds are snapshotted, parsed, and compared
by canonical effective connection parameters. Display fragments are excluded
from identity; meaningful packet encoding, SNI, credentials, paths, flow, TLS,
and transport parameters remain part of identity. Original URI strings are kept
unchanged in an ephemeral, mode-0600 local plan, never logged or uploaded.

The original three sources are controls. The three candidate sources are the
full igareck BLACK VLESS list, Vovaplus secure VLESS, and V2RayAggregator Eternity.
Each source contributes at most four unique supported configurations. For new
sources, only configurations absent from all original controls are eligible.
Within each source, supported protocols are stratified, then configurations are
ordered by canonical SHA-256. Duplicate choices across sources are tested once.
The previously working Shadowsocks endpoint is preferentially selected if it
occurs in current supported control snapshots; its absence is recorded rather
than substituting an old configuration.

This is a small feasibility sample, not representative source-wide reliability
evidence or a source ranking. Counts of novel configurations and novel
host:port endpoints are separate. Unsupported, unsafe, unavailable, unselected,
budget-skipped, and actually failed probes are distinct.

At most 24 unique configurations, four concurrent processes, two rounds through
the same core with starts at least 30 seconds apart, and 16 minutes of probing
within a 20-minute workflow limit:

1. Two verified HTTPS 204 endpoints per round, requiring empty body and <=4s.
2. If either succeeds, one exact 2 MiB Cloudflare download per round, requiring
   HTTP 200 and >=256 KiB/s including connection setup time.
3. YouTube and ChatGPT HTTPS pages, <=2 MiB each. HTTP 200 plus conservative page
   recognition is required; redirects and challenge pages do not qualify.

No logins, cookies, user accounts, private traffic, browser challenge solving,
or TLS verification exceptions. The destination proxy must resolve only to
public addresses and is pinned to one validated IP for the core. The SOCKS
listener is loopback-only and password-protected. There is no direct fallback.

The 30-second spacing tests short-term repeatability, not preservation of a
single TCP stream, hours of uptime, video playback, or logged-in ChatGPT use.
GitHub/dot-cloud success cannot establish accessibility from a Russian ISP.
Automated HTTP 403 or another unsuccessful page probe does not establish that
a human browser through that server cannot work.

## Limits and runtime

Maximum useful probe payload: 288 MiB, plus <=96 KiB of bounded 204 responses,
<=24 MiB input subscriptions, protocol overhead, and a 31,680,686-byte official
sing-box archive. `curl` and Python 3.12 standard library only; no pip packages.
Official sing-box 1.14.2 archive SHA-256:

`a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`

The immutable GitHub release asset digest was checked against the existing
project lock on October 4, 2026. The installer verifies the archive before
extracting only its regular-file binary, and the harness rechecks its binary
digest before use. No feed-supplied scripts or commands are executed.

## Execution

Offline: `python3 -m unittest -v test_trial`

On an authorized GitHub runner: `python3 prepare_inputs.py`, then
`python3 trial.py run --vantage 'GitHub hosted runner; not the user network'`.
The workflow limits the whole job to 20 minutes, allowing bounded input/core
preparation around the 16-minute probing limit.

Only `inventory.json`, `results.json`, and `core-verification.json` are uploaded.
They contain source provenance, aggregate counts, hash IDs, fixed diagnostic
labels, timings and byte counts, not proxy URIs, passwords, cookies or HTML.

## Local validation and current blocker

Offline tests and Python compilation passed. Live cloud tests have NOT run:
the official-core download failed with `curl: (6) Could not resolve host:
github.com` after one authorized retry. The absence of a live result is not a
failed-proxy result. Local snapshot statistics are provisional until refreshed
on the actual runner.
