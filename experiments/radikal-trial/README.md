# Isolated Radikal trial

This manual-only experiment evaluates
`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt`
without adding it to the six production sources or publishing to `checked`.
Dispatch **Isolated Radikal source trial** after reviewing its implementation.
There is no automatic schedule, publish option, write token, billing change or
user-device setting change.

## Scope and fail-closed budget

The complete parser-supported, deduplicated snapshot must contain 1–512 candidates.
Over 512 fails the whole trial; nothing is silently sampled or omitted. The
unchanged production pipeline freezes, preflights and probes at most eight
64-candidate shards, at most eight concurrently, with four workers per shard and
the normal 60-minute shard deadline. Every candidate is checked again now.

The wrapper narrows source/candidate/deep-budget globals only for the current
process, including the independent validator's imported constants; it always
restores them. It does not change TLS, DNS/public-address rules, pinned core,
retry limits, HTTPS probes, two full speed samples, stability window, service
recognition, freshness, exact-manifest identity or complete-coverage requirements.
All original candidate bytes before the display fragment remain unchanged.

Prepare reads the six production feeds as a contemporaneous parser-only novelty
baseline. It also reads up to the latest four first-parent `checked` commits,
with exact report digest and observation time. Those historical IDs mean
previously **assessed**, including failures. No old pass is imported or labeled
fresh. Missing sources/history, bad identities, budget overflow, missing shards,
unsafe schemas or stale/incomplete trials fail closed. Fewer than four existing
history commits are explicitly counted rather than padded.

## What the result measures

`trial-summary.json` contains protocol counts, fresh qualifiers for each existing
feed, and the number of fresh qualifiers absent from:

- all current production source candidates
- the latest checked report's assessed candidates
- all available four-report historical assessed candidates
- both the current source pool and historical pool

These are conservative identity-novelty counts. Baseline candidates are not
re-probed in this experiment, and previously failed identities count as already
seen. Consequently this is not a claim about the exact gain against a simultaneous
production run, nor an assertion that upstream's US/LAX health results prove
availability from Russia.

The summary includes actual shard elapsed seconds, preparation duration and
measured HTTP response-body bytes by probe stage. Bodies from retries/failures
are counted when curl reported them; missing byte measurements are counted
separately. These numbers exclude unknown failed transfers, headers/protocol
overhead and source/core downloads, and are not total network egress or billed
runner minutes. Source UTF-8 bytes exclude a possible decoded BOM; exact original
source bytes are independently identified by SHA-256. Worst-case documented
bulk/service-body budget is approximately 8 GiB at 512 candidates, plus small
204 responses, downloads and overhead; early failures usually reduce it.

Measurements are from ordinary GitHub-hosted runners, not a verified Russian
network. YouTube qualification covers recognized homepage HTML only, not video
or Googlevideo CDN playback. Public proxy endpoints remain untrusted.

`validated-trial/` contains the ordinary independently verified production-format
report, three service feeds, and cold-start split/history artifacts. The trial
does not load production stability history, so a single trial does not establish
multi-run stability. Nothing is written to a public subscription branch. Manifests and feed artifacts include public upstream connection
credentials, so they are retained for only one day and never printed to logs.
Do not treat artifact retention as a confidentiality boundary in a public repo.
The summary and logs contain only fixed diagnostics, hashes, counts and timings.

## Licensing

Source: https://github.com/0xRadikal/Free-v2ray-Configs (MIT).
The exact upstream MIT text is preserved in `UPSTREAM-LICENSE.txt` (verified
2026-10-05 from GitHub blob `4c64c1d3f3addc7f673d52fc748729bc883c36df`;
Copyright (c) 2026 0xRadikal). This trial
filters, deduplicates and relabels supported inputs and selects only fresh
qualifiers. The checker remains GPL-3.0-only under the repository `LICENSE`;
upstream MIT rights and notices are preserved. License notices grant no rights
to third-party proxy infrastructure or trademarks and do not establish endpoint
ownership or authorization. Distribute trial feeds with these notices.

## Offline verification

From repository root:

    python3 -m unittest discover -s tests -v
    python3 -m unittest discover -s experiments/radikal-trial/tests -v

All experiment tests use synthetic feed/probe/history fixtures. They do not
fetch sources, start a real proxy core, or connect to proxy endpoints. A successful
offline test is not a live source-trial result.
