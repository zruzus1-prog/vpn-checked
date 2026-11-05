# Isolated NoMoreWalls and Aetris source sample

This one-time experiment is triggered only by changes to its files on the branch
`experiment/sources-20261105`. It never runs the production publisher, fetches
or modifies checked/history, or generates a user subscription. The token has
contents-read permission only and checkout credentials are not persisted.

The runner freezes all six current production feeds plus two fixed public feeds:

- https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt
- https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/main/configs.txt

Canonical identities use the unchanged production parser and identity function.
Both new pools exclude identities in the contemporaneous production source pool.
Overlap between the two new pools is reported and assigned to NoMoreWalls for
sampling, so no effective configuration is probed twice.

At most 24 configurations per cohort (72 total) are chosen deterministically by
protocol round-robin, prioritizing distinct and baseline-new URI hosts and literal
IP prefixes. This is a deliberately diverse, nonrandom sample, not a census or a
representative estimate of feed success rates. The baseline is the current
parser-supported source pool, not exclusively production-qualified servers.
Different hostname strings and /24 IPv4 or /48 IPv6 prefixes are only diversity
proxies, not evidence of different owners, physical servers, or networks.

The three cohorts are interleaved on one runner with four workers and a 35-minute
probe deadline. The job limit is 55 minutes including tests and setup. The exact
production checker is reused without changes: strict TLS and public-IP pinning,
bounded retries, authenticated local proxy, 45 seconds of stability observations,
two 2 MiB downloads at >=256 KiB/s, and recognized YouTube/ChatGPT homepage HTML.
Requests retain the production limits of at most three endpoint addresses and two
attempts per stage. Each result is checked with the production diagnostic
validator before inclusion. Budget or infrastructure failures make the sample
incomplete; they are not interpreted as negative evidence about a server.

Only plan.json and report.json are uploaded for three days. They include source
hashes, anonymous candidate IDs, public endpoint IPs, and credential-free test
diagnostics. Source URI credentials, raw response bodies, temporary proxy configs,
subscription files and history are never uploaded.

The network vantage is a GitHub-hosted cloud runner, not a Russian ISP or the
user's connection. YouTube checks cover homepage HTML only, not playback or media
CDN availability. Passing this short experiment is not long-term reliability.
