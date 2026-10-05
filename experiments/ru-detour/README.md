# Isolated encrypted Russian-egress feasibility experiment

An extra remote path, never a test of the user's ISP or a proof of physical Russian location. No production output or history updates. Free standard public-repository GitHub-hosted runner only. No accounts, paid services, user credentials, private traffic, whitelist-only pools, or speed ranking.

## Pinned implementation

Based on main `976c84b3a09bb8a7decc1c623726f28749720986`; stable/reserve snapshot `797d47fa1b3e3b0f6e0981693bfa4000a2954769`. Reuses the strict URI parser, public-DNS validation, HTTPS page classification and SHA-verified official sing-box 1.14.2 archive lock from production. No production code is changed.

sing-box 1.14.2 VLESS and Shadowsocks outbound implementations use `dialer.New(..., options.DialerOptions, ...)`. Its common dialer selects `NewDetour` for an explicit tag. The candidate has `detour: ru-hop`; the sole upstream is an encrypted authenticated outbound. There is no direct, selector, URLTest or fallback outbound. The route rejects UDP. Local authenticated SOCKS listeners bind only to loopback. All raw configurations exist only in memory or mode-0600 temporary files; core logs, curl stderr and response bodies are never uploaded.

Primary source verification:
- https://github.com/SagerNet/sing-box/blob/v1.14.2/common/dialer/dialer.go
- https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/vless/outbound.go
- https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/shadowsocks/outbound.go
- https://sing-box.sagernet.org/configuration/shared/dial/

## Method

1. Fetch only the seven existing public sources; use country labels only as selection hints. Select up to 16 secure supported TCP configurations, favoring distinct endpoints. Do not sample whitelist-only labels or sources. UDP-dependent Hysteria2 is reported separately as unsupported.
2. Actually connect through each encrypted hop, obtain egress IP via two independent HTTPS services (ipify and myip), require exact agreement and a public IP. Cross-check that exact IP with ipwho.is and ipapi.co over validated HTTPS. Require both country codes RU, one consistent ASN, and neutral HTTPS 204 success. Record observation times and confidence; never claim physical RU confirmation. Reject egress matching the cloud baseline when available.
3. Choose up to two qualifying hops, preferring distinct ASNs. If none qualifies, stop with feasibility not established; do not call untested candidates dead.
4. Probe up to 24 exact chosen configurations through each hop and directly from the same cloud runner. The cohort contains user-reported stable negatives, still-unconfirmed reserve configurations and the prior locally working SS `e606956b7e70d0d2` if present. Only neutral HTTPS 204 and recognizable YouTube homepage HTML, no media, speed test, or account traffic. The 24 are deliberately diversity-enriched, not a population-representative sample. The positive control is historical; its current local status is unconfirmed. Count probe attempts separately from unique configurations and complete two-round pairs; no single pass is evidence of stability or local success.
5. Run at most two rounds separated by at least 90 seconds. Each four-candidate batch has control probes before and after. A failed/changed hop control downgrades every result in that batch to unknown. Direct-cloud controls are checked similarly. Report passed, failed tests and unknown separately. A failed remote test is not proof a node is dead or unusable locally.

## Limits and caveats

Three concurrent workers, 24-minute inner budget, 30-minute job cutoff, 196 MiB conservative application-response reservations including feed downloads. Official core archive/setup transfer and TLS/transport overhead are not application payload. Each page is capped at 1 MiB; an oversized YouTube response is unknown, not failed. Strict TLS verification; known HTTPS destinations and all source endpoint DNS addresses are public-validated and the selected address is pinned. One chosen IP per proxy configuration means multi-address failures are not exhaustive. DNS selection comes from the cloud runner, not a Russian ISP. A proxy may route distinct destinations differently; agreeing public IP services do not prove all second-hop traffic follows the same national path. GeoIP may be inaccurate. Home-page accessibility does not establish video playback, throughput, Karing parity or censorship resistance.

The isolated candidate branch replaces only its own existing `experiment.yml` workflow alias so it can be manually dispatched without modifying production main. No push/schedule trigger, no write permission, no secrets, no feed publication. Upload only credential-free `results.json`. Parent review is required before any remote run.


## One bounded diagnostic repair (2026-10-05)

First run 37355709446 (commit b5fecbee03f07356094a60bc68ddeac517fd3600) passed the mandatory actual-core runtime smoke, then produced 10 unknown hops and no candidate tests. Its cloud IP-attribution baseline was also unavailable, without sufficient per-service detail. The first run therefore establishes neither dead hops nor candidate accessibility.

The single repair rechecks only those same ten exact configuration IDs, if still available in the same seven feeds. There is no source/pool expansion. Cloud neutral HTTPS and two directly healthy independent IP services with agreeing cloud IP must be established before any hop connection. Every service control records time, fixed error, HTTP status and observed public IP, without bodies. The service pool is Cloudflare HTTPS trace, AWS HTTPS checkip, ipify and myip; the two selected healthy services must subsequently agree through each hop. Cloudflare `loc` and other incidental country strings never qualify geography. Each hop first must pass neutral HTTPS, then both IP services, then both original GeoIP providers with RU+matching ASN. Failure stage is retained. Failed controls or no qualified hop explicitly leave all24 configs unknown/not-run, with zero probe attempts.

Repair inner cap20minutes. Prior live time42.839seconds and full conservative first-run reservation38027264bytes are charged to the cumulative cap196MiB. A new request's unused byte reservation is refunded only after its process terminates and its output file is measured; process-level timeout reservations remain fully charged. Observed payload is a lower-bound diagnostic; the cumulative upper bound is the safety budget. Setup/core archives, smoke-test loopback data and encrypted transport overhead remain outside application payload. If this repair cannot establish controls or a qualifying hop, stop; no automatic third run.
