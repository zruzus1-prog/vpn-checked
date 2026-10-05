"""Pure deterministic diversity selection of already fresh-qualified endpoints.

This module never probes, fetches history, or changes connection settings. Its
prefixes and source owners are heuristics, not verified operators or geolocation.
Caps are hard: a short main list is preferable to silently weakening a cap.
"""
from collections import Counter
from fractions import Fraction
import ipaddress
from urllib.parse import urlsplit

MAIN_CAP = 40
EXPLORATORY_CAP = 10
PROTOCOL_CAP = 20
GROUP_CAP = 12
SOURCE_OWNER_CAP = 20
TIERS = ('strict-history', 'repeated-baseline', 'fresh-diversity')
POLICY = {
    'version': 'balanced-main-v1',
    'main_cap': MAIN_CAP,
    'maximum_non_strict_slots': EXPLORATORY_CAP,
    'maximum_per_endpoint_prefix': 1,
    'ipv4_prefix_length': 24,
    'ipv6_prefix_length': 48,
    'maximum_per_protocol': PROTOCOL_CAP,
    'maximum_per_protocol_transport_security_plugin_group': GROUP_CAP,
    'maximum_per_source_owner': SOURCE_OWNER_CAP,
    'source_accounting': 'all-distinct-contributing-owners-count; no-primary-source-assignment',
    'ranking': 'least-represented-group,scarce-group,least-represented-protocol,evidence-tier,source-balance,semantic-id',
    'scope': 'endpoint-prefix and upstream-owner heuristics; no ASN/operator/country/ISP independence claim',
}


def require(condition):
    if not condition:
        raise ValueError('invalid diversity candidate')


def endpoint_prefix(address):
    address = ipaddress.ip_address(address)
    # Check IPv4-mapped IPv6 by the embedded address, so it cannot bypass /24.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    require(address.is_global and not address.is_multicast)
    return str(ipaddress.ip_network((address, 24 if address.version == 4 else 48), strict=False))


def source_owners(sources):
    """Collapse multiple files from the same GitHub owner, count every owner."""
    require(bool(sources))
    owners = set()
    for source in sources:
        parsed = urlsplit(source)
        parts = parsed.path.strip('/').split('/')
        require(parsed.scheme == 'https' and parsed.hostname == 'raw.githubusercontent.com' and len(parts) >= 4)
        require(bool(parts[0]) and not parsed.username and not parsed.password)
        owners.add(parts[0].lower())
    return tuple(sorted(owners))


def connection_group(outbound):
    protocol = 'ss' if outbound['type'] == 'shadowsocks' else outbound['type']
    transport = 'udp' if protocol == 'hysteria2' else outbound.get('transport', {}).get('type', 'tcp')
    tls = outbound.get('tls', {})
    security = 'reality' if tls.get('reality') else ('tls' if tls.get('enabled') else 'none')
    return '/'.join((protocol, transport, security, outbound.get('plugin') or outbound.get('obfs', {}).get('type', 'plain')))


def select(candidates, *, exploratory_cap=EXPLORATORY_CAP):
    """Select IDs; cap=0 also supports an offline strict-only comparison.

    Required record keys: id, prefix, group, protocol, owners, tier. No speed,
    latency, raw pass count, exit country, or claimed Russian availability is a
    ranking input. Earlier qualification must produce the categorical tier.
    """
    require(type(exploratory_cap) is int and 0 <= exploratory_cap <= EXPLORATORY_CAP)
    by_id = {}
    for candidate in candidates:
        rid = candidate['id']
        require(isinstance(rid, str) and rid and rid not in by_id)
        require(candidate['tier'] in TIERS and candidate['owners'])
        record = dict(candidate)
        record['owners'] = tuple(sorted(set(owner.lower() for owner in candidate['owners'])))
        require(all(record['owners']) and candidate['group'].split('/')[0] == candidate['protocol'])
        network = ipaddress.ip_network(candidate['prefix'])
        require(candidate['prefix'] == str(network) and network.prefixlen == (24 if network.version == 4 else 48))
        require(endpoint_prefix(str(network.network_address)) == candidate['prefix'])
        by_id[rid] = record
    pool = list(by_id.values())
    sizes = Counter(x['group'] for x in pool)
    selected = []
    used = set()
    prefixes = Counter()
    owners = Counter()
    groups = Counter()
    protocols = Counter()
    non_strict = 0

    def reasons(x):
        blocked = []
        if len(selected) >= MAIN_CAP: blocked.append('main-cap')
        if prefixes[x['prefix']] >= 1: blocked.append('endpoint-prefix-cap')
        if groups[x['group']] >= GROUP_CAP: blocked.append('connection-group-cap')
        if protocols[x['protocol']] >= PROTOCOL_CAP: blocked.append('protocol-cap')
        if any(owners[o] >= SOURCE_OWNER_CAP for o in x['owners']): blocked.append('source-owner-cap')
        if x['tier'] != TIERS[0] and non_strict >= exploratory_cap: blocked.append('non-strict-slot-cap')
        return blocked

    while len(selected) < MAIN_CAP:
        available = [x for x in pool if x['id'] not in used and not reasons(x)]
        if not available:
            break
        def score(x):
            return (groups[x['group']], sizes[x['group']], protocols[x['protocol']],
                    TIERS.index(x['tier']), max(owners[o] for o in x['owners']),
                    Fraction(sum(owners[o] for o in x['owners']), len(x['owners'])), x['id'])
        chosen = min(available, key=score)
        selected.append(chosen['id'])
        used.add(chosen['id'])
        prefixes[chosen['prefix']] += 1
        groups[chosen['group']] += 1
        protocols[chosen['protocol']] += 1
        owners.update(chosen['owners'])
        non_strict += chosen['tier'] != TIERS[0]

    decisions = {rid: {'selected': rid in used,
                        'reasons': ['selected-' + x['tier']] if rid in used else reasons(x)}
                 for rid, x in sorted(by_id.items())}
    counts = lambda values: dict(sorted(Counter(values).items()))
    summary = {
        'strict_eligible_before_diversity': sum(x['tier'] == TIERS[0] for x in pool),
        'candidate_tier_counts': counts(x['tier'] for x in pool),
        'selected_tier_counts': {tier: sum(by_id[rid]['tier'] == tier for rid in selected) for tier in TIERS},
        'protocol_counts': dict(sorted(protocols.items())),
        'connection_group_counts': dict(sorted(groups.items())),
        'source_owner_counts': dict(sorted(owners.items())),
        'distinct_endpoint_prefixes': len(prefixes),
    }
    return selected, summary, decisions
