"""Bounded, owned-repository history; never a substitute for a fresh probe.

GitHub HTTPS/API and the protected-by-ownership checked branch are the trust root.
Upstream feeds cannot supply this state. A historic success can only nominate a
candidate for retest, never qualify an export. No configuration data is logged.
"""
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import urllib.request
import urllib.error

import checker as c
import diversity as d

SCHEMA = 1
MEASUREMENT_PROFILE = 'sing-box-1.14.2-v2/https204-stability45-2x2MiB-256KiBs-youtube-html-v1'
BOOTSTRAP_IMPLEMENTATIONS = {'8601c067ce2f7dde936b17808b7bf58906131d19',
                             '976c84b3a09bb8a7decc1c623726f28749720986',
                             '2ebfbd4c8d64c3c3d40577d3d5688cbf51579484',
                             '4a398dfbc1fae8da90eae755dcda8661871a1cd0',
                             'fcb28f217015b2fabe966b52713bcbe52bae62ad',
                             '144c2dea096443d2db6829fe0a8e61e88abdf6b2',
                             'b6ad19206976ccdc66069f929b0bb29e9cc8d82b'}
TWELVE_WAY_IMPLEMENTATIONS = {'b6ad19206976ccdc66069f929b0bb29e9cc8d82b'}
LEGACY_SPLIT_IMPLEMENTATIONS = {'976c84b3a09bb8a7decc1c623726f28749720986'}
# Captured allowlists, not a source list supplied by a historical report.
CURRENT_SOURCE_INVENTORY = tuple(c.SOURCES)
LEGACY_SOURCE_INVENTORY = CURRENT_SOURCE_INVENTORY[:-1]
MAX_AGE_SECONDS = 48 * 3600
MAX_BYTES = 48 * 1024 * 1024
MAX_RUNS = 64
MAX_ANCHOR_RUNS = 64  # Separate proof-only budget; never extends scored history.
MAX_ENTRIES = 8192  # Metadata churn budget, separate from live 4096-node probe cap
MAX_URI_BYTES = 16384
STABLE_CAP = 40
MIN_PASSES = 3
MIN_SPAN_SECONDS = 6 * 3600
MIN_RUN_GAP_SECONDS = 90 * 60
MIN_STABLE_KIB_S = 512
MIN_RATE = .90
SPLIT_FEEDS = {'stable': 'subscription-youtube-stable.txt', 'reserve': 'subscription-youtube-reserve.txt'}
STATE_KEYS = {'schema_version', 'measurement_profile', 'identity_version', 'created_at', 'runs', 'entries'}
RUN_KEYS = {'run_id', 'run_attempt', 'snapshot_at', 'implementation_sha', 'event'}
ENTRY_KEYS = {'id', 'uri', 'sources', 'last_upstream_seen_at', 'observations'}
OBS_KEYS = {'run_id', 'youtube', 'min_kib_s', 'median_ms', 'tested_address'}
LEGACY_POLICY = {'retention_seconds': MAX_AGE_SECONDS, 'metadata_entry_cap': MAX_ENTRIES, 'main_cap': STABLE_CAP,
          'minimum_distinct_passes': MIN_PASSES, 'minimum_span_seconds': MIN_SPAN_SECONDS,
          'minimum_run_gap_seconds': MIN_RUN_GAP_SECONDS, 'minimum_observed_pass_rate': MIN_RATE,
          'minimum_all_pass_speed_kib_s': MIN_STABLE_KIB_S, 'last_observed_passes_required': 2,
          'diversity': 'one-per-current-tested-address-after-qualification',
          'ranking': 'pass-rate,pass-count,worst-pass-speed,median-latency,semantic-id',
          'scope': 'YouTube-homepage-and-baseline-from-GitHub; not Russia or media-playback proof'}


POLICY = {**LEGACY_POLICY, 'main_cap': d.MAIN_CAP,
          'selection_policy': d.POLICY,
          'minimum_all_pass_speed_kib_s': MIN_STABLE_KIB_S,
          'minimum_speed_scope': 'strict-history tier only; other tiers retain fresh 256 KiB/s baseline',
          'diversity': 'hard endpoint-prefix,protocol,connection-group,and all-source-owner caps',
          'ranking': d.POLICY['ranking'],
          'history_scope': 'strict-history and repeated-baseline tiers; at most 20 explicitly classified diversity slots'}


def need(condition):
    if not condition:
        raise ValueError('invalid trusted history')


def stamp(value):
    need(isinstance(value, str) and len(value) <= 40)
    at = datetime.fromisoformat(value)
    need(at.tzinfo is not None and at.utcoffset().total_seconds() == 0)
    return at


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def empty(at):
    return {'schema_version': SCHEMA, 'measurement_profile': MEASUREMENT_PROFILE, 'identity_version': c.CANONICALIZATION_VERSION,
            'created_at': at, 'runs': [], 'entries': []}


def bounded_number(value):
    need(type(value) in (float, int) and math.isfinite(value) and value >= 0)


def validate(state, *, now, require_recent=False):
    need(isinstance(state, dict) and set(state) == STATE_KEYS and state['schema_version'] == SCHEMA)
    need(type(state['schema_version']) is int and state['identity_version'] == c.CANONICALIZATION_VERSION)
    need(state['measurement_profile'] == MEASUREMENT_PROFILE)
    created = stamp(state['created_at'])
    need(created <= now and (not require_recent or (now-created).total_seconds() <= MAX_AGE_SECONDS))
    need(len(encoded(state)) <= MAX_BYTES)
    runs = state['runs']
    need(isinstance(runs, list) and len(runs) <= MAX_RUNS)
    by_run = {}
    previous = None
    for run in runs:
        need(isinstance(run, dict) and set(run) == RUN_KEYS)
        need(isinstance(run['run_id'], str) and re.fullmatch(r'[0-9]{1,20}|local', run['run_id']))
        need(run['run_id'] not in by_run and run['event'] in ('schedule', 'workflow_dispatch', 'local'))
        need(isinstance(run['run_attempt'], str) and re.fullmatch(r'[1-9][0-9]{0,5}', run['run_attempt']))
        need(isinstance(run['implementation_sha'], str) and re.fullmatch('[0-9a-f]{40}', run['implementation_sha']))
        at = stamp(run['snapshot_at'])
        need(at <= created and (created-at).total_seconds() <= MAX_AGE_SECONDS)
        need(previous is None or at > previous)
        previous = at
        by_run[run['run_id']] = run
    entries = state['entries']
    need(isinstance(entries, list) and len(entries) <= MAX_ENTRIES)
    ids = set()
    for entry in entries:
        need(isinstance(entry, dict) and set(entry) == ENTRY_KEYS)
        uri = entry['uri']
        need(isinstance(entry['id'],str) and re.fullmatch('[0-9a-f]{16}',entry['id']) and entry['id'] not in ids)
        if uri is not None:
            need(isinstance(uri, str) and len(uri.encode()) <= MAX_URI_BYTES and entry['id'] == c.node_id(uri))
        ids.add(entry['id'])
        sources = entry['sources']
        need(isinstance(sources, list) and sources and sources == [u for u in c.SOURCES if u in sources])
        seen = stamp(entry['last_upstream_seen_at'])
        need(seen <= created and (created-seen).total_seconds() <= MAX_AGE_SECONDS)
        observations = entry['observations']
        need(isinstance(observations, list) and 0 < len(observations) <= MAX_RUNS)
        seen_runs = []
        has_pass = False
        for obs in observations:
            need(isinstance(obs, dict) and set(obs) == OBS_KEYS)
            rid = obs['run_id']
            need(rid in by_run and rid not in seen_runs and type(obs['youtube']) is bool)
            seen_runs.append(rid)
            if obs['youtube']:
                has_pass = True
                bounded_number(obs['min_kib_s']); bounded_number(obs['median_ms'])
                need(obs['min_kib_s'] >= c.MIN_BYTES_PER_SECOND/1024 and obs['median_ms'] <= 120000)
                need(isinstance(obs['tested_address'], str) and c.public_ip(obs['tested_address']))
            else:
                need(all(obs[k] is None for k in ('min_kib_s', 'median_ms', 'tested_address')))
        need(seen_runs == [r['run_id'] for r in runs if r['run_id'] in seen_runs])
        need((uri is not None) == has_pass)
    need([e['id'] for e in entries] == sorted(ids))
    return state


def prune(state, now):
    validate(state, now=now)
    kept_runs = [r for r in state['runs'] if (now-stamp(r['snapshot_at'])).total_seconds() <= MAX_AGE_SECONDS]
    ids = {r['run_id'] for r in kept_runs}
    entries = []
    for item in state['entries']:
        observations = [o for o in item['observations'] if o['run_id'] in ids]
        if (now-stamp(item['last_upstream_seen_at'])).total_seconds() <= MAX_AGE_SECONDS and observations:
            entries.append({**item, 'observations': observations,
                            'uri': item['uri'] if any(o['youtube'] for o in observations) else None})
    return {'schema_version': SCHEMA, 'measurement_profile': MEASUREMENT_PROFILE, 'identity_version': c.CANONICALIZATION_VERSION,
            'created_at': now.isoformat(), 'runs': kept_runs, 'entries': entries}


class CapacityError(ValueError):
    """Safe count-only nomination diagnostic, containing no upstream text."""
    def __init__(self, current, retained):
        self.current, self.retained = current, retained
        super().__init__(f'candidate capacity exceeded: current={current}, retained={retained}, total={current+retained}, cap={c.MAX_CANDIDATES}; no truncation or publication')


def nominate(state, current, at):
    """Current inventory wins exact URI; retained rows never refresh source time."""
    state = prune(state, stamp(at))
    current_ids = {row['id'] for row in current}
    retained = [{'id': e['id'], 'uri': e['uri'], 'sources': e['sources']}
                for e in state['entries'] if e['id'] not in current_ids and any(o['youtube'] for o in e['observations'])]
    if len(current) + len(retained) > c.MAX_CANDIDATES:
        raise CapacityError(len(current), len(retained))
    return sorted(current + retained, key=lambda e: e['id']), state


def measured_min_speed(row):
    """Use exact validated download timings, not one-decimal display rounding."""
    samples = []
    for stage in ('download-1', 'download-2'):
        matches = [a for a in row.get('attempts', []) if a.get('stage') == stage and
                   a.get('address') == row.get('tested_address') and a.get('passed') is True]
        need(bool(matches))
        elapsed = matches[-1].get('elapsed_seconds')
        bounded_number(elapsed); need(elapsed > 0)
        samples.append(c.DOWNLOAD_BYTES / elapsed / 1024)
    value = min(samples); bounded_number(value)
    return value


def update(state, current, results, *, at, implementation_sha, run_id, run_attempt, event, seen_at=None):
    """Record this fully verified run. A source absence is no observation by itself."""
    now = stamp(at)
    state = prune(state, now)
    # An already published logical run cannot be replayed as new evidence.
    need(run_id not in {r['run_id'] for r in state['runs']})
    runs = list(state['runs'])
    runs.append({'run_id': run_id, 'run_attempt': run_attempt, 'snapshot_at': at,
                 'implementation_sha': implementation_sha, 'event': event})
    need(len(runs) <= MAX_RUNS)
    current_by_id = {r['id']: r for r in current}
    entries = {e['id']: {**e, 'observations': [o for o in e['observations'] if o['run_id'] != run_id]} for e in state['entries']}
    for row in results:
        rid = row['id']
        passed = row['service_qualified']['youtube']
        upstream = current_by_id.get(rid)
        if upstream:
            entry = entries.setdefault(rid, {'id': rid, 'observations': []})
            entry.update({'uri': upstream['uri'] if passed or any(o['youtube'] for o in entry['observations']) else None, 'sources': upstream['sources'], 'last_upstream_seen_at': (seen_at or {}).get(rid, at)})
        else:
            need(rid in entries)
            entry = entries[rid]
        entry['observations'].append({'run_id': run_id, 'youtube': passed,
            'min_kib_s': measured_min_speed(row) if passed else None,
            'median_ms': row.get('median_ms') if passed else None,
            'tested_address': row.get('tested_address') if passed else None})
    output = {'schema_version': SCHEMA, 'measurement_profile': MEASUREMENT_PROFILE, 'identity_version': c.CANONICALIZATION_VERSION,
              'created_at': at, 'runs': runs, 'entries': [entries[rid] for rid in sorted(entries)]}
    validate(output, now=now)
    return output


def legacy_split(state, results, exports):
    """Qualify before diversity/ranking, with all overflow retained in reserve."""
    runs = {r['run_id']: r for r in state['runs']}
    current = {r['id']: r for r in results if r['service_qualified']['youtube']}
    qualified = []
    evidence = {}
    for entry in state['entries']:
        rid = entry['id']
        if rid not in current:
            continue
        # Real distinct runs, separated in time. Rapid manual retries cannot boost
        # evidence. Failures still remain in the pass-rate denominator below.
        observed = entry['observations']
        considered = [o for o in observed if runs[o['run_id']]['event'] != 'local']
        passes = [o for o in considered if o['youtube']]
        spaced = []
        for obs in passes:
            at = stamp(runs[obs['run_id']]['snapshot_at'])
            if not spaced or (at-spaced[-1][0]).total_seconds() >= MIN_RUN_GAP_SECONDS:
                spaced.append((at, obs))
        # Keep maximal count, but let the latest success extend the span.
        if len(spaced) >= 2 and passes:
            latest = passes[-1]
            spaced[-1] = (stamp(runs[latest['run_id']]['snapshot_at']), latest)
        rate = len(passes)/len(considered) if considered else 0
        span = (spaced[-1][0]-spaced[0][0]).total_seconds() if spaced else 0
        eligible = (len(spaced) >= MIN_PASSES and span >= MIN_SPAN_SECONDS and rate >= MIN_RATE and
                    len(considered) >= 2 and all(o['youtube'] for o in considered[-2:]) and
                    passes and min(o['min_kib_s'] for o in passes) >= MIN_STABLE_KIB_S and
                    current[rid]['min_kib_s'] >= MIN_STABLE_KIB_S and
                    measured_min_speed(current[rid]) >= MIN_STABLE_KIB_S)
        evidence[rid] = {'observed_runs': len(considered), 'passes': len(passes),
                        'spaced_passes': len(spaced), 'span_seconds': span, 'pass_rate': rate,
                        'eligible': bool(eligible)}
        if eligible:
            speeds = min(o['min_kib_s'] for o in passes)
            latency = sorted(o['median_ms'] for o in passes)[len(passes)//2]
            qualified.append((-rate, -len(spaced), -speeds, latency, rid))
    chosen = []
    addresses = set()
    for *_, rid in sorted(qualified):
        address = current[rid]['tested_address']
        if len(chosen) < STABLE_CAP and address not in addresses:
            chosen.append(rid); addresses.add(address)
    reserve = sorted(set(current)-set(chosen))
    return {'stable': [exports[rid] for rid in chosen], 'reserve': [exports[rid] for rid in reserve]}, {
        'policy': LEGACY_POLICY, 'eligible_before_diversity': len(qualified),
        'stable_ids': chosen, 'reserve_ids': reserve, 'evidence': evidence}


def split(state, results, exports):
    """Fresh qualification is mandatory; history chooses tiers, never freshness.

    The strict tier retains every original history/speed requirement. At most
    ten other fresh-baseline candidates can contribute missing variations.
    No connection URI or fragment is edited by this partition.
    """
    _, legacy = legacy_split(state, results, exports)
    evidence = legacy['evidence']
    current = {row['id']: row for row in results if row['service_qualified']['youtube']}
    need(set(current) == set(exports) and set(evidence) == set(current))
    entries = {entry['id']: entry for entry in state['entries']}
    candidates = []
    runs = {run['run_id']: run for run in state['runs']}
    for rid, row in sorted(current.items()):
        need(row['min_kib_s'] >= c.MIN_BYTES_PER_SECOND/1024 and
             measured_min_speed(row) >= c.MIN_BYTES_PER_SECOND/1024)
        entry = entries[rid]
        ev = evidence[rid]
        observed = [obs for obs in entry['observations'] if runs[obs['run_id']]['event'] != 'local']
        repeated = (ev['spaced_passes'] >= MIN_PASSES and ev['span_seconds'] >= MIN_SPAN_SECONDS and
                    ev['pass_rate'] >= MIN_RATE and len(observed) >= 2 and
                    all(obs['youtube'] for obs in observed[-2:]))
        tier = 'strict-history' if ev['eligible'] else 'repeated-baseline' if repeated else 'fresh-diversity'
        outbound = c.parse_uri(exports[rid])
        need(c.node_id(exports[rid]) == rid)
        protocol = 'ss' if outbound['type'] == 'shadowsocks' else outbound['type']
        candidate = {'id': rid, 'prefix': d.endpoint_prefix(row['tested_address']),
                     'protocol': protocol, 'group': d.connection_group(outbound),
                     'owners': d.source_owners(entry['sources']), 'tier': tier}
        candidates.append(candidate)
        ev.update({'tier': tier, 'repeated_cloud_evidence': bool(repeated),
                   'endpoint_prefix': candidate['prefix'], 'connection_group': candidate['group'],
                   'source_owners': list(candidate['owners'])})
    chosen, summary, decisions = d.select(candidates)
    for rid, decision in decisions.items():
        evidence[rid].update(decision)
    reserve = sorted(set(current)-set(chosen))
    return {'stable': [exports[rid] for rid in chosen], 'reserve': [exports[rid] for rid in reserve]}, {
        'policy': POLICY, 'eligible_before_diversity': len(candidates), 'selection': summary,
        'stable_ids': chosen, 'reserve_ids': reserve, 'evidence': evidence}


def split_for_report(state, results, exports, report, *, allow_legacy=False):
    """Only archived reports from explicit old commits may use the old selector.

    Current publication validation never opts into this read-only compatibility
    path. Authentication of the old commit/run is separately required by replay.
    """
    legacy = report['history'].get('policy') == LEGACY_POLICY
    if legacy:
        need(allow_legacy and report['production']['implementation_sha'] in LEGACY_SPLIT_IMPLEMENTATIONS)
        return legacy_split(state, results, exports)
    need(report['history'].get('policy') == POLICY)
    return split(state, results, exports)


def strict_json(data):
    def object_pairs(pairs):
        value = {}
        for k, v in pairs:
            need(k not in value); value[k] = v
        return value
    return json.loads(data, object_pairs_hook=object_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid history JSON')))


def remote_read(url, maximum, token=None):
    """Only fixed GitHub endpoints, bounded TLS fetches, no redirect credential leak."""
    allowed = ('https://api.github.com/repos/', 'https://raw.githubusercontent.com/')
    need(any(url.startswith(prefix) for prefix in allowed))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('history redirects forbidden')
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'vpn-checked-history'}
    if token and url.startswith(allowed[0]):
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        need(response.status == 200)
        data = response.read(maximum + 1)
    need(len(data) <= maximum)
    return data


def authenticate_publication(repo, commit, report, token, *, now):
    """A published own-repo commit plus successful exact Actions run/attempt.

    This does not defend against an authorized repository owner forging content;
    it excludes untrusted feed-supplied history and accidental foreign/run data.
    """
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repo))
    sha = commit['sha']; need(re.fullmatch('[0-9a-f]{40}', sha))
    from production import validate_core, local_lock
    validate_core(report.get('core'), local_lock()[0])
    need(report.get('identity_version') == c.CANONICALIZATION_VERSION)
    limits = report['limits']
    need(limits['stability_window_seconds'] == c.STABILITY_SECONDS and limits['download_bytes_per_sample'] == c.DOWNLOAD_BYTES and limits['download_samples'] == 2 and limits['min_kib_s'] == c.MIN_BYTES_PER_SECOND//1024)
    meta = report['production']
    need(meta.get('implementation_sha') in BOOTSTRAP_IMPLEMENTATIONS | {os.environ.get('GITHUB_SHA', '')})
    expected_keys = {'manifest_sha256','implementation_sha','run_id','run_attempt','source_snapshot_at','core_lock_sha256','shard_size','max_parallel_shards','shard_count','shards'}
    need(isinstance(meta, dict) and set(meta) == expected_keys)
    need(meta['source_snapshot_at'] == report['started_at'] and meta['core_lock_sha256'] == local_lock()[1])
    need(type(meta['shard_count']) is int and 0 < meta['shard_count'] <= (c.MAX_CANDIDATES + 63) // 64 and len(meta['shards']) == meta['shard_count'])
    expected_parallel = 12 if meta['implementation_sha'] in TWELVE_WAY_IMPLEMENTATIONS else 8
    need(meta['shard_size'] == 64 and meta['max_parallel_shards'] == expected_parallel)
    for key in ('manifest_sha256','core_lock_sha256'):
        need(isinstance(meta[key], str) and re.fullmatch('[0-9a-f]{64}', meta[key]))
    for index, receipt in enumerate(meta['shards']):
        need(isinstance(receipt, dict) and set(receipt) == {'id','sha256','started_at','completed_at'})
        need(receipt['id'] == f'{index:03d}' and re.fullmatch('[0-9a-f]{64}', receipt['sha256']))
        need(stamp(report['started_at']) <= stamp(receipt['started_at']) <= stamp(receipt['completed_at']) <= stamp(report['completed_at']))
    rid = meta['run_id']; need(isinstance(rid, str) and re.fullmatch(r'[0-9]{1,20}', rid))
    attempt = meta['run_attempt']; need(isinstance(attempt, str) and re.fullmatch('[1-9][0-9]{0,5}', attempt))
    base = 'https://api.github.com/repos/' + repo
    run = strict_json(remote_read(base+'/actions/runs/'+rid+'/attempts/'+attempt, 1024*1024, token))
    need(str(run['id']) == rid and str(run['run_attempt']) == attempt and run['conclusion'] == 'success' and run['status'] == 'completed')
    need(run['repository']['full_name'] == repo and run['head_repository']['full_name'] == repo and
         run['head_branch'] == 'main' and run['head_sha'] == meta['implementation_sha'] and
         run['path'] == '.github/workflows/check.yml' and run['event'] in ('schedule', 'workflow_dispatch'))
    jobs = strict_json(remote_read(base+'/actions/runs/'+rid+'/attempts/'+attempt+'/jobs?per_page=100', 4*1024*1024, token))
    need(jobs['total_count'] == len(jobs['jobs']))
    publication_jobs = [job for job in jobs['jobs'] if job['name'] == 'publish' and job['conclusion'] == 'success']
    need(len(publication_jobs) == 1)
    publication_job = publication_jobs[0]
    committed = stamp(commit['commit']['committer']['date'])
    need(stamp(run['run_started_at']) <= stamp(report['started_at']) <= stamp(report['completed_at']) <= committed+timedelta(seconds=1))
    need(stamp(publication_job['started_at']) <= committed+timedelta(seconds=1) and committed <= stamp(publication_job['completed_at']) <= stamp(run['updated_at']))
    if 'history' in report:
        parents = commit.get('parents')
        provenance = report['history']['provenance']
        expected_parent = provenance['checked_commit']
        need(isinstance(parents, list))
        if expected_parent is None:
            need(parents == [] and provenance['mode'] == 'cold-start')
        else:
            need(len(parents) == 1 and expected_parent == parents[0]['sha'])
    need(committed <= now and (now-stamp(report['started_at'])).total_seconds() <= MAX_AGE_SECONDS)
    need(commit['commit']['committer']['name'] == 'github-actions[bot]' and
         commit['commit']['committer']['email'] == '41898282+github-actions[bot]@users.noreply.github.com')
    return run['event']


@contextmanager
def archived_source_inventory(report):
    """Read-compatible exact six/seven inventories; no current-source relaxation."""
    import validate_output as output_validator
    sources = report.get('sources')
    need(isinstance(sources, list) and all(isinstance(source, dict) for source in sources))
    inventory = tuple(source.get('url') for source in sources)
    need(inventory in (LEGACY_SOURCE_INVENTORY, CURRENT_SOURCE_INVENTORY))
    previous = c.SOURCES, output_validator.SOURCES
    try:
        c.SOURCES = list(inventory)
        output_validator.SOURCES = c.SOURCES
        yield
    finally:
        c.SOURCES, output_validator.SOURCES = previous



BALANCED_40_IMPLEMENTATIONS = {
    '2ebfbd4c8d64c3c3d40577d3d5688cbf51579484',
    '4a398dfbc1fae8da90eae755dcda8661871a1cd0',
    'fcb28f217015b2fabe966b52713bcbe52bae62ad',
}


@contextmanager
def archived_selection_policy(report):
    """Reproduce the exact old 40-node split only for reviewed predecessors."""
    global POLICY
    if report['production']['implementation_sha'] not in BALANCED_40_IMPLEMENTATIONS:
        yield
        return
    names = ('MAIN_CAP', 'EXPLORATORY_CAP', 'PROTOCOL_CAP', 'GROUP_CAP', 'SOURCE_OWNER_CAP')
    previous = {name: getattr(d, name) for name in names}
    previous_policy, previous_selection = POLICY, d.POLICY
    try:
        for name, value in zip(names, (40, 10, 20, 12, 20)):
            setattr(d, name, value)
        d.POLICY = {**d.POLICY, 'version': 'balanced-main-v1', 'main_cap': 40,
                    'maximum_non_strict_slots': 10, 'maximum_per_protocol': 20,
                    'maximum_per_protocol_transport_security_plugin_group': 12,
                    'maximum_per_source_owner': 20}
        POLICY = {**POLICY, 'main_cap': 40, 'selection_policy': d.POLICY,
                  'history_scope': 'strict-history and repeated-baseline tiers; at most 10 explicitly classified diversity slots'}
        yield
    finally:
        POLICY, d.POLICY = previous_policy, previous_selection
        for name, value in previous.items():
            setattr(d, name, value)


def source_anchors_complete(snapshots, now):
    """Prove the seed for each earliest retained observation, without claims."""
    first = {}
    for snapshot in reversed(snapshots):
        at = stamp(snapshot['run']['snapshot_at'])
        if (now-at).total_seconds() <= MAX_AGE_SECONDS:
            for row in snapshot['rows']:
                first.setdefault(row['id'], (at, row['id'] in snapshot['current_ids']))
    needed = {rid: at for rid, (at, current) in first.items() if not current}
    for snapshot in snapshots:
        for row in snapshot['rows']:
            rid = row['id']
            if rid in needed and rid in snapshot['current_ids'] and stamp(snapshot['run']['snapshot_at']) <= needed[rid]:
                seen = stamp(max(snapshot['source_times'][u] for u in row['sources']))
                if 0 <= (needed[rid]-seen).total_seconds() <= MAX_AGE_SECONDS:
                    del needed[rid]
    return not needed


def load_remote(repo, token, *, now=None):
    """Rebuild history from bounded authenticated publications, never aggregates.

    Every observation comes from a separately validated report and exact success
    of its own Actions run. The latest cumulative file is cross-checked against
    this replay; it cannot authenticate invented older runs itself.
    """
    from validate_output import validate as validate_output
    now = now or datetime.now(timezone.utc)
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repo))
    base = 'https://api.github.com/repos/' + repo
    try:
        commits = strict_json(remote_read(base+'/commits?sha=checked&per_page=32', 8*1024*1024, token))
    except urllib.error.HTTPError as exc:
        if exc.code != 404: raise
        return empty(now.isoformat()), {'checked_commit': None, 'authenticated_snapshots': 0, 'mode': 'cold-start'}
    page_size = 32
    need(isinstance(commits, list) and len(commits) <= page_size)
    # At hourly cadence the inclusive 96-hour proof horizon can span 97
    # commits. Four fixed pages bound API work; live/anchor caps stay separate.
    for page in range(2, (MAX_RUNS + MAX_ANCHOR_RUNS) // page_size + 1):
        if len(commits) < (page - 1) * page_size:
            break
        if (now-stamp(commits[-1]['commit']['committer']['date'])).total_seconds() > 2 * MAX_AGE_SECONDS:
            break
        older = strict_json(remote_read(base+f'/commits?sha=checked&per_page=32&page={page}', 8*1024*1024, token))
        need(isinstance(older, list) and len(older) <= page_size)
        commits += older
    snapshots = []
    live_snapshots = anchor_snapshots = 0
    # One additional window supplies direct source-presence anchors for the
    # oldest retained measurements. Anchors never survive into output history.
    anchor_seconds = 2 * MAX_AGE_SECONDS
    newest = commits[0]['sha'] if commits else None
    latest_claim = None
    previous_commit = None
    seen_runs = set()
    for commit in commits:
        committed = stamp(commit['commit']['committer']['date'])
        need(committed <= now)
        if (now-committed).total_seconds() > MAX_AGE_SECONDS and source_anchors_complete(snapshots, now):
            break
        if (now-committed).total_seconds() > anchor_seconds:
            break
        sha = commit['sha']; need(re.fullmatch('[0-9a-f]{40}', sha))
        if previous_commit is not None:
            parents = previous_commit.get('parents')
            need(isinstance(parents, list) and len(parents) == 1 and parents[0]['sha'] == sha)
        previous_commit = commit
        root_url = 'https://raw.githubusercontent.com/' + repo + '/' + sha + '/'
        report_data = remote_read(root_url+'report.json', 64_000_000)
        report = strict_json(report_data)
        if not snapshots and (now-stamp(report['started_at'])).total_seconds() > MAX_AGE_SECONDS:
            break
        if (now-stamp(report['started_at'])).total_seconds() > anchor_seconds:
            break
        if report.get('schema_version') != 4 or report.get('identity_version') != c.CANONICALIZATION_VERSION:
            # Older formats cannot prove a compatible measurement history.
            break
        if (now-stamp(report['started_at'])).total_seconds() > MAX_AGE_SECONDS:
            anchor_snapshots += 1
            need(anchor_snapshots <= MAX_ANCHOR_RUNS)
        else:
            live_snapshots += 1
            need(live_snapshots <= MAX_RUNS)
        # Commit time is an authenticated historical horizon, not a relaxed
        # measurement window. The outer loop separately bounds anchor age.
        event = authenticate_publication(repo, commit, report, token, now=committed)
        meta = report['production']
        need(meta['run_id'] not in seen_runs)
        seen_runs.add(meta['run_id'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'report.json').write_bytes(report_data)
            for filename in c.FEEDS.values():
                (root/filename).write_bytes(remote_read(root_url+filename, 4_000_000))
            if 'history' in report:
                data = remote_read(root_url+'history.json', MAX_BYTES)
                state = strict_json(data)
                need(hashlib.sha256(data).hexdigest() == report['history']['state_sha256'])
                validate(state, now=stamp(report['completed_at']), require_recent=True)
                for filename in SPLIT_FEEDS.values():
                    (root/filename).write_bytes(remote_read(root_url+filename, 4_000_000))
                (root/'history.json').write_bytes(data)
                if not snapshots:
                    latest_claim = prune(state, now)
            with archived_source_inventory(report), archived_selection_policy(report):
                validate_output(root, as_of=stamp(report['completed_at']), allow_legacy_split=True)
            exports = {c.node_id(uri): uri for uri in (root/c.FEEDS['youtube']).read_text().splitlines()}
            # Retain only bounded compact facts, never all full attempt-heavy reports.
            rows = [{'id': row['id'], 'sources': row['sources'], 'original_uri_sha256': row['original_uri_sha256'], 'youtube': row['service_qualified']['youtube'],
                     'min_kib_s': measured_min_speed(row) if row['service_qualified']['youtube'] else None,
                     'median_ms': row.get('median_ms') if row['service_qualified']['youtube'] else None,
                     'tested_address': row.get('tested_address') if row['service_qualified']['youtube'] else None}
                    for row in report['results']]
            snapshots.append({'run': {'run_id': meta['run_id'], 'run_attempt': meta['run_attempt'],
                              'snapshot_at': report['started_at'], 'implementation_sha': meta['implementation_sha'], 'event': event},
                              'rows': rows, 'exports': exports,
                              'current_ids': set(report.get('history', {}).get('current_ids', [row['id'] for row in rows])),
                              'source_times': {source['url']: source['fetched_at'] for source in report['sources']}})
        del report, report_data
    if len(commits) == MAX_RUNS + MAX_ANCHOR_RUNS:
        need(source_anchors_complete(snapshots, now))
    runs, entries, original_hashes = [], {}, {}
    for snapshot in reversed(snapshots):
        run = snapshot['run']
        at = stamp(run['snapshot_at'])
        runs = [r for r in runs if (at-stamp(r['snapshot_at'])).total_seconds() <= MAX_AGE_SECONDS]
        retained_runs = {r['run_id'] for r in runs}
        # Match update(): prune before the new source snapshot can refresh an
        # identity. A true source-expiry gap starts a new nomination epoch.
        entries = {rid: {**entry, 'observations': [o for o in entry['observations'] if o['run_id'] in retained_runs]}
                   for rid, entry in entries.items()
                   if (at-stamp(entry['last_upstream_seen_at'])).total_seconds() <= MAX_AGE_SECONDS}
        entries = {rid: entry for rid, entry in entries.items() if entry['observations']}
        for entry in entries.values():
            if not any(o['youtube'] for o in entry['observations']):
                entry['uri'] = None
        runs.append(run)
        for row in snapshot['rows']:
            rid = row['id']
            original_hashes[rid] = row['original_uri_sha256']
            is_current = rid in snapshot['current_ids']
            if rid not in entries and not is_current:
                # Only the older anchor prefix may lack its own earlier seed.
                # Every retained in-window observation needs a direct source
                # appearance proven by an independently authenticated report.
                need((now-at).total_seconds() > MAX_AGE_SECONDS)
                continue
            entry = entries.setdefault(rid, {'id': rid, 'uri': None, 'sources': row['sources'], 'observations': []})
            if is_current:
                entry['sources'] = row['sources']
                entry['last_upstream_seen_at'] = max(snapshot['source_times'][u] for u in row['sources'])
            if row['youtube']:
                entry['uri'] = snapshot['exports'][rid]
            entry['observations'].append({'run_id': run['run_id'], **{key:row[key] for key in OBS_KEYS-{'run_id'}}})
        need(len(entries) <= MAX_ENTRIES)
    state = {'schema_version': SCHEMA, 'measurement_profile': MEASUREMENT_PROFILE,
             'identity_version': c.CANONICALIZATION_VERSION,
             'created_at': runs[-1]['snapshot_at'] if runs else now.isoformat(),
             'runs': runs, 'entries': [entries[rid] for rid in sorted(entries)]}
    state = prune(state, now)
    runs = state['runs']
    if latest_claim is not None:
        # Compare all claimed observations and source timestamps to independent
        # replay. Unknown claimed runs or conflicting facts fail closed. URI
        # fragments may differ because old public exports already carry a label.
        need(latest_claim['runs'] == runs)
        by_id = {entry['id']: entry for entry in state['entries']}
        need({entry['id'] for entry in latest_claim['entries']} == set(by_id))
        for claim in latest_claim['entries']:
            actual = by_id.get(claim['id'])
            need(actual is not None and claim['observations'] == actual['observations'] and
                 claim['last_upstream_seen_at'] == actual['last_upstream_seen_at'] and claim['sources'] == actual['sources'])
            if claim['uri'] is not None:
                need(actual['uri'] is not None and (claim['uri'].split('#',1)[0] == actual['uri'].split('#',1)[0] or
                     hashlib.sha256(claim['uri'].encode()).hexdigest() == original_hashes[claim['id']]))
                # Preserve original retained fragment only after facts match.
                actual['uri'] = claim['uri']
    return state, {'checked_commit': newest, 'authenticated_snapshots': len(runs),
                   'mode': 'retained-state' if latest_claim is not None else 'verified-bootstrap' if runs else 'expired-history'}
