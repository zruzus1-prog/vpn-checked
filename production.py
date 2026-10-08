#!/usr/bin/env python3
"""Freeze one source snapshot, probe every candidate, then fail-closed publish.

Only ``prepare`` downloads source feeds. Shards consume that exact, digest-bound
manifest, and merge/publish do no probing or source downloads. Credentials inside
candidate URIs are confined to one-day Actions artifacts, never printed in logs.
"""
import argparse
from collections import Counter
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import time

import checker as c
import history as h

SCHEMA = 1
SHARD_SIZE = 64
MAX_PARALLEL = 8
SHARD_SECONDS = 60 * 60
MAX_MANIFEST_BYTES = 24 * 1024 * 1024
MAX_SHARD_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 64_000_000
CORE_LOCK = Path(__file__).with_name('core-lock.json')
STAT_KEYS = {'raw_lines', 'raw_unique_lines', 'supported_lines', 'unique_candidates',
             'unique_endpoints', 'duplicate_supported_lines',
             'cross_source_duplicate_candidates', 'unsupported_or_rejected_lines',
             'candidate_protocol_counts'}
SOURCE_KEYS = {'url', 'downloaded', 'fetched_at', 'sha256', 'hash_scope', 'lines', 'raw_unique_lines',
               'supported_lines', 'unique_candidates', 'unique_endpoints',
               'duplicate_supported_lines', 'unsupported_or_rejected_lines',
               'rejection_categories', 'raw_protocol_counts', 'supported_protocol_counts'}
MANIFEST_KEYS = {'schema_version', 'created_at', 'implementation_sha', 'run_id',
                 'run_attempt', 'core_lock', 'core_lock_sha256', 'sources', 'stats',
                 'candidates', 'shard_size', 'shards', 'history'}
SHARD_KEYS = {'schema_version', 'manifest_sha256', 'shard_id', 'implementation_sha',
              'started_at', 'completed_at', 'core', 'origin', 'results', 'exports'}


class PipelineError(ValueError):
    """A fixed developer-authored diagnostic, safe to print without raw URIs."""
    pass


def require(condition, message):
    if not condition:
        raise PipelineError(message)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def read_bytes(path, maximum):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), 'invalid artifact file')
    require(path.stat().st_size <= maximum, 'artifact exceeds size bound')
    with path.open('rb') as handle:
        data = handle.read(maximum + 1)
    require(len(data) <= maximum, 'artifact exceeds size bound')
    return data


def read_json(path, maximum):
    data = read_bytes(path, maximum)
    value = json.loads(data, object_pairs_hook=strict_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    require(isinstance(value, dict), 'invalid artifact root')
    return value, digest(data)


def write_json(path, value, maximum):
    data = canonical_bytes(value)
    require(len(data) <= maximum, 'artifact exceeds size bound')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), 'refuse artifact symlink')
    path.write_bytes(data)
    return digest(data)


def integer(value, maximum, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, 'invalid bounded count')
    return value


def hex_value(value, length):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(length)+'}', value),
            'invalid digest or identity')
    return value


def instant(value):
    require(isinstance(value, str) and len(value) <= 40, 'invalid timestamp')
    parsed = datetime.fromisoformat(value)
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0,
            'timestamp must be UTC')
    return parsed


def fresh(value, now):
    parsed = instant(value)
    require(0 <= (now - parsed).total_seconds() < c.MAX_RESULT_AGE_SECONDS,
            'stale or future artifact')
    return parsed


def runtime_identity():
    implementation = os.environ.get('GITHUB_SHA', '')
    hex_value(implementation, 40)
    run_id = os.environ.get('GITHUB_RUN_ID', 'local')
    run_attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
    require(re.fullmatch(r'(?:[0-9]{1,20}|local)', run_id), 'invalid run identity')
    require(re.fullmatch(r'[1-9][0-9]{0,5}', run_attempt), 'invalid run attempt')
    return implementation, run_id, run_attempt


def local_lock():
    return read_json(CORE_LOCK, 16 * 1024)


def histogram(value, allowed, total):
    require(isinstance(value, dict) and not set(value) - allowed, 'invalid histogram')
    require(sum(integer(item, total) for item in value.values()) == total,
            'inconsistent histogram')


def validate_inventory(manifest):
    sources, stats, candidates = (manifest[key] for key in ('sources', 'stats', 'candidates'))
    require(isinstance(sources, list) and len(sources) == len(c.SOURCES), 'incomplete sources')
    require([source.get('url') for source in sources if isinstance(source, dict)] == c.SOURCES,
            'unexpected source inventory')
    require(isinstance(stats, dict) and set(stats) == STAT_KEYS, 'invalid candidate statistics')
    require(isinstance(candidates, list), 'invalid candidates')
    integer(len(candidates), c.MAX_CANDIDATES, 1)
    current_ids = set(manifest['history']['current_ids'])
    keys, ids = set(), set()
    by_source = {url: [] for url in c.SOURCES}
    parsed_candidates = []
    for candidate in candidates:
        require(isinstance(candidate, dict) and set(candidate) == {'id', 'uri', 'sources'},
                'invalid candidate record')
        uri = candidate['uri']
        parsed = c.parse_uri(uri)
        key = c.canonical_key(parsed)
        rid = hex_value(candidate['id'], 16)
        require(rid == c.node_id(uri) and rid not in ids and key not in keys,
                'duplicate or mismatched candidate identity')
        provenance = candidate['sources']
        require(isinstance(provenance, list) and provenance and
                provenance == [url for url in c.SOURCES if url in provenance],
                'invalid candidate provenance')
        ids.add(rid)
        keys.add(key)
        if rid in current_ids:
            parsed_candidates.append(parsed)
            for url in provenance:
                by_source[url].append(parsed)
    require([row['id'] for row in candidates] == sorted(ids), 'noncanonical candidate ordering')
    maximum = c.MAX_FEED_LINES * len(c.SOURCES)
    for source in sources:
        require(set(source) == SOURCE_KEYS and source['downloaded'] is True,
                'source was not successfully frozen')
        require(instant(source['fetched_at']) <= instant(manifest['created_at']),
                'source fetched after snapshot')
        hex_value(source['sha256'], 64)
        require(source['hash_scope'] == 'downloaded-source-bytes', 'source lacks exact-byte hash')
        raw = integer(source['lines'], c.MAX_FEED_LINES)
        integer(source['raw_unique_lines'], raw)
        supported = integer(source['supported_lines'], raw)
        unique = integer(source['unique_candidates'], supported)
        require(source['duplicate_supported_lines'] == supported - unique and
                type(source['duplicate_supported_lines']) is int, 'inconsistent source duplicates')
        rejected = integer(source['unsupported_or_rejected_lines'], raw)
        require(supported + rejected == raw, 'inconsistent source totals')
        parsed = by_source[source['url']]
        require(unique == len(parsed), 'incomplete source candidate coverage')
        endpoints = {(p['type'], p['server'], p['server_port']) for p in parsed}
        require(integer(source['unique_endpoints'], unique) == len(endpoints),
                'inconsistent source endpoints')
        histogram(source['raw_protocol_counts'], c.PROTOCOLS | {'other'}, raw)
        histogram(source['rejection_categories'], c.REJECTION_CATEGORIES, rejected)
        histogram(source['supported_protocol_counts'], c.PROTOCOLS, unique)
        require(source['supported_protocol_counts'] == dict(Counter(p['type'] for p in parsed)),
                'inconsistent source protocols')
    expected = {
        'raw_lines': sum(s['lines'] for s in sources),
        'supported_lines': sum(s['supported_lines'] for s in sources),
        'unique_candidates': len(current_ids),
        'unique_endpoints': len({(p['type'], p['server'], p['server_port']) for p in parsed_candidates}),
        'unsupported_or_rejected_lines': sum(s['unsupported_or_rejected_lines'] for s in sources),
        'candidate_protocol_counts': dict(Counter(p['type'] for p in parsed_candidates)),
    }
    expected['duplicate_supported_lines'] = expected['supported_lines'] - len(current_ids)
    expected['cross_source_duplicate_candidates'] = sum(s['unique_candidates'] for s in sources) - len(current_ids)
    for key, value in expected.items():
        require(type(stats[key]) is type(value) and stats[key] == value,
                'inconsistent global candidate statistics')
        if type(value) is int:
            integer(value, maximum)
    raw_unique = integer(stats['raw_unique_lines'], stats['raw_lines'])
    require(raw_unique >= max(s['raw_unique_lines'] for s in sources),
            'inconsistent unique source lines')


def validate_manifest(manifest, *, now=None):
    now = now or datetime.now(timezone.utc)
    require(set(manifest) == MANIFEST_KEYS and type(manifest['schema_version']) is int and
            manifest['schema_version'] == SCHEMA, 'unknown manifest schema')
    fresh(manifest['created_at'], now)
    implementation, run_id, attempt = runtime_identity()
    require((manifest['implementation_sha'], manifest['run_id'], manifest['run_attempt']) ==
            (implementation, run_id, attempt), 'manifest from a different implementation or run')
    lock, lock_digest = local_lock()
    require(manifest['core_lock'] == lock and manifest['core_lock_sha256'] == lock_digest,
            'manifest core lock mismatch')
    validate_history_manifest(manifest, now)
    validate_inventory(manifest)
    for source in manifest['sources']:
        fresh(source['fetched_at'], now)
    require(type(manifest['shard_size']) is int and manifest['shard_size'] == SHARD_SIZE,
            'unexpected shard bound')
    expected = [{'id': f'{index // SHARD_SIZE:03d}',
                 'candidate_ids': [row['id'] for row in manifest['candidates'][index:index+SHARD_SIZE]]}
                for index in range(0, len(manifest['candidates']), SHARD_SIZE)]
    require(manifest['shards'] == expected, 'incomplete, duplicated, or reordered shard matrix')
    return manifest


def validate_history_manifest(manifest, now):
    history = manifest['history']
    require(isinstance(history, dict) and set(history) == {'state', 'provenance', 'current_ids', 'event'},
            'invalid historical manifest')
    require(history['event'] in ('schedule', 'workflow_dispatch', 'local'), 'invalid history event')
    h.validate(history['state'], now=now)
    require(instant(history['state']['created_at']) <= instant(manifest['created_at']), 'future history state')
    provenance = history['provenance']
    require(isinstance(provenance, dict) and set(provenance) == {'checked_commit', 'authenticated_snapshots', 'mode'},
            'invalid history provenance')
    if provenance['checked_commit'] is not None:
        hex_value(provenance['checked_commit'], 40)
    integer(provenance['authenticated_snapshots'], h.MAX_RUNS)
    require(provenance['mode'] in ('cold-start', 'retained-state', 'verified-bootstrap', 'expired-history', 'local-empty'),
            'invalid history provenance mode')
    current_ids = history['current_ids']
    require(isinstance(current_ids, list) and current_ids == sorted(set(current_ids)), 'invalid current inventory')
    by_id = {row['id']: row for row in manifest['candidates']}
    require(set(current_ids) <= set(by_id), 'missing current candidate')
    historical = {e['id']: e for e in h.prune(history['state'], instant(manifest['created_at']))['entries']
                  if any(o['youtube'] for o in e['observations'])}
    retained = set(by_id)-set(current_ids)
    require(retained == set(historical)-set(current_ids), 'incomplete retained candidate inventory')
    for rid in retained:
        require(by_id[rid] == {k: historical[rid][k] for k in ('id', 'uri', 'sources')},
                'historical candidate altered')


def build_history(manifest, results, exports):
    by_id = {row['id']: row for row in manifest['candidates']}
    current = [by_id[rid] for rid in manifest['history']['current_ids']]
    times = {source['url']: source['fetched_at'] for source in manifest['sources']}
    state = h.update(manifest['history']['state'], current, results,
                     at=manifest['created_at'], implementation_sha=manifest['implementation_sha'],
                     run_id=manifest['run_id'], run_attempt=manifest['run_attempt'],
                     event=manifest['history']['event'],
                     seen_at={row['id']: max(times[u] for u in row['sources']) for row in current})
    feeds, ranking = h.split(state, results, exports)
    metadata = {'state_sha256': digest(h.encoded(state)), 'provenance': manifest['history']['provenance'],
                'current_candidates': len(current), 'retained_candidates': len(by_id)-len(current),
                'assessed_candidates': len(by_id), 'current_ids': manifest['history']['current_ids'],
                'split_counts': {key: len(value) for key, value in feeds.items()}, **ranking}
    return state, feeds, metadata


def load_manifest(path, digest_path=None):
    manifest, actual_digest = read_json(path, MAX_MANIFEST_BYTES)
    digest_path = digest_path or Path(path).with_suffix('.sha256')
    expected_digest = read_bytes(digest_path, 65).decode('ascii').strip()
    hex_value(expected_digest, 64)
    require(actual_digest == expected_digest, 'manifest digest mismatch')
    return validate_manifest(manifest), actual_digest


def prepare(path, *, use_history=False):
    normalized, provenance, sources, stats = c.collect_candidates()
    # Count-only overflow diagnostics never include candidate URIs or secrets.
    summary = {'prepared_at': now_iso(), 'sources': sources, 'stats': stats,
               'capacity': {'limit': c.MAX_CANDIDATES, 'current': len(normalized),
                            'retained': None, 'total': None, 'status': 'sources-collected'}}
    summary_path = Path(path).parent / 'prepare-summary.json'
    write_json(summary_path, summary, MAX_MANIFEST_BYTES)
    if len(normalized) > c.MAX_CANDIDATES:
        summary['capacity']['status'] = 'current-overflow'
        write_json(summary_path, summary, MAX_MANIFEST_BYTES)
        raise PipelineError(f'candidate capacity exceeded: current={len(normalized)}, cap={c.MAX_CANDIDATES}; no truncation or publication')
    print(json.dumps({'sources_available': sum(s.get('downloaded') is True for s in sources),
                      'sources_expected': len(c.SOURCES), 'supported_candidates': len(normalized)}))
    require(len(sources) == len(c.SOURCES) and all(s.get('downloaded') is True for s in sources),
            'one or more sources unavailable; do not publish')
    implementation, run_id, attempt = runtime_identity()
    lock, lock_digest = local_lock()
    candidates = sorted(({'id': c.node_id(uri), 'uri': uri, 'sources': provenance[key]}
                         for key, uri in normalized.items()), key=lambda row: row['id'])
    created_at = now_iso()
    if use_history:
        state, provenance_info = h.load_remote(os.environ.get('GITHUB_REPOSITORY', ''),
                                              os.environ.get('GH_TOKEN'), now=instant(created_at))
    else:
        state, provenance_info = h.empty(created_at), {'checked_commit': None, 'authenticated_snapshots': 0, 'mode': 'local-empty'}
    current_ids = [row['id'] for row in candidates]
    try:
        candidates, state = h.nominate(state, candidates, created_at)
    except h.CapacityError as exc:
        summary['capacity'].update(retained=exc.retained, total=exc.current+exc.retained,
                                   status='combined-overflow')
        write_json(summary_path, summary, MAX_MANIFEST_BYTES)
        raise PipelineError(str(exc)) from None
    summary['capacity'].update(retained=len(candidates)-len(current_ids), total=len(candidates),
                               status='within-limit')
    write_json(summary_path, summary, MAX_MANIFEST_BYTES)
    integer(len(candidates), c.MAX_CANDIDATES, 1)
    history_info = {'state': state, 'provenance': provenance_info, 'current_ids': current_ids,
                    'event': os.environ.get('GITHUB_EVENT_NAME', 'local')}
    manifest = {'schema_version': SCHEMA, 'created_at': created_at,
                'implementation_sha': implementation, 'run_id': run_id, 'run_attempt': attempt,
                'core_lock': lock, 'core_lock_sha256': lock_digest,
                'sources': sources, 'stats': stats, 'candidates': candidates, 'history': history_info,
                'shard_size': SHARD_SIZE,
                'shards': [{'id': f'{index // SHARD_SIZE:03d}',
                            'candidate_ids': [row['id'] for row in candidates[index:index+SHARD_SIZE]]}
                           for index in range(0, len(candidates), SHARD_SIZE)]}
    validate_manifest(manifest)
    actual_digest = write_json(path, manifest, MAX_MANIFEST_BYTES)
    Path(path).with_suffix('.sha256').write_text(actual_digest + '\n', encoding='ascii')
    matrix = {'include': [{'shard': shard['id']} for shard in manifest['shards']]}
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
            handle.write('matrix=' + json.dumps(matrix, separators=(',', ':')) + '\n')
            handle.write('manifest_sha256=' + actual_digest + '\n')
            handle.write('history_commit=' + (provenance_info['checked_commit'] or '') + '\n')
    print(json.dumps({'candidates': len(candidates), 'shards': len(manifest['shards']),
                      'manifest_sha256': actual_digest}))
    return manifest


def expected_shard(manifest, shard_id):
    matches = [shard for shard in manifest['shards'] if shard['id'] == shard_id]
    require(len(matches) == 1, 'unknown shard')
    return matches[0]


def validate_results(manifest, results, exports, ids, *, started_at, completed_at, now=None):
    now = now or datetime.now(timezone.utc)
    start, finish = fresh(started_at, now), fresh(completed_at, now)
    require(instant(manifest['created_at']) <= start <= finish, 'invalid shard time interval')
    require(isinstance(results, list) and len(results) == len(ids), 'incomplete shard assessments')
    require(isinstance(exports, dict) and not set(exports) - set(ids), 'unexpected shard exports')
    candidates = {row['id']: row for row in manifest['candidates']}
    found, required_exports = set(), set()
    for row in results:
        require(isinstance(row, dict), 'invalid assessment')
        rid = row.get('id')
        require(isinstance(rid, str) and rid in ids and rid not in found, 'duplicate or unexpected result ID')
        found.add(rid)
        candidate = candidates[rid]
        require(row.get('identity_version') == c.CANONICALIZATION_VERSION and
                row.get('original_uri_sha256') == digest(candidate['uri'].encode()),
                'result original identity mismatch')
        require(row.get('sources') == candidate['sources'], 'result provenance mismatch')
        require(row.get('protocol') == c.parse_uri(candidate['uri'])['type'], 'result protocol mismatch')
        checked, completed = fresh(row.get('checked_at'), now), fresh(row.get('completed_at'), now)
        require(start <= checked <= completed <= finish, 'invalid assessment time interval')
        reason = row.get('reason', '')
        require(reason == '' or reason in c.RESULT_FAILURE_REASONS, 'unknown assessment reason')
        from validate_output import validate_attempts
        validate_attempts(row)
        require(isinstance(reason, str) and reason not in ('budget', 'deep-budget') and
                not reason.startswith('core-'), 'incomplete or infrastructure-failed assessment')
        services = row.get('service_qualified')
        require(isinstance(services, dict) and set(services) == {'chatgpt', 'youtube'} and
                all(type(value) is bool for value in services.values()), 'invalid service assessment')
        require(type(row.get('qualified')) is bool and row['qualified'] == all(services.values()),
                'invalid combined assessment')
        if any(services.values()):
            required_exports.add(rid)
            require(row.get('baseline_qualified') is True and row.get('deep_tested') is True,
                    'unproven qualified assessment')
            uri = exports.get(rid)
            require(isinstance(uri, str) and c.canonical_key(c.parse_uri(uri)) ==
                    c.canonical_key(c.parse_uri(candidate['uri'])), 'export configuration mismatch')
            require(uri.split('#', 1)[0] == candidate['uri'].split('#', 1)[0],
                    'export changed original connection bytes')
            require(c.node_id(uri) == rid and row.get('subscription_sha256') == digest(uri.encode()),
                    'export digest mismatch')
    require(found == set(ids), 'missing candidate results')
    require(set(exports) == required_exports, 'missing or unexpected exports')


def validate_core(info, lock):
    require(isinstance(info, dict) and set(info) ==
            {'name', 'version', 'archive_sha256', 'binary_sha256', 'os', 'arch'},
            'invalid core provenance')
    require(info['name'] == 'sing-box' and info['version'] == lock['version'] and
            info['archive_sha256'] == lock['sha256'] and info['os'] == 'linux' and
            info['arch'] == 'amd64', 'unexpected core provenance')
    hex_value(info['binary_sha256'], 64)


def preflight_core(candidates, core, deadline):
    """Official core validates every candidate before its network classification.

    A parser/core mismatch is infrastructure failure, never a dead-server verdict.
    Discard core stderr because configuration errors can expose authentication data.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'config.json'
        for candidate in candidates:
            require(time.monotonic() + 12 < deadline, 'core preflight deadline')
            configuration = c.configuration(c.parse_uri(candidate['uri']), 1080, 'offline-schema-check')
            path.write_text(json.dumps(configuration), encoding='utf-8')
            path.chmod(0o600)
            answer = subprocess.run([core, 'check', '-c', str(path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=10, env={'PATH': os.environ['PATH'], 'HOME': directory})
            require(answer.returncode == 0, 'official core rejected candidate configuration')


def check_shard(manifest_path, shard_id, output, core):
    manifest, manifest_digest = load_manifest(manifest_path)
    shard = expected_shard(manifest, shard_id)
    ids = shard['candidate_ids']
    core_info = c.core_metadata(core)
    validate_core(core_info, manifest['core_lock'])
    started_at = now_iso()
    deadline = time.monotonic() + SHARD_SECONDS
    budget = c.DeepBudget(len(ids))
    by_id = {row['id']: row for row in manifest['candidates']}
    candidates = [by_id[rid] for rid in ids]
    preflight_core(candidates, core, deadline)
    results, exports = [], {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=c.WORKERS) as pool:
        for candidate, (result, uri) in zip(candidates, pool.map(
                lambda item: c.probe(item['uri'], core, deadline, budget), candidates)):
            require(result.get('id') == candidate['id'], 'probe identity mismatch')
            result['sources'] = candidate['sources']
            result['protocol'] = c.parse_uri(candidate['uri'])['type']
            results.append(result)
            if uri is not None:
                exports[candidate['id']] = uri
    completed_at = now_iso()
    require(time.monotonic() <= deadline, 'shard exceeded its deadline')
    validate_results(manifest, results, exports, ids, started_at=started_at, completed_at=completed_at)
    payload = {'schema_version': SCHEMA, 'manifest_sha256': manifest_digest,
               'shard_id': shard_id, 'implementation_sha': manifest['implementation_sha'],
               'started_at': started_at, 'completed_at': completed_at,
               'core': core_info, 'origin': c.probe_origin(), 'results': results, 'exports': exports}
    write_json(Path(output) / ('shard-' + shard_id + '.json'), payload, MAX_SHARD_BYTES)
    print(json.dumps({'shard': shard_id, 'assessed': len(results), 'exported': len(exports)}))
    return payload


def production_metadata(manifest, manifest_digest, receipts):
    return {'manifest_sha256': manifest_digest, 'implementation_sha': manifest['implementation_sha'],
            'run_id': manifest['run_id'], 'run_attempt': manifest['run_attempt'],
            'source_snapshot_at': manifest['created_at'],
            'core_lock_sha256': manifest['core_lock_sha256'], 'shard_size': SHARD_SIZE,
            'max_parallel_shards': MAX_PARALLEL, 'shard_count': len(manifest['shards']),
            'shards': receipts}


def resource_summary(results, receipts, started_at):
    attempts = [attempt for row in results for attempt in row.get('attempts', [])]
    finish = max((instant(receipt['completed_at']) for receipt in receipts), default=instant(started_at))
    return {'measured_response_body_bytes': sum(attempt.get('bytes', 0) for attempt in attempts),
            'body_accounting_scope': 'curl-reported bodies only; excludes TLS/proxy overhead and aborted unmeasured bodies',
            'http_attempts': len(attempts), 'assessment_wall_seconds': (finish-instant(started_at)).total_seconds(),
            'summed_shard_seconds': sum((instant(r['completed_at'])-instant(r['started_at'])).total_seconds() for r in receipts),
            'candidate_limit': c.MAX_CANDIDATES, 'maximum_parallel_shards': MAX_PARALLEL,
            'maximum_body_bound_bytes': len(results)*(c.DOWNLOAD_BYTES*2*c.MAX_ATTEMPTS+8*1024*1024+
                                               1024*c.MAX_ATTEMPTS*(len(c.QUICK_ENDPOINTS)*c.MAX_ENDPOINT_ADDRESSES+3))}


def merge(manifest_path, shard_dir, output):
    manifest, manifest_digest = load_manifest(manifest_path)
    shard_dir = Path(shard_dir)
    require(not shard_dir.is_symlink() and shard_dir.is_dir(), 'invalid shard directory')
    require({path.name for path in shard_dir.iterdir()} ==
            {'shard-' + shard['id'] + '.json' for shard in manifest['shards']},
            'missing or unexpected shard artifacts')
    all_results, all_exports, receipts = [], {}, []
    core_info = None
    origin = None
    for shard in manifest['shards']:
        payload, payload_digest = read_json(shard_dir / ('shard-' + shard['id'] + '.json'), MAX_SHARD_BYTES)
        require(set(payload) == SHARD_KEYS and type(payload['schema_version']) is int and
                payload['schema_version'] == SCHEMA, 'invalid shard schema')
        require(payload['manifest_sha256'] == manifest_digest and payload['shard_id'] == shard['id'] and
                payload['implementation_sha'] == manifest['implementation_sha'], 'shard belongs to another manifest')
        validate_core(payload['core'], manifest['core_lock'])
        require(isinstance(payload['origin'], dict) and payload['origin'] == c.probe_origin(),
                'unexpected probing origin')
        if core_info is None:
            core_info, origin = payload['core'], payload['origin']
        require(payload['core'] == core_info and payload['origin'] == origin, 'inconsistent shard infrastructure')
        validate_results(manifest, payload['results'], payload['exports'], shard['candidate_ids'],
                         started_at=payload['started_at'], completed_at=payload['completed_at'])
        all_results.extend(payload['results'])
        all_exports.update(payload['exports'])
        receipts.append({'id': shard['id'], 'sha256': payload_digest,
                         'started_at': payload['started_at'], 'completed_at': payload['completed_at']})
    require(len(all_results) == len(manifest['candidates']), 'incomplete total coverage')
    all_results.sort(key=lambda row: row['id'])
    accepted = {name: [] for name in c.FEEDS}
    for row in all_results:
        uri = all_exports.get(row['id'])
        if uri is not None:
            if row['qualified']:
                accepted['both'].append(uri)
            for service in ('chatgpt', 'youtube'):
                if row['service_qualified'][service]:
                    accepted[service].append(uri)
    metadata = production_metadata(manifest, manifest_digest, receipts)
    state, split_feeds, history_metadata = build_history(manifest, all_results, all_exports)
    resources = resource_summary(all_results, receipts, manifest['created_at'])
    c.write_report(Path(output), manifest['sources'], manifest['stats'], all_results, accepted,
                   manifest['created_at'], core_info, {'production': metadata, 'history': history_metadata, 'resources': resources})
    write_json(Path(output) / 'history.json', state, h.MAX_BYTES)
    for key, filename in h.SPLIT_FEEDS.items():
        lines = split_feeds[key]
        (Path(output) / filename).write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')
    verify_public(manifest_path, output)
    print(json.dumps({'assessed': len(all_results), 'shards': len(receipts),
                      'feed_counts': {name: len(lines) for name, lines in accepted.items()}}))
    return metadata


def verify_public(manifest_path, output):
    """Repeat the independent output validator and frozen-source binding at publish."""
    from validate_output import validate
    manifest, manifest_digest = load_manifest(manifest_path)
    validate(output)
    report, _ = read_json(Path(output) / 'report.json', MAX_REPORT_BYTES)
    validate_core(report.get('core'), manifest['core_lock'])
    require(report.get('probe_origin') == c.probe_origin(), 'unexpected public probing origin')
    require(report.get('coverage', {}).get('complete_supported') is True, 'incomplete coverage cannot publish')
    require(report['sources'] == manifest['sources'] and
            all(report.get(key) == value for key, value in manifest['stats'].items()),
            'report source snapshot mismatch')
    production = report.get('production')
    require(isinstance(production, dict), 'missing production provenance')
    receipts = production.get('shards')
    require(isinstance(receipts, list) and len(receipts) == len(manifest['shards']),
            'incomplete shard receipts')
    require(production == production_metadata(manifest, manifest_digest, receipts),
            'production manifest binding mismatch')
    by_shard = {}
    for receipt, shard in zip(receipts, manifest['shards']):
        require(isinstance(receipt, dict) and set(receipt) == {'id', 'sha256', 'started_at', 'completed_at'} and
                receipt['id'] == shard['id'], 'invalid shard receipt')
        hex_value(receipt['sha256'], 64)
        by_shard[shard['id']] = receipt
    results = report['results']
    require(isinstance(results, list) and len(results) == len(manifest['candidates']),
            'incomplete public assessment inventory')
    by_id = {}
    for row in results:
        require(isinstance(row, dict) and isinstance(row.get('id'), str) and row['id'] not in by_id,
                'duplicate public assessment')
        by_id[row['id']] = row
    require(set(by_id) == {row['id'] for row in manifest['candidates']}, 'public candidate identity mismatch')
    exports = {}
    for filename in c.FEEDS.values():
        for uri in read_bytes(Path(output) / filename, MAX_REPORT_BYTES).decode('utf-8').splitlines():
            rid = c.node_id(uri)
            require(rid not in exports or exports[rid] == uri, 'conflicting exported URI')
            exports[rid] = uri
    require(not set(exports) - set(by_id), 'unexpected public export')
    for shard in manifest['shards']:
        receipt = by_shard[shard['id']]
        validate_results(manifest, [by_id[rid] for rid in shard['candidate_ids']],
                         {rid: uri for rid, uri in exports.items() if rid in shard['candidate_ids']},
                         shard['candidate_ids'], started_at=receipt['started_at'], completed_at=receipt['completed_at'])
    state, split_feeds, history_metadata = build_history(manifest, results, exports)
    require(report['history'] == history_metadata, 'public history evidence mismatch')
    actual_state, state_hash = read_json(Path(output) / 'history.json', h.MAX_BYTES)
    require(actual_state == state and state_hash == history_metadata['state_sha256'], 'public history state mismatch')
    for key, filename in h.SPLIT_FEEDS.items():
        require(read_bytes(Path(output) / filename, 4_000_000).decode('utf-8').splitlines() == split_feeds[key],
                'public split feed mismatch')
    require(report['resources'] == resource_summary(results, receipts, manifest['created_at']),
            'public resource accounting mismatch')
    expected_report = c.report_payload(manifest['sources'], manifest['stats'], results,
        {key: read_bytes(Path(output)/filename, 4_000_000).decode('utf-8').splitlines() for key, filename in c.FEEDS.items()},
        manifest['created_at'], report['core'],
        {'production': production, 'history': history_metadata, 'resources': report['resources']},
        completed_at=report['completed_at'])
    require(report == expected_report, 'public report metadata mismatch')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare_parser = commands.add_parser('prepare')
    prepare_parser.add_argument('--manifest', required=True)
    prepare_parser.add_argument('--history', action='store_true')
    for name in ('shard', 'merge', 'verify-public'):
        command = commands.add_parser(name)
        command.add_argument('--manifest', required=True)
        command.add_argument('--output', required=True)
        if name == 'shard':
            command.add_argument('--shard', required=True)
            command.add_argument('--core', default=os.path.abspath(os.environ.get('SING_BOX', './bin/sing-box')))
        elif name == 'merge':
            command.add_argument('--shards', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.manifest, use_history=args.history)
    elif args.command == 'shard':
        check_shard(args.manifest, args.shard, args.output, args.core)
    elif args.command == 'merge':
        merge(args.manifest, args.shards, args.output)
    else:
        verify_public(args.manifest, args.output)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, RecursionError, subprocess.SubprocessError) as exc:
        # Candidate authentication data can occur in exception details.
        print('Production validation failed; no publication. ' +
              (str(exc) if isinstance(exc, PipelineError) else 'See stage and offline validation tests.'), file=sys.stderr)
        raise SystemExit(1)
