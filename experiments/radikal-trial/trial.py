#!/usr/bin/env python3
"""Isolated, manual, full-snapshot Radikal trial. Never publishes to checked.

Only prepare fetches candidate feeds. All quality/security decisions and complete
fresh coverage validation are delegated unchanged to the production pipeline.
Historical observations are only a conservative novelty baseline, never a pass.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import checker as c
import production as p
import validate_output as v

SOURCE = 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt'
CAP = 512
SNAPSHOTS = 4
PRODUCTION_SOURCES = tuple(url for url in c.SOURCES if url != SOURCE)
PRODUCTION_CAP = c.MAX_CANDIDATES
MAX_CONTEXT_BYTES = 8 * 1024 * 1024
CONTEXT_KEYS = {'schema_version', 'trial_source', 'trial_cap', 'identity_version',
                'implementation_sha', 'run_id', 'run_attempt', 'prepared_at',
                'manifest_sha256', 'current', 'history', 'prepare_elapsed_seconds',
                'trial_source_download'}


@contextmanager
def trial_scope():
    """Narrow source/budget only; restore globals even when validation fails."""
    patches = [(c, 'SOURCES', [SOURCE]), (v, 'SOURCES', [SOURCE]),
               (c, 'MAX_CANDIDATES', CAP), (v, 'MAX_CANDIDATES', CAP),
               (c, 'MAX_DEEP', CAP), (v, 'MAX_DEEP', CAP)]
    previous = [(module, name, getattr(module, name)) for module, name, _ in patches]
    try:
        for module, name, value in patches:
            setattr(module, name, value)
        yield
    finally:
        for module, name, value in previous:
            setattr(module, name, value)


def bounded_trial(manifest):
    """Extra experiment-specific guard, independent of production's limits."""
    p.require(0 < len(manifest['candidates']) <= CAP,
              'Radikal trial pool exceeds 512 or is empty; no truncation allowed')
    p.require(p.SHARD_SIZE == 64 and p.MAX_PARALLEL == 8,
              'review changed production shard limits before running this trial')
    p.require(len(manifest['shards']) <= 8 and
              all(len(shard['candidate_ids']) <= 64 for shard in manifest['shards']),
              'Radikal trial shard bound exceeded')
    p.require([source['url'] for source in manifest['sources']] == [SOURCE],
              'Radikal trial contains another source')


def checked_ids(values, maximum):
    p.require(isinstance(values, list) and len(values) <= maximum,
              'invalid comparison identity list')
    for value in values:
        p.hex_value(value, 16)
    p.require(values == sorted(set(values)), 'noncanonical comparison identities')
    return set(values)


def _collect_current():
    """Current six-source parser snapshot, not current network qualification."""
    p.require(tuple(c.SOURCES) == PRODUCTION_SOURCES and len(c.SOURCES) == 6,
              'review changed production source baseline before running trial')
    normalized, provenance, sources, stats = c.collect_candidates()
    candidates = sorted(({'id': c.node_id(uri), 'uri': uri, 'sources': provenance[key]}
                         for key, uri in normalized.items()), key=lambda row: row['id'])
    # Reuse production's independent exact source/identity/count verification.
    p.validate_inventory({'created_at': p.now_iso(), 'sources': sources,
                          'stats': stats, 'candidates': candidates,
                          'history': {'current_ids': [row['id'] for row in candidates]}})
    return {'captured_at': p.now_iso(), 'sources': sources, 'stats': stats,
            'candidate_ids': [row['id'] for row in candidates],
            'scope': 'current-parser-supported-candidates-not-network-qualification'}


def collect_current():
    """Keep the trial comparison against the six other production sources."""
    previous = c.SOURCES, v.SOURCES
    try:
        c.SOURCES = list(PRODUCTION_SOURCES)
        v.SOURCES = c.SOURCES
        return _collect_current()
    finally:
        c.SOURCES, v.SOURCES = previous


def git_output(arguments, limit):
    """Read only fixed git objects. No shell and no credentials in diagnostics."""
    result = subprocess.run(['git', *arguments], cwd=ROOT, capture_output=True,
                            timeout=30, check=False)
    p.require(result.returncode == 0 and len(result.stdout) <= limit,
              'cannot read bounded checked history')
    return result.stdout


def observed_report(data, commit):
    """Do not use historical booleans as proof of qualification or freshness."""
    p.hex_value(commit, 40)
    report = json.loads(data, object_pairs_hook=p.strict_object,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    p.require(isinstance(report, dict) and report.get('identity_version') == c.CANONICALIZATION_VERSION,
              'history identity version differs from trial')
    rows = report.get('results')
    p.require(isinstance(rows, list) and len(rows) <= PRODUCTION_CAP,
              'invalid history result inventory')
    ids = []
    for row in rows:
        p.require(isinstance(row, dict) and row.get('identity_version') == c.CANONICALIZATION_VERSION,
                  'invalid history identity record')
        ids.append(p.hex_value(row.get('id'), 16))
    p.require(len(ids) == len(set(ids)), 'duplicate history identity')
    completed = p.instant(report.get('completed_at'))
    p.require(completed <= datetime.now(timezone.utc), 'future history report')
    return {'commit': commit, 'report_sha256': p.digest(data),
            'completed_at': report['completed_at'], 'candidate_ids': sorted(ids)}


def capture_history(head):
    p.hex_value(head, 40)
    commits = git_output(['rev-list', '--first-parent', '--max-count=4', head], 164).decode('ascii').splitlines()
    p.require(1 <= len(commits) <= SNAPSHOTS and commits[0] == head,
              'missing checked history snapshots')
    snapshots = []
    for commit in commits:
        p.hex_value(commit, 40)
        object_name = commit + ':report.json'
        size = git_output(['cat-file', '-s', object_name], 20).decode('ascii').strip()
        p.require(size.isdecimal() and 0 < int(size) <= p.MAX_REPORT_BYTES,
                  'history report exceeds bound')
        data = git_output(['show', object_name], p.MAX_REPORT_BYTES)
        p.require(len(data) == int(size), 'history report size changed')
        snapshots.append(observed_report(data, commit))
    return {'scope': 'previously-assessed-identities-only-no-reused-qualification',
            'head_commit': head, 'requested_snapshots': SNAPSHOTS, 'snapshots': snapshots}


def validate_context(context, manifest, manifest_digest):
    p.require(isinstance(context, dict) and set(context) == CONTEXT_KEYS,
              'invalid trial comparison schema')
    p.require(type(context['schema_version']) is int and context['schema_version'] == 1 and
              type(context['trial_cap']) is int and context['trial_cap'] == CAP and
              context['trial_source'] == SOURCE and context['identity_version'] == c.CANONICALIZATION_VERSION,
              'different experiment comparison context')
    p.require((context['implementation_sha'], context['run_id'], context['run_attempt']) == p.runtime_identity(),
              'comparison belongs to another implementation or run')
    p.require(context['manifest_sha256'] == manifest_digest,
              'comparison belongs to another trial manifest')
    now = datetime.now(timezone.utc)
    p.fresh(context['prepared_at'], now)
    current = context['current']
    p.require(isinstance(current, dict) and set(current) ==
              {'captured_at', 'sources', 'stats', 'candidate_ids', 'scope'} and
              current['scope'] == 'current-parser-supported-candidates-not-network-qualification',
              'invalid current source comparison')
    p.fresh(current['captured_at'], now)
    ids = checked_ids(current['candidate_ids'], PRODUCTION_CAP)
    p.require(isinstance(current['stats'], dict) and current['stats'].get('unique_candidates') == len(ids),
              'inconsistent current source comparison')
    p.require(isinstance(current['sources'], list) and
              [source.get('url') for source in current['sources']] == list(PRODUCTION_SOURCES) and
              all(source.get('downloaded') is True for source in current['sources']),
              'incomplete current source comparison')
    for source in current['sources']:
        p.fresh(source['fetched_at'], now)
        p.hex_value(source['sha256'], 64)
    history = context['history']
    p.require(isinstance(history, dict) and set(history) ==
              {'scope', 'head_commit', 'requested_snapshots', 'snapshots'} and
              history['scope'] == 'previously-assessed-identities-only-no-reused-qualification' and
              type(history['requested_snapshots']) is int and history['requested_snapshots'] == SNAPSHOTS,
              'invalid history comparison')
    p.hex_value(history['head_commit'], 40)
    snapshots = history['snapshots']
    p.require(isinstance(snapshots, list) and 1 <= len(snapshots) <= SNAPSHOTS,
              'missing or excessive history snapshots')
    seen = set()
    for snapshot in snapshots:
        p.require(isinstance(snapshot, dict) and set(snapshot) ==
                  {'commit', 'report_sha256', 'completed_at', 'candidate_ids'},
                  'invalid history snapshot')
        p.hex_value(snapshot['commit'], 40)
        p.hex_value(snapshot['report_sha256'], 64)
        p.require(snapshot['commit'] not in seen, 'duplicate historical snapshot')
        seen.add(snapshot['commit'])
        p.require(p.instant(snapshot['completed_at']) <= now, 'future history observation')
        checked_ids(snapshot['candidate_ids'], PRODUCTION_CAP)
    p.require(snapshots[0]['commit'] == history['head_commit'], 'history head mismatch')
    value = context['prepare_elapsed_seconds']
    p.require(type(value) in (int, float) and 0 <= value <= 900, 'invalid prepare duration')
    download = context['trial_source_download']
    p.require(isinstance(download, dict) and set(download) == {'decoded_utf8_bytes', 'elapsed_seconds'},
              'invalid source body diagnostics')
    p.integer(download['decoded_utf8_bytes'], c.MAX_FEED)
    p.require(type(download['elapsed_seconds']) in (int, float) and 0 <= download['elapsed_seconds'] <= 65,
              'invalid source download duration')
    bounded_trial(manifest)
    return context


def load_context(directory):
    directory = Path(directory)
    manifest, manifest_digest = p.load_manifest(directory / 'manifest.json')
    context, actual = p.read_json(directory / 'comparison.json', MAX_CONTEXT_BYTES)
    expected = p.read_bytes(directory / 'comparison.sha256', 65).decode('ascii').strip()
    p.hex_value(expected, 64)
    p.require(actual == expected, 'trial comparison digest mismatch')
    return validate_context(context, manifest, manifest_digest), manifest


def prepare(directory, history_head):
    before = time.monotonic()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    current = collect_current()
    history = capture_history(history_head)
    download = {}
    original_download = c.download_feed

    def timed_download(url):
        started = time.monotonic()
        text = original_download(url)
        download.update(decoded_utf8_bytes=len(text.encode('utf-8')),
                        elapsed_seconds=round(time.monotonic() - started, 4))
        return text

    with trial_scope():
        c.download_feed = timed_download
        try:
            manifest = p.prepare(directory / 'manifest.json')
        finally:
            c.download_feed = original_download
        bounded_trial(manifest)
        _, manifest_digest = p.load_manifest(directory / 'manifest.json')
        implementation, run_id, attempt = p.runtime_identity()
        context = {'schema_version': 1, 'trial_source': SOURCE, 'trial_cap': CAP,
                   'identity_version': c.CANONICALIZATION_VERSION,
                   'implementation_sha': implementation, 'run_id': run_id, 'run_attempt': attempt,
                   'prepared_at': p.now_iso(), 'manifest_sha256': manifest_digest,
                   'current': current, 'history': history,
                   'prepare_elapsed_seconds': round(time.monotonic() - before, 4),
                   'trial_source_download': download}
        validate_context(context, manifest, manifest_digest)
        comparison_digest = p.write_json(directory / 'comparison.json', context, MAX_CONTEXT_BYTES)
        (directory / 'comparison.sha256').write_text(comparison_digest + '\n', encoding='ascii')
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
                handle.write('comparison_sha256=' + comparison_digest + '\n')
    return context


def check_shard(directory, shard_id, output, core):
    with trial_scope():
        load_context(directory)
        return p.check_shard(Path(directory) / 'manifest.json', shard_id, output, core)


def summarize(context, manifest, report):
    current = set(context['current']['candidate_ids'])
    snapshots = context['history']['snapshots']
    last_checked = set(snapshots[0]['candidate_ids'])
    history = set().union(*(set(snapshot['candidate_ids']) for snapshot in snapshots))
    trial_ids = {candidate['id'] for candidate in manifest['candidates']}
    yield_counts = {}
    for service in c.FEEDS:
        rows = [row for row in report['results'] if
                (row['qualified'] if service == 'both' else row['service_qualified'][service])]
        ids = {row['id'] for row in rows}
        yield_counts[service] = {
            'fresh_qualified': len(ids),
            'absent_from_current_source_candidates': len(ids - current),
            'absent_from_latest_checked_assessments': len(ids - last_checked),
            'absent_from_all_checked_history_assessments': len(ids - history),
            'absent_from_current_and_all_checked_history': len(ids - current - history),
            'fresh_qualified_protocol_counts': dict(Counter(row['protocol'] for row in rows)),
            'novel_qualified_protocol_counts': dict(Counter(row['protocol'] for row in rows
                                                        if row['id'] not in current | history)),
        }
    attempts = [attempt for row in report['results'] for attempt in row.get('attempts', [])]
    body_by_stage = Counter()
    missing_bytes = 0
    for attempt in attempts:
        if 'bytes' in attempt:
            body_by_stage[attempt['stage']] += attempt['bytes']
        else:
            missing_bytes += 1
    receipts = report['production']['shards']
    runtimes = {receipt['id']: round((p.instant(receipt['completed_at']) -
                                    p.instant(receipt['started_at'])).total_seconds(), 4)
                for receipt in receipts}
    return {
        'schema_version': 1, 'experiment': 'radikal-full-fresh-trial',
        'implementation_sha': manifest['implementation_sha'], 'run_id': manifest['run_id'],
        'source': SOURCE, 'source_sha256': manifest['sources'][0]['sha256'],
        'manifest_sha256': context['manifest_sha256'],
        'completed_at': report['completed_at'], 'probe_origin': report['probe_origin'],
        'coverage': report['coverage'], 'cap': CAP, 'omitted_candidates': 0,
        'trial_candidates': len(trial_ids),
        'trial_candidate_protocol_counts': report['candidate_protocol_counts'],
        'current_source_candidates': len(current),
        'history_snapshots_requested': SNAPSHOTS, 'history_snapshots_available': len(snapshots),
        'history_unique_assessed_candidates': len(history),
        'history_snapshots': [{key: value for key, value in snapshot.items() if key != 'candidate_ids'}
                              for snapshot in snapshots],
        'candidate_novelty': {'absent_from_current': len(trial_ids - current),
                              'absent_from_history': len(trial_ids - history),
                              'absent_from_current_and_history': len(trial_ids - current - history)},
        'yield': yield_counts,
        'diagnostics': report['diagnostics'],
        'source_download': context['trial_source_download'],
        'probe_reported_body_bytes': sum(body_by_stage.values()),
        'probe_reported_body_bytes_by_stage': dict(body_by_stage),
        'attempts_without_byte_measurement': missing_bytes,
        'prepare_elapsed_seconds': context['prepare_elapsed_seconds'],
        'shard_elapsed_seconds': runtimes,
        'sum_shard_elapsed_seconds': round(sum(runtimes.values()), 4),
        'prepare_to_merge_elapsed_seconds': round(context['prepare_elapsed_seconds'] +
                                                 (p.instant(report['completed_at']) -
                                                  p.instant(context['prepared_at'])).total_seconds(), 4),
        'interpretation': [
            'Every supported Radikal candidate receives new unchanged production checks; no sample or historical pass reuse.',
            'Novelty compares identities with current six-source candidates and up to four historical checked reports; baseline nodes were not re-probed by this trial.',
            'Previously assessed includes prior failures; this conservative novelty metric is not a count of additions to a contemporaneously tested production feed.',
            'Reported body bytes include measured retry/failure bodies but exclude unmeasured failures, source/core downloads and protocol overhead; not total egress.',
            'Source decoded UTF-8 byte count excludes a possible removed BOM; exact original bytes are bound by source SHA-256.',
            'Runner origin only; no Russian ISP availability or upstream US/LAX health claim is verified.',
            'YouTube qualification covers recognized homepage HTML, not video/CDN playback.',
            'Experiment-only one-day artifacts; nothing is published to the checked branch.',
        ],
    }


def merge(directory, shards, output):
    output = Path(output)
    with trial_scope():
        context, manifest = load_context(directory)
        feed_output = output / 'validated-trial'
        p.merge(Path(directory) / 'manifest.json', shards, feed_output)
        report = p.verify_public(Path(directory) / 'manifest.json', feed_output)
        summary = summarize(context, manifest, report)
        p.write_json(output / 'trial-summary.json', summary, MAX_CONTEXT_BYTES)
        print(json.dumps({'experiment': summary['experiment'], 'trial_candidates': summary['trial_candidates'],
                          'yield': summary['yield'], 'probe_reported_body_bytes': summary['probe_reported_body_bytes']}))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            lines = ['## Radikal isolated trial', '',
                     f"Fully assessed candidates: {summary['trial_candidates']}; omitted: 0", '',
                     f"Historical snapshots: {summary['history_snapshots_available']}/{SNAPSHOTS}", '']
            for service, counts in summary['yield'].items():
                lines.append(f"- {service}: {counts['fresh_qualified']} freshly qualified; "
                             f"{counts['absent_from_current_and_all_checked_history']} absent from current sources and checked history")
            lines += ['', f"Measured HTTP body bytes: {summary['probe_reported_body_bytes']}",
                      '', 'No publication. Runner-only measurements; no Russian-network or YouTube video-playback proof.',
                      'History is a novelty baseline only. See trial-summary.json for scope and cost limitations.']
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as handle:
                handle.write('\n'.join(lines) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('prepare')
    command.add_argument('--frozen', required=True)
    command.add_argument('--history-head', required=True)
    for name in ('shard', 'merge'):
        command = commands.add_parser(name)
        command.add_argument('--frozen', required=True)
        command.add_argument('--output', required=True)
        if name == 'shard':
            command.add_argument('--shard', required=True)
            command.add_argument('--core', default=str(ROOT / 'bin' / 'sing-box'))
        else:
            command.add_argument('--shards', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.frozen, args.history_head)
    elif args.command == 'shard':
        check_shard(args.frozen, args.shard, args.output, args.core)
    else:
        merge(args.frozen, args.shards, args.output)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, RecursionError, subprocess.SubprocessError):
        # Never print raw exceptions, candidate URIs, provider errors or passwords.
        print('Radikal trial failed closed. No publication; inspect the failing stage and offline tests.', file=sys.stderr)
        raise SystemExit(1)
