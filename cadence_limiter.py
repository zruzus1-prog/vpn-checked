"""EXPERIMENT: serialize successful snapshot timestamps at least one hour apart.

Run before prepare, under the existing workflow-wide lock, on EVERY publishing
path (scheduled and manual publish=true). Never apply only to the cron path.
Authentication/history errors are fatal just as in existing mandatory prepare.
After waiting, run normal prepare again, recollecting sources and history.
"""
from datetime import datetime, timezone, timedelta
import time
import history

INTERVAL = 3600
MAX_WAIT = 3660


def not_before(state, *, now):
    history.validate(state, now=now, require_recent=True)
    latest = max((history.stamp(run['snapshot_at']) for run in state['runs']), default=None)
    due = max(now, latest + timedelta(seconds=INTERVAL)) if latest else now
    # Historical/manual bursts before rollout may not satisfy the new spacing.
    # Never admit a65th live run; if clearing capacity needs >1h, fail safely.
    if len(state['runs']) >= history.MAX_RUNS:
        oldest = min(history.stamp(run['snapshot_at']) for run in state['runs'])
        due = max(due, oldest + timedelta(seconds=history.MAX_AGE_SECONDS + 1))
    return due


def wait_until(due, *, clock=lambda:datetime.now(timezone.utc), sleep=time.sleep, monotonic=time.monotonic):
    deadline = monotonic() + MAX_WAIT
    while True:
        budget = deadline-monotonic()
        if budget <= 0:
            raise ValueError('cadence wait exceeded bounded budget')
        remaining = (due-clock()).total_seconds()
        if remaining <= 0:
            return
        if remaining > INTERVAL + 1:
            raise ValueError('cadence wait exceeded bounded budget')
        sleep(min(remaining, 30, budget))


def verify_snapshot_slot(manifest, due):
    # Must be called AFTER the final ordinary prepare and before shards/publish.
    # Early/inconsistent wall-clock progress must fail rather than overfill history.
    if history.stamp(manifest['created_at']) < due:
        raise ValueError('snapshot precedes authenticated cadence slot')

# CLI integration keeps the ticket on the same runner, never in public feeds.
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import production

TICKET_KEYS = {'schema_version', 'implementation_sha', 'run_id', 'run_attempt',
               'event', 'publishing', 'observed_at', 'not_before', 'checked_commit'}


def publishing_mode():
    event = os.environ.get('GITHUB_EVENT_NAME')
    ref = os.environ.get('GITHUB_REF')
    value = os.environ.get('CADENCE_PUBLISH')
    history.need(value in ('true', 'false'))
    history.need(event in ('schedule', 'workflow_dispatch'))
    if event == 'schedule':
        history.need(ref == 'refs/heads/main' and value == 'true')
    if value == 'true':
        history.need(ref == 'refs/heads/main')
    return value == 'true'


def read_ticket(path):
    ticket, _ = production.read_json(path, 4096)
    history.need(isinstance(ticket, dict) and set(ticket) == TICKET_KEYS)
    history.need(type(ticket['schema_version']) is int and ticket['schema_version'] == 1)
    implementation, run_id, attempt = production.runtime_identity()
    history.need(ticket['implementation_sha'] == implementation and ticket['run_id'] == run_id and
                 ticket['run_attempt'] == attempt and ticket['event'] == os.environ.get('GITHUB_EVENT_NAME'))
    history.need(type(ticket['publishing']) is bool and ticket['publishing'] == publishing_mode())
    observed = history.stamp(ticket['observed_at'])
    due = history.stamp(ticket['not_before'])
    history.need(0 <= (due-observed).total_seconds() <= INTERVAL + 1)
    checked = ticket['checked_commit']
    history.need(checked is None or (isinstance(checked, str) and re.fullmatch('[0-9a-f]{40}', checked)))
    return ticket


def reserve(path, *, clock=lambda:datetime.now(timezone.utc), loader=history.load_remote):
    publishing = publishing_mode()
    implementation, run_id, attempt = production.runtime_identity()
    now = clock()
    due, checked = now, None
    if publishing:
        production.diagnostic_stage('prepare.history')
        state, provenance = loader(os.environ.get('GITHUB_REPOSITORY', ''), os.environ.get('GH_TOKEN'), now=now)
        history.need(run_id not in {run['run_id'] for run in state['runs']})
        due = not_before(state, now=now)
        checked = provenance['checked_commit']
        history.need(0 <= (due-now).total_seconds() <= INTERVAL + 1)
    ticket = {'schema_version': 1, 'implementation_sha': implementation,
              'run_id': run_id, 'run_attempt': attempt, 'event': os.environ['GITHUB_EVENT_NAME'],
              'publishing': publishing, 'observed_at': now.isoformat(),
              'not_before': due.isoformat(), 'checked_commit': checked}
    production.write_json(path, ticket, 4096)
    read_ticket(path)
    # Only fixed labels and time deltas, never history, tokens or candidate data.
    print(json.dumps({'cadence': 'reserved', 'wait_seconds': max(0, (due-clock()).total_seconds())}))
    return ticket


def wait_ticket(path, *, clock=lambda:datetime.now(timezone.utc), sleep=time.sleep, monotonic=time.monotonic):
    ticket = read_ticket(path)
    history.need(clock() >= history.stamp(ticket['observed_at']))
    wait_until(history.stamp(ticket['not_before']), clock=clock, sleep=sleep, monotonic=monotonic)


def verify_final(manifest, ticket):
    # The normal prepare authenticates history again. Reject intervening writers,
    # even if a subsequent publication lease would otherwise accept their head.
    if not ticket['publishing']:
        return
    created = history.stamp(manifest['created_at'])
    verify_snapshot_slot(manifest, history.stamp(ticket['not_before']))
    history.need(manifest['history']['provenance']['checked_commit'] == ticket['checked_commit'])
    state = manifest['history']['state']
    history.need(manifest['run_id'] not in {run['run_id'] for run in state['runs']})
    history.need(not_before(state, now=created) <= created)


def prepare_slot(ticket_path, manifest_path, *, clock=lambda:datetime.now(timezone.utc), prepare=production.prepare):
    ticket = read_ticket(ticket_path)
    history.need(clock() >= history.stamp(ticket['not_before']))
    # Do not expose matrix/digest outputs until all cadence checks pass.
    output_path = os.environ.pop('GITHUB_OUTPUT', None)
    try:
        manifest = prepare(manifest_path, use_history=True)
        verify_final(manifest, ticket)
        frozen, digest = production.read_json(manifest_path, production.MAX_MANIFEST_BYTES)
        history.need(frozen == manifest)
        production.validate_manifest(frozen)
        history.need(Path(manifest_path).with_suffix('.sha256').read_text().strip() == digest)
    finally:
        if output_path is not None:
            os.environ['GITHUB_OUTPUT'] = output_path
    if output_path:
        matrix = {'include': [{'shard': shard['id']} for shard in manifest['shards']]}
        with open(output_path, 'a', encoding='utf-8') as output:
            output.write('matrix=' + json.dumps(matrix, separators=(',', ':')) + '\n')
            output.write('manifest_sha256=' + digest + '\n')
            output.write('history_commit=' + (manifest['history']['provenance']['checked_commit'] or '') + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('reserve', 'wait', 'prepare'))
    parser.add_argument('--ticket', required=True)
    parser.add_argument('--manifest')
    args = parser.parse_args()
    production.diagnostic_stage('prepare')
    if args.command == 'reserve':
        reserve(args.ticket)
    elif args.command == 'wait':
        wait_ticket(args.ticket)
    else:
        history.need(bool(args.manifest))
        prepare_slot(args.ticket, args.manifest)


def run_cli():
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, RecursionError, subprocess.SubprocessError) as exc:
        production.emit_diagnostic('failure', exc)
        return 1
    production.emit_diagnostic('success')
    return 0


if __name__ == '__main__':
    raise SystemExit(run_cli())
