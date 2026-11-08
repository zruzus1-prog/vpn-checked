"""Offline proof that the retry-only upgrade retains exact predecessor history."""
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from unittest import TestCase
from unittest.mock import patch

import checker as c
import history as h
import production as p
import test_history as history_fixtures
import test_pipeline as fixtures
import validate_output as v

PREDECESSOR = '0df1fc752a9640937af4b04f490fdddce7d86420'
RETRY_IMPLEMENTATION = 'a' * 40  # Synthetic new GITHUB_SHA, not blanket trust.


class CoreRetryHistoryTrustTests(TestCase):
    fixtures = history_fixtures.AuthenticationTests.fixtures

    def test_predecessor_and_current_keep_exact_eight_way_evidence(self):
        self.assertEqual(p.MAX_PARALLEL, 8)
        self.assertNotIn(PREDECESSOR, h.TWELVE_WAY_IMPLEMENTATIONS)
        for implementation in (PREDECESSOR, RETRY_IMPLEMENTATION):
            for claimed in (8, 12):
                report, commit, run, jobs = self.fixtures()
                report['production'].update(implementation_sha=implementation,
                                            max_parallel_shards=claimed)
                run['head_sha'] = implementation
                with self.subTest(implementation=implementation, claimed=claimed), \
                     patch.dict(os.environ, {'GITHUB_SHA': RETRY_IMPLEMENTATION}), \
                     patch.object(h, 'remote_read', side_effect=[h.encoded(run), h.encoded(jobs)]):
                    if claimed == 8:
                        self.assertEqual(h.authenticate_publication('owner/repo', commit, report,
                                          None, now=history_fixtures.NOW), 'schedule')
                    else:
                        with self.assertRaises(ValueError):
                            h.authenticate_publication('owner/repo', commit, report, None,
                                                       now=history_fixtures.NOW)

    def test_exact_predecessor_does_not_authorize_an_unknown_commit(self):
        report, commit, _, _ = self.fixtures()
        report['production']['implementation_sha'] = 'b' * 40
        with patch.dict(os.environ, {'GITHUB_SHA': RETRY_IMPLEMENTATION}), \
             patch.object(h, 'remote_read') as read, self.assertRaises(ValueError):
            h.authenticate_publication('owner/repo', commit, report, None,
                                       now=history_fixtures.NOW)
        read.assert_not_called()

    def test_predecessor_still_requires_exact_core_run_and_successful_publish(self):
        for tamper in ('core', 'head', 'publish'):
            report, commit, run, jobs = self.fixtures()
            report['production']['implementation_sha'] = run['head_sha'] = PREDECESSOR
            if tamper == 'core':
                report['core']['archive_sha256'] = '0' * 64
            elif tamper == 'head':
                run['head_sha'] = 'b' * 40
            else:
                jobs['jobs'][0]['conclusion'] = 'failure'
            with self.subTest(tamper=tamper), \
                 patch.dict(os.environ, {'GITHUB_SHA': RETRY_IMPLEMENTATION}), \
                 patch.object(h, 'remote_read', side_effect=[h.encoded(run), h.encoded(jobs)]), \
                 self.assertRaises(ValueError):
                h.authenticate_publication('owner/repo', commit, report, None,
                                           now=history_fixtures.NOW)


class CoreRetryHistoryReplayTests(TestCase):
    setUp = fixtures.PipelineTests.setUp
    run_shards = fixtures.PipelineTests.run_shards

    def test_predecessor_upgrade_and_next_run_preserve_authenticated_artifacts(self):
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixtures.TEST_CLOCK[0] + timedelta(seconds=5)

        base = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
        api = 'https://api.github.com/repos/owner/repo'
        commits_url = api + '/commits?sha=checked&per_page=32'
        remote, commits = {}, []
        previous_sha = None
        phases = (PREDECESSOR, RETRY_IMPLEMENTATION, RETRY_IMPLEMENTATION)

        def read(url, maximum, token=None):
            # A closed fixture: there is no external read fallback.
            if url == commits_url and not commits:
                raise h.RemoteReadError('http_status', status=404, attempts=1)
            data = remote[url]
            self.assertLessEqual(len(data), maximum)
            return data

        for index, implementation in enumerate(phases):
            fixtures.TEST_CLOCK[0] = base + timedelta(hours=index * 2)
            with self.subTest(index=index, implementation=implementation), \
                 patch.dict(os.environ, {'GITHUB_SHA': implementation,
                                         'GITHUB_RUN_ID': str(100 + index),
                                         'GITHUB_EVENT_NAME': 'schedule',
                                         'GITHUB_REPOSITORY': 'owner/repo'}), \
                 patch.object(p, 'datetime', Clock), patch.object(v, 'datetime', Clock), \
                 patch.object(h, 'remote_read', side_effect=read), \
                 patch.object(c, 'download_feed', side_effect=lambda _: fixtures.feed(fixtures.uri(1))):
                manifest = p.prepare(self.manifest_path, use_history=True)
                self.assertEqual(manifest['history']['provenance']['checked_commit'], previous_sha)
                self.run_shards(manifest, fixtures.successful_probe)
                p.merge(self.manifest_path, self.shards, self.output)
                report = p.verify_public(self.manifest_path, self.output)
                state = json.loads((self.output / 'history.json').read_text())
                self.assertEqual(report['production']['max_parallel_shards'], 8)
                self.assertEqual(report['resources']['maximum_parallel_shards'], 8)
                self.assertTrue(report['coverage']['complete_supported'])
                self.assertEqual(len(state['runs']), index + 1)
                self.assertEqual([r['implementation_sha'] for r in state['runs']],
                                 list(phases[:index + 1]))

                done = p.instant(report['completed_at'])
                sha = f'{index + 1:040x}'
                commit = {'sha': sha, 'parents': [{'sha': previous_sha}] if previous_sha else [],
                          'commit': {'committer': {'name': 'github-actions[bot]',
                              'email': '41898282+github-actions[bot]@users.noreply.github.com',
                              'date': (done + timedelta(seconds=1)).isoformat()}}}
                run = {'id': 100 + index, 'run_attempt': 1, 'conclusion': 'success',
                       'status': 'completed', 'repository': {'full_name': 'owner/repo'},
                       'head_repository': {'full_name': 'owner/repo'}, 'head_branch': 'main',
                       'head_sha': implementation, 'path': '.github/workflows/check.yml',
                       'event': 'schedule', 'run_started_at': report['started_at'],
                       'updated_at': (done + timedelta(seconds=2)).isoformat()}
                root = 'https://raw.githubusercontent.com/owner/repo/' + sha + '/'
                for artifact in self.output.iterdir():
                    remote[root + artifact.name] = artifact.read_bytes()
                remote[api + f'/actions/runs/{100 + index}/attempts/1'] = h.encoded(run)
                remote[api + f'/actions/runs/{100 + index}/attempts/1/jobs?per_page=100'] = h.encoded({
                    'total_count': 1, 'jobs': [{'name': 'publish', 'conclusion': 'success',
                        'started_at': report['completed_at'], 'completed_at': run['updated_at']}]})
                commits.insert(0, commit)
                remote[commits_url] = h.encoded(commits)
                replayed, provenance = h.load_remote('owner/repo', None,
                                                    now=done + timedelta(seconds=3))
                self.assertEqual(replayed, h.prune(state, done + timedelta(seconds=3)))
                self.assertEqual(provenance['checked_commit'], sha)

                original = remote[root + 'report.json']
                tampered = copy.deepcopy(report)
                tampered['production']['implementation_sha'] = 'b' * 40
                remote[root + 'report.json'] = h.encoded(tampered)
                with self.assertRaises(ValueError):
                    h.load_remote('owner/repo', None, now=done + timedelta(seconds=3))
                remote[root + 'report.json'] = original
                previous_sha = sha
