"""Independent adversarial checks for bounded historical publication trust."""
import copy
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch
import unittest

import checker as c
import history as h
import production as p
import test_pipeline as fixtures
import test_history as histories


class HistoryBoundaryReviewTests(unittest.TestCase):
    setUp = fixtures.PipelineTests.setUp
    run_shards = fixtures.PipelineTests.run_shards
    prepare = fixtures.PipelineTests.prepare

    def forged_historical_output(self):
        item = histories.candidate()
        state, _, _ = histories.history_for([item], hours=(12, 6))
        with patch('history.load_remote', return_value=(state, {
                'checked_commit': 'b' * 40, 'authenticated_snapshots': 2,
                'mode': 'verified-bootstrap'})), \
             patch('checker.download_feed', side_effect=lambda _: fixtures.feed(item['uri'])), \
             patch.dict('os.environ', {'GITHUB_EVENT_NAME': 'schedule'}):
            manifest = p.prepare(self.manifest_path, use_history=True)
        self.run_shards(manifest, fixtures.successful_probe)
        p.merge(self.manifest_path, self.shards, self.output)
        report = json.loads((self.output / 'report.json').read_bytes())
        completed = p.instant(report['completed_at'])
        commit_time = (completed + timedelta(seconds=1)).isoformat()
        commit = {'sha': 'a' * 40, 'parents': [{'sha': 'b' * 40}], 'commit': {
            'committer': {'name': 'github-actions[bot]',
                          'email': '41898282+github-actions[bot]@users.noreply.github.com',
                          'date': commit_time}}}
        run = {'id': 123456, 'run_attempt': 1, 'conclusion': 'success', 'status': 'completed',
               'repository': {'full_name': 'owner/repo'},
               'head_repository': {'full_name': 'owner/repo'},
               'head_branch': 'main', 'head_sha': report['production']['implementation_sha'],
               'path': '.github/workflows/check.yml', 'event': 'schedule',
               'run_started_at': report['started_at'],
               'updated_at': (completed + timedelta(seconds=2)).isoformat()}
        return report, commit, run

    def test_unverified_prior_observations_cannot_authenticate_themselves(self):
        report, commit, run = self.forged_historical_output()
        root = 'https://raw.githubusercontent.com/owner/repo/' + commit['sha'] + '/'
        api = 'https://api.github.com/repos/owner/repo'
        def read(url, maximum, token=None):
            if url == api + '/commits?sha=checked&per_page=32':
                return h.encoded([commit])
            if url == api + '/actions/runs/123456/attempts/1':
                return h.encoded(run)
            if url == api + '/actions/runs/123456/attempts/1/jobs?per_page=100':
                return h.encoded({'total_count': 1, 'jobs': [
                    {'name': 'publish', 'conclusion': 'success', 'started_at': report['completed_at'], 'completed_at': run['updated_at']}]})
            if url.startswith(root):
                return (self.output / url.removeprefix(root)).read_bytes()
            raise ValueError('prior evidence is unavailable')
        with patch('history.remote_read', side_effect=read), self.assertRaises(ValueError):
            h.load_remote('owner/repo', None, now=datetime.now(timezone.utc))

    def test_retained_node_expires_between_prepare_and_publication(self):
        item = histories.candidate(900)
        state, _, _ = histories.history_for([item], hours=(46, 40, 1))
        state['entries'][0]['last_upstream_seen_at'] = (
            fixtures.TEST_CLOCK[0] - timedelta(hours=48) + timedelta(seconds=1)).isoformat()
        with patch('history.load_remote', return_value=(state, {
                'checked_commit': 'b' * 40, 'authenticated_snapshots': 3,
                'mode': 'verified-bootstrap'})), \
             patch('checker.download_feed', side_effect=lambda _: fixtures.feed(fixtures.uri(1))), \
             patch.dict('os.environ', {'GITHUB_EVENT_NAME': 'schedule'}):
            manifest = p.prepare(self.manifest_path, use_history=True)
        self.run_shards(manifest, fixtures.successful_probe)
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)

    def test_arbitrary_top_level_diagnostics_cannot_leak_secrets(self):
        manifest = self.prepare(1)
        self.run_shards(manifest, fixtures.successful_probe)
        p.merge(self.manifest_path, self.shards, self.output)
        report = json.loads((self.output / 'report.json').read_text())
        report['diagnostics'] = {'raw_stderr': 'synthetic-private-value'}
        (self.output / 'report.json').write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            p.verify_public(self.manifest_path, self.output)

    def test_latest_pass_can_extend_qualifying_span_despite_close_predecessor(self):
        state, rows, exports = histories.history_for(hours=(6.5, 5, 31/60, 0))
        feeds, proof = h.split(state, rows, exports)
        self.assertEqual(feeds['stable'], list(exports.values()))
        self.assertGreaterEqual(proof['evidence'][rows[0]['id']]['span_seconds'], 6*3600)

    def test_current_presence_uses_fetch_time_not_manifest_creation(self):
        state, rows, _ = histories.history_for()
        next_time = histories.NOW + timedelta(hours=2)
        seen = (next_time - timedelta(minutes=4)).isoformat()
        state = h.update(state, [histories.candidate()], rows, at=next_time.isoformat(),
                         implementation_sha='1' * 40, run_id='4', run_attempt='1',
                         event='schedule', seen_at={rows[0]['id']: seen})
        self.assertEqual(state['entries'][0]['last_upstream_seen_at'], seen)

    def test_failures_outside_spacing_still_prevent_ninety_percent(self):
        state, rows, exports = histories.history_for(
            hours=(12, 11.999, 6, 5.999, 0),
            passed=[True, False, True, False, True])
        feeds, proof = h.split(state, rows, exports)
        self.assertEqual(feeds['stable'], [])
        self.assertEqual(proof['evidence'][rows[0]['id']]['pass_rate'], .6)

    def test_overspeed_historical_pass_cannot_hide_slow_current_pass(self):
        state, rows, exports = histories.history_for()
        rows[0]['min_kib_s'] = 511.9
        self.assertEqual(h.split(state, rows, exports)[0]['stable'], [])


class HistoryReplayReviewTests(unittest.TestCase):
    setUp = fixtures.PipelineTests.setUp
    run_shards = fixtures.PipelineTests.run_shards

    def publications(self):
        """Generate real publisher artifacts at three synthetic, spaced times."""
        import validate_output as v
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixtures.TEST_CLOCK[0] + timedelta(seconds=5)
        actual_now = datetime.now(timezone.utc)
        state = None
        previous_sha = 'f' * 40
        commits = []
        remote = {}
        api = 'https://api.github.com/repos/owner/repo'
        for index, hours in enumerate((12, 6, 1)):
            fixtures.TEST_CLOCK[0] = actual_now - timedelta(hours=hours)
            if state is None:
                state = h.empty(fixtures.TEST_CLOCK[0].isoformat())
            provenance = {'checked_commit': previous_sha,
                          'authenticated_snapshots': index,
                          'mode': 'retained-state' if index else 'expired-history'}
            with patch.object(p, 'datetime', Clock), patch.object(v, 'datetime', Clock), \
                 patch('history.load_remote', return_value=(state, provenance)), \
                 patch('checker.download_feed', side_effect=lambda _: fixtures.feed(fixtures.uri(1))), \
                 patch.dict('os.environ', {'GITHUB_RUN_ID': str(100 + index),
                                          'GITHUB_EVENT_NAME': 'schedule'}):
                manifest = p.prepare(self.manifest_path, use_history=True)
                self.run_shards(manifest, fixtures.successful_probe)
                p.merge(self.manifest_path, self.shards, self.output)
            report = json.loads((self.output / 'report.json').read_bytes())
            state = json.loads((self.output / 'history.json').read_bytes())
            done = p.instant(report['completed_at'])
            sha = str(index + 1) * 40
            commit = {'sha': sha, 'parents': [{'sha': previous_sha}], 'commit': {
                'committer': {'name': 'github-actions[bot]',
                              'email': '41898282+github-actions[bot]@users.noreply.github.com',
                              'date': (done + timedelta(seconds=1)).isoformat()}}}
            run = {'id': 100 + index, 'run_attempt': 1, 'conclusion': 'success',
                   'status': 'completed', 'repository': {'full_name': 'owner/repo'},
                   'head_repository': {'full_name': 'owner/repo'}, 'head_branch': 'main',
                   'head_sha': report['production']['implementation_sha'],
                   'path': '.github/workflows/check.yml', 'event': 'schedule',
                   'run_started_at': report['started_at'],
                   'updated_at': (done + timedelta(seconds=2)).isoformat()}
            root = 'https://raw.githubusercontent.com/owner/repo/' + sha + '/'
            for path in self.output.iterdir():
                remote[root + path.name] = path.read_bytes()
            remote[api + '/actions/runs/' + str(100 + index) + '/attempts/1'] = h.encoded(run)
            remote[api + '/actions/runs/' + str(100 + index) + '/attempts/1/jobs?per_page=100'] = h.encoded({
                'total_count': 1, 'jobs': [{'name': 'publish', 'conclusion': 'success',
                                         'started_at': report['completed_at'],
                                         'completed_at': run['updated_at']}]})
            previous_sha = sha
            commits.append(commit)
        commits = list(reversed(commits)) + [{'sha': 'f' * 40, 'commit': {'committer': {
            'date': (actual_now - timedelta(hours=49)).isoformat()}}}]
        remote[api + '/commits?sha=checked&per_page=32'] = h.encoded(commits)
        return actual_now, remote, 'https://raw.githubusercontent.com/owner/repo/' + previous_sha + '/'

    def test_three_authentic_publications_replay_complete_evidence(self):
        now, remote, _ = self.publications()
        with patch('history.remote_read', side_effect=lambda url, maximum, token=None: remote[url]):
            state, provenance = h.load_remote('owner/repo', None, now=now)
        self.assertEqual([r['run_id'] for r in state['runs']], ['100', '101', '102'])
        self.assertEqual([o['run_id'] for o in state['entries'][0]['observations']], ['100', '101', '102'])
        self.assertEqual(provenance['authenticated_snapshots'], 3)
        self.assertEqual(provenance['checked_commit'], '3' * 40)

    def test_rehashed_old_failure_cannot_replace_authenticated_old_success(self):
        now, remote, root = self.publications()
        report = h.strict_json(remote[root + 'report.json'])
        state = h.strict_json(remote[root + 'history.json'])
        state['entries'][0]['observations'][0].update(
            youtube=False, min_kib_s=None, median_ms=None, tested_address=None)
        data = h.encoded(state)
        report['history']['state_sha256'] = p.digest(data)
        exports = {c.node_id(line): line for line in remote[root + c.FEEDS['youtube']].decode().splitlines()}
        feeds, ranking = h.split(state, report['results'], exports)
        report['history'].update(ranking)
        report['history']['split_counts'] = {key: len(lines) for key, lines in feeds.items()}
        remote[root + 'history.json'] = data
        remote[root + 'report.json'] = h.encoded(report)
        for key, filename in h.SPLIT_FEEDS.items():
            remote[root + filename] = ('\n'.join(feeds[key]) + ('\n' if feeds[key] else '')).encode()
        with patch('history.remote_read', side_effect=lambda url, maximum, token=None: remote[url]), \
             self.assertRaises(ValueError):
            h.load_remote('owner/repo', None, now=now)


if __name__ == '__main__':
    unittest.main()
