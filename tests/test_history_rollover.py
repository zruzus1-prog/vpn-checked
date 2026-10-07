"""Real authenticated publication replay across repeated 48-hour rollovers."""
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch
import unittest

import checker as c
import history as h
import production as p
import test_pipeline as fixtures


class RolloverTests(unittest.TestCase):
    setUp = fixtures.PipelineTests.setUp
    run_shards = fixtures.PipelineTests.run_shards

    def publications(self, *, passed=True, reappear=True,
                     hours=(50, 40, 30, 20, 10, 3), current_indexes=None, replay_seed=False):
        """Generate real publisher artifacts across two rolling-window seed expirations."""
        import validate_output as v
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixtures.TEST_CLOCK[0] + timedelta(seconds=5)
        actual_now = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
        state = None
        previous_sha = 'f' * 40
        commits = []
        remote = {}
        api = 'https://api.github.com/repos/owner/repo'
        for index, age in enumerate(hours):
            fixtures.TEST_CLOCK[0] = actual_now - timedelta(hours=age)
            if state is None:
                state = h.empty(fixtures.TEST_CLOCK[0].isoformat())
            provenance = {'checked_commit': previous_sha,
                          'authenticated_snapshots': len(h.prune(state, fixtures.TEST_CLOCK[0])['runs']),
                          'mode': 'retained-state' if index else 'expired-history'}
            if replay_seed and index:
                self.commit_pages(remote, api, commits)
                state = self.replay(remote, fixtures.TEST_CLOCK[0])
            present = index in current_indexes if current_indexes is not None else (index in (0, 2) or (reappear and index == 4))
            def probe(value, core, deadline, budget):
                if not passed and index in (1, 3) and c.node_id(value) == c.node_id(fixtures.uri(1)):
                    return fixtures.failed_probe(value, core, deadline, budget)
                return fixtures.successful_probe(value, core, deadline, budget)
            with patch.object(p, 'datetime', Clock), patch.object(v, 'datetime', Clock), \
                 patch('history.load_remote', return_value=(state, provenance)), \
                 patch('checker.download_feed', side_effect=lambda _: fixtures.feed(fixtures.uri(1) if present else fixtures.uri(2))), \
                 patch.dict('os.environ', {'GITHUB_RUN_ID': str(100 + index),
                                          'GITHUB_EVENT_NAME': 'schedule'}):
                manifest = p.prepare(self.manifest_path, use_history=True)
                self.run_shards(manifest, probe)
                p.merge(self.manifest_path, self.shards, self.output)
            report = json.loads((self.output / 'report.json').read_bytes())
            state = json.loads((self.output / 'history.json').read_bytes())
            done = p.instant(report['completed_at'])
            sha = f'{index + 1:040x}'
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
        self.commit_pages(remote, api, commits)
        return actual_now, remote, 'https://raw.githubusercontent.com/owner/repo/' + previous_sha + '/'

    def commit_pages(self, remote, api, commits):
        newest_first = list(reversed(commits))
        remote[api + '/commits?sha=checked&per_page=32'] = h.encoded(newest_first[:32])
        remote[api + '/commits?sha=checked&per_page=32&page=2'] = h.encoded(newest_first[32:64])

    def test_expired_epoch_reappearance_survives_generation_and_next_replay(self):
        now, remote, root = self.publications(hours=(78, 70, 46, 40, 35, 1),
                                              current_indexes={0, 5}, replay_seed=True)
        published = h.strict_json(remote[root + 'history.json'])
        entry = next(e for e in published['entries'] if e['id'] == c.node_id(fixtures.uri(1)))
        self.assertEqual([o['run_id'] for o in entry['observations']], ['105'])
        for hours in (0, 1, 8, 8.000001, 47, 47.000001, 49, 100):
            at = now + timedelta(hours=hours)
            self.assertEqual(self.replay(remote, at), h.prune(published, at))

    def test_week_of_two_hour_publications_with_chained_expiry_and_reappearance(self):
        # A one-second cron drift avoids deliberately expiring a nomination
        # between prepare and publish (covered by its own fail-closed test).
        now, remote, root = self.publications(hours=tuple(age-index/3600 for index, age in enumerate(range(170, -1, -2))),
                                              current_indexes={0, 10, 45, 70, 80}, replay_seed=True)
        published = h.strict_json(remote[root + 'history.json'])
        for hours in (1, 24, 28, 28.000001, 48, 48.000001, 96):
            at = now + timedelta(hours=hours)
            self.assertEqual(self.replay(remote, at), h.prune(published, at))

    def replay(self, remote, now):
        def read(url, maximum, token=None):
            data = remote[url]
            self.assertLessEqual(len(data), maximum)
            return data
        with patch('history.remote_read', side_effect=read):
            return h.load_remote('owner/repo', None, now=now)[0]

    def test_exact_cutoffs_and_repeated_rollovers_match_published_pruning(self):
        for passed in (True, False):
            now, remote, root = self.publications(passed=passed)
            published = h.strict_json(remote[root + 'history.json'])
            # Includes boundaries of later upstream sightings and all intervening
            # retained-only observations, plus complete expiry after 48 hours.
            for hours in (-2.000001, -2, -1.999999, 0, 7.999999, 8, 8.000001, 17.999999, 18, 18.000001,
                          28, 28.000001, 38, 38.000001, 45, 45.000001, 47, 50):
                at = now + timedelta(hours=hours)
                with self.subTest(passed=passed, hours=hours):
                    state = self.replay(remote, at)
                    self.assertEqual(state, h.prune(published, at))
                    self.assertEqual(h.encoded(state), h.encoded(self.replay(remote, at)))

    def test_retained_measurements_do_not_extend_expired_nomination(self):
        now, remote, root = self.publications(reappear=False)
        item_id = c.node_id(fixtures.uri(1))
        before = self.replay(remote, now + timedelta(hours=18))
        self.assertIn(item_id, {e['id'] for e in before['entries']})
        after = self.replay(remote, now + timedelta(hours=18, microseconds=1))
        self.assertNotIn(item_id, {e['id'] for e in after['entries']})
        self.assertTrue(after['runs'])  # Valid measurements are not erased globally.

    def test_absence_is_not_failure_but_retained_failed_probe_is(self):
        now, remote, root = self.publications(passed=False)
        state = self.replay(remote, now)
        entry = next(e for e in state['entries'] if e['id'] == c.node_id(fixtures.uri(1)))
        self.assertEqual([o['youtube'] for o in entry['observations']],
                         [False, True, False, True, True])
        self.assertEqual(entry['last_upstream_seen_at'],
                         (now - timedelta(hours=10)).isoformat())

    def rewrite_claim(self, remote, root, mutate):
        report = h.strict_json(remote[root + 'report.json'])
        state = h.strict_json(remote[root + 'history.json'])
        mutate(state)
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

    def test_rehashed_missing_or_forged_retained_observation_fails_closed(self):
        now, original, root = self.publications()
        for mutation in ('missing', 'forged'):
            remote = dict(original)
            def mutate(state):
                entry = next(e for e in state['entries'] if e['id'] == c.node_id(fixtures.uri(1)))
                if mutation == 'missing':
                    entry['observations'] = [o for o in entry['observations'] if o['run_id'] != '101']
                else:
                    next(o for o in entry['observations'] if o['run_id'] == '101').update(youtube=False, min_kib_s=None,
                                                   median_ms=None, tested_address=None)
            self.rewrite_claim(remote, root, mutate)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.replay(remote, now)

    def test_failed_source_cannot_fall_back_to_retained_history(self):
        with patch('checker.download_feed', side_effect=c.Rejected('unavailable')), \
             patch('history.load_remote') as load, self.assertRaises(ValueError):
            p.prepare(self.manifest_path, use_history=True)
        load.assert_not_called()
        self.assertFalse(self.manifest_path.exists())

    def test_exact_old_implementations_stay_trusted_but_unknown_commit_does_not(self):
        import test_history as histories
        for implementation in ('8601c067ce2f7dde936b17808b7bf58906131d19',
                               '976c84b3a09bb8a7decc1c623726f28749720986',
                               '2ebfbd4c8d64c3c3d40577d3d5688cbf51579484',
                               '4a398dfbc1fae8da90eae755dcda8661871a1cd0', '9' * 40):
            report, commit, run, jobs = histories.AuthenticationTests().fixtures()
            report['production']['implementation_sha'] = run['head_sha'] = implementation
            with patch('history.remote_read', side_effect=[h.encoded(run), h.encoded(jobs)]):
                if implementation == '9' * 40:
                    with self.assertRaises(ValueError):
                        h.authenticate_publication('owner/repo', commit, report, None, now=histories.NOW)
                else:
                    self.assertEqual(h.authenticate_publication('owner/repo', commit, report, None,
                                                               now=histories.NOW), 'schedule')

    def test_later_overlapping_source_fetch_is_not_a_prior_anchor(self):
        now = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
        row = {'id': 'a' * 16, 'sources': [c.SOURCES[0]]}
        earlier = {'run': {'snapshot_at': (now-timedelta(hours=2)).isoformat()},
                   'rows': [row], 'current_ids': set(), 'source_times': {}}
        later = {'run': {'snapshot_at': (now-timedelta(hours=1)).isoformat()},
                 'rows': [row], 'current_ids': {row['id']},
                 'source_times': {c.SOURCES[0]: (now-timedelta(hours=3)).isoformat()}}
        self.assertFalse(h.source_anchors_complete([later, earlier], now))

    def test_anchor_budget_counts_old_reports_even_on_first_metadata_page(self):
        now, remote, _ = self.publications()
        # The oldest source seed is on page one, but is proof-only at this time.
        with patch.object(h, 'MAX_ANCHOR_RUNS', 0), self.assertRaises(ValueError):
            self.replay(remote, now)

    def test_proof_only_pagination_is_bounded(self):
        now = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
        commit = {'sha': 'a' * 40, 'commit': {'committer': {'date': now.isoformat()}}}
        with patch('history.remote_read', side_effect=[h.encoded([commit] * h.MAX_RUNS),
                   h.encoded([commit] * (h.MAX_ANCHOR_RUNS + 1))]), self.assertRaises(ValueError):
            h.load_remote('owner/repo', None, now=now)

    def test_authenticated_replay_resource_limits_remain_enforced(self):
        now, remote, root = self.publications()
        with patch.object(h, 'MAX_ENTRIES', 1), self.assertRaises(ValueError):
            self.replay(remote, now)
        with patch.object(h, 'MAX_RUNS', 2), self.assertRaises(ValueError):
            self.replay(remote, now)


if __name__ == '__main__':
    unittest.main()
