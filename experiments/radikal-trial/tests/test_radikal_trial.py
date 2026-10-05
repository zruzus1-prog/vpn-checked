"""Synthetic-only experiment tests. No remote reads or live proxy connections."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
import checker as c
import production as p
import validate_output as v
from test_pipeline import ENV, TEST_CLOCK, core_info, failed_probe, feed, successful_probe, uri

spec = importlib.util.spec_from_file_location('radikal_trial', ROOT / 'experiments/radikal-trial/trial.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class RadikalTrialTests(unittest.TestCase):
    def setUp(self):
        TEST_CLOCK[0] = datetime.now(timezone.utc) - timedelta(minutes=15)
        for target in ('checker.utc_now', 'production.now_iso'):
            item = patch(target, side_effect=lambda: TEST_CLOCK[0].isoformat())
            item.start()
            self.addCleanup(item.stop)
        item = patch.dict(os.environ, {**ENV, 'GITHUB_STEP_SUMMARY': ''})
        item.start()
        self.addCleanup(item.stop)
        item = patch('builtins.print')
        item.start()
        self.addCleanup(item.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.frozen = self.root / 'frozen'
        self.shards = self.root / 'shards'
        self.output = self.root / 'output'
        self.original_sources = c.SOURCES
        self.original_cap = c.MAX_CANDIDATES
        self.head = 'a' * 40

    def history(self, ids=None):
        return {'scope': 'previously-assessed-identities-only-no-reused-qualification',
                'head_commit': self.head, 'requested_snapshots': 4,
                'snapshots': [{'commit': self.head, 'report_sha256': 'b' * 64,
                               'completed_at': c.utc_now(),
                               'candidate_ids': sorted(ids or [c.node_id(uri(2))])}]}

    def prepare(self, total=3):
        trial_raw = '\n'.join(uri(index) for index in range(1, total + 1))
        with patch('checker.download_feed', side_effect=lambda url: feed(trial_raw if url == t.SOURCE else uri(1))) as download, \
             patch.object(t, 'capture_history', return_value=self.history()):
            result = t.prepare(self.frozen, self.head)
        self.assertEqual(download.call_count, 7)
        self.assertIs(c.SOURCES, self.original_sources)
        self.assertEqual(c.MAX_CANDIDATES, self.original_cap)
        return result

    def shards_run(self, probe=failed_probe):
        with t.trial_scope():
            _, manifest = t.load_context(self.frozen)
        with patch('checker.download_feed', side_effect=AssertionError('no repeated source fetch')), \
             patch('checker.core_metadata', return_value=core_info()), \
             patch('production.preflight_core') as preflight, \
             patch('checker.probe', side_effect=probe) as check:
            for shard in manifest['shards']:
                t.check_shard(self.frozen, shard['id'], self.shards, '/mock/core')
        self.assertEqual(check.call_count, len(manifest['candidates']))
        self.assertEqual(sum(len(call.args[0]) for call in preflight.call_args_list), len(manifest['candidates']))
        return manifest

    def test_scope_narrows_only_and_restores_after_exception(self):
        values = (c.SOURCES, v.SOURCES, c.MAX_DEEP, v.MAX_DEEP, c.MAX_CANDIDATES, v.MAX_CANDIDATES)
        constants = (c.STABILITY_SECONDS, c.DOWNLOAD_BYTES, c.MAX_ATTEMPTS, c.MAX_ENDPOINT_ADDRESSES,
                     c.MIN_BYTES_PER_SECOND, c.MAX_RESULT_AGE_SECONDS, c.QUICK_TIMEOUT)
        with self.assertRaisesRegex(RuntimeError, 'synthetic'):
            with t.trial_scope():
                self.assertEqual(c.SOURCES, [t.SOURCE])
                self.assertEqual(v.SOURCES, [t.SOURCE])
                self.assertEqual(c.MAX_CANDIDATES, 512)
                self.assertEqual(v.MAX_DEEP, 512)
                raise RuntimeError('synthetic')
        self.assertEqual(values, (c.SOURCES, v.SOURCES, c.MAX_DEEP, v.MAX_DEEP, c.MAX_CANDIDATES, v.MAX_CANDIDATES))
        self.assertEqual(constants, (c.STABILITY_SECONDS, c.DOWNLOAD_BYTES, c.MAX_ATTEMPTS, c.MAX_ENDPOINT_ADDRESSES,
                                   c.MIN_BYTES_PER_SECOND, c.MAX_RESULT_AGE_SECONDS, c.QUICK_TIMEOUT))

    def test_all_512_candidates_are_kept_in_eight_shards(self):
        self.prepare(512)
        with t.trial_scope():
            _, manifest = t.load_context(self.frozen)
        self.assertEqual(len(manifest['candidates']), 512)
        self.assertEqual(len(manifest['shards']), 8)
        self.assertTrue(all(len(shard['candidate_ids']) == 64 for shard in manifest['shards']))

    def test_513_candidates_fail_whole_trial_without_sampling(self):
        with self.assertRaises(ValueError):
            self.prepare(513)
        self.assertFalse((self.frozen / 'manifest.json').exists())
        self.assertIs(c.SOURCES, self.original_sources)
        self.assertEqual(c.MAX_CANDIDATES, self.original_cap)

    def test_empty_trial_fails(self):
        with self.assertRaises(ValueError):
            self.prepare(0)
        self.assertFalse((self.frozen / 'manifest.json').exists())

    def test_missing_current_source_fails_before_trial_probes(self):
        with patch('checker.download_feed', side_effect=c.Rejected('synthetic failure')), \
             patch.object(t, 'capture_history') as history, \
             patch('checker.probe') as probe:
            with self.assertRaises(ValueError):
                t.prepare(self.frozen, self.head)
        history.assert_not_called()
        probe.assert_not_called()

    def test_fresh_probe_and_independent_merge_with_novelty(self):
        self.prepare()
        self.shards_run(successful_probe)
        with patch('checker.download_feed', side_effect=AssertionError('merge must not download')), \
             patch('checker.probe', side_effect=AssertionError('merge must not reprobe')):
            summary = t.merge(self.frozen, self.shards, self.output)
        for service in ('youtube', 'chatgpt', 'both'):
            self.assertEqual(summary['yield'][service]['fresh_qualified'], 3)
            self.assertEqual(summary['yield'][service]['absent_from_current_source_candidates'], 2)
            self.assertEqual(summary['yield'][service]['absent_from_all_checked_history_assessments'], 2)
            self.assertEqual(summary['yield'][service]['absent_from_current_and_all_checked_history'], 1)
        self.assertEqual(summary['omitted_candidates'], 0)
        self.assertEqual(summary['history_snapshots_available'], 1)
        self.assertEqual(summary['probe_reported_body_bytes'], 3 * (2 * c.DOWNLOAD_BYTES + 200))
        self.assertEqual(summary['attempts_without_byte_measurement'], 0)
        self.assertIs(summary['probe_origin']['russia_verified'], False)
        self.assertEqual(summary['yield']['youtube']['novel_qualified_protocol_counts'], {'vless': 1})
        self.assertIs(c.SOURCES, self.original_sources)

    def test_current_failed_results_never_inherit_a_historical_pass(self):
        self.prepare()
        self.shards_run()
        summary = t.merge(self.frozen, self.shards, self.output)
        self.assertTrue(all(value['fresh_qualified'] == 0 for value in summary['yield'].values()))
        self.assertEqual((self.output / 'validated-trial/subscription-youtube.txt').read_text(), '')

    def test_missing_shard_blocks_summary(self):
        self.prepare()
        self.shards.mkdir()
        with self.assertRaises(ValueError):
            t.merge(self.frozen, self.shards, self.output)
        self.assertFalse((self.output / 'trial-summary.json').exists())

    def test_incomplete_probe_blocks_shard(self):
        self.prepare()
        def incomplete(*args):
            result, line = failed_probe(*args)
            result['reason'] = 'budget'
            return result, line
        with self.assertRaises(ValueError):
            self.shards_run(incomplete)

    def test_comparison_tampering_rejected_before_probe(self):
        self.prepare()
        path = self.frozen / 'comparison.json'
        context = json.loads(path.read_text())
        context['current']['candidate_ids'] = []
        path.write_text(json.dumps(context))
        with patch('checker.probe') as probe, self.assertRaises(ValueError), t.trial_scope():
            t.load_context(self.frozen)
        probe.assert_not_called()

    def test_bound_comparison_cannot_be_reused_from_another_run(self):
        self.prepare()
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '789'}), t.trial_scope(), self.assertRaises(ValueError):
            t.load_context(self.frozen)

    def test_stale_comparison_rejected(self):
        self.prepare()
        path = self.frozen / 'comparison.json'
        context = json.loads(path.read_text())
        context['prepared_at'] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        actual = p.write_json(path, context, t.MAX_CONTEXT_BYTES)
        (self.frozen / 'comparison.sha256').write_text(actual + '\n')
        with t.trial_scope(), self.assertRaises(ValueError):
            t.load_context(self.frozen)

    def test_independent_cap_guard_rejects_oversize_manifest(self):
        with self.assertRaisesRegex(ValueError, '512'):
            t.bounded_trial({'candidates': [{}] * 513})

    def test_history_identity_only_does_not_read_pass_booleans(self):
        report = {'identity_version': c.CANONICALIZATION_VERSION, 'completed_at': c.utc_now(),
                  'results': [{'id': c.node_id(uri(1)), 'identity_version': c.CANONICALIZATION_VERSION,
                               'qualified': 'deliberately-not-trusted'}]}
        snapshot = t.observed_report(p.canonical_bytes(report), self.head)
        self.assertEqual(snapshot['candidate_ids'], [c.node_id(uri(1))])
        self.assertNotIn('qualified', json.dumps(snapshot))

    def test_history_duplicate_identity_rejected(self):
        row = {'id': c.node_id(uri(1)), 'identity_version': c.CANONICALIZATION_VERSION}
        report = {'identity_version': c.CANONICALIZATION_VERSION, 'completed_at': c.utc_now(),
                  'results': [row, row]}
        with self.assertRaises(ValueError):
            t.observed_report(p.canonical_bytes(report), self.head)

    def test_history_other_identity_version_rejected(self):
        report = {'identity_version': 'old', 'completed_at': c.utc_now(), 'results': []}
        with self.assertRaises(ValueError):
            t.observed_report(p.canonical_bytes(report), self.head)

    def test_history_read_is_bounded_and_uses_fixed_objects(self):
        body = p.canonical_bytes({'identity_version': c.CANONICALIZATION_VERSION,
                                  'completed_at': c.utc_now(), 'results': []})
        with patch.object(t, 'git_output', side_effect=[(self.head + '\n').encode(),
                                                      str(len(body)).encode(), body]) as git:
            history = t.capture_history(self.head)
        self.assertEqual(len(history['snapshots']), 1)
        self.assertEqual(git.call_args_list[1].args[0], ['cat-file', '-s', self.head + ':report.json'])
        self.assertEqual(git.call_args_list[2].args[0], ['show', self.head + ':report.json'])

    def test_history_size_guard_precedes_read(self):
        with patch.object(t, 'git_output', side_effect=[(self.head + '\n').encode(), b'999999999']) as git:
            with self.assertRaises(ValueError):
                t.capture_history(self.head)
        self.assertEqual(git.call_count, 2)

    def test_unknown_history_ref_not_passed_to_git(self):
        with patch.object(t, 'git_output') as git, self.assertRaises(ValueError):
            t.capture_history('--upload-pack=bad')
        git.assert_not_called()

    def test_workflow_has_manual_read_only_artifacts_no_publish(self):
        text = (ROOT / '.github/workflows/radikal-trial.yml').read_text()
        self.assertIn('workflow_dispatch:', text)
        self.assertNotIn('schedule:', text)
        self.assertNotIn('contents: write', text)
        self.assertNotIn('git push', text)
        self.assertNotIn('pull_request_target', text)
        self.assertNotIn('secrets.', text)
        self.assertIn('max-parallel: 8', text)
        self.assertEqual(text.count('retention-days: 1'), 3)
        self.assertEqual(text.count('persist-credentials: false'), 3)
        self.assertIn('EXPECTED_COMPARISON_SHA256', text)


if __name__ == '__main__':
    unittest.main()
