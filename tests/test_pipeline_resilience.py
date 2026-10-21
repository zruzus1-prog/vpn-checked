"""Independent service exports, deterministic retention margin and safe diagnostics."""
import copy
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import checker as c
import history as h
import production as p
import test_history as histories
import test_pipeline as fixtures


class PipelineResilienceTests(unittest.TestCase):
    setUp = fixtures.PipelineTests.setUp
    prepare = fixtures.PipelineTests.prepare
    run_shards = fixtures.PipelineTests.run_shards
    mutate_manifest = fixtures.PipelineTests.mutate_manifest

    def test_all_service_combinations_keep_independent_exports(self):
        manifest = self.prepare(4)
        def probe(value, core, deadline, budget):
            index = int(c.parse_uri(value)['uuid'].replace('-', ''), 16)
            if index == 4:
                return fixtures.failed_probe(value, core, deadline, budget)
            return fixtures.successful_probe(value, core, deadline, budget,
                {'youtube': index != 1, 'chatgpt': index != 2})
        self.run_shards(manifest, probe)
        p.merge(self.manifest_path, self.shards, self.output)
        report = p.verify_public(self.manifest_path, self.output)
        self.assertEqual(report['feed_counts'], {'both': 1, 'chatgpt': 2, 'youtube': 2})
        self.assertEqual(sum(report['history']['split_counts'].values()), 2)
        self.assertEqual(report['sampled'], 4)
        gpt_only = c.node_id(fixtures.uri(1))
        youtube = {c.node_id(uri) for uri in (self.output/c.FEEDS['youtube']).read_text().splitlines()}
        gpt = {c.node_id(uri) for uri in (self.output/c.FEEDS['chatgpt']).read_text().splitlines()}
        self.assertIn(gpt_only, gpt)
        self.assertNotIn(gpt_only, youtube)

    def history_manifest(self, remaining_seconds):
        item = histories.candidate(900)
        state, _, _ = histories.history_for([item], hours=(46, 40, 1))
        state['entries'][0]['last_upstream_seen_at'] = (
            fixtures.TEST_CLOCK[0] - timedelta(hours=48) + timedelta(seconds=remaining_seconds)).isoformat()
        with patch('history.load_remote', return_value=(state, {
                'checked_commit': 'b'*40, 'authenticated_snapshots': 3,
                'mode': 'verified-bootstrap'})), \
             patch('checker.download_feed', side_effect=lambda _: fixtures.feed(fixtures.uri(1))):
            manifest = p.prepare(self.manifest_path, use_history=True)
        return item, manifest

    def test_nomination_margin_is_bound_to_frozen_time_not_recomputed_at_merge(self):
        item, manifest = self.history_manifest(c.MAX_RESULT_AGE_SECONDS + 60)
        self.assertIn(item['id'], {row['id'] for row in manifest['candidates']})
        p.validate_manifest(manifest, now=p.instant(manifest['created_at'])+timedelta(minutes=15))
        self.run_shards(manifest, fixtures.successful_probe)
        p.merge(self.manifest_path, self.shards, self.output)
        self.assertEqual(p.verify_public(self.manifest_path, self.output)['sampled'], 2)

    def test_rehashed_manifest_cannot_add_near_expiry_historical_candidate(self):
        item, manifest = self.history_manifest(c.MAX_RESULT_AGE_SECONDS - 1)
        self.assertNotIn(item['id'], {row['id'] for row in manifest['candidates']})
        def mutate(value):
            value['candidates'].append(item)
            value['candidates'].sort(key=lambda row: row['id'])
            value['shards'][0]['candidate_ids'] = [row['id'] for row in value['candidates']]
        self.mutate_manifest(mutate)
        with self.assertRaisesRegex(ValueError, 'incomplete retained candidate inventory'):
            p.load_manifest(self.manifest_path)

    def test_rehashed_manifest_cannot_drop_eligible_historical_candidate(self):
        item, manifest = self.history_manifest(c.MAX_RESULT_AGE_SECONDS + 60)
        def mutate(value):
            value['candidates'] = [row for row in value['candidates'] if row['id'] != item['id']]
            value['shards'][0]['candidate_ids'] = [row['id'] for row in value['candidates']]
        self.mutate_manifest(mutate)
        with self.assertRaisesRegex(ValueError, 'incomplete retained candidate inventory'):
            p.load_manifest(self.manifest_path)


class SafeDiagnosticsTests(unittest.TestCase):
    def test_unknown_exceptions_never_emit_exception_text_or_sensitive_arguments(self):
        secret = 'vless://synthetic-private-value@example.invalid/?token=private-value'
        for exc in (ValueError(secret), KeyError(secret), OSError(secret),
                    subprocess.TimeoutExpired([secret], 10, output=secret, stderr=secret)):
            with self.subTest(kind=type(exc).__name__):
                p.diagnostic_stage('prepare.history')
                record = p.diagnostic_record('failure', exc)
                self.assertNotIn('private-value', json.dumps(record))
                self.assertEqual(record['stage'], 'prepare.history')
                self.assertEqual(record['outcome'], 'failure')

    def test_known_expiry_has_safe_specific_code(self):
        self.assertEqual(p.diagnostic_record('failure', ValueError(
            'historical candidate expired before publication'))['code'], 'history.retained_expired')

    def test_remote_error_uses_only_validated_structured_fields(self):
        exc = h.RemoteReadError('http_status', status=503, attempts=3)
        record = p.diagnostic_record('failure', exc)
        self.assertEqual(record['code'], 'history.fetch.http_status')
        self.assertEqual(record['http_status'], 503)
        self.assertEqual(record['attempts'], 3)

    def test_cli_writes_only_sanitized_failure_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'VPN_DIAGNOSTICS_DIR': directory}), \
                 patch.object(p, 'main', side_effect=ValueError('synthetic-private-value')), \
                 patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(p.run_cli(), 1)
            self.assertEqual([x.name for x in Path(directory).iterdir()], ['diagnostic.json'])
            data = (Path(directory)/'diagnostic.json').read_text()
            self.assertNotIn('synthetic-private-value', data + stderr.getvalue())
            self.assertEqual(json.loads(data)['code'], 'validation.failed')

    def test_only_sanitized_fixed_file_has_longer_retention(self):
        text = (Path(p.__file__).parent/'.github/workflows/check.yml').read_text()
        self.assertEqual(text.count('retention-days: 1\n'), 3)
        self.assertEqual(text.count('retention-days: 14\n'), 4)
        self.assertEqual(text.count('path: /tmp/pipeline-diagnostics/diagnostic.json'), 4)
        self.assertNotIn('path: /tmp/pipeline-diagnostics/\n', text)
        self.assertEqual(text.count('contents: write'), 1)
        self.assertEqual(text.count('continue-on-error: true'), 4)
        self.assertEqual(text.count('Keep sanitized pipeline diagnosis for 14 days\n'
                                    '        continue-on-error: true'), 4)
        publish_diagnosis = text.index('name: diagnostics-publish')
        publication = text.index('name: Preserve checked history and publish')
        self.assertLess(publish_diagnosis, publication)
        publish = text[text.index('\n  publish:'):]
        self.assertIn('        if: failure()', publish)
        self.assertTrue(text.rstrip().endswith('origin HEAD:refs/heads/checked'))


if __name__ == '__main__':
    unittest.main()
