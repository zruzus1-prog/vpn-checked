"""Offline frozen-snapshot, sharding, publication, and trust-boundary tests."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

import checker as c
import production as p

TEST_CLOCK=[datetime.now(timezone.utc)-timedelta(minutes=10)]

ENV = {'GITHUB_SHA': '1' * 40, 'GITHUB_RUN_ID': '123456',
       'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_ACTIONS': 'true', 'GITHUB_OUTPUT': ''}


def uri(index=1):
    return f'vless://{uuid.UUID(int=index)}@example.org:443?security=tls&sni=example.org#fixture'


def feed(text):
    value = c.FeedText(text)
    value.fetched_at = c.utc_now()
    value.sha256 = hashlib.sha256(text.encode()).hexdigest()
    return value


def core_info():
    lock, _ = p.local_lock()
    return {'name': 'sing-box', 'version': lock['version'],
            'archive_sha256': lock['sha256'], 'binary_sha256': 'a' * 64,
            'os': 'linux', 'arch': 'amd64'}


def failed_probe(value, core, deadline, budget):
    return {'id': c.node_id(value), 'identity_version': c.CANONICALIZATION_VERSION,
            'original_uri_sha256': p.digest(value.encode()),
            'checked_at': c.utc_now(), 'completed_at': c.utc_now(),
            'qualified': False, 'baseline_qualified': False, 'deep_tested': False,
            'service_qualified': {'youtube': False, 'chatgpt': False},
            'reason': 'endpoint-rejected', 'attempts': []}, None


def successful_probe(value, core, deadline, budget, services=None):
    assert budget.claim()
    services = services or {'youtube': True, 'chatgpt': True}
    start=datetime.fromisoformat(c.utc_now());stamp=start.isoformat()
    attempts=[]
    for stage,offset in (('quick-https',0),('download-1',1),('stability-15',16),('stability-30',31),('stability-45',46),('download-2',47)):
        download=stage.startswith('download')
        attempts.append({'stage':stage,'endpoint':c.SPEED_ENDPOINT if download else c.QUICK_ENDPOINTS[0],
            'address':'8.8.8.8','attempt':1,'started_at':(start+timedelta(seconds=offset)).isoformat(),
            'passed':True,'http_status':200 if download else 204,'bytes':c.DOWNLOAD_BYTES if download else 0,
            'elapsed_seconds':4 if download else .1,'error':None,'curl_exit':0})
    diagnostics={}
    for name,passed in services.items():
        status=200 if passed else 403
        attempts.append({'stage':'service-'+name,'endpoint':'https://www.youtube.com/' if name=='youtube' else 'https://chatgpt.com/',
            'address':'8.8.8.8','attempt':1,'started_at':(start+timedelta(seconds=51)).isoformat(),
            'http_status':status,'bytes':100,'elapsed_seconds':.1,'error':None,'curl_exit':0})
        diagnostics[name]={'label':'page-confirmed' if passed else 'http-403','http_status':status,
            'blocking_signals':[],'recognized_page':passed,'interpretation':'automated-http-test-only'}
    TEST_CLOCK[0]=start+timedelta(seconds=52)
    row={'id':c.node_id(value),'identity_version':c.CANONICALIZATION_VERSION,
        'original_uri_sha256':p.digest(value.encode()),'checked_at':stamp,'completed_at':TEST_CLOCK[0].isoformat(),
        'baseline_started_at':(start+timedelta(seconds=1)).isoformat(),'core_started':True,
        'qualified':all(services.values()),'baseline_qualified':True,'deep_tested':True,
        'service_qualified':services,'attempts':attempts,'resolved_addresses':['8.8.8.8'],'tested_address':'8.8.8.8',
        'stability_seconds':51,'min_kib_s':512,'download_kib_s':[512,512],'median_ms':100,
        'reachability':{name:proof['label'] for name,proof in diagnostics.items()},'service_diagnostics':diagnostics}

    exported = c.export_with_label(value, row)
    row['subscription_sha256'] = p.digest(exported.encode())
    return row, exported


class PipelineTests(unittest.TestCase):
    def setUp(self):
        TEST_CLOCK[0]=datetime.now(timezone.utc)-timedelta(minutes=10)
        for target in ('checker.utc_now','production.now_iso'):
            clock=patch(target,side_effect=lambda:TEST_CLOCK[0].isoformat())
            clock.start();self.addCleanup(clock.stop)
        quiet = patch('builtins.print')
        quiet.start()
        self.addCleanup(quiet.stop)
        self.environment = patch.dict(os.environ, ENV)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest_path = self.root / 'frozen' / 'manifest.json'
        self.shards = self.root / 'shards'
        self.output = self.root / 'output'

    def prepare(self, total=3):
        raw = '\n'.join(uri(index) for index in range(1, total + 1))
        with patch('checker.download_feed', side_effect=lambda _: feed(raw)) as download:
            manifest = p.prepare(self.manifest_path)
        self.assertEqual(download.call_count, len(c.SOURCES))
        return manifest

    def run_shards(self, manifest, probe=failed_probe):
        with patch('checker.download_feed', side_effect=AssertionError('sources must not be fetched again')), \
             patch('checker.core_metadata', return_value=core_info()), \
             patch('production.preflight_core') as preflight, \
             patch('checker.probe', side_effect=probe) as check:
            for shard in manifest['shards']:
                p.check_shard(self.manifest_path, shard['id'], self.shards, '/fake/core')
        self.assertEqual(check.call_count, len(manifest['candidates']))
        self.assertEqual(sum(len(call.args[0]) for call in preflight.call_args_list), len(manifest['candidates']))

    def mutate_manifest(self, change):
        manifest = json.loads(self.manifest_path.read_text())
        change(manifest)
        digest = p.write_json(self.manifest_path, manifest, p.MAX_MANIFEST_BYTES)
        self.manifest_path.with_suffix('.sha256').write_text(digest + '\n')

    def mutate_shard(self, change, shard='000'):
        path = self.shards / ('shard-' + shard + '.json')
        value = json.loads(path.read_text())
        change(value)
        p.write_json(path, value, p.MAX_SHARD_BYTES)

    def test_full_pool_above_old_512_cap_is_frozen_and_sharded_exactly_once(self):
        manifest = self.prepare(1100)
        self.assertEqual(len(manifest['candidates']), 1100)
        self.assertEqual(len(manifest['shards']), 18)
        ids = [rid for shard in manifest['shards'] for rid in shard['candidate_ids']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, [candidate['id'] for candidate in manifest['candidates']])
        self.assertTrue(all(1 <= len(shard['candidate_ids']) <= 64 for shard in manifest['shards']))
        self.assertEqual(p.load_manifest(self.manifest_path)[0], manifest)

    def test_actions_matrix_matches_frozen_shards(self):
        actions_output = self.root / 'github-output'
        with patch.dict(os.environ, {'GITHUB_OUTPUT': str(actions_output)}):
            manifest = self.prepare(65)
        values = dict(line.split('=', 1) for line in actions_output.read_text().splitlines())
        self.assertEqual(json.loads(values['matrix']),
                         {'include': [{'shard': shard['id']} for shard in manifest['shards']]})
        self.assertEqual(values['manifest_sha256'], p.digest(self.manifest_path.read_bytes()))

    def test_seven_source_inventory_is_required(self):
        self.assertEqual(len(c.SOURCES), 7)
        with patch('checker.download_feed', side_effect=[feed(uri())] * (len(c.SOURCES)-1) + [c.Rejected('offline')]):
            with self.assertRaises(ValueError):
                p.prepare(self.manifest_path)
        self.assertFalse(self.manifest_path.exists())

    def test_empty_and_over_resource_bound_fail_without_any_manifest(self):
        for count in (0, c.MAX_CANDIDATES + 1):
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.prepare(count)
            self.assertFalse(self.manifest_path.exists())

    def test_all_supported_candidates_receive_probe_and_merge_without_refetch(self):
        manifest = self.prepare(129)
        self.run_shards(manifest)
        with patch('checker.download_feed', side_effect=AssertionError('unexpected source refetch')):
            p.merge(self.manifest_path, self.shards, self.output)
        report = p.verify_public(self.manifest_path, self.output)
        self.assertEqual(report['sampled'], 129)
        self.assertTrue(report['coverage']['complete_supported'])
        self.assertEqual(report['coverage']['candidate_cap_skipped'], 0)
        self.assertEqual(report['production']['shard_count'], 3)
        self.assertEqual(report['feed_counts'], {'both': 0, 'chatgpt': 0, 'youtube': 0})

    def test_services_keep_independent_feeds_and_do_not_carry_stale_passes(self):
        manifest = self.prepare(2)
        def probe(value, core, deadline, budget):
            return successful_probe(value, core, deadline, budget,
                                    {'youtube': True, 'chatgpt': c.parse_uri(value)['uuid'] == str(uuid.UUID(int=1))})
        self.run_shards(manifest, probe)
        p.merge(self.manifest_path, self.shards, self.output)
        report = p.verify_public(self.manifest_path, self.output)
        self.assertEqual(report['feed_counts'], {'both': 1, 'chatgpt': 1, 'youtube': 2})
        self.run_shards(manifest, failed_probe)
        p.merge(self.manifest_path, self.shards, self.output)
        for filename in c.FEEDS.values():
            self.assertEqual((self.output / filename).read_text(), '')

    def test_manifest_byte_tamper_is_rejected(self):
        self.prepare()
        self.manifest_path.write_bytes(self.manifest_path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            p.load_manifest(self.manifest_path)

    def test_manifest_rehashed_semantic_tampering_fails(self):
        mutations = [
            lambda m: m['shards'][0]['candidate_ids'].pop(),
            lambda m: m['shards'].append(copy.deepcopy(m['shards'][0])),
            lambda m: m['candidates'].append(copy.deepcopy(m['candidates'][0])),
            lambda m: m['candidates'][0].update(id='0' * 16),
            lambda m: m['candidates'][0].update(sources=[]),
            lambda m: m['sources'][0].update(unique_candidates=0),
            lambda m: m['sources'][0].update(hash_scope='utf8-text'),
            lambda m: m['stats'].update(unique_candidates=1),
            lambda m: m.update(implementation_sha='2' * 40),
            lambda m: m.update(run_id='654321'),
            lambda m: m.update(run_attempt='2'),
            lambda m: m.update(core_lock_sha256='0' * 64),
            lambda m: m.update(shard_size=65),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.prepare()
                self.mutate_manifest(mutate)
                with self.assertRaises(ValueError):
                    p.load_manifest(self.manifest_path)

    def test_unknown_duplicate_or_missing_result_ids_are_rejected(self):
        mutations = [lambda data: data['results'].pop(),
                     lambda data: data['results'].append(copy.deepcopy(data['results'][0])),
                     lambda data: data['results'][1].update(id=data['results'][0]['id']),
                     lambda data: data['results'][0].update(id='0' * 16)]
        manifest = self.prepare()
        for mutate in mutations:
            self.run_shards(manifest)
            self.mutate_shard(mutate)
            with self.assertRaises(ValueError):
                p.merge(self.manifest_path, self.shards, self.output)

    def test_incomplete_shard_inventory_and_unexpected_artifact_are_rejected(self):
        manifest = self.prepare(65)
        self.run_shards(manifest)
        path = self.shards / 'shard-001.json'
        content = path.read_bytes()
        path.unlink()
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)
        path.write_bytes(content)
        (self.shards / 'extra.json').write_text('{}')
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)

    def test_wrong_manifest_shard_implementation_core_or_origin_fails(self):
        manifest = self.prepare()
        mutations = [lambda data: data.update(manifest_sha256='0' * 64),
                     lambda data: data.update(shard_id='999'),
                     lambda data: data.update(implementation_sha='2' * 40),
                     lambda data: data['core'].update(archive_sha256='0' * 64),
                     lambda data: data['origin'].update(country='RU', russia_verified=True),
                     lambda data: data['results'][0].update(original_uri_sha256='0' * 64)]
        for mutate in mutations:
            self.run_shards(manifest)
            self.mutate_shard(mutate)
            with self.assertRaises(ValueError):
                p.merge(self.manifest_path, self.shards, self.output)

    def test_budget_and_infrastructure_failures_are_not_server_rejections(self):
        manifest = self.prepare()
        for reason in ('budget', 'deep-budget', 'core-start-failed'):
            self.run_shards(manifest)
            self.mutate_shard(lambda data: data['results'][0].update(reason=reason))
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                p.merge(self.manifest_path, self.shards, self.output)

    def test_missing_unexpected_or_different_connection_export_fails(self):
        manifest = self.prepare()
        mutations = [lambda data: data['exports'].pop(next(iter(data['exports']))),
                     lambda data: data['exports'].update({'0' * 16: uri(100)}),
                     lambda data: data['exports'].update({next(iter(data['exports'])): uri(100)})]
        for mutate in mutations:
            self.run_shards(manifest, successful_probe)
            self.mutate_shard(mutate)
            with self.assertRaises(ValueError):
                p.merge(self.manifest_path, self.shards, self.output)

    def test_canonical_equivalent_rewritten_connection_bytes_are_rejected(self):
        manifest = self.prepare()
        self.run_shards(manifest, successful_probe)
        def rewrite(data):
            rid = next(iter(data['exports']))
            original = data['exports'][rid]
            changed = original.replace('?security=tls&sni=example.org', '?sni=example.org&security=tls')
            self.assertEqual(c.node_id(original), c.node_id(changed))
            data['exports'][rid] = changed
            next(row for row in data['results'] if row['id'] == rid)['subscription_sha256'] = p.digest(changed.encode())
        self.mutate_shard(rewrite)
        with self.assertRaisesRegex(ValueError, 'original connection bytes'):
            p.merge(self.manifest_path, self.shards, self.output)

    def test_failed_nodes_cannot_export_any_uri(self):
        manifest = self.prepare()
        self.run_shards(manifest)
        self.mutate_shard(lambda data: data['exports'].update({data['results'][0]['id']: uri()}))
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)

    def test_stale_source_manifest_or_node_prohibits_publication(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=c.MAX_RESULT_AGE_SECONDS + 1)).isoformat()
        manifest = self.prepare()
        self.run_shards(manifest)
        self.mutate_shard(lambda data: data['results'][0].update(checked_at=old))
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)
        self.mutate_manifest(lambda data: data['sources'][0].update(fetched_at=old))
        with self.assertRaises(ValueError):
            p.load_manifest(self.manifest_path)
        self.prepare()
        self.mutate_manifest(lambda data: data.update(created_at=old))
        with self.assertRaises(ValueError):
            p.load_manifest(self.manifest_path)

    def test_publication_revalidates_manifest_binding_and_core(self):
        manifest = self.prepare()
        self.run_shards(manifest, successful_probe)
        p.merge(self.manifest_path, self.shards, self.output)
        report_path = self.output / 'report.json'
        original = json.loads(report_path.read_text())
        for mutate in (lambda report: report['production'].update(manifest_sha256='0' * 64),
                       lambda report: report['core'].update(version='0.0.0'),
                       lambda report: report['production']['shards'].pop(),
                       lambda report: report['results'][0].update(sources=[])):
            report = copy.deepcopy(original)
            mutate(report)
            report_path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                p.verify_public(self.manifest_path, self.output)

    def test_prepare_failure_keeps_sanitized_source_inventory(self):
        with patch('checker.download_feed',side_effect=c.Rejected('not available')):
            with self.assertRaises(ValueError): p.prepare(self.manifest_path)
        summary=json.loads((self.manifest_path.parent/'prepare-summary.json').read_text())
        self.assertEqual(len(summary['sources']),len(c.SOURCES))
        self.assertTrue(all(not item['downloaded'] for item in summary['sources']))
        self.assertFalse(self.manifest_path.exists())
        self.assertNotIn('uri',json.dumps(summary))

    def test_core_preflight_checks_every_candidate_without_logging_credentials(self):
        candidates = [{'uri': uri(1)}, {'uri': uri(2)}]
        with patch('production.subprocess.run', return_value=Mock(returncode=0)) as run:
            p.preflight_core(candidates, '/fake/core', p.time.monotonic() + 60)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0][:2], ['/fake/core', 'check'])
        self.assertEqual(run.call_args.kwargs['timeout'], 10)
        self.assertEqual(run.call_args.kwargs['stderr'], p.subprocess.DEVNULL)
        self.assertEqual(set(run.call_args.kwargs['env']), {'PATH', 'HOME'})

    def test_core_schema_failure_stops_before_any_network_probe(self):
        self.prepare()
        with patch('checker.core_metadata', return_value=core_info()), \
             patch('production.subprocess.run', return_value=Mock(returncode=1)), \
             patch('checker.probe') as probe:
            with self.assertRaisesRegex(ValueError, 'official core rejected'):
                p.check_shard(self.manifest_path, '000', self.shards, '/fake/core')
        probe.assert_not_called()
        self.assertFalse(self.shards.exists())

    def test_json_duplicates_oversize_and_symlinks_rejected(self):
        path = self.root / 'bad.json'
        path.write_text('{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            p.read_json(path, 100)
        with self.assertRaises(ValueError):
            p.read_bytes(path, 5)
        link = self.root / 'link.json'
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            p.read_json(link, 100)


class WorkflowTests(unittest.TestCase):
    def test_read_only_probe_jobs_and_publish_guard(self):
        workflow = Path(p.__file__).with_name('.github') / 'workflows' / 'check.yml'
        text = workflow.read_text()
        self.assertEqual(text.count('contents: write'), 1)
        self.assertIn('default: false', text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("github.event_name == 'schedule'", text)
        self.assertIn("inputs.publish == true", text)
        self.assertIn('needs: [prepare, merge]', text)
        self.assertIn('max-parallel: 12', text)
        self.assertIn('fail-fast: false', text)
        self.assertIn('--force-with-lease="refs/heads/checked:$expected"', text)
        self.assertNotIn('git push --force origin', text)
        self.assertIn('git merge-base --is-ancestor "$expected" HEAD', text)
        self.assertEqual(text.count('ref: ${{ github.sha }}'), 4)
        self.assertEqual(text.count('persist-credentials: false'), 3)
        self.assertEqual(text.count('retention-days: 1'), 3)
        for action in re.findall(r'uses: ([^\s#]+)', text):
            self.assertRegex(action, r'@(?:[0-9a-f]{40})$')
        publish = text.rsplit('\n  publish:\n', 1)[1]
        self.assertIn('production.py verify-public', publish)
        self.assertNotIn('fetch_core.py', publish)
        self.assertNotIn('production.py shard ', publish)


if __name__ == '__main__':
    unittest.main()
