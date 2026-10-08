"""4096-count boundaries, atomic completeness, archive compatibility, safe budgets."""
import copy
import json
import shutil
import unittest
from unittest.mock import patch
import checker as c
import diversity as d
import history as h
import production as p
import test_pipeline as f
import test_history as hf


class CapacityTests(unittest.TestCase):
    setUp = f.PipelineTests.setUp
    prepare = f.PipelineTests.prepare
    def run_shards(self, manifest):
        with patch('checker.core_metadata',return_value=f.core_info()), patch('production.preflight_core'), patch('checker.probe',side_effect=f.failed_probe) as probes:
            for shard in manifest['shards']:
                p.check_shard(self.manifest_path,shard['id'],self.shards,'/fake/core')
        # Mock.call_count += 1 is not atomic across four worker threads.
        self.assertEqual(len(probes.call_args_list),len(manifest['candidates']))
        self.assertEqual({c.node_id(call.args[0]) for call in probes.call_args_list},
                         {row['id'] for row in manifest['candidates']})

    def test_exact_4096_full_merge_and_missing_duplicate_last_shard(self):
        manifest = self.prepare(4096)
        self.assertEqual(len(manifest['shards']), 64)
        self.assertEqual(p.MAX_PARALLEL, 8)
        self.run_shards(manifest)
        last = self.shards/'shard-063.json'
        data = last.read_bytes()
        last.unlink()
        with self.assertRaisesRegex(ValueError, 'missing or unexpected'):
            p.merge(self.manifest_path, self.shards, self.output)
        self.assertFalse((self.output/'report.json').exists())
        last.write_bytes((self.shards/'shard-062.json').read_bytes())
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)
        last.write_bytes(data)
        p.merge(self.manifest_path, self.shards, self.output)
        report=p.verify_public(self.manifest_path, self.output)
        self.assertEqual(report['sampled'],4096)
        self.assertEqual(report['production']['shard_count'],64)
        self.assertTrue(report['coverage']['complete_supported'])
        self.assertEqual(len(json.loads((self.output/'history.json').read_bytes())['entries']),4096)

    def test_current_4097_reports_count_only_without_manifest(self):
        with self.assertRaisesRegex(p.PipelineError,'current=4097, cap=4096'):
            self.prepare(4097)
        summary=json.loads((self.manifest_path.parent/'prepare-summary.json').read_bytes())
        self.assertEqual(summary['capacity'],{'limit':4096,'current':4097,'retained':None,'total':None,'status':'current-overflow'})
        self.assertNotIn('vless://',json.dumps(summary))
        self.assertFalse(self.manifest_path.exists())

    def test_combined_retained_overflow_reports_distinct_counts(self):
        state,_,_=hf.history_for()
        provenance={'checked_commit':'a'*40,'authenticated_snapshots':len(state['runs']),'mode':'retained-state'}
        f.TEST_CLOCK[0]=h.stamp(state['created_at'])
        # One fresh candidate plus one retained candidate exceeds a tiny test cap.
        with patch.object(c,'MAX_CANDIDATES',1),patch.object(h,'load_remote',return_value=(state,provenance)),patch('checker.download_feed',side_effect=lambda _:f.feed(f.uri(5000))):
            with self.assertRaisesRegex(p.PipelineError,'current=1, retained=1, total=2, cap=1'):
                p.prepare(self.manifest_path,use_history=True)
        summary=json.loads((self.manifest_path.parent/'prepare-summary.json').read_bytes())
        self.assertEqual(summary['capacity']['status'],'combined-overflow')
        self.assertFalse(self.manifest_path.exists())


class ArchiveCapacityTests(unittest.TestCase):
    def test_exact_64_shard_authentication_65_and_duplicate_rejected(self):
        report,commit,run,jobs=hf.AuthenticationTests().fixtures()
        receipt=report['production']['shards'][0]
        report['production'].update(shard_count=64,shards=[{**receipt,'id':f'{i:03d}'} for i in range(64)])
        with patch('history.remote_read',side_effect=[h.encoded(run),h.encoded(jobs)]):
            h.authenticate_publication('owner/repo',commit,report,None,now=hf.NOW)
        bad=copy.deepcopy(report);bad['production']['shards'][-1]['id']='062'
        with self.assertRaises(ValueError):h.authenticate_publication('owner/repo',commit,bad,None,now=hf.NOW)
        bad=copy.deepcopy(report);bad['production']['shard_count']=65
        with self.assertRaises(ValueError):h.authenticate_publication('owner/repo',commit,bad,None,now=hf.NOW)

    def test_archived_40_policy_is_exact_scoped_and_restored_on_failure(self):
        state,rows,exports=hf.history_for()
        original=copy.deepcopy(h.POLICY)
        report={'production':{'implementation_sha':'fcb28f217015b2fabe966b52713bcbe52bae62ad'}}
        with h.archived_selection_policy(report):
            self.assertEqual((d.MAIN_CAP,d.EXPLORATORY_CAP),(40,10))
            self.assertEqual(h.POLICY['main_cap'],40)
            old=copy.deepcopy(h.POLICY)
            report['history']={'policy':old}
            h.split_for_report(state,rows,exports,report,allow_legacy=True)
        self.assertEqual(h.POLICY,original)
        self.assertEqual((d.MAIN_CAP,d.EXPLORATORY_CAP),(80,20))
        with self.assertRaises(ValueError):h.split_for_report(state,rows,exports,report)
        report['production']['implementation_sha']='e'*40
        with h.archived_selection_policy(report),self.assertRaises(ValueError):
            h.split_for_report(state,rows,exports,report,allow_legacy=True)
        report['production']['implementation_sha']='fcb28f217015b2fabe966b52713bcbe52bae62ad'
        with self.assertRaises(RuntimeError):
            with h.archived_selection_policy(report):raise RuntimeError('fixture')
        self.assertEqual(h.POLICY,original)
        self.assertEqual(h.LEGACY_POLICY['main_cap'],40)

    def test_byte_budget_contracts_are_not_unbounded(self):
        self.assertEqual((p.MAX_REPORT_BYTES,p.MAX_MANIFEST_BYTES,p.MAX_SHARD_BYTES,h.MAX_BYTES),
                         (64_000_000,24*1024*1024,4*1024*1024,12*1024*1024))
        self.assertEqual((h.MAX_RUNS,h.MAX_AGE_SECONDS,h.MAX_ENTRIES),(32,48*3600,8192))
