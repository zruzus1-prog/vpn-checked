"""No-network history replay, resource accounting and split-feed trust tests."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import checker as c
import history as h
import production as p
import test_pipeline as pipeline
TEST_CLOCK=pipeline.TEST_CLOCK
successful_probe=pipeline.successful_probe
failed_probe=pipeline.failed_probe
uri=pipeline.uri
feed=pipeline.feed


NOW = datetime.now(timezone.utc)-timedelta(minutes=20)


def candidate(i=1):
    value=uri(i)
    return {'id':c.node_id(value),'uri':value,'sources':[c.SOURCES[0]]}


def row(item, passed=True, speed=600, ip='8.8.8.8'):
    return {'id':item['id'],'service_qualified':{'youtube':passed,'chatgpt':False},
            'min_kib_s':speed,'median_ms':100,'tested_address':ip,
            'attempts':[{'stage':stage,'address':ip,'passed':True,'elapsed_seconds':c.DOWNLOAD_BYTES/speed/1024}
                        for stage in ('download-1','download-2')]}


def history_for(items=None, hours=(12,6,0), passed=None, speeds=None, event='schedule'):
    items=items or [candidate()]
    state=h.empty((NOW-timedelta(hours=max(hours))).isoformat())
    for index,hours_ago in enumerate(hours):
        at=(NOW-timedelta(hours=hours_ago)).isoformat()
        results=[row(item, (passed or [True]*len(hours))[index], (speeds or [600]*len(hours))[index],
                     f'8.8.{n//250}.{n%250+1}') for n,item in enumerate(items)]
        state=h.update(state,items,results,at=at,implementation_sha='1'*40,
                       run_id=str(index+1),run_attempt='1',event=event)
    return state,results,{item['id']:item['uri'] for item in items}


class HistoryTests(unittest.TestCase):
    def test_three_spaced_passes_qualify_and_partition(self):
        state,rows,exports=history_for()
        feeds,proof=h.split(state,rows,exports)
        self.assertEqual(feeds['stable'],list(exports.values()))
        self.assertEqual(feeds['reserve'],[])
        self.assertEqual(proof['eligible_before_diversity'],1)

    def test_caps_zero_one_39_40_41_and_overflow(self):
        for n in (1,39,40,41):
            with self.subTest(n=n):
                state,rows,exports=history_for([candidate(i) for i in range(1,n+1)])
                feeds,_=h.split(state,rows,exports)
                self.assertEqual(len(feeds['stable']),min(40,n))
                self.assertEqual(len(feeds['reserve']),max(0,n-40))
                self.assertFalse(set(feeds['stable'])&set(feeds['reserve']))
                self.assertEqual(set(feeds['stable'])|set(feeds['reserve']),set(exports.values()))
        state,rows,exports=history_for(passed=[False,False,False])
        feeds,_=h.split(state,rows,{})
        self.assertEqual(feeds,{'stable':[],'reserve':[]})
        self.assertTrue(all(e['uri'] is None for e in state['entries']))

    def test_time_span_speed_and_local_evidence_do_not_force_fill(self):
        for kwargs in ({'hours':(2,1,0)}, {'hours':(5,3,0)}, {'hours':(12,0)},
                       {'speeds':[600,511.9,600]}, {'event':'local'}):
            with self.subTest(kwargs=kwargs):
                state,rows,exports=history_for(**kwargs)
                feeds,_=h.split(state,rows,exports)
                self.assertEqual(feeds['stable'],[])
                self.assertEqual(feeds['reserve'],list(exports.values()))

    def test_rapid_manual_failures_count_even_when_passes_are_spaced(self):
        state,rows,exports=history_for(hours=(12,6,5.99,0),passed=[True,True,False,True])
        feeds,proof=h.split(state,rows,exports)
        self.assertEqual(feeds['stable'],[])
        self.assertEqual(proof['evidence'][rows[0]['id']]['pass_rate'],.75)

    def test_last_two_observed_must_pass_even_when_rate_is_90_percent(self):
        state,rows,exports=history_for(hours=tuple(range(36,-1,-4)),passed=[True]*8+[False,True])
        self.assertEqual(h.split(state,rows,exports)[0]['stable'],[])

    def test_same_endpoint_ip_variants_stay_in_reserve(self):
        state,rows,exports=history_for([candidate(1),candidate(2)])
        rows[1]['tested_address']=rows[0]['tested_address']
        for attempt in rows[1]['attempts']:attempt['address']=rows[0]['tested_address']
        feeds,_=h.split(state,rows,exports)
        self.assertEqual(len(feeds['stable']),1)
        self.assertEqual(len(feeds['reserve']),1)

    def test_source_absence_does_not_refresh_retention_or_add_failure(self):
        state,rows,exports=history_for()
        previous=copy.deepcopy(state['entries'][0])
        at=NOW+timedelta(hours=2)
        candidates,pruned=h.nominate(state,[],at.isoformat())
        self.assertEqual(len(candidates),1)
        self.assertEqual(pruned['entries'][0],previous)
        updated=h.update(pruned,[],rows,at=at.isoformat(),implementation_sha='1'*40,
                         run_id='4',run_attempt='1',event='schedule')
        self.assertEqual(updated['entries'][0]['last_upstream_seen_at'],previous['last_upstream_seen_at'])
        self.assertEqual(len(updated['entries'][0]['observations']),4)

    def test_retention_anchors_upstream_presence_not_latest_pass(self):
        state,rows,exports=history_for()
        state['entries'][0]['last_upstream_seen_at']=(NOW-timedelta(hours=47)).isoformat()
        at=NOW+timedelta(hours=2)
        candidates,pruned=h.nominate(state,[],at.isoformat())
        self.assertEqual(candidates,[])
        self.assertEqual(pruned['entries'],[])

    def test_current_uri_wins_without_semantic_identity_change(self):
        state,rows,exports=history_for()
        current=candidate();current['uri']+='-new-label'
        actual,_=h.nominate(state,[current],NOW.isoformat())
        self.assertEqual(actual,[current])

    def test_replayed_logical_run_and_attempt_cannot_create_evidence(self):
        state,rows,exports=history_for()
        with self.assertRaises(ValueError):
            h.update(state,[candidate()],rows,at=(NOW+timedelta(hours=2)).isoformat(),
                     implementation_sha='1'*40,run_id='3',run_attempt='2',event='workflow_dispatch')

    def test_state_schema_identity_profile_uri_and_timestamps_fail_closed(self):
        state,_,_=history_for()
        mutators=[lambda s:s.update(extra=True),lambda s:s.update(measurement_profile='unknown'),
                  lambda s:s['entries'][0].update(id='0'*16),
                  lambda s:s['entries'][0].update(last_upstream_seen_at=(NOW+timedelta(seconds=1)).isoformat()),
                  lambda s:s['entries'][0].update(last_upstream_seen_at='2026-10-05T00:00:00'),
                  lambda s:s['entries'][0].update(uri='vless://invalid'),
                  lambda s:s['entries'][0]['observations'][0].update(min_kib_s=float('nan')),
                  lambda s:s['entries'][0]['observations'].append(copy.deepcopy(s['entries'][0]['observations'][0]))]
        for mutate in mutators:
            bad=copy.deepcopy(state);mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):h.validate(bad,now=NOW)

    def test_duplicate_json_keys_and_oversize_history_rejected(self):
        with self.assertRaises(ValueError):h.strict_json('{"a":1,"a":2}')
        state,_,_=history_for()
        with patch.object(h,'MAX_BYTES',10),self.assertRaises(ValueError):h.validate(state,now=NOW)

    def test_merged_candidate_overflow_is_whole_run_failure(self):
        state,_,_=history_for()
        with patch.object(c,'MAX_CANDIDATES',1),self.assertRaises(ValueError):
            h.nominate(state,[candidate(2)],NOW.isoformat())

    def test_no_authentication_strings_in_history_error(self):
        state,_,_=history_for();state['entries'][0]['uri']='trojan://TOP-SECRET@127.0.0.1:443'
        try:h.validate(state,now=NOW)
        except ValueError as exc:self.assertNotIn('TOP-SECRET',str(exc))
        else:self.fail('invalid history accepted')

    def test_export_label_is_idempotent_without_connection_changes(self):
        value=uri(1)+'%F0%9F%87%B3%F0%9F%87%B1'
        first=c.export_with_label(value,{'id':c.node_id(value)})
        second=c.export_with_label(first,{'id':c.node_id(first)})
        self.assertEqual(first,second)
        self.assertEqual(value.split('#')[0],second.split('#')[0])


class HistoryPipelineTests(unittest.TestCase):
    setUp=pipeline.PipelineTests.setUp
    run_shards=pipeline.PipelineTests.run_shards
    mutate_manifest=pipeline.PipelineTests.mutate_manifest
    def prepare_history(self):
        state,_,_=history_for([candidate(900)],hours=(30,24,18))
        # Pipeline fixture clock is 10 min ago, state is older than that.
        with patch('history.load_remote',return_value=(state,{'checked_commit':'a'*40,'authenticated_snapshots':3,'mode':'verified-bootstrap'})), \
             patch('checker.download_feed',side_effect=lambda _:feed(uri(1))), \
             patch.dict(os.environ,{'GITHUB_EVENT_NAME':'workflow_dispatch'}):
            return p.prepare(self.manifest_path,use_history=True)

    def test_current_and_missing_retained_candidates_are_both_freshly_probed(self):
        manifest=self.prepare_history()
        self.assertEqual(len(manifest['candidates']),2)
        self.assertEqual(manifest['stats']['unique_candidates'],1)
        self.run_shards(manifest,successful_probe)
        p.merge(self.manifest_path,self.shards,self.output)
        report=p.verify_public(self.manifest_path,self.output)
        self.assertEqual(report['history']['current_candidates'],1)
        self.assertEqual(report['history']['retained_candidates'],1)
        self.assertEqual(report['sampled'],2)
        self.assertTrue(report['coverage']['complete_supported'])
        self.assertEqual(len((self.output/h.SPLIT_FEEDS['stable']).read_text().splitlines()),1)
        self.assertEqual(sum(report['history']['split_counts'].values()),report['feed_counts']['youtube'])
        retained=next(e for e in json.loads((self.output/'history.json').read_text())['entries'] if e['id']==candidate(900)['id'])
        self.assertEqual(retained['last_upstream_seen_at'],manifest['history']['state']['entries'][0]['last_upstream_seen_at'])
        self.assertGreater(report['resources']['measured_response_body_bytes'],0)

    def test_empty_successful_sources_can_retest_unexpired_history(self):
        state,_,_=history_for([candidate(900)],hours=(30,24,18))
        with patch('history.load_remote',return_value=(state,{'checked_commit':'a'*40,'authenticated_snapshots':3,'mode':'verified-bootstrap'})), \
             patch('checker.download_feed',side_effect=lambda _:feed('')), \
             patch.dict(os.environ,{'GITHUB_EVENT_NAME':'workflow_dispatch'}):
            manifest=p.prepare(self.manifest_path,use_history=True)
        self.assertEqual(manifest['stats']['unique_candidates'],0)
        self.assertEqual(len(manifest['candidates']),1)
        self.run_shards(manifest,successful_probe)
        p.merge(self.manifest_path,self.shards,self.output)
        report=p.verify_public(self.manifest_path,self.output)
        self.assertEqual(report['history']['retained_candidates'],1)
        self.assertEqual(report['feed_counts']['youtube'],1)

    def test_historical_pass_with_current_failure_exports_nothing(self):
        manifest=self.prepare_history();self.run_shards(manifest,failed_probe)
        p.merge(self.manifest_path,self.shards,self.output)
        report=p.verify_public(self.manifest_path,self.output)
        self.assertEqual(report['feed_counts']['youtube'],0)
        self.assertEqual(report['history']['split_counts'],{'stable':0,'reserve':0})

    def test_altered_historical_connection_and_presence_inventory_rejected(self):
        self.prepare_history()
        self.mutate_manifest(lambda m:m['candidates'][0].update(uri=uri(42)))
        with self.assertRaises(ValueError):p.load_manifest(self.manifest_path)

    def test_history_output_and_split_tampering_rejected(self):
        manifest=self.prepare_history();self.run_shards(manifest,successful_probe)
        p.merge(self.manifest_path,self.shards,self.output)
        (self.output/h.SPLIT_FEEDS['stable']).write_text('')
        with self.assertRaises(ValueError):p.verify_public(self.manifest_path,self.output)


class AuthenticationTests(unittest.TestCase):
    def fixtures(self):
        from test_pipeline import core_info
        at=(NOW-timedelta(minutes=5)).isoformat()
        done=(NOW-timedelta(minutes=4)).isoformat()
        lock,lock_digest=p.local_lock()
        report={'schema_version':4,'identity_version':c.CANONICALIZATION_VERSION,
            'core':core_info(),'started_at':at,'completed_at':done,
            'limits':{'stability_window_seconds':c.STABILITY_SECONDS,'download_bytes_per_sample':c.DOWNLOAD_BYTES,
                      'download_samples':2,'min_kib_s':c.MIN_BYTES_PER_SECOND//1024},
            'production':{'manifest_sha256':'c'*64,'implementation_sha':next(iter(h.BOOTSTRAP_IMPLEMENTATIONS)),
                'run_id':'123','run_attempt':'1','source_snapshot_at':at,'core_lock_sha256':lock_digest,
                'shard_size':64,'max_parallel_shards':8,'shard_count':1,
                'shards':[{'id':'000','sha256':'e'*64,'started_at':at,'completed_at':done}]}}
        commit={'sha':'b'*40,'commit':{'committer':{'name':'github-actions[bot]',
            'email':'41898282+github-actions[bot]@users.noreply.github.com','date':NOW.isoformat()}}}
        run={'id':123,'run_attempt':1,'conclusion':'success','status':'completed',
            'repository':{'full_name':'owner/repo'},'head_repository':{'full_name':'owner/repo'},
            'head_branch':'main','head_sha':next(iter(h.BOOTSTRAP_IMPLEMENTATIONS)),
            'path':'.github/workflows/check.yml','event':'schedule',
            'run_started_at':at,'updated_at':NOW.isoformat()}
        jobs={'total_count':1,'jobs':[{'name':'publish','conclusion':'success','started_at':done,'completed_at':NOW.isoformat()}]}
        return report,commit,run,jobs

    def test_exact_successful_own_publication_is_authenticated(self):
        report,commit,run,jobs=self.fixtures()
        with patch('history.remote_read',side_effect=[h.encoded(run),h.encoded(jobs)]):
            self.assertEqual(h.authenticate_publication('owner/repo',commit,report,'token',now=NOW),'schedule')

    def test_dry_run_fork_wrong_event_head_attempt_and_policy_rejected(self):
        mutators=[lambda r,j:j['jobs'][0].update(conclusion='skipped'),
                  lambda r,j:r.update(head_branch='experiment'),
                  lambda r,j:r['head_repository'].update(full_name='attacker/repo'),
                  lambda r,j:r.update(event='pull_request'),
                  lambda r,j:r.update(head_sha='f'*40),
                  lambda r,j:r.update(run_attempt=2),
                  lambda r,j:r.update(conclusion='failure')]
        for mutate in mutators:
            report,commit,run,jobs=self.fixtures();mutate(run,jobs)
            with self.subTest(mutate=mutate),patch('history.remote_read',side_effect=[h.encoded(run),h.encoded(jobs)]),self.assertRaises(ValueError):
                h.authenticate_publication('owner/repo',commit,report,None,now=NOW)
        report,commit,run,jobs=self.fixtures();report['production']['implementation_sha']='f'*40
        with self.assertRaises(ValueError):h.authenticate_publication('owner/repo',commit,report,None,now=NOW)

    def test_source_supplied_repository_or_redirect_target_cannot_be_read(self):
        for url in ('http://api.github.com/repos/a/b','https://evil.example/history.json','https://127.0.0.1/history.json'):
            with self.subTest(url=url),self.assertRaises(ValueError):h.remote_read(url,100)
        with self.assertRaises(ValueError):h.load_remote('../outside','token',now=NOW)


class MetadataBudgetTests(unittest.TestCase):
    def test_metadata_budget_is_separate_from_live_probe_budget(self):
        state,_,_=history_for([candidate(1),candidate(2)],passed=[False,False,False])
        with patch.object(c,'MAX_CANDIDATES',1):
            h.validate(state,now=NOW)
            candidates,_=h.nominate(state,[candidate(3)],NOW.isoformat())
            self.assertEqual(len(candidates),1)
        with patch.object(h,'MAX_ENTRIES',1),self.assertRaises(ValueError):h.validate(state,now=NOW)

    def test_failed_observation_persists_across_absence_without_a_uri(self):
        state,_,_=history_for(passed=[False,False,False])
        retained=h.prune(state,NOW+timedelta(hours=1))
        self.assertEqual(retained['entries'][0]['observations'],state['entries'][0]['observations'])
        self.assertIsNone(retained['entries'][0]['uri'])
        self.assertEqual(h.nominate(state,[],(NOW+timedelta(hours=1)).isoformat())[0],[])


class SpeedPrecisionTests(unittest.TestCase):
    def test_rounded_512_cannot_bless_a_511_96_sample(self):
        state,rows,exports=history_for(speeds=[600,600,511.96])
        rows[0]['min_kib_s']=512.0
        self.assertLess(state['entries'][0]['observations'][-1]['min_kib_s'],512)
        self.assertEqual(h.split(state,rows,exports)[0]['stable'],[])
