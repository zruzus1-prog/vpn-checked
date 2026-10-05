"""No-network adversarial diversity, exact partition, and archive regressions."""
from collections import Counter
import copy
import json
import random
import unittest
from unittest.mock import patch

import checker as c
import diversity as d
import history as h
import production as p
import test_history as fixtures
import test_pipeline as pipeline


def item(n, *, protocol=None, group=None, owners=None, tier='strict-history', prefix=None):
    protocol = protocol or ('ss', 'vless', 'trojan', 'vmess', 'hysteria2')[n % 5]
    return {'id': f'{n:016x}', 'prefix': prefix or f'8.{n//250}.{n%250}.0/24',
            'protocol': protocol, 'group': group or protocol+'/tcp/tls/plain',
            'owners': owners or ('owner'+str(n % 5),), 'tier': tier}


class DiversityTests(unittest.TestCase):
    def assert_caps(self, candidates, selected):
        by_id = {x['id']: x for x in candidates}
        rows = [by_id[rid] for rid in selected]
        self.assertLessEqual(len(selected), 40)
        self.assertEqual(len({x['prefix'] for x in rows}), len(rows))
        self.assertLessEqual(sum(x['tier'] != 'strict-history' for x in rows), 10)
        for key, cap in [('protocol',20), ('group',12)]:
            self.assertTrue(all(n <= cap for n in Counter(x[key] for x in rows).values()))
        owners = Counter(o.lower() for x in rows for o in set(x['owners']))
        self.assertTrue(all(n <= 20 for n in owners.values()))

    def test_zero_one_39_40_41_and_small_cohort(self):
        for n in (0, 1, 3, 39, 40, 41):
            pool = [item(i) for i in range(n)]
            chosen, summary, decisions = d.select(pool)
            self.assertEqual(len(chosen), min(n,40))
            self.assertEqual(set(decisions), {x['id'] for x in pool})
            self.assert_caps(pool, chosen)

    def test_single_group_cannot_force_forty(self):
        pool = [item(i, protocol='ss') for i in range(100)]
        chosen, _, _ = d.select(pool)
        self.assertEqual(len(chosen), 12)

    def test_many_transports_cannot_bypass_protocol_cap(self):
        pool = [item(i, protocol='vless', group='vless/transport'+str(i%8)+'/tls/plain') for i in range(100)]
        chosen, _, _ = d.select(pool)
        self.assertEqual(len(chosen), 20)

    def test_all_source_owners_count_and_duplicate_aliases_do_not_game_quota(self):
        pool = [item(i, owners=('shared', 'Shared', 'other'+str(i%5))) for i in range(70)]
        chosen, summary, _ = d.select(pool)
        self.assertEqual(len(chosen), 20)
        self.assertEqual(summary['source_owner_counts']['shared'], 20)
        self.assertEqual(sum(summary['source_owner_counts'].values()), 40)

    def test_same_owner_multiple_feeds_collapse_honestly(self):
        sources = ['https://raw.githubusercontent.com/Owner/repo/main/one',
                   'https://raw.githubusercontent.com/owner/repo/refs/heads/main/two',
                   'https://raw.githubusercontent.com/Second/repo/main/one']
        self.assertEqual(d.source_owners(sources), ('owner','second'))
        self.assertEqual(d.source_owners(sources*2), ('owner','second'))

    def test_same_prefix_ipv4_and_ipv6_cannot_fill_multiple_slots(self):
        for prefix in ('8.8.8.0/24','2606:4700:4700::/48'):
            chosen,_,_=d.select([item(i,prefix=prefix) for i in range(40)])
            self.assertEqual(len(chosen),1)
        self.assertEqual(d.endpoint_prefix('8.8.8.8'),d.endpoint_prefix('8.8.8.99'))
        self.assertEqual(d.endpoint_prefix('::ffff:8.8.8.8'),'8.8.8.0/24')
        self.assertEqual(d.endpoint_prefix('2606:4700:4700::1111'),'2606:4700:4700::/48')
        self.assertNotEqual(d.endpoint_prefix('2606:4700:4701::1111'),d.endpoint_prefix('2606:4700:4700::1111'))

    def test_invalid_prefix_private_address_or_duplicate_id_fails_closed(self):
        for address in ('127.0.0.1','::1','::ffff:127.0.0.1','10.0.0.1'):
            with self.subTest(address=address),self.assertRaises(ValueError):d.endpoint_prefix(address)
        for prefix in ('8.8.0.0/16','8.8.8.8/32','2606:4700::/32'):
            with self.subTest(prefix=prefix),self.assertRaises(ValueError):d.select([item(1,prefix=prefix)])
        with self.assertRaises(ValueError):d.select([item(1),item(1)])

    def test_exploration_is_bounded_at_ten_and_not_thirty_or_forty(self):
        pool=[item(i,tier='fresh-diversity') for i in range(100)]
        chosen,summary,_=d.select(pool)
        self.assertEqual(len(chosen),10)
        self.assertEqual(summary['selected_tier_counts']['fresh-diversity'],10)
        self.assertEqual(d.select(pool,exploratory_cap=0)[0],[])
        with self.assertRaises(ValueError):d.select(pool,exploratory_cap=11)

    def test_repeated_baseline_and_fresh_trials_share_same_ten_slot_budget(self):
        pool=[item(i,tier='fresh-diversity' if i%2 else 'repeated-baseline') for i in range(100)]
        chosen,summary,_=d.select(pool)
        self.assertEqual(len(chosen),10)
        self.assertEqual(sum(summary['selected_tier_counts'].values()),10)

    def test_strict_first_then_repeated_inside_each_group(self):
        pool=[item(i,protocol='ss',tier=t) for i,t in enumerate(['fresh-diversity','repeated-baseline','strict-history'])]
        self.assertEqual(d.select(pool)[0], [pool[2]['id'],pool[1]['id'],pool[0]['id']])

    def test_count_speed_and_latency_cannot_dominate_after_threshold(self):
        pool=[item(1,protocol='ss'),item(2,protocol='ss')]
        for x in pool:x['owners']=('same',)
        pool[0].update(spaced_passes=3,speed=512,latency=900)
        pool[1].update(spaced_passes=99,speed=999999,latency=1)
        self.assertEqual(d.select(pool)[0][0],pool[0]['id'])

    def test_rarest_missing_transport_not_swamped_by_large_reality_pool(self):
        pool=[item(i,protocol='vless',group='vless/tcp/reality/plain') for i in range(100)]
        obfs=item(100,protocol='ss',group='ss/tcp/none/obfs-local',tier='repeated-baseline')
        pool.append(obfs)
        self.assertEqual(d.select(pool)[0][0],obfs['id'])

    def test_shuffle_and_ties_are_deterministic_and_do_not_mutate_inputs(self):
        pool=[item(i) for i in range(200)]
        expected=d.select(pool);original=copy.deepcopy(pool)
        for seed in range(10):
            shuffled=list(pool);random.Random(seed).shuffle(shuffled)
            self.assertEqual(d.select(shuffled),expected)
        self.assertEqual(pool,original)

    def test_adversarial_random_cohort_caps_and_every_exclusion_explained(self):
        rng=random.Random(42)
        pool=[]
        for i in range(900):
            x=item(i,tier=rng.choice(d.TIERS),owners=('owner'+str(rng.randrange(4)),),
                   prefix=f'8.8.{rng.randrange(100)}.0/24')
            x['group']=x['protocol']+'/'+rng.choice(('tcp','ws','grpc'))+'/tls/plain'
            pool.append(x)
        chosen,_,decisions=d.select(pool)
        self.assert_caps(pool,chosen)
        self.assertTrue(all(x['reasons'] for x in decisions.values()))

    def test_obfuscation_and_transport_groups_preserve_real_settings(self):
        plain={'type':'shadowsocks'};obfs={**plain,'plugin':'obfs-local'}
        self.assertNotEqual(d.connection_group(plain),d.connection_group(obfs))
        hy={'type':'hysteria2','tls':{'enabled':True}}
        self.assertNotEqual(d.connection_group(hy),d.connection_group({**hy,'obfs':{'type':'salamander'}}))
        self.assertNotEqual(d.connection_group({'type':'vless','tls':{'enabled':True}}),
                            d.connection_group({'type':'vless','tls':{'enabled':True},'transport':{'type':'ws'}}))


class DiversityHistoryTests(unittest.TestCase):
    def test_all_old_strict_gates_still_define_strict_tier(self):
        cases=[({},'strict-history'),({'speeds':[600,511.9,600]},'repeated-baseline'),
               ({'hours':(2,1,0)},'fresh-diversity'),({'hours':(5,3,0)},'fresh-diversity'),
               ({'hours':(12,0)},'fresh-diversity'),({'event':'local'},'fresh-diversity'),
               ({'hours':(12,6,5.99,0),'passed':[True,True,False,True]},'fresh-diversity')]
        for kwargs,tier in cases:
            with self.subTest(kwargs=kwargs):
                state,rows,exports=fixtures.history_for(**kwargs)
                feeds,proof=h.split(state,rows,exports)
                rid=rows[0]['id'];ev=proof['evidence'][rid]
                self.assertEqual(ev['tier'],tier)
                self.assertEqual(ev['eligible'],tier=='strict-history')
                self.assertEqual(ev['selected'],True)
                self.assertEqual(set(feeds['stable'])|set(feeds['reserve']),set(exports.values()))

    def test_missing_fresh_pass_never_qualifies_from_history(self):
        state,rows,exports=fixtures.history_for(passed=[True,True,False])
        feeds,proof=h.split(state,rows,{})
        self.assertEqual(feeds,{'stable':[],'reserve':[]})
        self.assertEqual(proof['evidence'],{})

    def test_exact_not_rounded_baseline_remains_mandatory(self):
        state,rows,exports=fixtures.history_for()
        rows[0]['min_kib_s']=256
        for attempt in rows[0]['attempts']:
            attempt['elapsed_seconds']=c.DOWNLOAD_BYTES/255.999/1024
        with self.assertRaises(ValueError):h.split(state,rows,exports)

    def test_original_flags_and_connection_bytes_and_partition_are_untouched(self):
        state,rows,exports=fixtures.history_for([fixtures.candidate(i) for i in range(50)])
        original=dict(exports)
        feeds,proof=h.split(state,rows,exports)
        self.assertEqual(exports,original)
        self.assertFalse(set(feeds['stable'])&set(feeds['reserve']))
        self.assertEqual(set(feeds['stable'])|set(feeds['reserve']),set(original.values()))
        self.assertEqual(len(feeds['stable'])+len(feeds['reserve']),len(original))
        self.assertEqual(len(feeds['stable']),1)  # All fixtures share one /24.

    def test_duplicate_provenance_cannot_evade_owner_cap_via_files(self):
        self.assertEqual(d.source_owners(c.SOURCES).count('igareck'),1)

    def test_old_selector_only_allowed_for_explicit_archive_commit(self):
        state,rows,exports=fixtures.history_for()
        report={'history':{'policy':h.LEGACY_POLICY},'production':{'implementation_sha':'976c84b3a09bb8a7decc1c623726f28749720986'}}
        expected=h.legacy_split(state,rows,exports)
        self.assertEqual(h.split_for_report(state,rows,exports,report,allow_legacy=True),expected)
        with self.assertRaises(ValueError):h.split_for_report(state,rows,exports,report)
        report['production']['implementation_sha']='e'*40
        with self.assertRaises(ValueError):h.split_for_report(state,rows,exports,report,allow_legacy=True)
        self.assertIn('976c84b3a09bb8a7decc1c623726f28749720986',h.BOOTSTRAP_IMPLEMENTATIONS)
        self.assertIn('8601c067ce2f7dde936b17808b7bf58906131d19',h.BOOTSTRAP_IMPLEMENTATIONS)


class DiversityPublicationTests(unittest.TestCase):
    setUp=pipeline.PipelineTests.setUp
    run_shards=pipeline.PipelineTests.run_shards
    prepare=pipeline.PipelineTests.prepare

    def test_publication_recomputes_tiers_caps_and_selection_evidence(self):
        manifest=self.prepare(3)
        self.run_shards(manifest,pipeline.successful_probe)
        p.merge(self.manifest_path,self.shards,self.output)
        report=p.verify_public(self.manifest_path,self.output)
        original=json.loads((self.output/'report.json').read_bytes())
        rid=report['history']['stable_ids'][0]
        mutations=[lambda r:r['history']['selection']['selected_tier_counts'].update({'strict-history':1}),
                   lambda r:r['history']['evidence'][rid].update({'tier':'strict-history'}),
                   lambda r:r['history']['evidence'][rid].update({'endpoint_prefix':'8.8.0.0/16'}),
                   lambda r:r['history']['policy']['selection_policy'].update({'maximum_non_strict_slots':40}),
                   lambda r:r['history'].update({'policy':h.LEGACY_POLICY})]
        for mutate in mutations:
            bad=copy.deepcopy(original);mutate(bad)
            (self.output/'report.json').write_text(json.dumps(bad))
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):p.verify_public(self.manifest_path,self.output)
        (self.output/'report.json').write_text(json.dumps(original))
        p.verify_public(self.manifest_path,self.output)


if __name__=='__main__':unittest.main()
