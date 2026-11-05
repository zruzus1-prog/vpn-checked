import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('source_trial',Path(__file__).with_name('trial.py'))
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)

def uri(i):
 return f'vless://00000000-0000-4000-8000-000000000001@8.{i//256}.{i%256}.1:443?security=tls&sni=example.com&type=tcp'
def pool(start,n):return {t.c.node_id(uri(i)):uri(i) for i in range(start,start+n)}

class TrialTests(unittest.TestCase):
 def test_selection_bounded_unique_reproducible(self):
  p=pool(0,60);a=t.select(p,set(),set());b=t.select(dict(reversed(list(p.items()))),set(),set())
  self.assertEqual(a,b);self.assertEqual(len(a),24);self.assertEqual(len(set(a)),24)
 def test_selection_prefers_novel_hosts(self):
  p=pool(0,40);bh,_=t.hostsets(dict(list(p.items())[:24]));selected=t.select(p,bh,set(),8)
  self.assertTrue(all(t.c.parse_uri(p[key])['server'] not in bh for key in selected))
 def test_prefix_not_dns_or_operator_claim(self):
  self.assertEqual(t.prefix('8.8.8.8'),'8.8.8.0/24');self.assertIsNone(t.prefix('example.com'))
 def test_inventory_restores_production_sources_after_failure(self):
  original=list(t.c.SOURCES)
  with patch.object(t.c,'collect_candidates',side_effect=ValueError('mock')):
   with self.assertRaises(ValueError):t.inventory(tuple(t.EXTRA.values()))
  self.assertEqual(t.c.SOURCES,original)
 def test_blocks_local_live_run(self):
  with patch.dict(t.os.environ,{'GITHUB_ACTIONS':'false'}):
   with self.assertRaisesRegex(ValueError,'GitHub Actions only'):t.run()
 def test_rejects_fabricated_service_without_baseline(self):
  with self.assertRaises(ValueError):t.check_result({'id':'a','identity_version':t.c.CANONICALIZATION_VERSION,'qualified':False,'service_qualified':{'youtube':True,'chatgpt':False}},'a')
 def test_mock_complete_run_no_uris_and_no_duplicate_ids(self):
  base=pool(0,30);n=pool(30,30);a={**pool(55,30),**dict(list(base.items())[:3])}
  def inv(urls):
   p=base if len(urls)==6 else n if urls[0]==t.EXTRA['nomorewalls'] else a
   return p,[],{}
  seen=[]
  def probe(u,*args):
   key=t.c.node_id(u);seen.append(key);stamp=t.c.utc_now()
   return {'id':key,'identity_version':t.c.CANONICALIZATION_VERSION,'checked_at':stamp,'completed_at':stamp,'qualified':False,'baseline_qualified':False,'service_qualified':{'youtube':False,'chatgpt':False},'attempts':[],'reason':'quick-https-failed'},None
  with tempfile.TemporaryDirectory() as d,patch.dict(t.os.environ,{'GITHUB_ACTIONS':'true'}),patch.object(t,'OUTPUT',Path(d)/'out'),patch.object(t.c,'core_metadata',return_value={}),patch.object(t,'inventory',side_effect=inv),patch.object(t.c,'probe',side_effect=probe),patch('builtins.print'):
   t.run();raw=(t.OUTPUT/'report.json').read_text();report=json.loads(raw);plan=json.loads((t.OUTPUT/'plan.json').read_text())
   self.assertEqual(len(seen),72);self.assertEqual(len(set(seen)),72)
   self.assertTrue(report['complete_sample']);self.assertEqual(len(plan['cross_extra_overlap_ids']),5)
   self.assertNotIn('vless://',raw);self.assertNotIn('00000000-0000',raw)
   for k,group in report['results'].items():self.assertEqual(len(group),24)
if __name__=='__main__':unittest.main()
