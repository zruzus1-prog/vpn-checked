#!/usr/bin/env python3
"""One bounded, non-publishing source experiment. No history or subscription writes."""
import concurrent.futures as futures
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import checker as c
import validate_output as v
EXTRA={
 'nomorewalls':'https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt',
 'aetris':'https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/main/configs.txt',
}
COHORTS=('baseline','nomorewalls','aetris')
PER_COHORT=24
WORKERS=4
SECONDS=35*60
MAX_POOL=12000
OUTPUT=Path('/tmp/source-trial-output')

def require(ok,message):
 if not ok:raise ValueError(message)

def prefix(host):
 try:
  ip=ipaddress.ip_address(host)
  return str(ipaddress.ip_network(host+('/24' if ip.version==4 else '/48'),strict=False))
 except ValueError:return None

def hostsets(pool):
 hosts={c.parse_uri(u)['server'].lower() for u in pool.values()}
 return hosts,{p for h in hosts if (p:=prefix(h))}

def inventory(urls):
 previous=c.SOURCES
 try:
  c.SOURCES=list(urls)
  pool,_,sources,stats=c.collect_candidates()
 finally:c.SOURCES=previous
 require(all(s['downloaded'] for s in sources) and len(sources)==len(urls),'incomplete source downloads')
 require(0<len(pool)<=MAX_POOL,'empty or oversized source pool')
 return {c.node_id(uri):uri for uri in pool.values()},sources,stats

def select(pool,baseline_hosts,baseline_prefixes,cap=PER_COHORT):
 """Deterministic protocol round-robin, favor distinct and baseline-new hosts/prefixes."""
 parsed={key:c.parse_uri(uri) for key,uri in pool.items()}
 buckets={p:[] for p in sorted({o['type'] for o in parsed.values()})}
 for key,o in parsed.items():buckets[o['type']].append(key)
 chosen=[];hosts=set();prefixes=set()
 while len(chosen)<min(cap,len(pool)):
  for protocol in buckets:
   if not buckets[protocol]:continue
   def priority(key):
    host=parsed[key]['server'].lower();net=prefix(host)
    return (host in hosts,net is not None and net in prefixes,host in baseline_hosts,net is not None and net in baseline_prefixes,key)
   key=min(buckets[protocol],key=priority);buckets[protocol].remove(key)
   chosen.append(key);host=parsed[key]['server'].lower();hosts.add(host)
   if (net:=prefix(host)):prefixes.add(net)
   if len(chosen)>=cap:break
 return chosen

def check_result(row,expected_id):
 require(row.get('id')==expected_id,'wrong candidate identity')
 require(row.get('identity_version')==c.CANONICALIZATION_VERSION,'wrong identity version')
 require(set(row.get('service_qualified',{}))=={'youtube','chatgpt'},'wrong service flags')
 require(all(type(x) is bool for x in row['service_qualified'].values()),'invalid service boolean')
 require(row.get('qualified')==all(row['service_qualified'].values()),'inconsistent both-service flag')
 if any(row['service_qualified'].values()):require(row.get('baseline_qualified') is True,'service without baseline')
 v.validate_attempts(row)
 if row.get('baseline_qualified'):
  require(row['stability_seconds']>=c.STABILITY_SECONDS,'short stability')
  require(row['min_kib_s']>=c.MIN_BYTES_PER_SECOND/1024,'slow baseline')


def summarize(rows):
 return {'assessed':len(rows),'baseline_qualified':sum(r.get('baseline_qualified') is True for r in rows),
  'youtube':sum(r['service_qualified']['youtube'] for r in rows),
  'chatgpt':sum(r['service_qualified']['chatgpt'] for r in rows),
  'both':sum(r['qualified'] for r in rows),
  'failures':dict(Counter(r.get('reason','none') for r in rows)),
  'confirmed_youtube_tested_addresses':sorted({r['tested_address'] for r in rows if r['service_qualified']['youtube']})}

def run():
 require(os.environ.get('GITHUB_ACTIONS')=='true','live experiment is GitHub Actions only')
 require(len(c.SOURCES)==6,'review changed production baseline')
 require(c.WORKERS==4 and c.STABILITY_SECONDS==45 and c.DOWNLOAD_BYTES==2097152 and c.MIN_BYTES_PER_SECOND==262144,'review changed production criteria')
 require(c.MAX_ENDPOINT_ADDRESSES==3 and c.MAX_ATTEMPTS==2,'review changed request bounds')
 OUTPUT.mkdir(parents=True,exist_ok=False)
 started=c.utc_now();core=str(ROOT/'bin/sing-box');core_proof=c.core_metadata(core)
 baseline,base_sources,base_stats=inventory(tuple(c.SOURCES))
 bh,bp=hostsets(baseline);pools={'baseline':baseline};feeds={};novelty={};full_extras={}
 for name,url in EXTRA.items():
  pool,sources,stats=inventory((url,));full_extras[name]=pool
  fresh={key:uri for key,uri in pool.items() if key not in baseline}
  hosts,prefixes=hostsets(pool)
  novelty[name]={'supported_unique':len(pool),'new_config_ids':sorted(fresh),
   'new_hosts':len(hosts-bh),'new_literal_ip_prefixes':len(prefixes-bp)}
  pools[name]=fresh;feeds[name]={'sources':sources,'stats':stats}
 overlap=set(pools['nomorewalls'])&set(pools['aetris'])
 # Do not spend two probes on the same effective configuration.
 pools['aetris']={key:uri for key,uri in pools['aetris'].items() if key not in overlap}
 selected={name:select(pool,bh if name!='baseline' else set(),bp if name!='baseline' else set()) for name,pool in pools.items()}
 require(all(selected.values()),'empty experiment cohort')
 plan={'schema':1,'started_at':started,'implementation_sha':os.environ.get('GITHUB_SHA'),
  'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
  'core':core_proof,'baseline_sources':base_sources,'baseline_stats':base_stats,'extra_sources':feeds,
  'novelty':novelty,'cross_extra_overlap_ids':sorted(overlap),'selected_ids':selected,
  'selection':'nonrandom deterministic protocol round-robin prioritizing distinct and baseline-new URI hosts and literal-IP prefixes; max 24 per cohort; shared extra IDs assigned to NoMoreWalls',
  'limits':{'per_cohort':PER_COHORT,'total_nodes':sum(map(len,selected.values())),'workers':WORKERS,'probe_budget_seconds':SECONDS,'stability_seconds':45,'download_bytes_each':2097152,'download_samples':2,'minimum_kib_s':256,'max_endpoint_addresses':3,'max_attempts_per_stage':2,'max_large_response_body_bytes':72*16*1024*1024},
  'scope':'cloud runner only; baseline is contemporaneous parser-supported candidate pool, not production-qualified subscription; nonrandom diversity-prioritized cohorts are not a fair whole-source superiority comparison; homepage HTML, not video playback; no Russian-network proof; sampled outcomes cannot be extrapolated to complete feeds'}
 (OUTPUT/'plan.json').write_text(json.dumps(plan,indent=2))
 work=[]
 for i in range(max(map(len,selected.values()))):
  for name in COHORTS:
   if i<len(selected[name]):work.append((name,selected[name][i]))
 deadline=time.monotonic()+SECONDS;rows={name:[] for name in COHORTS}
 with futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
  pending={pool.submit(c.probe,pools[name][key],core,deadline):(name,key) for name,key in work}
  for future in futures.as_completed(pending):
   name,key=pending[future];row,_=future.result();check_result(row,key);rows[name].append(row)
   print(json.dumps({'cohort':name,'id':key,'baseline':row.get('baseline_qualified',False),'youtube':row['service_qualified']['youtube'],'reason':row.get('reason')}),flush=True)
 for name in COHORTS:
  rows[name].sort(key=lambda row:row['id'])
  require([r['id'] for r in rows[name]]==sorted(selected[name]),'incomplete result coverage')
 report={'schema':1,'started_at':started,'completed_at':c.utc_now(),'probe_origin':c.probe_origin(),
  'plan_sha256':hashlib.sha256((OUTPUT/'plan.json').read_bytes()).hexdigest(),
  'results':rows,'summary':{name:summarize(rows[name]) for name in COHORTS},
  'complete_sample':not any(r.get('reason') in ('budget','core-stopped','core-start-failed','deep-budget') for group in rows.values() for r in group),
  'scope':plan['scope']}
 (OUTPUT/'report.json').write_text(json.dumps(report,indent=2))
 print(json.dumps(report['summary'],indent=2),flush=True)
 require(report['complete_sample'],'infrastructure or time budget prevented complete sample')

if __name__=='__main__':run()
