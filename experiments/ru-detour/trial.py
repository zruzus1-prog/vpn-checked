#!/usr/bin/env python3
"""Bounded experimental TCP detour vantage. No publication or direct fallback."""
from __future__ import annotations
import collections
import concurrent.futures
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse as U
import unicodedata

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import checker as c

BASE_COMMIT = '976c84b3a09bb8a7decc1c623726f28749720986'
CHECKED_COMMIT = '797d47fa1b3e3b0f6e0981693bfa4000a2954769'
CORE = ROOT / 'bin/sing-box'
OUT = Path(__file__).resolve().parent
WORKERS = 3
MAX_HOPS = 16
MAX_HEALTHY = 2
MAX_CANDIDATES = 24
ROUNDS = 2
ROUND_GAP = 90
TOTAL_SECONDS = 20 * 60
PREVIOUS_OBSERVED_BYTES = 579195
PREVIOUS_RESERVED_BYTES = 38027264
PREVIOUS_LIVE_SECONDS = 42.839
PREVIOUS_RUN_ID = 37355709446
PAYLOAD_LIMIT = 196 * 1024 * 1024 - PREVIOUS_RESERVED_BYTES
RECHECK_HOP_IDS = {'400b3ba29801032a','4aa51b7b19565c3e','4c572f1024425ca7','6e6b9c0d1fdcf892',
                   '7b8b0d577e626905','a40b47ec1b339108','ab9f4f3938535877','b5f4d516e17a1807',
                   'c67b850a8fa6c578','fe6e1ed0fe57e1d4'}
TCP_TYPES = {'vless', 'shadowsocks', 'vmess', 'trojan'}
IP_SERVICES = [('cloudflare', 'https://www.cloudflare.com/cdn-cgi/trace', 'trace'),
               ('aws', 'https://checkip.amazonaws.com/', 'text'),
               ('ipify', 'https://api.ipify.org?format=json', 'json'),
               ('myip', 'https://api.myip.com/', 'json')]
ACTIVE_EGRESS = []
NEUTRAL = 'https://www.gstatic.com/generate_204'
YOUTUBE = 'https://www.youtube.com/'
PUBLIC_HOSTS = {'api.ipify.org', 'api.myip.com', 'ipwho.is', 'ipapi.co',
                'www.gstatic.com', 'www.youtube.com', 'raw.githubusercontent.com',
                'www.cloudflare.com', 'checkip.amazonaws.com'}

class Unknown(Exception):
    pass

class Budget:
    def __init__(self, seconds=TOTAL_SECONDS, payload=PAYLOAD_LIMIT):
        self.deadline = time.monotonic() + seconds
        self.maximum = payload
        self.reserved = 0
        self.observed = 0
        self.lock = threading.Lock()
        self.exhausted = False
    def claim(self, amount, reserve_seconds=0):
        with self.lock:
            if time.monotonic() + reserve_seconds >= self.deadline or self.reserved + amount > self.maximum:
                self.exhausted = True
                raise Unknown('budget-exhausted')
            self.reserved += amount
    def observe(self, amount, allocation):
        with self.lock:
            self.observed += amount
            # Release unused reservation only after the process has terminated and its file is measured.
            # Process-level timeouts retain the entire cap, covering unobserved partial bytes.
            self.reserved += amount-allocation
            if self.reserved>self.maximum:self.exhausted=True

BUDGET = Budget()
DNS_CACHE = {}
DNS_LOCK = threading.Lock()


def fixed_error(exc):
    if isinstance(exc, Unknown): return str(exc)
    if isinstance(exc, c.RequestFailed): return exc.category
    return 'unavailable-or-invalid'


def endpoint(url):
    parsed = U.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in PUBLIC_HOSTS or
            parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise Unknown('endpoint-not-allowlisted')
    with DNS_LOCK:
        if parsed.hostname not in DNS_CACHE:
            DNS_CACHE[parsed.hostname] = c.resolve_public(parsed.hostname, all_addresses=True)[0]
        address = DNS_CACHE[parsed.hostname]
    return parsed.hostname, address


def request(url, session=None, limit=16384, timeout=12):
    """Pin validated public destination IP, preserving HTTPS SNI/Host, no redirects."""
    BUDGET.claim(limit, reserve_seconds=timeout+25)
    hostname, address = endpoint(url)
    connect_address = '['+address+']' if ':' in address else address
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / 'body'
        args = ['curl', '--disable', '--silent', '--noproxy', '', '--proto', '=https',
                '--proto-redir', '=https', '--connect-timeout', '6', '--max-time', str(timeout),
                '--max-filesize', str(limit), '--output', str(target), '--write-out',
                '%{http_code} %{size_download} %{time_total}', '--connect-to',
                f'{hostname}:443:{connect_address}:443']
        if session:
            args += ['--proxy', f'socks5h://127.0.0.1:{session[0]}',
                     '--proxy-user', 'trial:'+session[1]]
        else:
            args += ['--proxy', '']
        args += [url]
        try:
            proc = subprocess.run(args, capture_output=True, timeout=timeout+2,
                                  env={'PATH': os.environ['PATH'], 'HOME': '/nonexistent'})
        except subprocess.TimeoutExpired:
            raise Unknown('curl-process-timeout') from None
        data = target.read_bytes() if target.exists() else b''
        BUDGET.observe(len(data),limit)
        try:
            status, size, elapsed = proc.stdout.decode('ascii').split()
            status, size, elapsed = int(status), int(size), float(elapsed)
            if len(data)>limit or size>limit: raise ValueError()
        except (ValueError, UnicodeError):
            raise Unknown('invalid-curl-metrics') from None
        result = {'http_status': status, 'bytes': len(data), 'elapsed_seconds': elapsed,
                  'curl_exit': proc.returncode, 'destination_ip': address}
        if proc.returncode:
            result['error'] = c.CURL_ERROR_CATEGORIES.get(proc.returncode, 'curl-error')
        return result, data


def get_json(url, session=None):
    detail, data = request(url, session)
    if detail.get('error') or detail['http_status'] != 200:
        raise Unknown(detail.get('error', 'http-not-200'))
    try:
        value=json.loads(data)
        if not isinstance(value,dict): raise ValueError()
        return value
    except (ValueError, UnicodeError): raise Unknown('invalid-json') from None


def prepare_outbound(uri):
    original = c.parse_uri(uri)
    if original['type'] not in TCP_TYPES:
        raise Unknown('unsupported-udp-transport')
    if original.get('tls', {}).get('insecure'):
        raise Unknown('insecure-tls')
    addresses = c.resolve_public(original['server'], all_addresses=True)
    out = c.pin_outbound(original, addresses[0])
    out['network'] = 'tcp'
    return out, {'protocol': original['type'], 'endpoint_ip': addresses[0],
                 'endpoint_port': original['server_port'], 'addresses_validated': len(addresses),
                 'tls_mode': 'reality' if original.get('tls', {}).get('reality', {}).get('enabled')
                             else ('strict-tls' if original.get('tls', {}).get('enabled') else 'aead')}


def configuration(candidate, port, password, hop=None):
    out = copy.deepcopy(candidate)
    out['tag'] = 'candidate'
    out.pop('detour', None)
    outbounds = [out]
    if hop is not None:
        upstream = copy.deepcopy(hop)
        upstream['tag'] = 'ru-hop'
        upstream.pop('detour', None)
        out['detour'] = 'ru-hop'
        outbounds.append(upstream)
    return {'log': {'disabled': True},
            'inbounds': [{'type': 'socks', 'tag': 'input', 'listen': '127.0.0.1',
                          'listen_port': port, 'users': [{'username': 'trial', 'password': password}]}],
            'outbounds': outbounds,
            'route': {'rules': [{'network': 'udp', 'action': 'reject'}], 'final': 'candidate'}}


@contextlib.contextmanager
def core_session(out, hop=None):
    BUDGET.claim(0, reserve_seconds=7)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    password = secrets.token_urlsafe(20)
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / 'config.json'
        path.write_text(json.dumps(configuration(out, port, password, hop)))
        path.chmod(0o600)
        check = subprocess.run([str(CORE), 'check', '-c', str(path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if check.returncode: raise Unknown('core-config-invalid')
        proc = subprocess.Popen([str(CORE), 'run', '-c', str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={'PATH': os.environ['PATH'], 'HOME': '/nonexistent'})
        try:
            ready = False
            for _ in range(40):
                if proc.poll() is not None: raise Unknown('core-stopped')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1): pass
                    ready = True; break
                except OSError: time.sleep(.05)
            if not ready: raise Unknown('core-not-ready')
            yield (port, password)
            if proc.poll() is not None: raise Unknown('core-stopped')
        finally:
            proc.terminate()
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()


def ip_observation(service, session=None):
    name,url,kind=service
    observation={'service':name,'checked_at':c.utc_now(),'healthy':False}
    try:
        detail,data=request(url,session)
        observation.update(detail)
        if detail.get('error') or detail['http_status']!=200:
            observation['reason']=detail.get('error','http-not-200');return observation
        if kind=='json':
            value=json.loads(data)
            if not isinstance(value,dict):raise Unknown('ip-schema-invalid')
            address=value['ip']
        elif kind=='trace':
            values=[line[3:] for line in data.decode('ascii').splitlines() if line.startswith('ip=')]
            if len(values)!=1:raise Unknown('ip-schema-invalid')
            address=values[0]
        elif kind=='text':address=data.decode('ascii').strip()
        else:raise Unknown('ip-format-invalid')
        if not isinstance(address,str) or '%' in address:raise Unknown('ip-schema-invalid')
        address=str(ipaddress.ip_address(address))
        if not c.public_ip(address):raise Unknown('nonpublic-egress')
        observation.update(ip=address,healthy=True)
    except (ValueError,TypeError,RecursionError,KeyError,OSError,subprocess.SubprocessError,Unknown) as exc:
        observation['reason']=fixed_error(exc)
    return observation


def establish_egress_controls():
    global ACTIVE_EGRESS
    ACTIVE_EGRESS=[]
    observations=[ip_observation(service) for service in IP_SERVICES]
    good=[(service,obs) for service,obs in zip(IP_SERVICES,observations) if obs['healthy']]
    # Independent operators with equal observed egress. Never silently relax to one service.
    for index,(first,obs) in enumerate(good):
        for second,other in good[index+1:]:
            if first[0]!=second[0] and obs['ip']==other['ip']:
                ACTIVE_EGRESS=[first,second]
                return observations,obs['ip']
    return observations,None


def egress(session, observations=None):
    observations=[] if observations is None else observations
    if len(ACTIVE_EGRESS)!=2:raise Unknown('egress-controls-not-established')
    for service in ACTIVE_EGRESS:
        result=ip_observation(service,session)
        observations.append(result)
        if not result['healthy']:raise Unknown('egress-service-not-confirmed')
    if observations[0]['ip']!=observations[1]['ip']:
        raise Unknown('egress-services-disagree')
    return observations


def geolocate(address):
    if not c.public_ip(address): raise Unknown('nonpublic-egress')
    records = []
    for name, url in [('ipwho.is', f'https://ipwho.is/{address}'),
                      ('ipapi.co', f'https://ipapi.co/{address}/json/')]:
        try:
            data = get_json(url)
            if data.get('success') is False or data.get('error'):
                raise Unknown('geo-api-error')
            if data.get('ip') != address: raise Unknown('geo-ip-mismatch')
            country = data.get('country_code')
            if not isinstance(country,str) or not re.fullmatch('[A-Z]{2}', country): raise Unknown('geo-country-invalid')
            connection=data.get('connection', {})
            if name=='ipwho.is' and not isinstance(connection,dict):
                raise Unknown('geo-schema-invalid')
            asn = connection.get('asn') if name=='ipwho.is' else data.get('asn')
            asn = str(asn or '').removeprefix('AS')
            if not re.fullmatch('[0-9]+',asn) or not (1<=int(asn)<=4294967295): asn = None
            records.append({'provider': name, 'country_code': country,
                            'asn': 'AS'+asn if asn else None, 'checked_at': c.utc_now()})
        except (ValueError, TypeError, RecursionError, OSError, subprocess.SubprocessError, Unknown) as exc:
            records.append({'provider': name, 'error': fixed_error(exc)})
    return records


def qualify_geo(records):
    good = [x for x in records if x.get('country_code')]
    asns = {x['asn'] for x in good if x.get('asn')}
    return len(good)==2 and all(x['country_code']=='RU' and x.get('asn') for x in good) and len(asns)==1


def validate_hop(item, cloud_ip=None):
    record = {'id': item['id'], 'checked_at': c.utc_now(), 'state': 'unknown',
              'source_indexes': item['source_indexes'], 'physical_russia_confirmed': False}
    try:
        record['stage']='endpoint-validation'
        out, meta = prepare_outbound(item['uri']); record.update(meta)
        record['stage']='core-start'
        with core_session(out) as session:
            record['stage']='neutral-https'
            neutral, _ = request(NEUTRAL, session);record['neutral']=neutral
            if neutral.get('error') or neutral['http_status']!=204:
                raise Unknown('hop-neutral-not-confirmed')
            record['stage']='egress-attribution'
            record['egress']=[]
            observations = egress(session,record['egress'])
        if cloud_ip and observations[0]['ip']==cloud_ip:
            raise Unknown('hop-egress-equals-cloud-baseline')
        record['stage']='geo-attribution'
        record['geo'] = geolocate(observations[0]['ip'])
        record['geo_confidence'] = 'two-database-agreement' if qualify_geo(record['geo']) else 'not-established'
        complete_geo=len(record['geo'])==2 and all(x.get('country_code') and x.get('asn') and not x.get('error') for x in record['geo'])
        record['state'] = 'apparently-ru-healthy' if qualify_geo(record['geo']) else ('not-qualified' if complete_geo else 'unknown')
        if record['state']=='unknown':record['reason']='geo-not-established'
        if record['state']=='apparently-ru-healthy':
            record['stage']='qualified'
            record['asn'] = next(x['asn'] for x in record['geo'] if x.get('asn'))
            return record, out
    except (ValueError, TypeError, RecursionError, KeyError, OSError, subprocess.SubprocessError, Unknown) as exc:
        record['reason'] = fixed_error(exc)
    return record, None


def hop_control(out, expected_ip):
    result = {'checked_at': c.utc_now(), 'healthy': False}
    try:
        with core_session(out) as session:
            detail, _ = request(NEUTRAL, session)
            result['neutral'] = detail
            if detail.get('error') or detail['http_status']!=204:raise Unknown('control-neutral-not-confirmed')
            result['egress']=[]
            egress(session,result['egress'])
            result['healthy'] = (result['egress'][0]['ip']==expected_ip and
                                 detail['http_status']==204 and not detail.get('error'))
    except (ValueError, TypeError, RecursionError, KeyError, OSError, subprocess.SubprocessError, Unknown) as exc:
        result['reason'] = fixed_error(exc)
    return result


def cloud_control():
    result={'checked_at':c.utc_now(),'healthy':False}
    try:
        detail,_=request(NEUTRAL)
        result['neutral']=detail
        result['healthy']=detail['http_status']==204 and not detail.get('error')
    except (ValueError,TypeError,RecursionError,OSError,subprocess.SubprocessError,Unknown) as exc:
        result['reason']=fixed_error(exc)
    return result


def assess(item, hop=None):
    result = {'id': item['id'], 'group': item['group'], 'checked_at': c.utc_now(), 'state': 'unknown'}
    try:
        out, meta = prepare_outbound(item['uri']); result.update(meta)
        with core_session(out, hop) as session:
            neutral, _ = request(NEUTRAL, session)
            result['neutral'] = neutral
            if neutral.get('error') in ('timeout','response-too-large') or neutral['http_status']==429:
                result['reason']='neutral-inconclusive'; return result
            if neutral.get('error') or neutral['http_status']!=204:
                result['state']='failed'; result['reason']='neutral-not-confirmed'; return result
            page, data = request(YOUTUBE, session, limit=1024*1024, timeout=16)
            result['youtube'] = page
            if page.get('error') in ('timeout','response-too-large') or page['http_status']==429:
                result['reason']='youtube-inconclusive'; return result
            if page.get('error'):
                result['state']='failed'; result['reason']='youtube-request-failed'; return result
            evidence = c.service_assessment('youtube', page['http_status'], data.decode('utf-8', errors='replace'))
            result['youtube_evidence'] = evidence
            result['state'] = 'passed' if evidence['label']=='page-confirmed' else 'failed'
            result['reason'] = evidence['label']
    except (ValueError, TypeError, RecursionError, KeyError, OSError, subprocess.SubprocessError, Unknown) as exc:
        result['reason'] = fixed_error(exc)
    return result


def classify_batch(results, before, after):
    if not before.get('healthy') or not after.get('healthy'):
        for result in results:
            result['uncontrolled_state'] = result['state']
            result['state'] = 'unknown'
            result['reason'] = 'hop-control-failed'
    return results


def full_label(uri):
    parsed=U.urlsplit(uri)
    name=U.unquote(parsed.fragment)
    if parsed.scheme.lower()=='vmess':
        try:name=json.loads(c.b64(parsed.netloc+parsed.path)).get('ps','')
        except (ValueError,AttributeError):name=''
    if not isinstance(name,str):return ''
    return ''.join(ch for ch in unicodedata.normalize('NFKC',name) if not unicodedata.category(ch).startswith('C'))


def choose_hops(items):
    hints=[]; rejected=collections.Counter()
    for item in items:
        names=item.get('labels',[full_label(item['uri'])])
        if any(re.search(r'white|whitelist|бел[ыа]|\[wl\]', name, re.I) for name in names): continue
        if not any(re.search(r'🇷🇺|росси|russia|\bRU\b|moscow|москва', name, re.I) for name in names): continue
        out=c.parse_uri(item['uri'])
        if out['type'] not in TCP_TYPES:
            rejected['unsupported-udp-transport']+=1; continue
        hints.append(item)
    # Independent endpoint first, then different authenticated config on same endpoint.
    selected=[]; endpoints=set()
    for unique in (True, False):
        for item in sorted(hints, key=lambda x: x['id']):
            out=c.parse_uri(item['uri']); key=(out['server'],out['server_port'])
            if item in selected or (unique and key in endpoints): continue
            selected.append(item); endpoints.add(key)
            if len(selected)==MAX_HOPS: return selected, dict(rejected)
    return selected, dict(rejected)


def load_selection():
    selected=json.loads((OUT/'selection.json').read_text())
    if not isinstance(selected,list) or not (1<=len(selected)<=MAX_CANDIDATES):raise Unknown('selection-invalid')
    if any(not isinstance(x,dict) or not re.fullmatch('[0-9a-f]{16}',x.get('id','')) or
           x.get('group') not in ('stable-local-negative','reserve-unconfirmed','prior-local-positive') for x in selected):
        raise Unknown('selection-invalid')
    if len({x['id'] for x in selected})!=len(selected):raise Unknown('selection-duplicates')
    return selected


def load_inputs():
    items={}; sources=[]
    for index, url in enumerate(c.SOURCES):
        try:
            detail, data = request(url, limit=c.MAX_FEED, timeout=20)
            if detail.get('error') or detail['http_status']!=200: raise Unknown('source-download-failed')
            text=data.decode('utf-8-sig'); lines=c.feed_lines(text)
            rejected=0
            for uri in lines:
                try:
                    ident=c.node_id(uri)
                    if ident not in items: items[ident]={'id':ident, 'uri':uri, 'source_indexes':[],'labels':[]}
                    if full_label(uri) not in items[ident]['labels']:items[ident]['labels'].append(full_label(uri))
                    if index not in items[ident]['source_indexes']: items[ident]['source_indexes'].append(index)
                except (ValueError,KeyError,TypeError,RecursionError): rejected+=1
            sources.append({'index':index, 'url':url, 'fetched_at':c.utc_now(),
                            'sha256':hashlib.sha256(data).hexdigest(), 'lines':len(lines), 'rejected':rejected})
        except (ValueError,TypeError,RecursionError,OSError,subprocess.SubprocessError,Unknown) as exc:
            sources.append({'index':index,'url':url,'error':fixed_error(exc)})
    selected=load_selection()
    # The checked commit pins the actual user-visible negative/control cohort.
    snapshot={}
    for group, filename in [('stable-local-negative','subscription-youtube-stable.txt'),
                            ('reserve-unconfirmed','subscription-youtube-reserve.txt')]:
        url=f'https://raw.githubusercontent.com/zruzus1-prog/vpn-checked/{CHECKED_COMMIT}/{filename}'
        detail,data=request(url,limit=c.MAX_FEED,timeout=20)
        if detail.get('error') or detail['http_status']!=200: raise Unknown('checked-snapshot-unavailable')
        for uri in c.feed_lines(data.decode('utf-8-sig')):
            ident=c.node_id(uri); snapshot[ident]={'id':ident,'uri':uri,'group':group}
    candidates=[]; absent=[]
    for row in selected[:MAX_CANDIDATES]:
        ident=row['id']
        if ident in snapshot:
            item=dict(snapshot[ident]); item['group']=row['group']; candidates.append(item)
        elif ident in items and row['group']=='prior-local-positive':
            item=dict(items[ident]); item['group']=row['group']; candidates.append(item)
        else: absent.append({'id':ident,'group':row['group'],'reason':'snapshot-config-unavailable'})
    previous_pool=[item for ident,item in items.items() if ident in RECHECK_HOP_IDS]
    hops, excluded=choose_hops(previous_pool)
    return candidates,hops,{'sources':sources,'candidate_ids':[{'id':x['id'],'group':x['group']} for x in candidates],
                           'missing_candidates':absent,'hop_ids':[x['id'] for x in hops],
                           'hop_label_hints_only':True,'hop_unsupported':excluded,
                           'recheck_only_previous_hop_ids':True,
                           'previous_hops_unavailable_or_excluded':sorted(RECHECK_HOP_IDS-{x['id'] for x in hops})}


def save(report):
    (OUT/'results.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')


def run():
    started_monotonic=time.monotonic()
    candidates=[];expected_candidates=[]
    report={'schema_version':1,'started_at':c.utc_now(),'main_commit':BASE_COMMIT,'checked_commit':CHECKED_COMMIT,
            'scope':'encrypted-TCP-accessibility-only','physical_russia_confirmed':False,'user_isp_tested':False,
            'selection_scope':'deliberately-diversity-enriched-exact-24-not-population-representative',
            'prior_positive_control':'historical-user-report-current-local-status-unconfirmed',
            'video_playback_tested':False,'udp_tested':False,'throughput_ranked':False,
            'limits':{'max_hop_candidates':MAX_HOPS,'max_healthy_hops':MAX_HEALTHY,'max_candidates':MAX_CANDIDATES,
                      'rounds':ROUNDS,'round_gap_seconds':ROUND_GAP,'workers':WORKERS,
                      'application_payload_reservation_cap':PAYLOAD_LIMIT,'wall_seconds':TOTAL_SECONDS},
            'hop_validation':[],'batches':[],'status':'running',
            'previous_run':{'run_id':PREVIOUS_RUN_ID,'observed_bytes':PREVIOUS_OBSERVED_BYTES,
                            'reserved_bytes':PREVIOUS_RESERVED_BYTES,'live_seconds':PREVIOUS_LIVE_SECONDS}}
    save(report)
    try:
        expected_candidates=load_selection()
        report['expected_candidate_ids']=expected_candidates
        report['core']=c.core_metadata(str(CORE))
        candidates,hops,inventory=load_inputs(); report['inventory']=inventory; save(report)
        report['cloud_neutral_control']=cloud_control()
        report['cloud_ip_service_controls'],cloud_ip=establish_egress_controls()
        report['active_ip_services']=[x[0] for x in ACTIVE_EGRESS]
        save(report)
        if not report['cloud_neutral_control']['healthy'] or cloud_ip is None:
            report['status']='probe-controls-not-established'
            report['reason']='cloud-neutral-or-two-independent-ip-services-unavailable'
            return report
        report['cloud_egress_ip']=cloud_ip
        healthy=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for record,out in pool.map(lambda item:validate_hop(item,cloud_ip),hops):
                report['hop_validation'].append(record)
                if out is not None: healthy.append((record,out))
                save(report)
        # Prefer two different ASNs, allow a second same-ASN vantage only if necessary.
        chosen=[]; asns=set()
        for distinct in (True,False):
            for record,out in healthy:
                if any(record['id']==x[0]['id'] or record['egress'][0]['ip']==x[0]['egress'][0]['ip'] for x in chosen): continue
                if distinct and record['asn'] in asns: continue
                chosen.append((record,out)); asns.add(record['asn'])
                if len(chosen)==MAX_HEALTHY: break
            if len(chosen)==MAX_HEALTHY: break
        report['chosen_hops']=[x[0]['id'] for x in chosen]; save(report)
        if not chosen:
            report['status']='ru-hop-feasibility-not-established'; return report
        report['planned_matrix']=[{'round':r+1,'path':h[0]['id'] if h[0] else 'direct-cloud',
                                   'id':item['id'],'group':item['group']}
                                  for r in range(ROUNDS) for h in [(None,None),*chosen] for item in candidates]
        for round_id in range(ROUNDS):
            if round_id: time.sleep(min(ROUND_GAP,max(0,BUDGET.deadline-time.monotonic())))
            if time.monotonic()>=BUDGET.deadline: raise Unknown('budget-exhausted')
            for hop_record,hop in [(None,None),*chosen]:
                for offset in range(0,len(candidates),4):
                    if BUDGET.exhausted: raise Unknown('budget-exhausted')
                    BUDGET.claim(0,reserve_seconds=150)
                    items=candidates[offset:offset+4]
                    path=hop_record['id'] if hop_record else 'direct-cloud'
                    batch={'round':round_id+1,'path':path,'batch':offset//4,'started_at':c.utc_now()}
                    if hop:
                        expected_ip=hop_record['egress'][0]['ip']
                        batch['control_before']=hop_control(hop,expected_ip)
                    else:
                        batch['control_before']=cloud_control()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
                        batch['results']=list(pool.map(lambda item: assess(item,hop),items))
                    if hop:
                        batch['control_after']=hop_control(hop,expected_ip)
                    else:
                        batch['control_after']=cloud_control()
                    classify_batch(batch['results'],batch['control_before'],batch['control_after'])
                    if not hop:
                        for result in batch['results']:
                            if result.get('reason')=='hop-control-failed': result['reason']='cloud-control-failed'
                    batch['completed_at']=c.utc_now();report['batches'].append(batch);save(report)
        report['status']='incomplete' if BUDGET.exhausted else 'completed'
        if BUDGET.exhausted:report['reason']='budget-exhausted'
    except (ValueError,TypeError,RecursionError,KeyError,OSError,subprocess.SubprocessError,Unknown) as exc:
        report['status']='incomplete'; report['reason']=fixed_error(exc)
    finally:
        report['completed_at']=c.utc_now()
        report['payload_reserved_bytes']=BUDGET.reserved
        report['payload_observed_bytes']=BUDGET.observed
        completed={(batch['round'],batch['path'],r['id']) for batch in report['batches'] for r in batch['results']}
        report['not_run']=[{**row,'state':'unknown','reason':report.get('reason','not-run')}
                           for row in report.get('planned_matrix',[]) if (row['round'],row['path'],row['id']) not in completed]
        if not report.get('planned_matrix'):
            report['not_run']=[{'id':item['id'],'group':item['group'],'path':'ru-detour-not-established','round':None,
                                'state':'unknown','reason':report['status'],'scope':'candidate-blocked-before-matrix'} for item in expected_candidates]
        else:
            represented={row['id'] for row in report['planned_matrix']}
            report['not_run'] += [{'id':item['id'],'group':item['group'],'path':'candidate-input-unavailable','round':None,
                                  'state':'unknown','reason':'snapshot-config-unavailable','scope':'candidate-blocked-before-matrix'}
                                 for item in expected_candidates if item['id'] not in represented]
            if any(item['id'] not in represented for item in expected_candidates) and report['status']=='completed':
                report['status']='incomplete';report['reason']='some-snapshot-configs-unavailable'
        report['candidate_probe_attempts']=sum(len(x['results']) for x in report['batches'])
        report['candidate_unique_tested']=len({x['id'] for batch in report['batches'] for x in batch['results']})
        report['candidate_unique_not_tested']=len({x['id'] for x in report['not_run']}-{x['id'] for batch in report['batches'] for x in batch['results']})
        report['cumulative_observed_bytes']=PREVIOUS_OBSERVED_BYTES+BUDGET.observed
        report['cumulative_payload_upper_bound_bytes']=PREVIOUS_RESERVED_BYTES+BUDGET.reserved
        report['cumulative_live_seconds']=PREVIOUS_LIVE_SECONDS+time.monotonic()-started_monotonic
        report['summary']=dict(collections.Counter([r['state'] for batch in report['batches'] for r in batch['results']]+
                                                   ['unknown']*len(report['not_run'])))
        save(report)
        print(json.dumps({k:report[k] for k in ('status','summary','payload_reserved_bytes','payload_observed_bytes')}))
    return report

if __name__=='__main__': run()
