#!/usr/bin/env python3
"""Isolated public-proxy feasibility trial; no feed-supplied code is executed.

prepare is offline; run requires an official SHA-verified sing-box supplied by
the operator. Existing repository files are never imported or executed.
"""
import argparse
import base64
from collections import Counter
import concurrent.futures
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse as U
import uuid
import unicodedata
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
MAX_FEED = 4 * 1024 * 1024
DOWNLOAD = 2 * 1024 * 1024
MAX_NODES = 24
PER_FEED = 4
WORKERS = 4
BUDGET_SECONDS = 960
ROUND_GAP = 30
ENV = {'PATH': os.environ['PATH'], 'HOME': '/nonexistent'}

class Excluded(ValueError):
    def __init__(self, category):
        self.category = category
        super().__init__(category)

def bounded(value, maximum=8192):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Excluded('unsafe-string')
    return value

def decode64(value):
    bounded(value, MAX_FEED * 2)
    try:
        return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf8')
    except (ValueError, UnicodeError):
        raise Excluded('invalid-base64')

def hostname(value):
    bounded(value, 253)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if (not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value)
            or '..' in value or value.lower() == 'localhost'
            or value.lower().endswith(('.localhost', '.local', '.internal'))):
            raise Excluded('invalid-hostname')
        return value.lower()

def public_ip(value):
    ip = ipaddress.ip_address(value)
    return (ip.is_global and not ip.is_multicast
            and not getattr(ip, 'ipv4_mapped', None)
            and not getattr(ip, 'sixtofour', None)
            and not getattr(ip, 'teredo', None)
            and not (ip.version == 6 and any(ip in ipaddress.ip_network(n) for n in ('64:ff9b::/96', '64:ff9b:1::/48'))))

def parse(uri):
    """Conservative mapping: unknown transport/auth options are never dropped."""
    bounded(uri)
    try:
        u = U.urlsplit(uri)
        scheme = u.scheme.lower()
        if scheme == 'vmess':
            v = json.loads(decode64(u.netloc + u.path))
            if not isinstance(v, dict):
                raise Excluded('unsupported-vmess')
            if any(k in v and str(v[k]).lower() not in ('0','false','') for k in ('insecure','allowInsecure','skip-cert-verify')):
                raise Excluded('insecure-tls-requested')
            if set(v) - {'v','ps','add','port','id','aid','scy','net','type','host','path','tls','sni','alpn','fp'}:
                raise Excluded('unsupported-option')
            for k, value in v.items():
                if type(value) not in (str, int) or (not isinstance(value, str) and k not in ('v','port','aid')):
                    raise Excluded('invalid-vmess-field')
                if isinstance(value, str): bounded(value, 4096)
            if str(v.get('aid', '0')) != '0' or v.get('type', 'none') not in ('','none'):
                raise Excluded('unsupported-vmess')
            server, port = hostname(v['add']), int(v['port'])
            out = {'type': 'vmess', 'uuid': str(uuid.UUID(v['id'])), 'security': v.get('scy','auto'), 'alter_id': 0}
            if out['security'] not in ('auto','aes-128-gcm','chacha20-poly1305'):
                raise Excluded('unsupported-vmess-cipher')
            q = {'security': v.get('tls','none'), 'sni': v.get('sni') or v.get('host') or server,
                 'type': v.get('net','tcp'), 'host': v.get('host',''), 'path': v.get('path','/')}
            for k in ('alpn','fp'):
                if v.get(k): q[k] = v[k]
        else:
            if scheme not in ('vless','trojan','ss','hy2','hysteria2'):
                raise Excluded('unsupported-protocol')
            if scheme == 'ss' and '@' not in u.netloc:
                u = U.urlsplit('ss://' + decode64(u.netloc) + ('?' + u.query if u.query else ''))
            server, port = hostname(u.hostname or ''), u.port
            pairs = U.parse_qsl(u.query, keep_blank_values=True)
            if len(pairs) != len(dict(pairs)): raise Excluded('duplicate-option')
            q = dict(pairs)
            for k in ('insecure','allowInsecure','skip-cert-verify'):
                if k in q and q[k].lower() not in ('0','false',''):
                    raise Excluded('insecure-tls-requested')
            allowed = {'security','sni','peer','type','host','path','fp','alpn'}
            if scheme == 'vless': allowed |= {'pbk','sid','flow','encryption','packetEncoding','headerType','headertype'}
            elif scheme in ('hy2','hysteria2'): allowed |= {'obfs','obfs-password','upmbps'}
            elif scheme == 'ss': allowed = {'plugin'}
            if set(q) - allowed: raise Excluded('unsupported-option')
            if scheme == 'ss':
                auth = U.unquote(u.netloc.rsplit('@',1)[0])
                if ':' not in auth: auth = decode64(auth)
                method, password = auth.split(':',1)
                if method not in ('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305'):
                    raise Excluded('unsupported-shadowsocks-cipher')
                out = {'type':'shadowsocks', 'method':method, 'password':bounded(password)}
                if 'plugin' in q:
                    parts = q['plugin'].split(';')
                    if len(parts) != 3 or parts[0] != 'obfs-local' or '\\' in q['plugin']:
                        raise Excluded('unsupported-plugin')
                    opts = {}
                    for part in parts[1:]:
                        if part.count('=') != 1: raise Excluded('unsupported-plugin')
                        k,value=part.split('=',1)
                        if k in opts: raise Excluded('duplicate-plugin-option')
                        opts[k]=value
                    if set(opts) != {'obfs','obfs-host'} or opts['obfs'] != 'tls' or not opts['obfs-host']:
                        raise Excluded('unsupported-plugin')
                    bounded(opts['obfs-host'],253)
                    if len(opts['obfs-host'].encode('utf8'))>253 or any(unicodedata.category(c).startswith('C') or unicodedata.category(c) in ('Zl','Zp') for c in opts['obfs-host']):
                        raise Excluded('unsafe-plugin-host')
                    out.update(plugin='obfs-local',plugin_opts='obfs=tls;obfs-host='+opts['obfs-host'])
                q = {}
            elif scheme == 'vless':
                if u.password is not None: raise Excluded('ambiguous-credentials')
                if q.get('encryption','none') != 'none': raise Excluded('unsupported-encryption')
                packet = q.get('packetEncoding','xudp')
                if packet not in ('','xudp','packetaddr'): raise Excluded('unsupported-packet-encoding')
                out = {'type':'vless','uuid':str(uuid.UUID(U.unquote(u.username or ''))),'packet_encoding':packet}
                if q.get('flow'):
                    if q['flow'] != 'xtls-rprx-vision': raise Excluded('unsupported-flow')
                    out['flow']=q['flow']
                headers = set(q) & {'headerType','headertype'}
                if headers and (len(headers) != 1 or q[next(iter(headers))] != 'none' or q.get('type','tcp') not in ('tcp','raw')):
                    raise Excluded('unsupported-tcp-header')
            elif scheme == 'trojan':
                if u.password is not None: raise Excluded('ambiguous-credentials')
                out = {'type':'trojan', 'password':bounded(U.unquote(u.username or ''))}
                q.setdefault('security','tls')
            else:
                if q.get('upmbps','0') != '0': raise Excluded('unsupported-bandwidth-option')
                out = {'type':'hysteria2','password':bounded(U.unquote(u.netloc.rsplit('@',1)[0])),'up_mbps':0}
                q.setdefault('security','tls')
                if q.get('obfs'):
                    if q['obfs'] != 'salamander' or not q.get('obfs-password'): raise Excluded('unsupported-obfuscation')
                    out['obfs']={'type':'salamander','password':bounded(q['obfs-password'])}
        if not isinstance(port,int) or not 1 <= port <= 65535: raise Excluded('invalid-port')
        security=q.get('security','none')
        if out['type'] != 'shadowsocks':
            if security not in ('tls','reality'): raise Excluded('unencrypted-proxy-transport')
            tls={'enabled':True,'server_name':hostname(q.get('sni') or q.get('peer') or server)}
            if q.get('alpn'):
                alpn=q['alpn'].split(',')
                if set(alpn)-{'h2','http/1.1','h3'}: raise Excluded('unsupported-alpn')
                tls['alpn']=alpn
            if q.get('fp'):
                if q['fp'] not in ('chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'):
                    raise Excluded('unsupported-fingerprint')
                tls['utls']={'enabled':True,'fingerprint':q['fp']}
            if security == 'reality':
                if (out['type'] != 'vless' or not re.fullmatch(r'[A-Za-z0-9_-]{43}',q.get('pbk',''))
                    or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}',q.get('sid',''))):
                    raise Excluded('invalid-reality')
                tls['reality']={'enabled':True,'public_key':q['pbk'],'short_id':q.get('sid','')}
                tls.setdefault('utls',{'enabled':True,'fingerprint':'chrome'})
            out['tls']=tls
        transport=q.get('type','tcp')
        if transport == 'raw' and out['type'] == 'vless': transport='tcp'
        if transport not in ('tcp','ws') or (out['type']=='hysteria2' and transport!='tcp'):
            raise Excluded('unsupported-transport')
        if transport == 'ws':
            path=bounded(q.get('path','/'))
            if not path.startswith('/'): raise Excluded('invalid-ws-path')
            out['transport']={'type':'ws','path':path}
            if q.get('host'): out['transport']['headers']={'Host':hostname(q['host'])}
        out.update(server=server,server_port=port,tag='proxy')
        return out
    except Excluded: raise
    except (ValueError,KeyError,TypeError,AttributeError,RecursionError):
        raise Excluded('malformed')

def identity(out):
    return hashlib.sha256(json.dumps(out,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def read_feed(path):
    data=Path(path).read_bytes()
    if len(data)>MAX_FEED: raise Excluded('feed-too-large')
    text=data.decode('utf-8-sig')
    if '://' not in text: text=decode64(''.join(text.split()))
    lines=[x.strip() for x in text.splitlines() if '://' in x]
    if len(lines)>20000: raise Excluded('feed-too-many-lines')
    return data,lines

def prepare(manifest,vantage='dot cloud, not Russian ISP or user network'):
    if len(manifest)>6: raise ValueError('At most six feeds allowed')
    candidates={}; source_records=[]; sets={}
    for src in manifest:
        record={k:src[k] for k in ('id','url','role')}
        rejected=Counter(); protocols=Counter(); supported=0; ids=set()
        try:
            data,lines=read_feed(ROOT/src['file'])
            for line in lines:
                protocols[line.split('://',1)[0].lower()]+=1
                try: out=parse(line)
                except Excluded as exc:
                    rejected[exc.category]+=1
                    continue
                supported+=1; key=identity(out); ids.add(key)
                node=candidates.setdefault(key,{'id':key,'uri':line,'outbound':out,'sources':[]})
                if src['id'] not in node['sources']: node['sources'].append(src['id'])
            record.update(status='read',sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),raw_lines=len(lines),raw_unique_lines=len(set(lines)),
                          supported_lines=supported,unique_supported=len(ids),unsupported_or_unsafe=sum(rejected.values()),exclusions=dict(rejected),raw_protocols=dict(protocols))
        except (OSError,UnicodeError,Excluded) as exc:
            record.update(status='unavailable',reason=exc.category if isinstance(exc,Excluded) else type(exc).__name__)
        sets[src['id']]=ids;source_records.append(record)
    control_ids=set().union(*(sets[s['id']] for s in manifest if s['role']=='control'))
    known_control={k for k in control_ids if candidates[k]['outbound']['server']=='134.195.101.117'
                   and candidates[k]['outbound']['server_port']==2377
                   and candidates[k]['outbound']['type']=='shadowsocks'
                   and candidates[k]['outbound'].get('method')=='chacha20-ietf-poly1305'
                   and candidates[k]['outbound'].get('plugin')=='obfs-local'
                   and candidates[k]['outbound'].get('plugin_opts','').startswith('obfs=tls;')}
    selected=set()
    for src, record in zip(manifest,source_records):
        pool=sets[src['id']]
        novel=pool-control_ids if src['role']=='candidate' else pool
        # For new sources, probe only novel configurations, then protocol-stratify
        # deterministically; a small sample is feasibility evidence, not ranking.
        picks=sorted(known_control & pool)[:PER_FEED] if src['role']=='control' else []
        buckets={}
        for key in sorted(novel-set(picks)): buckets.setdefault(candidates[key]['outbound']['type'],[]).append(key)
        while buckets and len(picks)<PER_FEED:
            for proto in sorted(tuple(buckets)):
                picks.append(buckets[proto].pop(0))
                if not buckets[proto]: del buckets[proto]
                if len(picks)==PER_FEED: break
        selected.update(picks)
        record.update(overlap_with_original_controls=len(pool & control_ids) if src['role']=='candidate' else None,
                      novel_to_original_controls=len(novel) if src['role']=='candidate' else None,
                      selected_ids=picks,selected_count=len(picks),unselected_eligible=max(0,len(novel)-len(picks)))
        endpoints={(candidates[k]['outbound']['server'],candidates[k]['outbound']['server_port']) for k in pool}
        control_endpoints={(candidates[k]['outbound']['server'],candidates[k]['outbound']['server_port']) for k in control_ids}
        record.update(unique_supported_host_ports=len(endpoints),
                      novel_supported_host_ports=len(endpoints-control_endpoints) if src['role']=='candidate' else None,
                      selected_protocols=dict(Counter(candidates[k]['outbound']['type'] for k in picks)))
    if len(selected)>MAX_NODES: raise AssertionError('Node cap')
    summary={'schema':1,'prepared_at':datetime.now(timezone.utc).isoformat(),'vantage':vantage,
             'sampling':'Up to four per source, protocol-stratified then canonical SHA-256; candidates only novel relative to original controls',
             'sources':source_records,'unique_supported_all_sources':len(candidates),'unique_supported_controls':len(control_ids),
             'cross_source_overlap':[{ 'a':a,'b':b,'shared_configurations':len(sets[a]&sets[b])} for a in sorted(sets) for b in sorted(sets) if a<b],
             'selected_unique':len(selected),'budget':{'max_nodes':24,'per_source':4,'workers':4,'rounds':2,'min_round_start_gap_seconds':30,
                 'max_seconds':BUDGET_SECONDS,'max_workflow_seconds':1200,'max_probe_payload_bytes':24*2*3*DOWNLOAD,'max_feed_bytes':6*MAX_FEED},
             'known_control_endpoint':{'status':'present' if known_control else 'absent-from-current-supported-snapshots','matched_configuration_ids':sorted(known_control)},
             'claim':'Bounded feasibility sample; unsupported and unselected entries have no live failure result'}
    (ROOT/'inventory.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    plan=[candidates[key] for key in sorted(selected)]
    private=ROOT/'selected-private.json';private.write_text(json.dumps(plan,ensure_ascii=False,indent=2)+'\n');private.chmod(0o600)
    return summary

def resolve(server):
    try: ips={str(ipaddress.ip_address(server))}
    except ValueError:
        code='import socket,sys,json; print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))'
        try:
            r=subprocess.run([sys.executable,'-c',code,server],capture_output=True,text=True,env=ENV,timeout=5,check=True)
            if len(r.stdout)>65536: raise Excluded('dns-too-large')
            ips=set(json.loads(r.stdout))
        except (subprocess.SubprocessError,ValueError): raise Excluded('dns-failed')
    if not ips or not all(public_ip(x) for x in ips): raise Excluded('nonpublic-endpoint')
    return sorted(ips,key=lambda x:(':' in x,x))[0]

def request(url, port, password, limit, timeout, directory):
    body=directory/'response.tmp'
    args=['curl','--disable','--silent','--show-error','--noproxy','','--proto','=https','--proto-redir','=https',
          '--proxy',f'socks5h://127.0.0.1:{port}','--proxy-user','trial:'+password,'--connect-timeout','4',
          '--max-time',str(timeout),'--max-filesize',str(limit),'--output',str(body),'--write-out','%{json}',url]
    try: proc=subprocess.run(args,capture_output=True,env=ENV,timeout=timeout+2)
    except subprocess.TimeoutExpired: return {'curl_exit':-1,'status':'subprocess-timeout'},''
    try: meta=json.loads(proc.stdout)
    except ValueError: meta={}
    data=body.read_bytes() if body.exists() else b''
    body.unlink(missing_ok=True)
    result={'curl_exit':proc.returncode,'http_status':meta.get('http_code'), 'bytes':meta.get('size_download'),
            'seconds':meta.get('time_total'),'tls_verify_result':meta.get('ssl_verify_result'),
            'status':'complete' if proc.returncode==0 and len(data)<=limit else 'request-failed'}
    return result,data[:limit].decode('utf8',errors='replace')

class Signals(HTMLParser):
    def __init__(self):
        super().__init__();self.skip=0;self.title_on=False;self.title=[];self.visible=[];self.challenge=False
    def handle_starttag(self,tag,attrs):
        d=dict(attrs)
        if tag in ('script','style','template'): self.skip+=1
        if self.skip:return
        if tag=='title':self.title_on=True
        identity=' '.join((d.get('id',''),d.get('class',''))).lower()
        if any(marker in identity for marker in ('cf-chl-','challenge-form','g-recaptcha','h-captcha')):self.challenge=True
        if tag=='form' and any(x in d.get('action','').lower() for x in ('consent.google.com','consent.youtube.com','/sorry/')):self.challenge=True
    def handle_endtag(self,tag):
        if tag in ('script','style','template'): self.skip=max(0,self.skip-1)
        if tag=='title':self.title_on=False
    def handle_data(self,data):
        if self.skip:return
        self.visible.append(data.lower())
        if self.title_on:self.title.append(data.lower())

def page_label(name,result,body):
    if result['status']!='complete':return 'not-confirmed'
    if result['http_status']!=200:return 'http-'+str(result['http_status'])
    s=Signals();s.feed(body)
    title=' '.join(' '.join(s.title).split());visible=' '.join(s.visible);lower=body.lower()
    if (s.challenge or any(x in title for x in ('just a moment','attention required','before you continue','access denied','captcha'))
        or any(x in visible for x in ('verify you are human','checking your browser','our systems have detected unusual traffic','enable javascript and cookies to continue','service is not available in your country'))):
        return 'challenge-or-blocked'
    recognized=(title=='youtube' and 'ytinitialdata' in lower and 'ytcfg.set' in lower) if name=='youtube' else (
        bool(re.fullmatch(r'chatgpt(?:\s*[-|].*)?',title)) and any(x in lower for x in ('__next_data__','__reactroutercontext','id="__next"')))
    return 'page-confirmed' if recognized else 'unrecognized-page'

def probe(node,core,deadline):
    result={'id':node['id'],'sources':node['sources'],'protocol':node['outbound']['type'],'rounds':[]}
    if time.monotonic()+100>=deadline:return {**result,'status':'budget-not-tested'}
    proc=None
    try:
        out=json.loads(json.dumps(node['outbound']));out['server']=resolve(out['server'])
        with socket.socket() as sock: sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            directory=Path(tmp);password=secrets.token_urlsafe(24)
            config={'log':{'disabled':True},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port,
                    'users':[{'username':'trial','password':password}]}],'outbounds':[out],'route':{'final':'proxy'}}
            cfg=directory/'config.json';cfg.write_text(json.dumps(config));cfg.chmod(0o600)
            checked=subprocess.run([str(core),'check','-c',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV,timeout=5)
            if checked.returncode:return {**result,'status':'core-unsupported-not-network-failed'}
            proc=subprocess.Popen([str(core),'run','-c',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV)
            time.sleep(.4)
            if proc.poll() is not None:return {**result,'status':'core-start-failed'}
            started=time.monotonic()
            for i in range(2):
                time.sleep(max(0,started+ROUND_GAP*i-time.monotonic()))
                if time.monotonic()+45>=deadline:return {**result,'status':'budget-incomplete'}
                round_result={'round':i+1,'offset_seconds':round(time.monotonic()-started,3),'https':[]}
                for url in ('https://www.gstatic.com/generate_204','https://cp.cloudflare.com/generate_204'):
                    item,_=request(url,port,password,1024,6,directory);item['url']=url
                    item['passed']=item['status']=='complete' and item['http_status']==204 and item['bytes']==0 and 0<(item.get('seconds') or 0)<=4
                    round_result['https'].append(item)
                if any(x['passed'] for x in round_result['https']):
                    speed,_=request(f'https://speed.cloudflare.com/__down?bytes={DOWNLOAD}',port,password,DOWNLOAD,12,directory)
                    speed['kib_s']=round(speed['bytes']/1024/speed['seconds'],2) if speed.get('bytes') and speed.get('seconds') else None
                    speed['passed']=speed['status']=='complete' and speed['http_status']==200 and speed['bytes']==DOWNLOAD and (speed['kib_s'] or 0)>=256
                    round_result['speed']=speed
                    round_result['services']={}
                    for name,url in (('youtube','https://www.youtube.com/'),('chatgpt','https://chatgpt.com/')):
                        item,body=request(url,port,password,DOWNLOAD,8,directory);item['label']=page_label(name,item,body)
                        round_result['services'][name]=item
                else:round_result['deep_not_attempted']='both-https-controls-failed'
                result['rounds'].append(round_result)
            result['status']='completed'
            result['repeated_https_success']=all(all(x['passed'] for x in r['https']) for r in result['rounds'])
            result['repeated_speed_success']=all(r.get('speed',{}).get('passed',False) for r in result['rounds'])
            result['repeated_service_success']={s:all(r.get('services',{}).get(s,{}).get('label')=='page-confirmed' for r in result['rounds']) for s in ('youtube','chatgpt')}
    except Excluded as exc:result['status']=exc.category
    except (OSError,subprocess.SubprocessError):result['status']='local-process-error'
    finally:
        if proc:
            proc.terminate()
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    return result

def run(core,vantage='dot cloud, not Russian ISP or user network'):
    inventory=json.loads((ROOT/'inventory.json').read_text());inventory['vantage']=vantage
    start=datetime.now(timezone.utc).isoformat();deadline=time.monotonic()+BUDGET_SECONDS
    (ROOT/'results.json').write_text(json.dumps({'status':'starting','started_at':start,'inventory':inventory,'results':[]},ensure_ascii=False,indent=2)+'\n')
    if not core.is_file():raise ValueError('Official verified sing-box binary is missing')
    verification=json.loads((ROOT/'core-verification.json').read_text())
    if verification.get('archive_sha256')!='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6' or hashlib.sha256(core.read_bytes()).hexdigest()!=verification.get('binary_sha256'):
        raise ValueError('Core does not match pinned official verification record')
    plan=json.loads((ROOT/'selected-private.json').read_text())
    if not plan or len(plan)>24:
        (ROOT/'results.json').write_text(json.dumps({'status':'not-started-invalid-or-empty-plan','started_at':start,'inventory':inventory,'results':[]},ensure_ascii=False,indent=2)+'\n')
        raise ValueError('No nodes, or node cap exceeded')
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures=[pool.submit(probe,node,core,deadline) for node in plan]
        for f in concurrent.futures.as_completed(futures):
            result=f.result();results.append(result)
            print(json.dumps({'id':result['id'][:12],'status':result['status'],'rounds':len(result['rounds'])}),flush=True)
            report={'status':'completed' if len(results)==len(plan) else 'running','started_at':start,'updated_at':datetime.now(timezone.utc).isoformat(),'inventory':inventory,'results':sorted(results,key=lambda x:x['id'])}
            (ROOT/'results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','run']);parser.add_argument('--manifest',default='feeds.json');parser.add_argument('--core',default='bin/sing-box');parser.add_argument('--vantage',default='dot cloud, not Russian ISP or user network')
    args=parser.parse_args()
    if args.action=='prepare':print(json.dumps(prepare(json.loads((ROOT/args.manifest).read_text())),ensure_ascii=False,indent=2))
    else:run((ROOT/args.core).resolve(),args.vantage)
