#!/usr/bin/env python3
"""Bounded public-feed checker. Python standard library, sing-box and curl only."""
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import socket
import secrets
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse as U
from datetime import datetime, timezone

SOURCES = [
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt',
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt',
 'https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt',
]
MAX_CANDIDATES = 150
WORKERS = 4
BUDGET = 1020
MAX_DEEP = 32
STABILITY_SECONDS = 45
DOWNLOAD_BYTES = 2 * 1024 * 1024
MIN_BYTES_PER_SECOND = 256 * 1024
FEEDS = {"both": "subscription.txt", "chatgpt": "subscription-gpt.txt", "youtube": "subscription-youtube.txt"}
MAX_FEED = 4 * 1024 * 1024
CIPHERS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'}

class Rejected(ValueError):
    pass

def b64(s):
    if len(s) > MAX_FEED * 2:
        raise Rejected('oversize')
    try:
        return base64.b64decode(s + '=' * (-len(s) % 4), altchars=b'-_', validate=True).decode('utf-8')
    except (ValueError, UnicodeError) as e:
        raise Rejected('base64') from e

def clean(s, limit=1024):
    if not isinstance(s, str) or len(s) > limit or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise Rejected('unsafe string')
    return s

def host(s):
    clean(s, 253)
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', s) or '..' in s or s.lower().endswith(('.localhost', '.local', '.internal')) or s.lower() == 'localhost':
            raise Rejected('host')
        return s.lower()

def public_ip(s):
    ip = ipaddress.ip_address(s)
    # IPv6 transition mechanisms can embed otherwise blocked IPv4 destinations.
    if ip.version == 6 and any(ip in ipaddress.ip_network(n) for n in ('64:ff9b::/96','64:ff9b:1::/48')): return False
    return ip.is_global and not ip.is_multicast and not getattr(ip, 'ipv4_mapped', None) and not getattr(ip, 'sixtofour', None) and not getattr(ip, 'teredo', None)

def resolve_public(server):
    try:
        ips = {str(ipaddress.ip_address(server))}
    except ValueError:
        # A blocked OS resolver must not strand a worker beyond the run deadline.
        code = 'import socket,json,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))'
        try:
            proc = subprocess.run([sys.executable, '-c', code, server], capture_output=True,
                                  text=True, timeout=5, check=True,
                                  env={'PATH':os.environ['PATH'],'HOME':'/nonexistent'})
            if len(proc.stdout)>65536: raise Rejected('oversize DNS result')
            ips=set(json.loads(proc.stdout))
        except (subprocess.SubprocessError, ValueError, TypeError) as exc:
            raise Rejected('DNS failed') from exc
    if not ips or any(not public_ip(ip) for ip in ips):
        raise Rejected('nonpublic endpoint')
    return sorted(ips, key=lambda x: (':' in x, x))[0]

def parse_uri(uri):
    clean(uri, 8192)
    u = U.urlsplit(uri)
    scheme = u.scheme.lower()
    if scheme == 'vmess':
        try: v = json.loads(b64(u.netloc + u.path))
        except (ValueError, RecursionError) as exc: raise Rejected('vmess JSON') from exc
        if not isinstance(v, dict): raise Rejected('vmess object')
        for key,value in v.items():
            if key in ('v','port','aid'):
                if type(value) not in (str,int): raise Rejected('vmess numeric field')
            elif not isinstance(value,str): raise Rejected('vmess string field')
            if isinstance(value,str): clean(value,4096)
        allowed = {'v','ps','add','port','id','aid','scy','net','type','host','path','tls','sni','alpn','fp'}
        if set(v) - allowed or str(v.get('aid', '0')) != '0' or v.get('net','tcp') not in ('tcp','ws') or v.get('type','none') not in ('','none'):
            raise Rejected('unsupported vmess')
        server, port = host(v['add']), int(v['port'])
        out = {'type':'vmess','uuid':str(v['id']),'security':v.get('scy','auto'),'alter_id':0}
        q = {'security':v.get('tls','none'), 'sni':v.get('sni') or v.get('host') or server, 'type':v.get('net','tcp'), 'path':v.get('path','/'), 'host':v.get('host','')}
        if v.get('fp'): q['fp'] = v['fp']
        if v.get('alpn'): q['alpn'] = v['alpn']
    else:
        if scheme not in ('ss','trojan','vless','hy2','hysteria2'):
            raise Rejected('unsupported scheme')
        # Legacy SS base64 encodes the whole authority.
        if scheme == 'ss' and '@' not in u.netloc:
            u = U.urlsplit('ss://' + b64(u.netloc) + ('?' + u.query if u.query else ''))
        server, port = host(u.hostname or ''), u.port
        if scheme in ('trojan','vless') and u.password is not None: raise Rejected('ambiguous credentials')
        pairs = U.parse_qsl(u.query, keep_blank_values=True, strict_parsing=False)
        if len(pairs) != len(dict(pairs)):
            raise Rejected('duplicate option')
        q = dict(pairs)
        allowed = {'security','sni','peer','type','host','path','fp','alpn','pbk','sid','flow','encryption','obfs','obfs-password'}
        if set(q) - allowed:
            raise Rejected('unsupported option')
        if scheme == 'ss':
            auth = U.unquote(u.netloc.rsplit('@',1)[0])
            if ':' not in auth: auth = b64(auth)
            method, password = auth.split(':', 1)
            if method not in CIPHERS or q:
                raise Rejected('unsupported ss')
            out = {'type':'shadowsocks', 'method':method, 'password':clean(password)}
        elif scheme == 'trojan':
            out = {'type':'trojan','password':clean(U.unquote(u.username or ''))}
            q.setdefault('security', 'tls')
        elif scheme in ('hy2','hysteria2'):
            out = {'type':'hysteria2','password':clean(U.unquote(u.netloc.rsplit('@',1)[0]))}
            q.setdefault('security','tls')
            if q.get('obfs'):
                if q['obfs'] != 'salamander' or not q.get('obfs-password'): raise Rejected('obfs')
                out['obfs'] = {'type':'salamander','password':clean(q['obfs-password'])}
        else:
            out = {'type':'vless','uuid':U.unquote(u.username or '')}
            if q.get('encryption','none') != 'none': raise Rejected('encryption')
            if q.get('flow'):
                if q['flow'] != 'xtls-rprx-vision': raise Rejected('flow')
                out['flow'] = q['flow']
    if not isinstance(port,int) or not 1 <= port <= 65535: raise Rejected('port')
    if out['type'] in ('vless','vmess'):
        import uuid
        out['uuid'] = str(uuid.UUID(out['uuid']))
    security = q.get('security','none')
    if security not in ('none','','tls','reality'): raise Rejected('security')
    if out['type'] in ('vless','vmess') and security not in ('tls','reality'): raise Rejected('TLS required')
    if out['type'] in ('trojan','hysteria2') and security != 'tls': raise Rejected('TLS required')
    if security in ('tls','reality'):
        tls = {'enabled':True,'server_name':host(q.get('sni') or q.get('peer') or server)}
        if q.get('alpn'):
            alpn = q['alpn'].split(',')
            if any(x not in ('h2','http/1.1','h3') for x in alpn): raise Rejected('alpn')
            tls['alpn'] = alpn
        if q.get('fp'):
            if q['fp'] not in ('chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'): raise Rejected('fingerprint')
            tls['utls'] = {'enabled':True,'fingerprint':q['fp']}
        if security == 'reality':
            if out['type'] != 'vless' or not re.fullmatch(r'[A-Za-z0-9_-]{43}',q.get('pbk','')) or not re.fullmatch(r'[0-9a-fA-F]{0,16}',q.get('sid','')) or len(q.get('sid','')) % 2:
                raise Rejected('reality')
            tls['reality'] = {'enabled':True,'public_key':q['pbk'],'short_id':q.get('sid','')}
            tls.setdefault('utls', {'enabled':True,'fingerprint':'chrome'})
        out['tls'] = tls
    transport = q.get('type','tcp')
    if transport not in ('tcp','ws'): raise Rejected('transport')
    if out['type'] == 'hysteria2' and transport != 'tcp': raise Rejected('transport')
    if transport == 'ws':
        path = clean(q.get('path','/'))
        if not path.startswith('/'): raise Rejected('path')
        out['transport'] = {'type':'ws','path':path}
        if q.get('host'): out['transport']['headers'] = {'Host':host(q['host'])}
    out.update(server=server, server_port=port, tag='proxy')
    return out

def feed_lines(text):
    if len(text.encode()) > MAX_FEED: raise Rejected('feed too large')
    if '://' not in text:
        text = b64(''.join(text.split()))
    return [s.strip() for s in text.splitlines() if '://' in s][:20000]

def configuration(out, port, password="test-only"):
    return {'log':{'disabled':True},'inbounds':[{'type':'socks','tag':'in','listen':'127.0.0.1','listen_port':port,'users':[{'username':'checker','password':password}]}], 'outbounds':[out], 'route':{'final':'proxy'}}

def curl(url, proxy=None, timeout=5, limit=262144, password=None, body=False):
    """Verified HTTPS only; never follow redirects or inherit credentials/proxies."""
    with tempfile.TemporaryDirectory() as td:
        target = str(Path(td) / 'body') if body else '/dev/null'
        args = ['curl','--disable','--silent','--show-error','--noproxy','',
                '--proto','=https','--proto-redir','=https','--connect-timeout','3',
                '--max-time',str(timeout),'--max-filesize',str(limit),
                '--output',target,'--write-out','%{http_code} %{size_download} %{time_total}']
        if proxy: args += ['--proxy', f'socks5h://127.0.0.1:{proxy}']
        else: args += ['--proxy','']
        if password: args += ['--proxy-user','checker:'+password]
        args += [url]
        p = subprocess.run(args, capture_output=True, timeout=timeout+2,
                           env={'PATH':os.environ['PATH'],'HOME':'/nonexistent'})
        if p.returncode: raise Rejected('request failed')
        status,size,elapsed = p.stdout.decode().split()
        values = int(status),int(size),float(elapsed)
        if body:
            data = Path(target).read_bytes()
            if len(data) > limit: raise Rejected('oversize response')
            return (*values, data.decode('utf-8', errors='replace'))
        return values


class DeepBudget:
    """Do not spend sustained-check bandwidth on more than MAX_DEEP candidates."""
    def __init__(self, maximum=MAX_DEEP):
        self.maximum = maximum
        self.used = 0
        self.lock = threading.Lock()

    def claim(self):
        with self.lock:
            if self.used >= self.maximum: return False
            self.used += 1
            return True


def service_label(name, status, body):
    # Strict positive identification; false negatives are preferable to fake passes.
    if status != 200: return 'http-' + str(status)
    page = body.lower()
    blocked = ('just a moment', 'attention required', 'before you continue',
               'verify you are human', 'cf-chl-', 'unusual traffic',
               'captcha', 'access denied', 'unsupported_country',
               'service is not available in your country')
    if any(marker in page for marker in blocked): return 'challenge-or-blocked'
    if re.search(r'<form[^>]+action=["\'][^"\']*consent\.', page):
        return 'consent-required'
    if name == 'youtube':
        valid = '<title>youtube</title>' in page and 'ytinitialdata' in page and 'ytcfg.set' in page
    elif name == 'chatgpt':
        valid = bool(re.search(r'<title[^>]*>\s*chatgpt(?:\s*[-|]|</title>)', page)) and any(
            marker in page for marker in ('__next_data__', '__reactroutercontext', 'id="__next"'))
    else:
        raise ValueError('unknown service')
    return 'page-confirmed' if valid else 'unrecognized-page'


def probe(uri, core, deadline, deep_budget=None):
    result = {'id':hashlib.sha256(uri.encode()).hexdigest()[:16], 'qualified':False,
              'baseline_qualified':False, 'service_qualified':{'youtube':False,'chatgpt':False}}
    if time.monotonic() >= deadline: result['reason']='budget'; return result, None
    proc = None; phase='endpoint-rejected'
    try:
        out = parse_uri(uri)
        out['server'] = resolve_public(out['server'])
        if time.monotonic() + 10 >= deadline: raise Rejected('budget')
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); port = s.getsockname()[1]
        with tempfile.TemporaryDirectory() as td:
            password = secrets.token_urlsafe(24)
            config = Path(td)/'config.json'; config.write_text(json.dumps(configuration(out,port,password)))
            config.chmod(0o600)
            phase='core-start-failed'
            proc = subprocess.Popen([core,'run','-c',str(config)], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env={'PATH':os.environ['PATH'],'HOME':td})
            time.sleep(.35)
            if proc.poll() is not None: raise Rejected('core failed')
            result['core_started']=True; phase='quick-https-failed'
            timings=[]
            def request(url, **kwargs):
                timeout = kwargs.get('timeout', 5)
                if time.monotonic() + timeout + 2 >= deadline: raise Rejected('deadline')
                if proc.poll() is not None: raise Rejected('core stopped')
                return curl(url, port, password=password, **kwargs)
            def https_check(url):
                status,size,elapsed = request(url, limit=1024)
                if status != 204 or size != 0 or not 0 < elapsed <= 4: raise Rejected('stability')
                timings.append(elapsed)
            for url in ('https://www.gstatic.com/generate_204','https://cp.cloudflare.com/generate_204'):
                https_check(url)
            phase='deep-budget'
            if time.monotonic() + 100 >= deadline: raise Rejected('budget')
            if deep_budget is not None and not deep_budget.claim(): raise Rejected('deep cap')
            result['deep_tested']=True
            stable_start=time.monotonic()
            speeds=[]
            def download():
                status,size,elapsed = request('https://speed.cloudflare.com/__down?bytes='+str(DOWNLOAD_BYTES),
                                             timeout=12, limit=DOWNLOAD_BYTES)
                if status != 200 or size != DOWNLOAD_BYTES or elapsed <= 0 or size/elapsed < MIN_BYTES_PER_SECOND:
                    raise Rejected('throughput')
                speeds.append(size/elapsed/1024)
            phase='throughput-failed'
            download()
            phase='stability-failed'
            for offset,url in ((15,'https://www.gstatic.com/generate_204'),
                               (30,'https://cp.cloudflare.com/generate_204'),
                               (STABILITY_SECONDS,'https://www.gstatic.com/generate_204')):
                target=stable_start+offset
                if target + 7 >= deadline: raise Rejected('deadline')
                time.sleep(max(0,target-time.monotonic()))
                https_check(url)
            phase='throughput-failed'
            download()
            result.update(baseline_qualified=True, median_ms=round(statistics.median(timings)*1000),
                          min_kib_s=round(min(speeds),1), download_kib_s=[round(x,1) for x in speeds],
                          stability_seconds=round(time.monotonic()-stable_start,1))
            phase='service-failed'
            labels={}
            for name,url in (('youtube','https://www.youtube.com/'),('chatgpt','https://chatgpt.com/')):
                try:
                    code,_,_,body = request(url,timeout=8,limit=2*1024*1024,body=True)
                    labels[name] = service_label(name,code,body)
                except (Rejected,subprocess.TimeoutExpired): labels[name]='not-confirmed'
            if proc.poll() is not None: raise Rejected('core stopped')
            services={name:label=='page-confirmed' for name,label in labels.items()}
            result.update(qualified=all(services.values()), service_qualified=services, reachability=labels)
            if not any(services.values()):
                result['reason']='services-not-confirmed'
                return result,None
            label = f"checked {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')} {result['id']} {result['median_ms']}ms {result['min_kib_s']}KiBps YT:{labels['youtube']} GPT:{labels['chatgpt']}"
            exported=uri.split('#',1)[0]+'#'+U.quote(label)
            result['subscription_sha256']=hashlib.sha256(exported.encode()).hexdigest()
            return result,exported
    except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):
        result['qualified']=False
        result['service_qualified']={'youtube':False,'chatgpt':False}
        result['reason']=phase
        return result,None
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()

def download_feed(url):
    p = subprocess.run(['curl','--disable','--silent','--fail','--proto','=https','--proxy','','--connect-timeout','5','--max-time','20','--max-filesize',str(MAX_FEED),url],capture_output=True,timeout=22, env={'PATH':os.environ['PATH'],'HOME':'/nonexistent'})
    if p.returncode or len(p.stdout)>MAX_FEED: raise Rejected('feed download')
    return p.stdout.decode('utf-8-sig')

def main():
    start = datetime.now(timezone.utc).isoformat(); deadline=time.monotonic()+BUDGET
    output=Path('public'); output.mkdir(exist_ok=True)
    # Clear in this run before fetching; never carry forward last run's nodes.
    for filename in FEEDS.values(): (output/filename).write_text('')
    candidates=[]; sources=[]; normalized={}; provenance={}; rejected=0
    for url in SOURCES:
        try:
            lines=feed_lines(download_feed(url))
            for line in lines:
                try:
                    key=json.dumps(parse_uri(line),sort_keys=True,separators=(',',':'))
                    normalized.setdefault(key,line)
                    provenance.setdefault(key,[])
                    if url not in provenance[key]: provenance[key].append(url)
                except (ValueError,KeyError,TypeError): rejected+=1
            sources.append({'url':url,'downloaded':True,'lines':len(lines)})
        except (ValueError,OSError,subprocess.TimeoutExpired): sources.append({'url':url,'downloaded':False})
    if not any(source['downloaded'] for source in sources): raise RuntimeError('all sources unavailable; do not publish')
    candidates=list(normalized.values())
    if not candidates: raise RuntimeError('no supported candidates; possible source format change; do not publish')
    random.SystemRandom().shuffle(candidates)
    total=len(candidates); candidates=candidates[:MAX_CANDIDATES]
    source_by_id={hashlib.sha256(uri.encode()).hexdigest()[:16]:provenance[json.dumps(parse_uri(uri),sort_keys=True,separators=(',',':'))] for uri in candidates}
    results=[]; accepted={key:[] for key in FEEDS}; deep_budget=DeepBudget()
    core=os.path.abspath(os.environ.get('SING_BOX','./bin/sing-box'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for result,line in pool.map(lambda u:probe(u,core,deadline,deep_budget),candidates):
            result['sources']=source_by_id[result['id']]
            results.append(result)
            if line:
                if result['qualified']: accepted['both'].append(line)
                for service in ('chatgpt','youtube'):
                    if result['service_qualified'][service]: accepted[service].append(line)
    if any(r.get('reason')=='core-start-failed' for r in results) and not any(r.get('core_started') for r in results):
        raise RuntimeError('core startup failed; do not publish')
    report={'schema_version':2,'started_at':start,'completed_at':datetime.now(timezone.utc).isoformat(),
            'vantage':'GitHub-hosted runner, not the user network','sources':sources,
            'unsupported_or_rejected_lines':rejected,'unique_candidates':total,'sampled':len(candidates),
            'deep_tested':deep_budget.used,'qualified':len(accepted['both']),
            'feed_counts':{key:len(lines) for key,lines in accepted.items()},'results':results,
            'method':'2 quick HTTPS 204 checks; repeated verified HTTPS through same core at 15/30/45 seconds; two exact 2MiB downloads each >=256KiB/s; HTTP 200 and recognized YouTube/ChatGPT page content, no redirects/challenges; no playback/login/chat test',
            'limits':{'candidate_cap':MAX_CANDIDATES,'deep_cap':MAX_DEEP,'workers':WORKERS,
                      'budget_seconds':BUDGET,'stability_window_seconds':STABILITY_SECONDS,
                      'download_bytes_per_sample':DOWNLOAD_BYTES,'download_samples':2,
                      'min_kib_s':MIN_BYTES_PER_SECOND//1024},'max_age_hours':12}
    for key,filename in FEEDS.items():
        (output/filename).write_text('\n'.join(accepted[key])+ ('\n' if accepted[key] else ''))
    (output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'sampled':len(candidates),'deep_tested':deep_budget.used,'feed_counts':report['feed_counts']}))

if __name__ == '__main__': main()
