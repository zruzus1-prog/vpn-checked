#!/usr/bin/env python3
"""Bounded public-feed checker. Python standard library, sing-box and curl only."""
import base64
import concurrent.futures
import hashlib
from html.parser import HTMLParser
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
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
import unicodedata
from datetime import datetime, timezone

SOURCES = [
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt',
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt',
 'https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt',
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt',
 'https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure/vless.txt',
 'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt',
 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt',
]
MAX_CANDIDATES = 2048
WORKERS = 4
BUDGET = 90 * 60
MAX_DEEP = MAX_CANDIDATES
STABILITY_SECONDS = 45
DOWNLOAD_BYTES = 2 * 1024 * 1024
MIN_BYTES_PER_SECOND = 256 * 1024
FEEDS = {"both": "subscription.txt", "chatgpt": "subscription-gpt.txt", "youtube": "subscription-youtube.txt"}
MAX_FEED = 4 * 1024 * 1024
MAX_FEED_LINES = 20000
from uri_parser import (Rejected, b64, clean, host, ss_plugin, parse_uri,
                        CIPHERS, PARSER_REASONS)
PROTOCOLS = {'vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks'}
REJECTION_CATEGORIES = {x.lower().replace(' ', '-') for x in PARSER_REASONS} | {
    'insecure-tls-requested', 'malformed',
}
RESULT_FAILURE_REASONS = {'budget', 'endpoint-rejected', 'core-start-failed',
    'core-stopped', 'quick-https-failed', 'deep-budget', 'throughput-failed', 'stability-failed',
    'service-failed', 'services-not-confirmed'}
CANONICALIZATION_VERSION = 'sing-box-1.14.2-v2'
MAX_RESULT_AGE_SECONDS = 7200
MAX_ENDPOINT_ADDRESSES = 3
QUICK_TIMEOUT = 10
MAX_ATTEMPTS = 2
RETRY_DELAY = .75
QUICK_ENDPOINTS = ('https://www.gstatic.com/generate_204',
                   'https://cp.cloudflare.com/generate_204')
SPEED_ENDPOINT = 'https://speed.cloudflare.com/__down?bytes='+str(DOWNLOAD_BYTES)
CURL_ERROR_CATEGORIES = {5:'proxy-dns',6:'dns',7:'connect',18:'partial-transfer',
    28:'timeout',35:'tls-handshake',51:'tls-certificate',52:'empty-reply',
    55:'send',56:'receive',58:'tls-local-certificate',60:'tls-certificate',
    63:'response-too-large',77:'tls-ca',83:'tls-issuer',90:'tls-pin',
    91:'tls-status',92:'http2-stream',97:'proxy-handshake'}
TRANSIENT_CURL_CODES = {5,6,7,18,28,35,52,55,56,92,97}
TRANSIENT_HTTP_STATUSES = {408,425,429,500,502,503,504}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def canonical_key(out):
    """Supported authenticated-stream settings, independent of name or test IP."""
    return json.dumps(out,sort_keys=True,separators=(',',':'))


def node_id(uri):
    return hashlib.sha256((CANONICALIZATION_VERSION+'\n'+canonical_key(parse_uri(uri))).encode()).hexdigest()[:16]


def probe_origin():
    # GitHub's location and the proxy's exit address are not a Russian ISP test.
    return {'origin_id':'github-actions' if os.environ.get('GITHUB_ACTIONS')=='true' else 'local-unverified',
            'provider':'github-actions' if os.environ.get('GITHUB_ACTIONS')=='true' else 'local',
            'network_kind':'datacenter' if os.environ.get('GITHUB_ACTIONS')=='true' else 'unknown',
            'country':'unknown','path_status':'unknown','russia_verified':False}


def core_metadata(core):
    lock=json.loads(Path(__file__).with_name('core-lock.json').read_text())
    proof_path=Path(core).with_name('core-verification.json')
    proof=json.loads(proof_path.read_text())
    binary_sha=hashlib.sha256(Path(core).read_bytes()).hexdigest()
    if proof.get('archive_sha256')!=lock['sha256'] or proof.get('binary_sha256')!=binary_sha or proof.get('version')!=lock['version']:
        raise ValueError('core verification mismatch')
    return {'name':'sing-box','version':lock['version'],'archive_sha256':lock['sha256'],
            'binary_sha256':binary_sha,'os':'linux','arch':'amd64'}

class BudgetExceeded(Rejected):
    """A run deadline is incomplete coverage, never evidence of a bad node."""
    pass

class CoreStopped(Rejected):
    """An unexpected core exit is infrastructure failure, never node quality."""
    pass

def public_ip(s):
    ip = ipaddress.ip_address(s)
    # IPv6 transition mechanisms can embed otherwise blocked IPv4 destinations.
    if ip.version == 6 and any(ip in ipaddress.ip_network(n) for n in ('64:ff9b::/96','64:ff9b:1::/48')): return False
    return ip.is_global and not ip.is_multicast and not getattr(ip, 'ipv4_mapped', None) and not getattr(ip, 'sixtofour', None) and not getattr(ip, 'teredo', None)

def resolve_public(server, all_addresses=False):
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
    ordered=sorted(ips, key=lambda x: (':' in x, x))
    return ordered if all_addresses else ordered[0]

def feed_lines(text):
    if len(text.encode()) > MAX_FEED: raise Rejected('feed too large')
    if '://' not in text:
        text = b64(''.join(text.split()))
    lines = [s.strip() for s in text.splitlines() if '://' in s]
    if len(lines) > MAX_FEED_LINES: raise Rejected('too many feed lines')
    return lines

def configuration(out, port, password="test-only"):
    return {'log':{'disabled':True},'inbounds':[{'type':'socks','tag':'in','listen':'127.0.0.1','listen_port':port,'users':[{'username':'checker','password':password}]}], 'outbounds':[out], 'route':{'final':'proxy'}}

class RequestFailed(Rejected):
    def __init__(self, category, transient=False):
        super().__init__(category)
        self.category=category
        self.transient=transient


def curl(url, proxy=None, timeout=QUICK_TIMEOUT, limit=262144, password=None, body=False, diagnostic=None):
    """Verified HTTPS only, bounded bytes/time, no redirects or inherited proxies.

    Capture numeric curl timings and a fixed error category, never stderr,
    credentials, response headers, page bodies, or temporary SOCKS passwords.
    """
    diagnostic={} if diagnostic is None else diagnostic
    with tempfile.TemporaryDirectory() as td:
        target = str(Path(td) / 'body') if body else '/dev/null'
        args = ['curl','--disable','--silent','--show-error','--noproxy','',
                '--proto','=https','--proto-redir','=https','--connect-timeout','6',
                '--max-time',str(timeout),'--max-filesize',str(limit),
                '--output',target,'--write-out','%{http_code} %{size_download} %{time_total} %{time_connect} %{time_appconnect} %{time_starttransfer}']
        if proxy: args += ['--proxy', f'socks5h://127.0.0.1:{proxy}']
        else: args += ['--proxy','']
        if password: args += ['--proxy-user','checker:'+password]
        args += [url]
        try:
            p = subprocess.run(args, capture_output=True, timeout=timeout+2,
                               env={'PATH':os.environ['PATH'],'HOME':'/nonexistent'})
        except subprocess.TimeoutExpired as exc:
            diagnostic.update(error='process-timeout',curl_exit=None)
            raise RequestFailed('process-timeout',True) from exc
        diagnostic['curl_exit']=p.returncode
        try:
            fields=p.stdout.decode('ascii').split()
            status,size,elapsed=int(fields[0]),int(fields[1]),float(fields[2])
            import math
            if not (0<=status<=599 and 0<=size<=limit and math.isfinite(elapsed) and elapsed>=0):
                raise ValueError('bad metrics')
            diagnostic.update(http_status=status,bytes=size,elapsed_seconds=elapsed)
            for name,item in zip(('connect_seconds','tls_seconds','first_byte_seconds'),fields[3:6]):
                value=float(item)
                if not math.isfinite(value) or value<0: raise ValueError('bad metrics')
                diagnostic[name]=value
        except (ValueError,UnicodeError,IndexError):
            if not p.returncode:
                diagnostic['error']='invalid-curl-metrics'
                raise RequestFailed('invalid-curl-metrics')
        if p.returncode:
            category=CURL_ERROR_CATEGORIES.get(p.returncode,'curl-error')
            diagnostic['error']=category
            raise RequestFailed(category,p.returncode in TRANSIENT_CURL_CODES)
        diagnostic['error']=None
        values=status,size,elapsed
        if body:
            data = Path(target).read_bytes()
            if len(data) > limit: raise RequestFailed('response-too-large')
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


class PageSignals(HTMLParser):
    """Inspect HTML text/structure without executing scripts or solving challenges."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ignored=[]
        self.title_depth=0
        self.heading_depth=0
        self.text=[]
        self.title=[]
        self.headings=[]
        self.structure=set()

    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag in ('script','style','template'):
            self.ignored.append(tag)
            return
        if self.ignored: return
        if tag=='title': self.title_depth+=1
        if tag in ('h1','h2'): self.heading_depth+=1
        identity=' '.join((attrs.get('id') or '',attrs.get('class') or '')).lower()
        if re.search(r'(?:^|\s)(?:cf-chl-|challenge-form|g-recaptcha|h-captcha)',identity):
            self.structure.add('challenge-element')
        if tag=='form':
            action=U.urlsplit(attrs.get('action') or '')
            destination=(action.hostname or '').lower()
            if destination in ('consent.google.com','consent.youtube.com'):
                self.structure.add('consent-form')
            if action.path.startswith('/sorry/'):
                self.structure.add('traffic-verification-form')
        if tag=='iframe':
            src=(attrs.get('src') or '').lower()
            if '/recaptcha/' in src or 'hcaptcha.com/' in src or 'challenges.cloudflare.com/' in src:
                self.structure.add('challenge-frame')

    def handle_endtag(self,tag):
        if self.ignored:
            if tag==self.ignored[-1]: self.ignored.pop()
            return
        if tag=='title': self.title_depth=max(0,self.title_depth-1)
        if tag in ('h1','h2'): self.heading_depth=max(0,self.heading_depth-1)

    def handle_data(self,data):
        if self.ignored: return
        text=' '.join(data.lower().split())
        if text:
            self.text.append(text)
            if self.title_depth: self.title.append(text)
            if self.heading_depth: self.headings.append(text)


def service_assessment(name,status,body):
    """Status and bounded named evidence only; never retain HTML/cookies/tokens."""
    signals=PageSignals()
    try: signals.feed(body)
    except (ValueError,RecursionError):
        return {'label':'unrecognized-page','http_status':status,'blocking_signals':['malformed-html'],
                'recognized_page':False,'interpretation':'automated-http-test-only'}
    page=body.lower()
    title=' '.join(signals.title)
    if name=='youtube':
        recognized=title=='youtube' and 'ytinitialdata' in page and 'ytcfg.set' in page
    elif name=='chatgpt':
        recognized=bool(re.fullmatch(r'chatgpt(?:\s*[-|].*)?',title)) and any(
            marker in page for marker in ('__next_data__','__reactroutercontext','id="__next"'))
    else: raise ValueError('unknown service')
    found=set(signals.structure)
    prominent=' '.join(signals.title+signals.headings)
    visible=' '.join(signals.text)
    # Generic words in JS/configuration (e.g. CAPTCHA feature names) are NOT a block.
    prominent_markers=('just a moment','attention required','before you continue',
                       'access denied','captcha','unsupported_country')
    for marker in prominent_markers:
        if marker in prominent: found.add('title-or-heading:'+marker.replace(' ','-'))
    visible_markers=('verify you are human','checking your browser',
                     'our systems have detected unusual traffic',
                     'enable javascript and cookies to continue',
                     'service is not available in your country')
    for marker in visible_markers:
        if marker in visible: found.add('page-text:'+marker.replace(' ','-'))
    if status!=200: label='http-'+str(status)
    elif found: label='challenge-or-blocked'
    elif recognized: label='page-confirmed'
    else: label='unrecognized-page'
    return {'label':label,'http_status':status,'blocking_signals':sorted(found),
            'recognized_page':recognized,'interpretation':'automated-http-test-only'}


def service_label(name,status,body):
    return service_assessment(name,status,body)['label']


def safe_source_label(value, limit=36):
    """Keep a compact plain-text source name; remove controls, bidi and markup."""
    if not isinstance(value,str): return ''
    value=unicodedata.normalize('NFC',value)
    allowed_punctuation=set(' .,-_|()[]…')
    value=''.join(char if (unicodedata.category(char)[0] in 'LMN' or
                         unicodedata.category(char)=='So' or char in allowed_punctuation)
                  else ' ' for char in value)
    value=' '.join(value.split())
    if len(value)>limit:
        value=value[:limit-1].rstrip()
        # Do not leave half a country-flag pair at a truncation boundary.
        regional=0
        for char in reversed(value):
            if '\U0001f1e6'<=char<='\U0001f1ff': regional+=1
            else: break
        if regional%2: value=value[:-1]
        value=value.rstrip()+'…'
    return value


def source_name(uri):
    u=U.urlsplit(uri)
    name=U.unquote(u.fragment)
    protocol={'ss':'SS','vless':'VLESS','vmess':'VMess','trojan':'Trojan','hy2':'HY2','hysteria2':'HY2'}.get(u.scheme.lower())
    suffix=f" · {protocol} · {node_id(uri)[:6]}"
    if name.endswith(suffix): name=name[:-len(suffix)]
    if not name and u.scheme.lower()=='vmess':
        try: name=json.loads(b64(u.netloc+u.path)).get('ps','')
        except (ValueError,AttributeError,RecursionError): name=''
    return safe_source_label(name)


def export_with_label(uri,result):
    """Only the URI fragment changes; transport/authentication bytes stay intact."""
    name=source_name(uri) or 'Страна не указана'
    protocol={'ss':'SS','vless':'VLESS','vmess':'VMess','trojan':'Trojan',
              'hy2':'HY2','hysteria2':'HY2'}[U.urlsplit(uri).scheme.lower()]
    label=f"{name} · {protocol} · {result['id'][:6]}"
    return uri.split('#',1)[0]+'#'+U.quote(label,safe='')


def pin_outbound(original, address):
    """Pin only the dial target, retaining original TLS and HTTP authority.

    Pinned sing-box WS defaults to serverAddr.String() for request Host, whereas
    HTTPUpgrade defaults to TLS server_name. Preserve that deliberate difference.
    https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2raywebsocket/client.go
    https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2rayhttpupgrade/client.go
    """
    if not public_ip(address): raise Rejected('nonpublic endpoint')
    import copy
    out=copy.deepcopy(original)
    transport=out.get('transport',{})
    if transport.get('type')=='ws' and not transport.get('headers',{}).get('Host'):
        server=original['server']
        authority=('['+server+']' if ':' in server else server)+':'+str(original['server_port'])
        transport.setdefault('headers',{})['Host']=authority
    out['server']=address
    return out


def probe(uri, core, deadline, deep_budget=None):
    result = {'id':node_id(uri),'identity_version':CANONICALIZATION_VERSION,
              'original_uri_sha256':hashlib.sha256(uri.encode()).hexdigest(),
              'checked_at':utc_now(),'qualified':False,'baseline_qualified':False,
              'service_qualified':{'youtube':False,'chatgpt':False},'attempts':[]}
    proc=None; phase='endpoint-rejected'
    try:
        if time.monotonic() >= deadline: raise BudgetExceeded('deadline')
        original=parse_uri(uri)
        result['protocol']=original['type']
        addresses=resolve_public(original['server'],all_addresses=True)
        if isinstance(addresses,str): addresses=[addresses]
        result['resolved_addresses']=addresses[:MAX_ENDPOINT_ADDRESSES]
        # All returned addresses were validated before this bounded selection.
        result['address_limit']=MAX_ENDPOINT_ADDRESSES
        result['resolved_address_count']=len(addresses)
        diagnostics=result['attempts']; timings=[]
        for address_index,address in enumerate(addresses[:MAX_ENDPOINT_ADDRESSES]):
            if time.monotonic()+15>=deadline: raise BudgetExceeded('deadline')
            out=pin_outbound(original,address)
            result['tested_address']=address
            with socket.socket() as s:
                s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
            with tempfile.TemporaryDirectory() as td:
                password=secrets.token_urlsafe(24)
                config=Path(td)/'config.json';config.write_text(json.dumps(configuration(out,port,password)))
                config.chmod(0o600)
                phase='core-start-failed'
                proc=subprocess.Popen([core,'run','-c',str(config)],stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,env={'PATH':os.environ['PATH'],'HOME':td})
                try:
                    time.sleep(.35)
                    if proc.poll() is not None: raise Rejected('core failed')
                    result['core_started']=True
                    def request(url,stage,attempt=1,**kwargs):
                        timeout=kwargs.get('timeout',QUICK_TIMEOUT)
                        if time.monotonic()+timeout+2>=deadline: raise BudgetExceeded('deadline')
                        if proc.poll() is not None: raise CoreStopped('core stopped')
                        diagnostic={'stage':stage,'endpoint':url,'address':address,
                                    'attempt':attempt,'started_at':utc_now()}
                        diagnostics.append(diagnostic)
                        before=time.monotonic()
                        try:
                            answer=curl(url,port,password=password,diagnostic=diagnostic,**kwargs)
                            diagnostic.update(http_status=answer[0],bytes=answer[1],elapsed_seconds=answer[2])
                            diagnostic.setdefault('error',None)
                            return answer
                        except (BudgetExceeded,CoreStopped): raise
                        except subprocess.TimeoutExpired as exc:
                            diagnostic.update(error='process-timeout',curl_exit=None)
                            raise RequestFailed('process-timeout',True) from exc
                        except RequestFailed:
                            raise
                        except (Rejected,OSError) as exc:
                            diagnostic.setdefault('error','request-failed')
                            raise RequestFailed('request-failed') from exc
                        finally:
                            diagnostic['duration_seconds']=round(max(0,time.monotonic()-before),4)
                    def checked_request(url,stage,predicate,**kwargs):
                        for attempt in range(1,MAX_ATTEMPTS+1):
                            retry=False
                            try:
                                answer=request(url,stage,attempt,**kwargs)
                                passed=predicate(*answer[:3])
                                diagnostics[-1]['passed']=passed
                                if passed: return answer
                                status,size,elapsed=answer[:3]
                                diagnostics[-1]['error']='http-status' if status not in (200,204) else 'response-shape-or-speed'
                                retry=status in TRANSIENT_HTTP_STATUSES or (stage.startswith('download') and status==200)
                            except RequestFailed as exc:
                                diagnostics[-1]['passed']=False
                                retry=exc.transient
                            if not retry or attempt==MAX_ATTEMPTS: raise Rejected('probe not confirmed')
                            if time.monotonic()+RETRY_DELAY+kwargs.get('timeout',QUICK_TIMEOUT)+2>=deadline:
                                raise BudgetExceeded('deadline')
                            time.sleep(RETRY_DELAY*attempt)
                    def https_check(url,stage):
                        answer=checked_request(url,stage,lambda status,size,elapsed: status==204 and size==0 and 0<elapsed<=QUICK_TIMEOUT,
                                               timeout=QUICK_TIMEOUT,limit=1024)
                        timings.append(answer[2])
                    phase='quick-https-failed'; healthy=[]
                    for url in QUICK_ENDPOINTS:
                        try:
                            https_check(url,'quick-https');healthy.append(url)
                        except (BudgetExceeded,CoreStopped): raise
                        except Rejected: pass
                    if not healthy:
                        # Retry a different validated endpoint address; never resolve
                        # it again behind the SSRF guard or silently fall back direct.
                        if address_index+1<min(len(addresses),MAX_ENDPOINT_ADDRESSES): continue
                        raise Rejected('quick checks failed')
                    result['quick_endpoints_passed']=healthy
                    phase='deep-budget'
                    if time.monotonic()+120>=deadline: raise BudgetExceeded('deadline')
                    if deep_budget is not None and not deep_budget.claim(): raise Rejected('deep cap')
                    result['deep_tested']=True
                    stable_start=time.monotonic();result['baseline_started_at']=utc_now();speeds=[]
                    def download(sample):
                        answer=checked_request(SPEED_ENDPOINT,'download-'+str(sample),
                            lambda status,size,elapsed: status==200 and size==DOWNLOAD_BYTES and elapsed>0 and size/elapsed>=MIN_BYTES_PER_SECOND,
                            timeout=12,limit=DOWNLOAD_BYTES)
                        speeds.append(answer[1]/answer[2]/1024)
                    phase='throughput-failed';download(1)
                    phase='stability-failed'
                    for check_index,offset in enumerate((15,30,STABILITY_SECONDS)):
                        target=stable_start+offset
                        if target+QUICK_TIMEOUT+2>=deadline: raise BudgetExceeded('deadline')
                        time.sleep(max(0,target-time.monotonic()))
                        https_check(healthy[check_index%len(healthy)],'stability-'+str(offset))
                    phase='throughput-failed';download(2)
                    result.update(baseline_qualified=True,median_ms=round(statistics.median(timings)*1000),
                        min_kib_s=round(min(speeds),1),download_kib_s=[round(x,1) for x in speeds],
                        stability_seconds=round(time.monotonic()-stable_start,1))
                    phase='service-failed';labels={};service_diagnostics={}
                    for name,url in (('youtube','https://www.youtube.com/'),('chatgpt','https://chatgpt.com/')):
                        try:
                            for attempt in range(1,MAX_ATTEMPTS+1):
                                try:
                                    answer=request(url,'service-'+name,attempt,timeout=10,limit=2*1024*1024,body=True)
                                    if answer[0] not in TRANSIENT_HTTP_STATUSES or attempt==MAX_ATTEMPTS: break
                                except RequestFailed as exc:
                                    if not exc.transient or attempt==MAX_ATTEMPTS: raise
                                time.sleep(RETRY_DELAY)
                            code,_,_,body=answer
                            service_diagnostics[name]=service_assessment(name,code,body)
                            labels[name]=service_diagnostics[name]['label']
                        except (BudgetExceeded,CoreStopped): raise
                        except (Rejected,subprocess.TimeoutExpired):
                            labels[name]='not-confirmed'
                            service_diagnostics[name]={'label':'not-confirmed','http_status':None,'blocking_signals':[],
                                'recognized_page':False,'interpretation':'automated-http-test-only'}
                    if proc.poll() is not None: raise CoreStopped('core stopped')
                    services={name:label=='page-confirmed' for name,label in labels.items()}
                    result.update(qualified=all(services.values()),service_qualified=services,
                        reachability=labels,service_diagnostics=service_diagnostics,
                        youtube_evidence={'scope':'homepage-html-only','video_playback_tested':False,
                                          'googlevideo_media_tested':False})
                    if not any(services.values()):
                        result['reason']='services-not-confirmed';return result,None
                    exported=export_with_label(uri,result)
                    result['subscription_sha256']=hashlib.sha256(exported.encode()).hexdigest()
                    return result,exported
                finally:
                    if proc:
                        proc.terminate()
                        try: proc.wait(timeout=2)
                        except subprocess.TimeoutExpired: proc.kill();proc.wait()
                        proc=None
        raise Rejected('no public address')
    except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as exc:
        result['qualified']=False;result['service_qualified']={'youtube':False,'chatgpt':False}
        result['reason']='budget' if isinstance(exc,BudgetExceeded) else ('core-stopped' if isinstance(exc,CoreStopped) else phase)
        return result,None
    finally:
        result['completed_at']=utc_now()

class FeedText(str):
    """Decoded content with exact downloaded-byte provenance (no source secrets)."""
    pass


def download_feed(url):
    p = subprocess.run(['curl','--disable','--silent','--fail','--proto','=https','--proxy','',
        '--connect-timeout','5','--max-time','20','--retry','2','--retry-delay','1',
        '--retry-max-time','45','--max-filesize',str(MAX_FEED),url],capture_output=True,
        timeout=65,env={'PATH':os.environ['PATH'],'HOME':'/nonexistent'})
    if p.returncode or len(p.stdout)>MAX_FEED: raise Rejected('feed download')
    text=FeedText(p.stdout.decode('utf-8-sig'))
    text.sha256=hashlib.sha256(p.stdout).hexdigest()
    text.fetched_at=utc_now()
    return text


def rejection_category(uri, error):
    """Return only fixed categories; exception text can contain credentials."""
    try:
        u=U.urlsplit(uri)
        options=json.loads(b64(u.netloc+u.path)) if u.scheme=='vmess' else dict(U.parse_qsl(u.query))
        if isinstance(options,dict) and any(
            key in options and str(options[key]).lower() not in ('0','false','')
            for key in ('insecure','allowInsecure','skip-cert-verify')):
            return 'insecure-tls-requested'
    except (ValueError,TypeError,RecursionError):
        pass
    reason=str(error)
    return reason.lower().replace(' ','-') if reason in PARSER_REASONS else 'malformed'


def collect_candidates():
    """Read every bounded source; deduplicate effective configurations, not names."""
    normalized={}; provenance={}; sources=[]; raw_unique=set()
    for url in SOURCES:
        try:
            text=download_feed(url)
            lines=feed_lines(text)
            provenance_meta={'fetched_at':getattr(text,'fetched_at',utc_now()),
                'sha256':getattr(text,'sha256',hashlib.sha256(text.encode()).hexdigest()),
                'hash_scope':'downloaded-source-bytes' if isinstance(text,FeedText) else 'utf8-text'}
            local={}; supported=0; reasons=Counter(); protocols=Counter()
            raw_unique.update(lines)
            for line in lines:
                scheme=line.split('://',1)[0].lower()
                protocol={'ss':'shadowsocks','hy2':'hysteria2'}.get(scheme,scheme)
                protocols[protocol if protocol in PROTOCOLS else 'other']+=1
                try:
                    parsed=parse_uri(line)
                    key=canonical_key(parsed)
                    local[key]=parsed
                    normalized.setdefault(key,line)
                    provenance.setdefault(key,[])
                    if url not in provenance[key]: provenance[key].append(url)
                    supported+=1
                except (ValueError,KeyError,TypeError) as exc:
                    reasons[rejection_category(line,exc)]+=1
            sources.append({'url':url,'downloaded':True,**provenance_meta,'lines':len(lines),
                'raw_unique_lines':len(set(lines)), 'supported_lines':supported,
                'unique_candidates':len(local),
                'unique_endpoints':len({(p['type'],p['server'],p['server_port']) for p in local.values()}),
                'duplicate_supported_lines':supported-len(local),
                'unsupported_or_rejected_lines':sum(reasons.values()),
                'rejection_categories':dict(reasons), 'raw_protocol_counts':dict(protocols),
                'supported_protocol_counts':dict(Counter(p['type'] for p in local.values()))})
        except (ValueError,OSError,subprocess.TimeoutExpired):
            sources.append({'url':url,'downloaded':False,'reason':'source-unavailable-or-invalid'})
    available=[s for s in sources if s['downloaded']]
    parsed=[json.loads(key) for key in normalized]
    supported=sum(s['supported_lines'] for s in available)
    stats={'raw_lines':sum(s['lines'] for s in available),'raw_unique_lines':len(raw_unique),
           'supported_lines':supported,'unique_candidates':len(normalized),
           'unique_endpoints':len({(p['type'],p['server'],p['server_port']) for p in parsed}),
           'duplicate_supported_lines':supported-len(normalized),
           'cross_source_duplicate_candidates':sum(s['unique_candidates'] for s in available)-len(normalized),
           'unsupported_or_rejected_lines':sum(s['unsupported_or_rejected_lines'] for s in available),
           'candidate_protocol_counts':dict(Counter(p['type'] for p in parsed))}
    return normalized,provenance,sources,stats


def select_candidates(normalized):
    """Complete deterministic selection or an explicit safety-budget failure."""
    if len(normalized)>MAX_CANDIDATES:
        raise RuntimeError('supported pool exceeds resource budget; no candidates silently dropped')
    keys=sorted(normalized,key=lambda key:(hashlib.sha256(key.encode()).digest(),key))
    return [normalized[key] for key in keys]


def coverage_summary(sources, total, results):
    skipped_deadline=sum(r.get('reason')=='budget' for r in results)
    skipped_deep=sum(r.get('reason')=='deep-budget' for r in results)
    cap_skipped=total-len(results)
    available=sum(s['downloaded'] is True for s in sources)
    complete=(available==len(SOURCES) and len(sources)==len(SOURCES) and
              cap_skipped==0 and skipped_deadline==0 and skipped_deep==0)
    return {'scope':'parser-supported-unique-configurations',
            'selection':'complete-frozen-snapshot-shards',
            'sources_expected':len(SOURCES),'sources_available':available,
            'selected_candidates':len(results),
            'completed_assessments':len(results)-skipped_deadline-skipped_deep,
            'candidate_cap_skipped':cap_skipped,'deadline_skipped':skipped_deadline,
            'deep_cap_skipped':skipped_deep,'complete_supported':complete}


def report_payload(sources,stats,results,accepted,started_at,core_metadata=None,extra_metadata=None,completed_at=None):
    report={'schema_version':4,'started_at':started_at,'completed_at':completed_at or utc_now(),
        'vantage':'Recorded probe origin only; not the user network',
        'probe_origin':probe_origin(),'identity_version':CANONICALIZATION_VERSION,
        'identity_scope':'supported-authenticated-stream-settings; REALITY fallback spx variants may deduplicate',
        'core':core_metadata,'sources':sources,**stats,'sampled':len(results),
        'coverage':coverage_summary(sources,(extra_metadata or {}).get('history',{}).get('assessed_candidates',stats['unique_candidates']),results),
        'deep_tested':sum(r.get('deep_tested') is True for r in results),
        'qualified':len(accepted['both']),'feed_counts':{key:len(lines) for key,lines in accepted.items()},
        'results':results,
        'method':'At least one verified HTTPS 204 endpoint; bounded transient retries; public-address alternatives before deep testing; repeated HTTPS at 15/30/45 seconds; two exact 2MiB downloads each >=256KiB/s; recognized service homepage, no redirects/challenges',
        'interpretation':'YouTube means recognized homepage HTML only, not video/CDN playback; ChatGPT HTTP 403 is diagnostic and never gates the YouTube feed; no Russian ISP reachability claim',
        'diagnostics':{'failure_reasons':dict(Counter(r.get('reason','primary-qualified' if r['qualified'] else 'service-only') for r in results)),
            'service_labels':{name:dict(Counter(r.get('reachability',{}).get(name,'not-tested') for r in results)) for name in ('youtube','chatgpt')},
            'probe_errors':dict(Counter(a['error'] for r in results for a in r.get('attempts',[]) if a.get('error'))),
            'blocking_signals':{name:dict(Counter(marker for r in results for marker in r.get('service_diagnostics',{}).get(name,{}).get('blocking_signals',[]))) for name in ('youtube','chatgpt')}},
        'limits':{'candidate_cap':MAX_CANDIDATES,'deep_cap':MAX_DEEP,'workers_per_shard':WORKERS,
            'budget_seconds_per_shard':3600,'stability_window_seconds':STABILITY_SECONDS,
            'download_bytes_per_sample':DOWNLOAD_BYTES,'download_samples':2,
            'max_attempts_per_sample':MAX_ATTEMPTS,'max_public_addresses':MAX_ENDPOINT_ADDRESSES,
            'max_bulk_bytes_per_node':DOWNLOAD_BYTES*2*MAX_ATTEMPTS,
            'max_download_body_bytes_per_node':DOWNLOAD_BYTES*2*MAX_ATTEMPTS+8*1024*1024,
            'min_kib_s':MIN_BYTES_PER_SECOND//1024,'max_result_age_seconds':MAX_RESULT_AGE_SECONDS},
        'max_age_hours':12,
        'freshness_note':'A failed run leaves the previously published snapshot unchanged; its timestamps never refresh. Clients reading raw URI lists do not enforce expiration.'}
    if extra_metadata:
        if set(extra_metadata)&set(report): raise ValueError('metadata cannot override report fields')
        report.update(extra_metadata)
    return report


def write_report(output,sources,stats,results,accepted,started_at,core_metadata=None,extra_metadata=None):
    output=Path(output);output.mkdir(exist_ok=True,parents=True)
    report=report_payload(sources,stats,results,accepted,started_at,core_metadata,extra_metadata)
    for key,filename in FEEDS.items():
        (output/filename).write_text('\n'.join(accepted[key])+ ('\n' if accepted[key] else ''))
    (output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


def main():
    # Local convenience entry point. Production uses production.py frozen shards.
    start=utc_now();deadline=time.monotonic()+BUDGET
    output=Path('public');output.mkdir(exist_ok=True)
    for filename in FEEDS.values(): (output/filename).write_text('')
    (output/'report.json').unlink(missing_ok=True)
    normalized,provenance,sources,stats=collect_candidates()
    if not all(source['downloaded'] for source in sources):
        raise RuntimeError('one or more sources unavailable; do not publish incomplete output')
    candidates=select_candidates(normalized)
    if not candidates: raise RuntimeError('no supported candidates; possible source format change; do not publish')
    source_by_id={node_id(uri):provenance[canonical_key(parse_uri(uri))] for uri in candidates}
    protocol_by_id={node_id(uri):parse_uri(uri)['type'] for uri in candidates}
    results=[];accepted={key:[] for key in FEEDS};deep_budget=DeepBudget(len(candidates))
    core=os.path.abspath(os.environ.get('SING_BOX','./bin/sing-box'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for result,line in pool.map(lambda u:probe(u,core,deadline,deep_budget),candidates):
            result['sources']=source_by_id[result['id']]
            result['protocol']=protocol_by_id[result['id']]
            results.append(result)
            if line:
                if result['qualified']: accepted['both'].append(line)
                for service in ('chatgpt','youtube'):
                    if result['service_qualified'][service]: accepted[service].append(line)
    if any(r.get('reason') in ('core-start-failed','core-stopped','budget','deep-budget') for r in results):
        raise RuntimeError('infrastructure failure or incomplete checks; do not publish')
    report=write_report(output,sources,stats,results,accepted,start)
    print(json.dumps({'sampled':len(candidates),'deep_tested':deep_budget.used,
                      'coverage':report['coverage'],'feed_counts':report['feed_counts']}))

if __name__ == '__main__': main()
