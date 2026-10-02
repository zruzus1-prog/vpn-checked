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
]
MAX_CANDIDATES = 512
WORKERS = 4
BUDGET = 90 * 60
MAX_DEEP = 512
STABILITY_SECONDS = 45
DOWNLOAD_BYTES = 2 * 1024 * 1024
MIN_BYTES_PER_SECOND = 256 * 1024
FEEDS = {"both": "subscription.txt", "chatgpt": "subscription-gpt.txt", "youtube": "subscription-youtube.txt"}
MAX_FEED = 4 * 1024 * 1024
MAX_FEED_LINES = 20000
CIPHERS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'}
PROTOCOLS = {'vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks'}
PARSER_REASONS = {
    'oversize', 'base64', 'unsafe string', 'host', 'vmess JSON', 'vmess object',
    'vmess numeric field', 'vmess string field', 'unsupported vmess',
    'unsupported scheme', 'ambiguous credentials', 'duplicate option',
    'unsupported option', 'unsupported ss', 'obfs', 'encryption', 'flow',
    'port', 'security', 'TLS required', 'alpn', 'fingerprint', 'reality',
    'transport', 'path', 'unsupported ss plugin', 'unsafe obfs host',
    'packet encoding', 'header type', 'hy2 bandwidth',
}
REJECTION_CATEGORIES = {x.lower().replace(' ', '-') for x in PARSER_REASONS} | {
    'insecure-tls-requested', 'malformed',
}
RESULT_FAILURE_REASONS = {'budget', 'endpoint-rejected', 'core-start-failed',
    'quick-https-failed', 'deep-budget', 'throughput-failed', 'stability-failed',
    'service-failed', 'services-not-confirmed'}

class Rejected(ValueError):
    pass

class BudgetExceeded(Rejected):
    """A run deadline is incomplete coverage, never evidence of a bad node."""
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

def ss_plugin(value):
    """A narrow built-in sing-box obfs-local adapter, never an executable name.

    The TLS-obfs host is opaque camouflage data, not a DNS/certificate host.
    Preserve its bytes. Only the separately validated server is ever dialled.
    Reference: SagerNet/sing-box v1.14.2 transport/sip003/obfs.go and plugin.go.
    """
    value=clean(value,1024)
    if '\\' in value: raise Rejected('unsupported ss plugin')
    parts=value.split(';')
    if len(parts)!=3 or parts[0]!='obfs-local': raise Rejected('unsupported ss plugin')
    options={}
    for part in parts[1:]:
        if part.count('=')!=1: raise Rejected('unsupported ss plugin')
        key,item=part.split('=',1)
        if key in options: raise Rejected('unsupported ss plugin')
        options[key]=item
    if set(options)!={'obfs','obfs-host'} or options['obfs']!='tls':
        raise Rejected('unsupported ss plugin')
    camouflage=clean(options['obfs-host'],253)
    if (not camouflage or len(camouflage.encode('utf-8'))>253 or
            any(unicodedata.category(char).startswith('C') or
                unicodedata.category(char) in ('Zl','Zp') for char in camouflage)):
        raise Rejected('unsafe obfs host')
    return {'plugin':'obfs-local','plugin_opts':'obfs=tls;obfs-host='+camouflage}

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
        if scheme == 'ss': allowed = {'plugin'}
        elif scheme == 'vless': allowed |= {'packetEncoding','headerType','headertype'}
        elif scheme in ('hy2','hysteria2'): allowed |= {'upmbps'}
        if set(q) - allowed:
            raise Rejected('unsupported option')
        if scheme == 'ss':
            auth = U.unquote(u.netloc.rsplit('@',1)[0])
            if ':' not in auth: auth = b64(auth)
            method, password = auth.split(':', 1)
            if method not in CIPHERS:
                raise Rejected('unsupported ss')
            out = {'type':'shadowsocks', 'method':method, 'password':clean(password)}
            if 'plugin' in q: out.update(ss_plugin(q['plugin']))
            q = {}
        elif scheme == 'trojan':
            out = {'type':'trojan','password':clean(U.unquote(u.username or ''))}
            q.setdefault('security', 'tls')
        elif scheme in ('hy2','hysteria2'):
            # sing-box v1.14.2 option.Hysteria2OutboundOptions.UpMbps defaults to
            # zero. Only this no-bandwidth-override form is supported here.
            if q.get('upmbps','0')!='0': raise Rejected('hy2 bandwidth')
            out = {'type':'hysteria2','password':clean(U.unquote(u.netloc.rsplit('@',1)[0])),
                   'up_mbps':0}
            q.setdefault('security','tls')
            if q.get('obfs'):
                if q['obfs'] != 'salamander' or not q.get('obfs-password'): raise Rejected('obfs')
                out['obfs'] = {'type':'salamander','password':clean(q['obfs-password'])}
        else:
            # v1.14.2 protocol/vless/outbound.go: absent -> xudp, explicit empty
            # disables packet encoding. Preserve that meaningful distinction.
            packet_encoding=q.get('packetEncoding','xudp')
            if packet_encoding not in ('','packetaddr','xudp'): raise Rejected('packet encoding')
            out = {'type':'vless','uuid':U.unquote(u.username or ''),'packet_encoding':packet_encoding}
            if q.get('encryption','none') != 'none': raise Rejected('encryption')
            header_keys=set(q)&{'headerType','headertype'}
            # Xray v25.3.6 transport_internet.go defines none as a no-op and
            # raw as the tcp alias; do not generalize to http/other headers.
            if header_keys and (len(header_keys)!=1 or q[next(iter(header_keys))]!='none' or
                                q.get('type','tcp') not in ('tcp','raw')):
                raise Rejected('header type')
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
    if out['type']=='vless' and transport=='raw': transport='tcp'
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
    lines = [s.strip() for s in text.splitlines() if '://' in s]
    if len(lines) > MAX_FEED_LINES: raise Rejected('too many feed lines')
    return lines

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
    allowed_punctuation=set(' .,-_|()[]')
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


def probe(uri, core, deadline, deep_budget=None):
    result = {'id':hashlib.sha256(uri.encode()).hexdigest()[:16], 'qualified':False,
              'baseline_qualified':False, 'service_qualified':{'youtube':False,'chatgpt':False}}
    if time.monotonic() >= deadline: result['reason']='budget'; return result, None
    proc = None; phase='endpoint-rejected'
    try:
        out = parse_uri(uri)
        result['protocol'] = out['type']
        out['server'] = resolve_public(out['server'])
        if time.monotonic() + 10 >= deadline: raise BudgetExceeded('budget')
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
                if time.monotonic() + timeout + 2 >= deadline: raise BudgetExceeded('deadline')
                if proc.poll() is not None: raise Rejected('core stopped')
                return curl(url, port, password=password, **kwargs)
            def https_check(url):
                status,size,elapsed = request(url, limit=1024)
                if status != 204 or size != 0 or not 0 < elapsed <= 4: raise Rejected('stability')
                timings.append(elapsed)
            for url in ('https://www.gstatic.com/generate_204','https://cp.cloudflare.com/generate_204'):
                https_check(url)
            phase='deep-budget'
            if time.monotonic() + 100 >= deadline: raise BudgetExceeded('budget')
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
                if target + 7 >= deadline: raise BudgetExceeded('deadline')
                time.sleep(max(0,target-time.monotonic()))
                https_check(url)
            phase='throughput-failed'
            download()
            result.update(baseline_qualified=True, median_ms=round(statistics.median(timings)*1000),
                          min_kib_s=round(min(speeds),1), download_kib_s=[round(x,1) for x in speeds],
                          stability_seconds=round(time.monotonic()-stable_start,1))
            phase='service-failed'
            labels={}; diagnostics={}
            for name,url in (('youtube','https://www.youtube.com/'),('chatgpt','https://chatgpt.com/')):
                try:
                    code,_,_,body = request(url,timeout=8,limit=2*1024*1024,body=True)
                    diagnostics[name] = service_assessment(name,code,body)
                    labels[name] = diagnostics[name]['label']
                except BudgetExceeded:
                    raise
                except (Rejected,subprocess.TimeoutExpired):
                    labels[name]='not-confirmed'
                    diagnostics[name]={'label':'not-confirmed','http_status':None,'blocking_signals':[],
                                       'recognized_page':False,'interpretation':'automated-http-test-only'}
            if proc.poll() is not None: raise Rejected('core stopped')
            services={name:label=='page-confirmed' for name,label in labels.items()}
            result.update(qualified=all(services.values()), service_qualified=services, reachability=labels, service_diagnostics=diagnostics)
            if not any(services.values()):
                result['reason']='services-not-confirmed'
                return result,None
            exported=export_with_label(uri,result)
            result['subscription_sha256']=hashlib.sha256(exported.encode()).hexdigest()
            return result,exported
    except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as exc:
        result['qualified']=False
        result['service_qualified']={'youtube':False,'chatgpt':False}
        result['reason']='budget' if isinstance(exc,BudgetExceeded) else phase
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
            lines=feed_lines(download_feed(url))
            local={}; supported=0; reasons=Counter(); protocols=Counter()
            raw_unique.update(lines)
            for line in lines:
                scheme=line.split('://',1)[0].lower()
                protocol={'ss':'shadowsocks','hy2':'hysteria2'}.get(scheme,scheme)
                protocols[protocol if protocol in PROTOCOLS else 'other']+=1
                try:
                    parsed=parse_uri(line)
                    key=json.dumps(parsed,sort_keys=True,separators=(',',':'))
                    local[key]=parsed
                    normalized.setdefault(key,line)
                    provenance.setdefault(key,[])
                    if url not in provenance[key]: provenance[key].append(url)
                    supported+=1
                except (ValueError,KeyError,TypeError) as exc:
                    reasons[rejection_category(line,exc)]+=1
            sources.append({'url':url,'downloaded':True,'lines':len(lines),
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
    # Hash the canonical effective configuration: source order/name changes cannot
    # change scheduling. A cap is explicit incompleteness, never random coverage.
    keys=sorted(normalized,key=lambda key:(hashlib.sha256(key.encode()).digest(),key))
    return [normalized[key] for key in keys[:MAX_CANDIDATES]]


def coverage_summary(sources, total, results):
    skipped_deadline=sum(r.get('reason')=='budget' for r in results)
    skipped_deep=sum(r.get('reason')=='deep-budget' for r in results)
    cap_skipped=total-len(results)
    available=sum(s['downloaded'] is True for s in sources)
    complete=(available==len(SOURCES) and len(sources)==len(SOURCES) and
              cap_skipped==0 and skipped_deadline==0 and skipped_deep==0)
    return {'scope':'parser-supported-unique-configurations',
            'selection':'deterministic-normalized-sha256',
            'sources_expected':len(SOURCES),'sources_available':available,
            'selected_candidates':len(results),
            'completed_assessments':len(results)-skipped_deadline-skipped_deep,
            'candidate_cap_skipped':cap_skipped,'deadline_skipped':skipped_deadline,
            'deep_cap_skipped':skipped_deep,'complete_supported':complete}


def main():
    start = datetime.now(timezone.utc).isoformat(); deadline=time.monotonic()+BUDGET
    output=Path('public'); output.mkdir(exist_ok=True)
    # Clear in this run before fetching; never carry forward last run's nodes.
    for filename in FEEDS.values(): (output/filename).write_text('')
    normalized,provenance,sources,stats=collect_candidates()
    if not any(source['downloaded'] for source in sources): raise RuntimeError('all sources unavailable; do not publish')
    candidates=select_candidates(normalized)
    if not candidates: raise RuntimeError('no supported candidates; possible source format change; do not publish')
    source_by_id={hashlib.sha256(uri.encode()).hexdigest()[:16]:provenance[json.dumps(parse_uri(uri),sort_keys=True,separators=(',',':'))] for uri in candidates}
    protocol_by_id={hashlib.sha256(uri.encode()).hexdigest()[:16]:parse_uri(uri)['type'] for uri in candidates}
    results=[]; accepted={key:[] for key in FEEDS}; deep_budget=DeepBudget(MAX_DEEP)
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
    if any(r.get('reason')=='core-start-failed' for r in results) and not any(r.get('core_started') for r in results):
        raise RuntimeError('core startup failed; do not publish')
    report={'schema_version':3,'started_at':start,'completed_at':datetime.now(timezone.utc).isoformat(),
            'vantage':'GitHub-hosted runner, not the user network','sources':sources,
            **stats,'sampled':len(candidates),
            'coverage':coverage_summary(sources,len(normalized),results),
            'deep_tested':deep_budget.used,'qualified':len(accepted['both']),
            'feed_counts':{key:len(lines) for key,lines in accepted.items()},'results':results,
            'method':'2 quick HTTPS 204 checks; repeated verified HTTPS through same core at 15/30/45 seconds; two exact 2MiB downloads each >=256KiB/s; HTTP 200 and recognized YouTube/ChatGPT page content, no redirects/challenges; no playback/login/chat test',
            'diagnostics':{'failure_reasons':dict(Counter(r.get('reason','primary-qualified' if r['qualified'] else 'service-only') for r in results)),
                           'service_labels':{name:dict(Counter(r.get('reachability',{}).get(name,'not-tested') for r in results)) for name in ('youtube','chatgpt')},
                           'blocking_signals':{name:dict(Counter(marker for r in results for marker in r.get('service_diagnostics',{}).get(name,{}).get('blocking_signals',[]))) for name in ('youtube','chatgpt')}},
            'interpretation':'HTTP failures from this automated runner do not establish impossibility in a human browser; no playback/login/chat test',
            'limits':{'candidate_cap':MAX_CANDIDATES,'deep_cap':MAX_DEEP,'workers':WORKERS,
                      'budget_seconds':BUDGET,'stability_window_seconds':STABILITY_SECONDS,
                      'download_bytes_per_sample':DOWNLOAD_BYTES,'download_samples':2,
                      'min_kib_s':MIN_BYTES_PER_SECOND//1024},'max_age_hours':12}
    for key,filename in FEEDS.items():
        (output/filename).write_text('\n'.join(accepted[key])+ ('\n' if accepted[key] else ''))
    (output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'sampled':len(candidates),'deep_tested':deep_budget.used,
                      'coverage':report['coverage'],'feed_counts':report['feed_counts']}))

if __name__ == '__main__': main()
