"""Conservative, offline URI -> sing-box 1.14.2 outbound conversion.

The caller must preserve the original URI for publication. An outbound here is
for TCP/HTTPS probing, not a round-trip serializer or Karing/UDP parity promise.
Unknown options and requests for disabled certificate verification fail closed.

Primary references (reviewed 2026-10-04):
https://github.com/XTLS/Xray-core/discussions/716
https://github.com/SagerNet/sing-box/blob/v1.14.2/option/v2ray_transport.go
https://github.com/2dust/v2rayN/blob/3187eeef79ef12ea80fc81a618513839d3e398c2/v2rayN/ServiceLib/Handler/Fmt/VmessFmt.cs

REALITY spx is omitted ONLY for authenticated-success equivalence: Xray uses
SpiderX in its unauthenticated fallback crawler, which sing-box does not
reproduce. Proxy success says nothing about fallback camouflage. Never strip
spx from the original URI or claim full client equivalence.
"""
import base64
import ipaddress
import json
import re
import unicodedata
import urllib.parse as U
import uuid

MAX_FEED = 4 * 1024 * 1024
# Local resource policy, not the core's uint32 schema maximum. Reject larger
# settings rather than silently changing their requested transport semantics.
MAX_WS_EARLY_DATA = 64 * 1024
CIPHERS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
           '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
           '2022-blake3-chacha20-poly1305'}
PROTOCOLS = {'vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks'}
INSECURE_FLAGS = {'insecure', 'allowInsecure', 'skip-cert-verify'}
FINGERPRINTS = {'chrome', 'firefox', 'safari', 'ios', 'android', 'edge',
                '360', 'qq', 'random', 'randomized'}
PARSER_REASONS = {
    'oversize', 'base64', 'unsafe string', 'host', 'vmess JSON', 'vmess object',
    'vmess numeric field', 'vmess string field', 'unsupported vmess',
    'unsupported scheme', 'ambiguous credentials', 'duplicate option',
    'unsupported option', 'unsupported ss', 'obfs', 'encryption', 'flow',
    'port', 'security', 'TLS required', 'alpn', 'fingerprint', 'reality',
    'transport', 'path', 'unsupported ss plugin', 'unsafe obfs host',
    'packet encoding', 'header type', 'hy2 bandwidth', 'ss2022 key',
    'grpc mode', 'grpc authority', 'grpc service', 'websocket early data',
    'httpupgrade early data', 'insecure-tls-requested', 'malformed',
}
REJECTION_CATEGORIES = {x.lower().replace(' ', '-') for x in PARSER_REASONS}


class Rejected(ValueError):
    """Fixed, non-secret reason suitable for aggregate rejection reporting."""
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


def _secure_flags(options):
    """Remove explicit false values only; never use arbitrary truthiness."""
    for key in INSECURE_FLAGS & options.keys():
        value = options[key]
        false = (value is False or (type(value) is int and value == 0) or
                 (isinstance(value, str) and value.lower() in ('', '0', 'false')))
        if not false:
            raise Rejected('insecure-tls-requested')
    return {key: value for key, value in options.items() if key not in INSECURE_FLAGS}


def _unique_object(pairs):
    if len(pairs) != len(dict(pairs)):
        raise Rejected('duplicate option')
    return dict(pairs)


def _ss_password(method, password):
    password = clean(password)
    if not method.startswith('2022-'):
        return password
    # v1.14.2 go.mod pins sing-shadowsocks2 v0.2.1. Standard padded Base64,
    # every component exactly the method's key length, no ChaCha20 EIH chain.
    # https://github.com/SagerNet/sing-shadowsocks2/blob/v0.2.1/shadowaead_2022/method.go
    keys = password.split(':')
    size = 16 if method == '2022-blake3-aes-128-gcm' else 32
    if method == '2022-blake3-chacha20-poly1305' and len(keys) != 1:
        raise Rejected('ss2022 key')
    try:
        if any(len(base64.b64decode(key, validate=True)) != size for key in keys):
            raise Rejected('ss2022 key')
    except (ValueError, UnicodeError) as exc:
        raise Rejected('ss2022 key') from exc
    return password


def _path(value):
    value = clean(value)
    # Origin-form only; no fragment, malformed escapes or encoded controls.
    if (not value.startswith('/') or value.startswith('//') or '#' in value or
            re.search(r'%(?![0-9a-fA-F]{2})', value)):
        raise Rejected('path')
    clean(U.unquote(value))
    return value


def _ws_path(value):
    path = _path(value)
    base, separator, query = path.partition('?')
    if not separator:
        return {'type': 'ws', 'path': path}
    pairs = U.parse_qsl(query, keep_blank_values=True)
    if not any(key == 'ed' for key, _ in pairs):
        return {'type': 'ws', 'path': path}
    # Xray removes ?ed=N and sends early data in Sec-WebSocket-Protocol.
    # Only single decimal ed: mixed/duplicate queries are not reserialized.
    # https://github.com/XTLS/Xray-core/blob/v25.3.6/infra/conf/transport_internet.go
    # https://github.com/XTLS/Xray-core/blob/v25.3.6/transport/internet/websocket/dialer.go
    # https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2raywebsocket/conn.go
    if (len(pairs) != 1 or '&' in query or ';' in query or
            not re.fullmatch(r'ed=[0-9]+', query)):
        raise Rejected('websocket early data')
    amount = int(pairs[0][1])
    # Pinned EarlyWebsocketConn.writeRequest slices the actual first write;
    # it does not allocate maxEarlyData eagerly. The local bound nevertheless
    # caps Base64 header amplification independently of first-write size.
    if not 0 <= amount <= MAX_WS_EARLY_DATA:
        raise Rejected('websocket early data')
    return {'type': 'ws', 'path': base, 'max_early_data': amount,
            'early_data_header_name': 'Sec-WebSocket-Protocol'}


def _parse_vmess(u):
    if u.query:
        raise Rejected('unsupported option')
    try:
        v = json.loads(b64(u.netloc + u.path), object_pairs_hook=_unique_object)
    except Rejected:
        raise
    except (ValueError, RecursionError) as exc:
        raise Rejected('vmess JSON') from exc
    if not isinstance(v, dict):
        raise Rejected('vmess object')
    v = _secure_flags(v)
    for key, value in v.items():
        if key in ('v', 'port', 'aid'):
            if type(value) not in (str, int):
                raise Rejected('vmess numeric field')
        elif not isinstance(value, str):
            raise Rejected('vmess string field')
        if isinstance(value, str):
            clean(value, 4096)
    allowed = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type',
               'host', 'path', 'tls', 'sni', 'alpn', 'fp', 'security', 'vcn', 'pcs'}
    if set(v) - allowed or str(v.get('aid', '0')) != '0':
        raise Rejected('unsupported vmess')
    # v2rayN uses scy (default auto), not security. Only redundant auto/default
    # metadata is neutral; conflicting cipher, certificate pin/name must fail.
    # https://github.com/2dust/v2rayN/blob/3187eeef79ef12ea80fc81a618513839d3e398c2/v2rayN/ServiceLib/Models/Dto/VmessQRCode.cs
    cipher = v.get('scy') or 'auto'
    if ('security' in v and (v['security'] not in ('', 'auto') or cipher != 'auto')
            or v.get('vcn') or v.get('pcs')):
        raise Rejected('unsupported vmess')
    if cipher not in ('auto', 'aes-128-gcm', 'chacha20-poly1305'):
        raise Rejected('unsupported vmess')
    network = v.get('net', 'tcp')
    header = v.get('type', 'none')
    accepted_headers = {'', 'none'}
    if network in ('ws', 'httpupgrade'):
        accepted_headers.add('auto')  # v2rayN ignores type on these transports.
    elif network == 'grpc':
        accepted_headers.add('gun')
    if header not in accepted_headers:
        raise Rejected('unsupported vmess')
    server, port = host(v['add']), int(v['port'])
    out = {'type': 'vmess', 'uuid': v['id'], 'security': cipher, 'alter_id': 0}
    q = {'security': v.get('tls', 'none'),
         'sni': v.get('sni') or v.get('host') or server, 'type': network}
    if network == 'grpc':
        q.update(serviceName=v.get('path', ''), authority=v.get('host', ''))
    else:
        q.update(path=v.get('path', '/'), host=v.get('host', ''))
    for key in ('alpn', 'fp'):
        if v.get(key):
            q[key] = v[key]
    return server, port, out, q


def _parse_uri(uri):
    clean(uri, 8192)
    u = U.urlsplit(uri)
    scheme = u.scheme.lower()
    if scheme == 'vmess':
        server, port, out, q = _parse_vmess(u)
    else:
        if scheme not in ('ss', 'trojan', 'vless', 'hy2', 'hysteria2'):
            raise Rejected('unsupported scheme')
        if scheme == 'ss' and '@' not in u.netloc:
            u = U.urlsplit('ss://' + b64(u.netloc) + ('?' + u.query if u.query else ''))
        if u.path not in ('', '/'):
            raise Rejected('path')
        server, port = host(u.hostname or ''), u.port
        if scheme in ('trojan', 'vless') and u.password is not None:
            raise Rejected('ambiguous credentials')
        q = _unique_object(U.parse_qsl(u.query, keep_blank_values=True))
        for key, value in q.items():
            clean(key, 128)
            clean(value, 4096)
        q = _secure_flags(q)
        allowed = {'security', 'sni', 'peer', 'type', 'host', 'path', 'fp', 'alpn'}
        if scheme == 'ss':
            allowed = {'plugin'}
        elif scheme == 'vless':
            allowed |= {'pbk', 'sid', 'spx', 'flow', 'encryption',
                        'packetEncoding', 'headerType', 'headertype'}
        elif scheme in ('hy2', 'hysteria2'):
            allowed |= {'obfs', 'obfs-password', 'upmbps'}
        if q.get('type') == 'grpc' and scheme in ('vless', 'trojan'):
            allowed |= {'serviceName', 'mode', 'authority'}
        if set(q) - allowed:
            raise Rejected('unsupported option')
        if scheme == 'ss':
            auth = U.unquote(u.netloc.rsplit('@', 1)[0])
            if ':' not in auth:
                auth = b64(auth)
            method, password = auth.split(':', 1)
            if method not in CIPHERS:
                raise Rejected('unsupported ss')
            out = {'type': 'shadowsocks', 'method': method,
                   'password': _ss_password(method, password)}
            if 'plugin' in q:
                out.update(ss_plugin(q['plugin']))
            q = {}
        elif scheme == 'trojan':
            out = {'type': 'trojan', 'password': clean(U.unquote(u.username or ''))}
            q.setdefault('security', 'tls')
        elif scheme in ('hy2', 'hysteria2'):
            if q.get('upmbps', '0') != '0':
                raise Rejected('hy2 bandwidth')
            out = {'type': 'hysteria2',
                   'password': clean(U.unquote(u.netloc.rsplit('@', 1)[0])), 'up_mbps': 0}
            q.setdefault('security', 'tls')
            if q.get('obfs'):
                if q['obfs'] != 'salamander' or not q.get('obfs-password'):
                    raise Rejected('obfs')
                out['obfs'] = {'type': 'salamander', 'password': clean(q['obfs-password'])}
            elif q.get('obfs-password'):
                raise Rejected('obfs')
        else:
            # Explicit empty disables encoding; absence defaults to xudp.
            # URI none maps to explicit empty, with NO UDP/Karing parity claim.
            # https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/vless/outbound.go
            packet = q.get('packetEncoding', 'xudp')
            if packet == 'none':
                packet = ''
            if packet not in ('', 'packetaddr', 'xudp'):
                raise Rejected('packet encoding')
            out = {'type': 'vless', 'uuid': U.unquote(u.username or ''),
                   'packet_encoding': packet}
            if q.get('encryption', 'none') != 'none':
                raise Rejected('encryption')
            headers = set(q) & {'headerType', 'headertype'}
            if headers and (len(headers) != 1 or q[next(iter(headers))] != 'none' or
                            q.get('type', 'tcp') not in ('tcp', 'raw')):
                raise Rejected('header type')
            if q.get('flow'):
                if q['flow'] != 'xtls-rprx-vision':
                    raise Rejected('flow')  # Never rewrite vision-udp443.
                out['flow'] = q['flow']
    if type(port) is not int or not 1 <= port <= 65535:
        raise Rejected('port')
    if out['type'] in ('vless', 'vmess'):
        out['uuid'] = str(uuid.UUID(out['uuid']))
    security = q.get('security', 'none')
    if security not in ('none', '', 'tls', 'reality'):
        raise Rejected('security')
    if out['type'] in ('vless', 'vmess') and security not in ('tls', 'reality'):
        raise Rejected('TLS required')
    if out['type'] in ('trojan', 'hysteria2') and security != 'tls':
        raise Rejected('TLS required')
    if 'spx' in q:
        # SpiderX only affects !uConn.Verified fallback, not authenticated proxy.
        # Caller must retain original URI including spx for publication.
        # https://github.com/XTLS/Xray-core/blob/v25.3.6/transport/internet/reality/reality.go
        if security != 'reality':
            raise Rejected('reality')
        if q['spx']:
            _path(q['spx'])
    if security in ('tls', 'reality'):
        tls = {'enabled': True, 'server_name': host(q.get('sni') or q.get('peer') or server)}
        if q.get('alpn'):
            alpn = q['alpn'].split(',')
            if any(x not in ('h2', 'http/1.1', 'h3') for x in alpn):
                raise Rejected('alpn')
            tls['alpn'] = alpn
        fingerprint = q.get('fp')
        if not fingerprint and out['type'] == 'vless':
            fingerprint = 'chrome'  # URI proposal #716, section 4.4.0.
        if fingerprint:
            if fingerprint not in FINGERPRINTS:
                raise Rejected('fingerprint')
            tls['utls'] = {'enabled': True, 'fingerprint': fingerprint}
        if security == 'reality':
            if (out['type'] != 'vless' or
                    not re.fullmatch(r'[A-Za-z0-9_-]{43}', q.get('pbk', '')) or
                    not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', q.get('sid', ''))):
                raise Rejected('reality')
            tls['reality'] = {'enabled': True, 'public_key': q['pbk'],
                              'short_id': q.get('sid', '')}
            tls.setdefault('utls', {'enabled': True, 'fingerprint': 'chrome'})
        out['tls'] = tls
    transport = q.get('type', 'tcp')
    if out['type'] == 'vless' and transport == 'raw':
        transport = 'tcp'
    if transport not in ('tcp', 'ws', 'httpupgrade', 'grpc'):
        raise Rejected('transport')
    if out['type'] == 'hysteria2' and transport != 'tcp':
        raise Rejected('transport')
    if transport == 'ws':
        out['transport'] = _ws_path(q.get('path', '/'))
        if q.get('host'):
            out['transport']['headers'] = {'Host': host(q['host'])}
    elif transport == 'httpupgrade':
        path = _path(q.get('path', '/'))
        if any(key == 'ed' for key, _ in U.parse_qsl(path.partition('?')[2], keep_blank_values=True)):
            raise Rejected('httpupgrade early data')
        # Native HTTPUpgrade, never WS approximation. No early-data equivalent.
        # https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2rayhttpupgrade/client.go
        out['transport'] = {'type': 'httpupgrade', 'path': path}
        if q.get('host'):
            out['transport']['host'] = host(q['host'])
    elif transport == 'grpc':
        if q.get('mode', 'gun') != 'gun':
            raise Rejected('grpc mode')
        if q.get('authority') or q.get('host'):
            raise Rejected('grpc authority')
        if 'path' in q:
            raise Rejected('unsupported option')
        # Target uses /service_name/Tun, authority comes from TLS server_name.
        # Independent authority, multi and guna have no supported mapping.
        # https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2raygrpc/client.go
        # https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2raygrpc/custom_name.go
        service = clean(q.get('serviceName', ''))
        # Xray escapes service names and permits custom /service/method paths;
        # sing-box concatenates its service name with /Tun. Only the simple
        # unambiguous subset is mapped; do not silently change custom methods.
        # https://github.com/XTLS/Xray-core/blob/v25.3.6/transport/internet/grpc/config.go
        if not re.fullmatch(r'[A-Za-z0-9_.-]*', service):
            raise Rejected('grpc service')
        out['transport'] = {'type': 'grpc', 'service_name': service}
    out.update(server=server, server_port=port, tag='proxy')
    return out


def parse_uri(uri):
    """Return a bounded outbound or a fixed non-secret rejection reason."""
    try:
        return _parse_uri(uri)
    except Rejected:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise Rejected('malformed') from exc
