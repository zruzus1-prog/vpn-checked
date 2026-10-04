"""Offline compatibility/safety fixtures; all identities and keys are synthetic.

Source references live beside each mapping in uri_parser.py. These tests assert
configuration semantics, not reachability, authenticated service access, UDP,
Russian-network success, or equivalence to every client implementation.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.parse as U

import uri_parser as p

UUID = '12345678-1234-1234-1234-123456789abc'
VLESS = f'vless://{UUID}@example.org:443?security=tls&sni=example.org'
REALITY = VLESS.replace('security=tls', 'security=reality') + '&pbk=' + 'A' * 43


def encode(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')


def vmess(**updates):
    data = {'v': '2', 'ps': 'Synthetic test', 'add': 'example.org', 'port': 443,
            'id': UUID, 'aid': 0, 'scy': 'auto', 'net': 'ws', 'type': 'none',
            'host': 'example.org', 'path': '/ws', 'tls': 'tls', 'sni': 'example.org'}
    data.update(updates)
    return 'vmess://' + encode(json.dumps(data))


def ss(method='aes-128-gcm', password='synthetic-test-only', raw=False):
    auth = method + ':' + password
    return 'ss://' + (U.quote(auth, safe=':') if raw else encode(auth)) + '@example.org:8388'


def key(size, byte=0):
    return base64.b64encode(bytes([byte]) * size).decode()


class CompatibilityTests(unittest.TestCase):
    def assert_rejected(self, uri, reason=None):
        with self.assertRaises(p.Rejected) as context:
            p.parse_uri(uri)
        if reason:
            self.assertEqual(str(context.exception), reason)
        self.assertIn(str(context.exception), p.PARSER_REASONS)

    def test_default_vless_fingerprint_is_chrome_strict_tls(self):
        out = p.parse_uri(VLESS)
        self.assertEqual(out['tls'], {'enabled': True, 'server_name': 'example.org',
                                      'utls': {'enabled': True, 'fingerprint': 'chrome'}})
        self.assertNotIn('insecure', out['tls'])
        self.assertEqual(p.parse_uri(VLESS + '&fp=firefox')['tls']['utls']['fingerprint'], 'firefox')
        self.assert_rejected(VLESS + '&fp=unsafe', 'fingerprint')

    def test_other_protocols_do_not_gain_unrequested_fingerprint(self):
        for uri in (vmess(), 'trojan://synthetic@example.org:443', 'hy2://synthetic@example.org:443'):
            self.assertNotIn('utls', p.parse_uri(uri)['tls'])

    def test_false_tls_flags_on_uri(self):
        for scheme, uri in [('vless', VLESS), ('trojan', 'trojan://synthetic@example.org:443?security=tls'),
                            ('hy2', 'hy2://synthetic@example.org:443?security=tls')]:
            expected = p.parse_uri(uri)
            for flag in sorted(p.INSECURE_FLAGS):
                for value in ('0', 'false', '', 'False', 'FALSE'):
                    with self.subTest(scheme=scheme, flag=flag, value=value):
                        self.assertEqual(p.parse_uri(uri + '&' + flag + '=' + value), expected)

    def test_nonfalse_tls_flags_fail_closed(self):
        for flag in sorted(p.INSECURE_FLAGS):
            for value in ('1', 'true', 'yes', 'no', 'off', 'null', '00', '0.0', '-0', '%20false', 'false%20'):
                with self.subTest(flag=flag, value=value):
                    self.assert_rejected(VLESS + '&' + flag + '=' + value, 'insecure-tls-requested')

    def test_false_json_flags_only_allow_exact_types(self):
        for flag in sorted(p.INSECURE_FLAGS):
            for value in (False, 0, '0', 'false', '', 'FALSE'):
                self.assertEqual(p.parse_uri(vmess(**{flag: value})), p.parse_uri(vmess()))
            for value in (True, 1, None, [], {}, 0.0, 'off', ' true'):
                self.assert_rejected(vmess(**{flag: value}), 'insecure-tls-requested')

    def test_one_true_alias_cannot_be_overridden(self):
        self.assert_rejected(VLESS + '&insecure=false&allowInsecure=1', 'insecure-tls-requested')
        self.assert_rejected(vmess(insecure=False, allowInsecure=True), 'insecure-tls-requested')

    def test_duplicate_flags_and_json_fields_rejected(self):
        self.assert_rejected(VLESS + '&insecure=false&insecure=true', 'duplicate option')
        data = json.dumps({'add': 'example.org', 'port': 443, 'id': UUID, 'tls': 'tls'})
        data = data[:-1] + ',"insecure":false,"insecure":true}'
        self.assert_rejected('vmess://' + encode(data), 'duplicate option')
        self.assert_rejected(VLESS + '&security=tls', 'duplicate option')

    def test_packet_encoding_none_is_explicit_empty_not_default(self):
        self.assertEqual(p.parse_uri(VLESS)['packet_encoding'], 'xudp')
        for value in ('', 'none'):
            out = p.parse_uri(VLESS + '&packetEncoding=' + value)
            self.assertIn('packet_encoding', out)
            self.assertEqual(out['packet_encoding'], '')
            self.assertIn('"packet_encoding": ""', json.dumps(out))
        for value in ('xudp', 'packetaddr'):
            self.assertEqual(p.parse_uri(VLESS + '&packetEncoding=' + value)['packet_encoding'], value)
        self.assert_rejected(VLESS + '&packetEncoding=udp', 'packet encoding')

    def test_reality_spiderx_only_authenticated_success_mapping(self):
        base = p.parse_uri(REALITY)
        for value in ('', '%2F', '%2Fsynthetic%3Fx%3D1'):
            uri = REALITY + '&spx=' + value + '#synthetic-label'
            self.assertEqual(p.parse_uri(uri), base)
            self.assertIn('&spx=' + value, uri)  # Caller retains the original text.
        self.assert_rejected(VLESS + '&spx=%2F', 'reality')
        self.assert_rejected(REALITY + '&spx=https%3A%2F%2Fevil.example', 'path')

    def test_reality_authentication_fields_still_required(self):
        for suffix in ('&pbk=bad', '&pbk=' + 'A' * 43 + '&sid=abc', '&pbk=' + 'A' * 43 + '&sid=zz'):
            self.assert_rejected(VLESS.replace('security=tls', 'security=reality') + suffix, 'reality')
        self.assert_rejected(VLESS.replace('security=tls', 'security=reality') + '&spx=%2F', 'reality')

    def test_native_httpupgrade_host_path(self):
        uri = VLESS + '&type=httpupgrade&host=front.example.org&path=%2Fupgrade%3Fa%3D1'
        out = p.parse_uri(uri)
        self.assertEqual(out['transport'], {'type': 'httpupgrade', 'path': '/upgrade?a=1', 'host': 'front.example.org'})
        self.assertTrue(out['tls']['enabled'])
        self.assertEqual(p.parse_uri(VLESS + '&type=httpupgrade')['transport']['path'], '/')

    def test_httpupgrade_never_rewrites_early_data(self):
        for path in ('/up?ed=2048', '/up?ed=0', '/up?ed=', '/up?a=1&ed=2'):
            self.assert_rejected(VLESS + '&type=httpupgrade&path=' + U.quote(path, safe=''), 'httpupgrade early data')
        self.assert_rejected(VLESS + '&type=httpupgrade&ed=2048', 'unsupported option')

    def test_grpc_gun_service_name_and_default(self):
        for suffix in ('', '&mode=gun', '&mode=gun&authority='):
            out = p.parse_uri(VLESS + '&type=grpc&serviceName=grpc_service.test-1' + suffix)
            self.assertEqual(out['transport'], {'type': 'grpc', 'service_name': 'grpc_service.test-1'})
            self.assertEqual(out['tls']['server_name'], 'example.org')
        self.assertEqual(p.parse_uri(VLESS + '&type=grpc')['transport'], {'type': 'grpc', 'service_name': ''})

    def test_grpc_rejects_independent_authority_and_other_modes(self):
        for suffix, reason in [('&authority=example.org', 'grpc authority'), ('&host=example.org', 'grpc authority'),
                               ('&mode=multi', 'grpc mode'), ('&mode=guna', 'grpc mode'), ('&mode=', 'grpc mode'),
                               ('&path=%2Fservice', 'unsupported option')]:
            self.assert_rejected(VLESS + '&type=grpc' + suffix, reason)
        for name in ('/service/Custom', 'service/sub', 'service%2Fsub', 'with space', 'x?y', 'x#z'):
            self.assert_rejected(VLESS + '&type=grpc&serviceName=' + U.quote(name, safe=''), 'grpc service')

    def test_grpc_fields_never_dropped_on_other_transports(self):
        for suffix in ('&serviceName=x', '&mode=gun', '&authority='):
            self.assert_rejected(VLESS + suffix, 'unsupported option')

    def test_ws_early_data_single_parameter(self):
        self.assertEqual(p.MAX_WS_EARLY_DATA, 65536)
        for amount in (0, 1, 2048, 4096, 65536):
            out = p.parse_uri(VLESS + '&type=ws&path=' + U.quote('/ws?ed=' + str(amount), safe=''))
            self.assertEqual(out['transport'], {'type': 'ws', 'path': '/ws', 'max_early_data': amount,
                                                'early_data_header_name': 'Sec-WebSocket-Protocol'})

    def test_ws_early_data_ambiguous_query_rejected(self):
        for query in ('ed=-1', 'ed=65537', 'ed=4294967295', 'ed=4294967296', 'ed=2.0', 'ed=', 'ed', 'ed=2&ed=3',
                      'ed=2&x=1', 'x=1&ed=2', 'ed=2&', 'ed=2;', '%65d=2', 'ed=%32'):
            with self.subTest(query=query):
                self.assert_rejected(VLESS + '&type=ws&path=' + U.quote('/ws?' + query, safe=''), 'websocket early data')

    def test_ws_ordinary_query_preserved_exactly(self):
        path = '/ws?a=two%20words&z=%2F&a=other'
        out = p.parse_uri(VLESS + '&type=ws&path=' + U.quote(path, safe=''))
        self.assertEqual(out['transport'], {'type': 'ws', 'path': path})
        self.assert_rejected(VLESS + '&type=ws&ed=2048', 'unsupported option')

    def test_vmess_auto_only_neutral_for_ws_and_httpupgrade(self):
        for network in ('ws', 'httpupgrade'):
            self.assertEqual(p.parse_uri(vmess(net=network, type='auto')), p.parse_uri(vmess(net=network)))
        self.assert_rejected(vmess(net='tcp', type='auto'), 'unsupported vmess')
        self.assert_rejected(vmess(net='grpc', type='auto'), 'unsupported vmess')
        self.assert_rejected(vmess(type='http'), 'unsupported vmess')

    def test_vmess_neutral_metadata_is_narrow(self):
        self.assertEqual(p.parse_uri(vmess(security='auto', vcn='', pcs='')), p.parse_uri(vmess()))
        for values in ({'security': 'aes-128-gcm'}, {'security': 'auto', 'scy': 'aes-128-gcm'},
                       {'vcn': 'different.example'}, {'pcs': 'fake-pin'}, {'group': 'display'},
                       {'level': 0}, {'mux': False}, {'scy': 'none'}, {'scy': 'zero'}):
            self.assert_rejected(vmess(**values), 'unsupported vmess' if all(isinstance(x, str) for x in values.values()) else 'vmess string field')

    def test_unproven_neutral_metadata_is_still_unsupported(self):
        # No verified importer contract makes these safe to ignore. Do not
        # generalize the narrowly documented neutral VMess cases above.
        self.assert_rejected(vmess(serverPort='0'), 'unsupported vmess')
        self.assert_rejected(vmess(serverPort=0), 'vmess string field')
        self.assert_rejected(vmess(nation=''), 'unsupported vmess')

    def test_vmess_grpc_maps_only_simple_gun(self):
        out = p.parse_uri(vmess(net='grpc', type='gun', host='', path='service'))
        self.assertEqual(out['transport'], {'type': 'grpc', 'service_name': 'service'})
        self.assert_rejected(vmess(net='grpc', type='multi', host='', path='service'), 'unsupported vmess')
        self.assert_rejected(vmess(net='grpc', type='gun', host='example.org', path='service'), 'grpc authority')

    def test_vmess_early_data_uses_same_mapping(self):
        out = p.parse_uri(vmess(path='/ws?ed=2048'))
        self.assertEqual(out['transport']['max_early_data'], 2048)
        self.assertEqual(out['transport']['path'], '/ws')
        self.assert_rejected(vmess(path='/ws?ed=2048&x=1'), 'websocket early data')

    def test_ss2022_single_keys_and_aes_chains(self):
        for method, size in [('2022-blake3-aes-128-gcm', 16), ('2022-blake3-aes-256-gcm', 32),
                             ('2022-blake3-chacha20-poly1305', 32)]:
            for raw in (False, True):
                out = p.parse_uri(ss(method, key(size), raw=raw))
                self.assertEqual(out['method'], method)
                self.assertEqual(out['password'], key(size))
        for method, size in [('2022-blake3-aes-128-gcm', 16), ('2022-blake3-aes-256-gcm', 32)]:
            chain = ':'.join(key(size, byte) for byte in range(3))
            self.assertEqual(p.parse_uri(ss(method, chain))['password'], chain)

    def test_ss2022_keys_fail_closed_and_are_not_normalized(self):
        for method, size in [('2022-blake3-aes-128-gcm', 16), ('2022-blake3-aes-256-gcm', 32),
                             ('2022-blake3-chacha20-poly1305', 32)]:
            for password in ('', 'passphrase', key(size - 1), key(size + 1), key(size).rstrip('='),
                             key(size) + ':', ':' + key(size), key(size) + ':' + key(size - 1),
                             key(size, 255).replace('/', '_'), key(size) + '\n'):
                with self.subTest(method=method, password_length=len(password)):
                    self.assert_rejected(ss(method, password))
        self.assert_rejected(ss('2022-blake3-chacha20-poly1305', key(32) + ':' + key(32)), 'ss2022 key')

    def test_original_ss_aead_and_obfs_remain_supported(self):
        for method in ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'):
            uri = ss(method)
            self.assertEqual(p.parse_uri(uri)['password'], 'synthetic-test-only')
        uri = ss() + '?plugin=' + U.quote('obfs-local;obfs=tls;obfs-host=camouflage.example', safe='')
        out = p.parse_uri(uri)
        self.assertEqual(out['plugin'], 'obfs-local')
        self.assertEqual(out['plugin_opts'], 'obfs=tls;obfs-host=camouflage.example')
        self.assert_rejected(ss('none'), 'unsupported ss')
        self.assert_rejected(ss('rc4-md5'), 'unsupported ss')

    def test_legacy_ss_full_authority_remains_supported(self):
        uri = 'ss://' + encode('aes-128-gcm:synthetic-test-only@example.org:8388')
        self.assertEqual(p.parse_uri(uri), p.parse_uri(ss()))

    def test_no_cleartext_or_unsupported_xhttp_visionudp443(self):
        for uri in (VLESS.replace('security=tls', 'security=none'),
                    vmess(tls=''), 'trojan://synthetic@example.org:443?security=none',
                    'hy2://synthetic@example.org:443?security=none'):
            self.assert_rejected(uri, 'TLS required')
        for transport in ('xhttp', 'splithttp', 'quic', 'kcp', 'http'):
            self.assert_rejected(VLESS + '&type=' + transport, 'transport')
        self.assert_rejected(REALITY + '&flow=xtls-rprx-vision-udp443', 'flow')
        self.assert_rejected(VLESS + '&encryption=mlkem768x25519.test', 'encryption')

    def test_unknown_options_are_never_ignored(self):
        for option in ('extra={}', 'insecureSkipVerify=0', 'mux=false', 'ech=', 'pqv=', 'service_name=x', 'obfs=salamander'):
            self.assert_rejected(VLESS + '&' + option, 'unsupported option')
        self.assert_rejected(vmess() + '?allowInsecure=false', 'unsupported option')

    def test_malformed_inputs_have_fixed_nonsecret_reason(self):
        for uri in (None, 7, '', 'vless://bad-secret@example.org:443?security=tls',
                    'vless://x@[bad:443', 'vless://x@example.org:abc?security=tls',
                    'vmess://' + encode('{}'), 'vmess://' + encode('[]')):
            self.assert_rejected(uri)
        for path in ('/ws\r\nInjected: x', '/ws%0D%0AInjected', '//other.example/ws', 'relative', '/x#fragment', '/bad%xy'):
            self.assert_rejected(VLESS + '&type=ws&path=' + U.quote(path, safe=''))

    def test_aliases_security_and_port_boundaries_remain_checked(self):
        self.assertNotIn('transport', p.parse_uri(VLESS + '&type=raw&headerType=none'))
        self.assert_rejected(VLESS + '&headerType=http', 'header type')
        self.assert_rejected(VLESS + '&headerType=none&headertype=none', 'header type')
        for port in ('0', '65536', '-1'):
            self.assert_rejected(VLESS.replace(':443?', ':' + port + '?'))
        for hostname in ('localhost', 'private.local', 'private.internal'):
            self.assert_rejected(VLESS.replace('@example.org:', '@' + hostname + ':'), 'host')


@unittest.skipUnless(os.environ.get('SING_BOX_TEST_BIN'), 'set SING_BOX_TEST_BIN for optional pinned-core config checks')
class PinnedCoreConfigTests(unittest.TestCase):
    def test_synthetic_generated_configs_pass_core_check(self):
        core = os.environ['SING_BOX_TEST_BIN']
        version = subprocess.run([core, 'version'], text=True, capture_output=True, check=True).stdout
        self.assertIn('sing-box version 1.14.2', version)
        uris = [VLESS, REALITY + '&spx=%2F', VLESS + '&type=ws&path=%2Fws%3Fed%3D2048',
                VLESS + '&type=httpupgrade&path=%2Fupgrade', VLESS + '&type=grpc&serviceName=test&mode=gun',
                vmess(type='auto', security='auto'), vmess(net='grpc', host='', path='test'),
                ss('2022-blake3-aes-128-gcm', key(16) + ':' + key(16, 1)),
                ss('2022-blake3-aes-256-gcm', key(32)), ss('2022-blake3-chacha20-poly1305', key(32))]
        with tempfile.TemporaryDirectory() as td:
            for index, uri in enumerate(uris):
                config = {'log': {'disabled': True}, 'outbounds': [p.parse_uri(uri)]}
                filename = Path(td) / f'{index}.json'
                filename.write_text(json.dumps(config))
                result = subprocess.run([core, 'check', '-c', str(filename)], text=True,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, f'synthetic config {index}: {result.stderr}')


if __name__ == '__main__':
    unittest.main()
