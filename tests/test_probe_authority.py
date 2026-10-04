"""DNS pinning must change the dial address, never HTTP transport authority.

Pinned sing-box v1.14.2 differs intentionally: WS defaults to serverAddr.String(),
whereas HTTPUpgrade defaults to TLS ServerName before serverAddr.String().
Sources: transport/v2raywebsocket/client.go and
transport/v2rayhttpupgrade/client.go in the official v1.14.2 tag.
"""
import copy
import unittest

import checker as c


BASE = ('vless://12345678-1234-1234-1234-123456789abc@example.org:8443'
        '?security=tls&sni=front.example.org')


class ProbeAuthorityTests(unittest.TestCase):
    def pinned(self, uri, address='8.8.8.8'):
        original = c.parse_uri(uri)
        expected = copy.deepcopy(original)
        identity = c.canonical_key(original)
        pinned = c.pin_outbound(original, address)
        self.assertEqual(pinned['server'], address)
        self.assertEqual(pinned['server_port'], original['server_port'])
        self.assertEqual(pinned['tls'], original['tls'])
        self.assertEqual(original, expected)
        self.assertEqual(c.canonical_key(original), identity)
        return original, pinned

    def test_ws_implicit_host_keeps_original_hostname_and_port(self):
        original, pinned = self.pinned(BASE + '&type=ws&path=%2Fws')
        self.assertEqual(pinned['transport']['headers']['Host'], 'example.org:8443')
        self.assertEqual(pinned['tls']['server_name'], 'front.example.org')
        self.assertNotIn('headers', original['transport'])

    def test_ws_explicit_host_is_preserved(self):
        original, pinned = self.pinned(BASE + '&type=ws&host=explicit.example.org&path=%2Fws')
        self.assertEqual(pinned['transport'], original['transport'])
        self.assertEqual(pinned['transport']['headers']['Host'], 'explicit.example.org')

    def test_ws_ipv6_authority_keeps_brackets_and_port(self):
        uri = BASE.replace('@example.org:', '@[2606:4700:4700::1111]:') + '&type=ws'
        _, pinned = self.pinned(uri, '2606:4700:4700::1001')
        self.assertEqual(pinned['transport']['headers']['Host'], '[2606:4700:4700::1111]:8443')

    def test_httpupgrade_implicit_host_uses_unchanged_tls_name(self):
        original, pinned = self.pinned(BASE + '&type=httpupgrade&path=%2Fupgrade')
        # Either leaving the native default or making it explicit is equivalent.
        effective_host = pinned['transport'].get('host') or pinned['tls']['server_name']
        self.assertEqual(effective_host, 'front.example.org')
        self.assertNotIn('host', original['transport'])

    def test_httpupgrade_explicit_host_is_preserved(self):
        original, pinned = self.pinned(BASE + '&type=httpupgrade&host=explicit.example.org')
        self.assertEqual(pinned['transport'], original['transport'])

    def test_grpc_keeps_service_and_tls_authority(self):
        original, pinned = self.pinned(BASE + '&type=grpc&serviceName=test')
        self.assertEqual(pinned['transport'], original['transport'])
        self.assertEqual(pinned['tls']['server_name'], 'front.example.org')

    def test_pinned_configuration_has_no_mutable_aliases_to_source(self):
        original, pinned = self.pinned(BASE + '&type=ws&host=explicit.example.org')
        expected = copy.deepcopy(original)
        pinned['transport']['headers']['Host'] = 'different.example.org'
        pinned['tls']['server_name'] = 'different.example.org'
        self.assertEqual(original, expected)


if __name__ == '__main__':
    unittest.main()
