"""Names are display metadata only, never an inferred country or connection edit."""
import base64
import json
import unittest
import unicodedata
import urllib.parse as U

import checker as c

URI='vless://12345678-1234-1234-1234-123456789abc@example.org:443?security=tls&sni=example.org'
RESULT={'median_ms':191,'id':'6435d192ed6addfc'}


class LabelTests(unittest.TestCase):
    def test_source_flag_and_name_first(self):
        uri=URI+'#'+U.quote('🇨🇦 [BL] Сервер 12')
        exported=c.export_with_label(uri,RESULT)
        self.assertEqual(U.unquote(U.urlsplit(exported).fragment),'🇨🇦 [BL] Сервер 12 · VLESS · 6435d1')
        self.assertEqual(uri.split('#',1)[0],exported.split('#',1)[0])
        self.assertEqual(c.parse_uri(uri),c.parse_uri(exported))

    def test_controls_bidi_markup_and_injection_removed(self):
        name='🇩🇪 Germany\n\r\t\x00\u202e<script>alert(1)</script> #vpn://evil %0A'
        label=c.safe_source_label(name,100)
        self.assertFalse(any(unicodedata.category(x).startswith('C') for x in label))
        self.assertTrue(label.startswith('🇩🇪 Germany'))
        for char in '<>:#%/': self.assertNotIn(char,label)
        exported=c.export_with_label(URI+'#'+U.quote(name),RESULT)
        self.assertEqual(len(exported.splitlines()),1)
        self.assertEqual(c.parse_uri(exported),c.parse_uri(URI))

    def test_name_truncated_without_breaking_flag(self):
        self.assertLessEqual(len(c.safe_source_label('A'*200)),36)
        self.assertTrue(c.safe_source_label('A'*200).endswith('…'))
        value=c.safe_source_label('A'*34+'🇨🇦'+'B'*10)
        self.assertNotIn('🇨…',value)

    def test_missing_name_does_not_invent_country(self):
        text=U.unquote(U.urlsplit(c.export_with_label(URI,RESULT)).fragment)
        self.assertTrue(text.startswith('Страна не указана'))
        self.assertNotIn('🇨🇦',text)

    def test_existing_percent_encoding_and_credentials_untouched(self):
        uri='trojan://p%40ss%3Aword@example.org:443?sni=example.org&type=ws&path=%2Ffoo%3Fx%3D1#'+U.quote('🇫🇷 Paris')
        exported=c.export_with_label(uri,RESULT)
        self.assertEqual(uri.split('#',1)[0],exported.split('#',1)[0])
        self.assertEqual(c.parse_uri(uri),c.parse_uri(exported))

    def test_vmess_embedded_source_name_read_without_reencoding(self):
        value={'add':'example.org','port':443,'id':'12345678-1234-1234-1234-123456789abc','tls':'tls','ps':'🇳🇱 Amsterdam'}
        uri='vmess://'+base64.b64encode(json.dumps(value).encode()).decode()
        exported=c.export_with_label(uri,RESULT)
        self.assertTrue(U.unquote(U.urlsplit(exported).fragment).startswith('🇳🇱 Amsterdam'))
        self.assertEqual(exported.split('#',1)[0],uri)
        self.assertEqual(c.parse_uri(uri),c.parse_uri(exported))


if __name__=='__main__':unittest.main()
