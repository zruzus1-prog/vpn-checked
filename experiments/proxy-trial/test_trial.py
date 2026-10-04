import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse as U
import trial

V='vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls'

class Parsing(unittest.TestCase):
    def test_fragments_dont_change_identity(self):
        self.assertEqual(trial.identity(trial.parse(V+'#one')),trial.identity(trial.parse(V+'#two')))
    def test_query_order_does_not_change_identity(self):
        a=V+'&type=ws&host=EXAMPLE.COM&path=%2Fx%3Fed%3D2048'
        b=V+'&path=%2Fx%3Fed%3D2048&host=example.com&type=ws'
        self.assertEqual(trial.identity(trial.parse(a)),trial.identity(trial.parse(b)))
        self.assertEqual(trial.parse(a)['transport']['path'],'/x?ed=2048')
    def test_important_semantics_retained(self):
        a=trial.parse(V);b=trial.parse(V+'&packetEncoding=')
        self.assertNotEqual(trial.identity(a),trial.identity(b))
        self.assertEqual(b['packet_encoding'],'')
        self.assertNotEqual(trial.identity(a),trial.identity(trial.parse(V+'&sni=other.example')))
    def test_tcp_raw_noop_alias(self):
        self.assertEqual(trial.parse(V),trial.parse(V+'&type=raw&headerType=none'))
    def test_unknown_not_ignored(self):
        for suffix in ('&spx=%2F','&pqv=abc','&type=grpc','&type=xhttp','&headerType=http','&security=tls'):
            with self.subTest(suffix=suffix),self.assertRaises(trial.Excluded):trial.parse(V+suffix)
    def test_tls_cannot_be_disabled(self):
        for v in (V+'&allowInsecure=true',V.replace('security=tls','security=none'),'trojan://pw@example.com:443?security=none'):
            with self.subTest(v=v),self.assertRaises(trial.Excluded):trial.parse(v)
    def test_unencrypted_rejected(self):
        with self.assertRaises(trial.Excluded):trial.parse(V.split('?')[0])
    def test_ss_base64_auth(self):
        auth=base64.urlsafe_b64encode(b'aes-256-gcm:pass:word').decode().rstrip('=')
        p=trial.parse('ss://'+auth+'@example.com:443')
        self.assertEqual(p['password'],'pass:word')
    def test_obfs_builtin_only(self):
        auth=base64.b64encode(b'aes-256-gcm:pass').decode()
        good='ss://'+auth+'@example.com:443?plugin='+U.quote('obfs-local;obfs=tls;obfs-host=example.com')
        self.assertEqual(trial.parse(good)['plugin'],'obfs-local')
        for val in ('curl;obfs=tls;obfs-host=example.com','obfs-local;obfs=tls;obfs-host=example.com;exec=x'):
            with self.assertRaises(trial.Excluded):trial.parse(good.split('?')[0]+'?plugin='+U.quote(val))
    def test_vmess_insecure_classification(self):
        v={'add':'example.com','port':'443','id':'11111111-1111-4111-8111-111111111111','skip-cert-verify':True}
        with self.assertRaises(trial.Excluded) as ctx:trial.parse('vmess://'+base64.b64encode(json.dumps(v).encode()).decode())
        self.assertEqual(ctx.exception.category,'insecure-tls-requested')
    def test_reality_and_ipv6(self):
        v=V.replace('example.com','[2606:4700::1111]').replace('security=tls','security=reality&pbk='+'A'*43+'&sid=1234')
        self.assertEqual(trial.parse(v)['tls']['reality']['short_id'],'1234')
        with self.assertRaises(trial.Excluded):trial.parse(v+'&sid=123')
    def test_public_endpoints_only(self):
        for ip in ('127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:8.8.8.8','64:ff9b::808:808','2002:0808:0808::1','224.0.0.1'):
            self.assertFalse(trial.public_ip(ip),ip)
        self.assertTrue(trial.public_ip('8.8.8.8'))

class Inventory(unittest.TestCase):
    def test_deterministic_and_novel(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(trial,'ROOT',Path(tmp)):
            root=Path(tmp);(root/'a').write_text(V+'#one\n'+V+'#duplicate\n')
            n=V.replace('example.com','other.example')
            (root/'b').write_text(V+'#from-b\n'+n+'\n')
            m=[{'id':'a','url':'https://example/a','role':'control','file':'a'}, {'id':'b','url':'https://example/b','role':'candidate','file':'b'}]
            r=trial.prepare(m);first=json.loads((root/'selected-private.json').read_text())
            trial.prepare(m);second=json.loads((root/'selected-private.json').read_text())
            self.assertEqual(first,second);self.assertEqual(r['selected_unique'],2)
            self.assertEqual(r['sources'][1]['novel_to_original_controls'],1)
            self.assertEqual(r['sources'][0]['unique_supported'],1)
    def test_unsupported_not_failed(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(trial,'ROOT',Path(tmp)):
            root=Path(tmp);(root/'a').write_text(V+'&type=xhttp\n')
            r=trial.prepare([{'id':'a','url':'https://example/a','role':'control','file':'a'}])
            self.assertEqual(r['selected_unique'],0);self.assertEqual(r['sources'][0]['unsupported_or_unsafe'],1)

class HTTP(unittest.TestCase):
    def test_real_page_and_script_captcha(self):
        body='<title>YouTube</title><script>ytInitialData={};ytcfg.set({captcha:false});</script>'
        self.assertEqual(trial.page_label('youtube',{'status':'complete','http_status':200},body),'page-confirmed')
    def test_block_and_redirect(self):
        r={'status':'complete','http_status':200}
        self.assertEqual(trial.page_label('youtube',r,'<title>Just a moment</title>'),'challenge-or-blocked')
        self.assertEqual(trial.page_label('youtube',{**r,'http_status':302},''),'http-302')
    def test_no_network_in_offline_tests(self):
        with patch.object(trial.subprocess,'run',side_effect=AssertionError('No processes in parse')):
            trial.parse(V)

if __name__=='__main__':unittest.main()
