import base64
import json
import unittest
from unittest.mock import patch, Mock
import checker as c

UUID='12345678-1234-1234-1234-123456789abc'
VLESS=f'vless://{UUID}@example.org:443?security=tls&sni=example.org'

def encode(s): return base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')

class ParserTests(unittest.TestCase):
    def test_vless_tls(self):
        p=c.parse_uri(VLESS)
        self.assertEqual(p['tls'],{'enabled':True,'server_name':'example.org'})
        self.assertNotIn('insecure',p['tls'])
    def test_ss(self):
        p=c.parse_uri('ss://'+encode('aes-128-gcm:abc')+'@example.org:8388')
        self.assertEqual(p['password'],'abc')
    def test_legacy_ss(self):
        self.assertEqual(c.parse_uri('ss://'+encode('aes-128-gcm:abc@example.org:8388'))['server_port'],8388)
    def test_vmess(self):
        p=c.parse_uri('vmess://'+encode(json.dumps({'add':'example.org','port':'443','id':UUID,'tls':'tls','net':'ws','host':'example.org','path':'/ws'})))
        self.assertEqual(p['transport']['type'],'ws')
    def test_hy2(self):
        p=c.parse_uri('hy2://pass@example.org:443?sni=example.org&obfs=salamander&obfs-password=x')
        self.assertEqual(p['type'],'hysteria2')
    def test_trojan(self):
        self.assertTrue(c.parse_uri('trojan://pass@example.org:443')['tls']['enabled'])
    def test_rejects_insecure_and_unknown_options(self):
        for q in ('allowInsecure=1','insecure=1','skip-cert-verify=true','plugin=x','security=tls'):
            with self.subTest(q=q), self.assertRaises(ValueError): c.parse_uri(VLESS+'&'+q)
    def test_rejects_cleartext_and_unsupported(self):
        for uri in (f'vless://{UUID}@example.org:443', VLESS+'&type=grpc', VLESS+'&path=%0D%0Axx&type=ws', 'ss://'+encode('none:abc')+'@example.org:443','vmess://'+encode('[]')):
            with self.subTest(uri=uri), self.assertRaises(ValueError): c.parse_uri(uri)
    def test_feed(self):
        self.assertEqual(c.feed_lines(encode(VLESS+'\n')), [VLESS])
        self.assertEqual(c.feed_lines(VLESS+'\n# comment\n'),[VLESS])
    def test_port(self):
        for port in (0,65536):
            with self.assertRaises(ValueError): c.parse_uri(VLESS.replace(':443',':'+str(port)))
    def test_host(self):
        for s in ('localhost','foo.local','foo.internal','x\n.org','x/y','-bad'):
            with self.assertRaises(ValueError): c.host(s)

class SecurityTests(unittest.TestCase):
    def test_private_and_special_addresses(self):
        for ip in ('127.0.0.1','10.0.0.1','169.254.169.254','192.168.0.1','0.0.0.0','::1','fe80::1','fc00::1','::ffff:8.8.8.8','2002:0808:0808::1','224.0.0.1','100.64.0.1','64:ff9b::a00:1','64:ff9b:1::a00:1'):
            with self.subTest(ip=ip): self.assertFalse(c.public_ip(ip))
        self.assertTrue(c.public_ip('8.8.8.8'))
    def test_mixed_dns_rejected(self):
        with patch('checker.subprocess.run',return_value=Mock(stdout='["8.8.8.8","10.0.0.1"]')):
            with self.assertRaises(ValueError): c.resolve_public('example.org')
    def test_pin_public_dns(self):
        with patch('checker.subprocess.run',return_value=Mock(stdout='["8.8.8.8"]')): self.assertEqual(c.resolve_public('example.org'),'8.8.8.8')
    def test_no_direct_fallback(self):
        cfg=c.configuration(c.parse_uri(VLESS),1080)
        self.assertEqual(cfg['route']['final'],'proxy')
        self.assertEqual(len(cfg['outbounds']),1)
        self.assertEqual(cfg['inbounds'][0]['listen'],'127.0.0.1')
    def test_curl_fail_closed(self):
        with patch('checker.subprocess.run',return_value=Mock(returncode=1,stdout=b'204 0 0.1')):
            with self.assertRaises(ValueError): c.curl('https://www.gstatic.com/generate_204',1080)
    def test_curl_flags(self):
        with patch('checker.subprocess.run',return_value=Mock(returncode=0,stdout=b'204 0 0.1')) as run:
            self.assertEqual(c.curl('https://www.gstatic.com/generate_204',1080),(204,0,.1))
            args=run.call_args.args[0]
            self.assertIn('socks5h://127.0.0.1:1080',args)
            self.assertNotIn('-L',args)
            self.assertNotIn('--insecure',args)
    def test_budget_never_connects(self):
        with patch('checker.socket.getaddrinfo') as dns:
            result,line=c.probe(VLESS,'absent',0)
            self.assertFalse(result['qualified']); self.assertIsNone(line); dns.assert_not_called()


class ProbeTests(unittest.TestCase):
    def test_qualified_node_requires_all_baseline_checks(self):
        process=Mock(); process.poll.return_value=None
        with patch('checker.resolve_public',return_value='8.8.8.8'), patch('checker.subprocess.Popen',return_value=process), patch('checker.time.sleep'), patch('checker.curl',side_effect=[(204,0,.1),(204,0,.2),(200,c.DOWNLOAD_BYTES,4)]+[(204,0,.2)]*3+[(200,c.DOWNLOAD_BYTES,4),(200,100,1,'<title>YouTube</title>ytInitialData ytcfg.set'),(403,100,1,'blocked')]):
            result,line=c.probe(VLESS,'/fake/core',c.time.monotonic()+180)
        self.assertFalse(result['qualified']); self.assertTrue(result['baseline_qualified']); self.assertIn('checked',line)
        self.assertEqual(result['reachability']['chatgpt'],'http-403')
        self.assertEqual(result['median_ms'],200)
        process.terminate.assert_called_once()
    def test_blocked_baseline_never_qualifies(self):
        process=Mock(); process.poll.return_value=None
        with patch('checker.resolve_public',return_value='8.8.8.8'), patch('checker.subprocess.Popen',return_value=process), patch('checker.time.sleep'), patch('checker.curl',return_value=(403,0,.1)):
            result,line=c.probe(VLESS,'/fake/core',c.time.monotonic()+180)
        self.assertFalse(result['qualified']); self.assertIsNone(line)
        process.terminate.assert_called_once()
    def test_partial_download_never_qualifies(self):
        process=Mock(); process.poll.return_value=None
        with patch('checker.resolve_public',return_value='8.8.8.8'), patch('checker.subprocess.Popen',return_value=process), patch('checker.time.sleep'), patch('checker.curl',side_effect=[(204,0,.1)]*2+[(200,65536,1)]):
            result,line=c.probe(VLESS,'/fake/core',c.time.monotonic()+180)
        self.assertFalse(result['qualified']); self.assertIsNone(line)
    def test_nonpublic_never_launches_core(self):
        with patch('checker.resolve_public',side_effect=c.Rejected('private')), patch('checker.subprocess.Popen') as popen:
            result,line=c.probe(VLESS,'/fake/core',c.time.monotonic()+180)
        popen.assert_not_called(); self.assertIsNone(line)
    def test_failed_sources_fail_job_not_publish(self):
        import tempfile, os
        cwd=os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as td:
                os.chdir(td); c.Path('public').mkdir(); c.Path('public/subscription.txt').write_text('stale')
                with patch('checker.download_feed',side_effect=c.Rejected('failed')):
                    with self.assertRaises(RuntimeError): c.main()
                self.assertEqual(c.Path('public/subscription.txt').read_text(),'')
                self.assertFalse(c.Path('public/report.json').exists())
        finally: os.chdir(cwd)

if __name__=='__main__': unittest.main()
