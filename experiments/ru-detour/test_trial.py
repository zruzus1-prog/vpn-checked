import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import trial as t

SS={'type':'shadowsocks','tag':'proxy','server':'8.8.8.8','server_port':443,
    'method':'aes-128-gcm','password':'synthetic-test-only','network':'tcp'}
VLESS={'type':'vless','tag':'proxy','server':'1.1.1.1','server_port':443,
       'uuid':'00000000-0000-0000-0000-000000000001','network':'tcp',
       'tls':{'enabled':True,'server_name':'example.com'}}

class TrialTests(unittest.TestCase):
    def test_detour_fail_closed(self):
        candidate=copy.deepcopy(VLESS);hop=copy.deepcopy(SS)
        config=t.configuration(candidate,1234,'temporary-password',hop)
        self.assertEqual(config['route']['final'],'candidate')
        self.assertEqual(config['outbounds'][0]['detour'],'ru-hop')
        self.assertEqual(config['outbounds'][1]['tag'],'ru-hop')
        self.assertNotIn('detour',config['outbounds'][1])
        self.assertFalse(any(x['type'] in ('direct','selector','urltest') for x in config['outbounds']))
        self.assertEqual(config['route']['rules'],[{'network':'udp','action':'reject'}])
        self.assertEqual(candidate,VLESS);self.assertEqual(hop,SS)
    def test_direct_baseline_means_single_encrypted_candidate(self):
        config=t.configuration(SS,1234,'temporary-password')
        self.assertEqual(len(config['outbounds']),1)
        self.assertEqual(config['outbounds'][0]['type'],'shadowsocks')
        self.assertNotIn('detour',config['outbounds'][0])
    def test_fail_control_downgrades_pass_and_fail(self):
        results=[{'state':'passed'},{'state':'failed'}]
        t.classify_batch(results,{'healthy':True},{'healthy':False})
        self.assertTrue(all(r['state']=='unknown' for r in results))
        self.assertEqual([r['uncontrolled_state'] for r in results],['passed','failed'])
    def test_good_controls_preserve(self):
        results=[{'state':'failed'}]
        self.assertEqual(t.classify_batch(results,{'healthy':True},{'healthy':True}),results)
    def test_geo_requires_two_same_country_and_asn(self):
        records=[{'country_code':'RU','asn':'AS1'},{'country_code':'RU','asn':'AS1'}]
        self.assertTrue(t.qualify_geo(records))
        for other in ([records[0]], [records[0],{'error':'unavailable'}],
                      [records[0],{'country_code':'DE','asn':'AS1'}],
                      [records[0],{'country_code':'RU','asn':'AS2'}],
                      [records[0],{'country_code':'RU','asn':None}]):
            self.assertFalse(t.qualify_geo(other))
    def test_budget_caps_reserved_bytes(self):
        budget=t.Budget(payload=10)
        budget.claim(6)
        with self.assertRaises(t.Unknown):budget.claim(5)
        self.assertEqual(budget.reserved,6)
    def test_budget_caps_time(self):
        with self.assertRaises(t.Unknown):t.Budget(seconds=-1).claim(1)
    def test_endpoint_allowlist_and_https(self):
        for url in ('http://api.ipify.org','https://evil.example/','https://user:secret@api.ipify.org',
                    'https://api.ipify.org:444/','https://127.0.0.1/'):
            with self.assertRaises(t.Unknown):t.endpoint(url)
    def test_endpoint_rejects_private_dns(self):
        with patch.object(t.c,'resolve_public',side_effect=t.c.Rejected('nonpublic endpoint')):
            with self.assertRaises(t.c.Rejected):t.endpoint('https://api.ipify.org/')
    def test_public_ip_transition_and_private(self):
        for address in ('127.0.0.1','10.1.2.3','169.254.169.254','::1','64:ff9b::a00:1','::ffff:8.8.8.8'):
            self.assertFalse(t.c.public_ip(address))
    def test_encrypted_parser_rejects_insecure_and_plain_vless(self):
        for uri in ('vless://00000000-0000-0000-0000-000000000001@1.1.1.1:443?security=none',
                    'vless://00000000-0000-0000-0000-000000000001@1.1.1.1:443?security=tls&allowInsecure=1'):
            with self.assertRaises(t.c.Rejected):t.prepare_outbound(uri)
    def test_udp_excluded(self):
        with patch.object(t.c,'parse_uri',return_value={'type':'hysteria2'}):
            with self.assertRaisesRegex(t.Unknown,'unsupported-udp'):t.prepare_outbound('test')
    def test_public_endpoint_pinning_retains_tls(self):
        uri='vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&sni=example.com&type=ws&path=%2F'
        with patch.object(t.c,'resolve_public',return_value=['8.8.8.8']):out,meta=t.prepare_outbound(uri)
        self.assertEqual(out['server'],'8.8.8.8')
        self.assertEqual(out['tls']['server_name'],'example.com')
        self.assertEqual(out['transport']['headers']['Host'],'example.com:443')
    def test_curl_has_tls_public_pin_no_redirects_and_no_environment_proxy(self):
        class P: returncode=0;stdout=b'204 0 0.1';stderr=b''
        with patch.object(t,'endpoint',return_value=('www.gstatic.com','8.8.8.8')),\
             patch.object(t.subprocess,'run',return_value=P()) as run,patch.object(t,'BUDGET',t.Budget()):
            t.request(t.NEUTRAL,(1234,'temporary-password'))
            args=run.call_args.args[0]
            self.assertIn('www.gstatic.com:443:8.8.8.8:443',args)
            self.assertIn('socks5h://127.0.0.1:1234',args)
            self.assertNotIn('--insecure',args);self.assertNotIn('-k',args)
            self.assertNotIn('--location',args)
            self.assertEqual(run.call_args.kwargs['env']['HOME'],'/nonexistent')
    def test_full_label_excludes_long_whitelist_suffix_and_duplicate_labels(self):
        uri='vless://00000000-0000-0000-0000-000000000001@1.1.1.1:443?security=tls#RU%20'+('longname'*8)+'%20whitelist'
        selected,_=t.choose_hops([{'id':'1','uri':uri}])
        self.assertEqual(selected,[])
        clean=uri.split('#')[0]+'#RU'
        selected,_=t.choose_hops([{'id':'1','uri':clean,'labels':['RU','RU later duplicate whitelist']}])
        self.assertEqual(selected,[])
    def test_geo_invalid_connection_schema_is_unknown(self):
        with patch.object(t,'get_json',return_value={'ip':'8.8.8.8','country_code':'RU','connection':None}):
            records=t.geolocate('8.8.8.8')
        self.assertEqual(records[0]['error'],'geo-schema-invalid')
        self.assertFalse(t.qualify_geo(records))
    def test_geo_rejects_nonstring_country(self):
        for value in (12,True,None,[],{}):
            with patch.object(t,'get_json',return_value={'ip':'8.8.8.8','country_code':value,'connection':{'asn':1},'asn':'AS1'}):
                self.assertFalse(t.qualify_geo(t.geolocate('8.8.8.8')))
    def test_geo_rejects_invalid_asn_numbers(self):
        for value in (0,4294967296,'１２３','AS-1'):
            with patch.object(t,'get_json',return_value={'ip':'8.8.8.8','country_code':'RU','connection':{'asn':value},'asn':value}):
                self.assertFalse(t.qualify_geo(t.geolocate('8.8.8.8')))
    def test_timeout_and_rate_limit_are_unknown(self):
        import contextlib
        for detail in ({'error':'timeout','http_status':0},{'http_status':429}):
            with patch.object(t,'prepare_outbound',return_value=(SS,{})),\
                 patch.object(t,'core_session',return_value=contextlib.nullcontext((1,'temporary'))),\
                 patch.object(t,'request',return_value=(detail,b'')):
                result=t.assess({'id':'a','group':'reserve-unconfirmed','uri':'synthetic'})
            self.assertEqual(result['state'],'unknown')
    def test_deadline_reserves_time_before_start(self):
        budget=t.Budget(seconds=10)
        with self.assertRaises(t.Unknown):budget.claim(1,reserve_seconds=11)
        self.assertTrue(budget.exhausted)
    def test_nonobject_json_is_unknown(self):
        with patch.object(t,'request',return_value=({'http_status':200},b'[]')):
            with self.assertRaises(t.Unknown):t.get_json('https://api.ipify.org')
    def test_ip_formats_require_one_public_string_ip(self):
        good={'http_status':200,'bytes':20,'curl_exit':0}
        cases=[(('cloudflare','https://www.cloudflare.com/cdn-cgi/trace','trace'),b'ip=8.8.8.8\nloc=RU\n',True),
               (('cloudflare','https://www.cloudflare.com/cdn-cgi/trace','trace'),b'ip=8.8.8.8\nip=1.1.1.1\n',False),
               (('aws','https://checkip.amazonaws.com/','text'),b'8.8.8.8\n',True),
               (('aws','https://checkip.amazonaws.com/','text'),b'8.8.8.8\n1.1.1.1',False),
               (('aws','https://checkip.amazonaws.com/','text'),b'<html>8.8.8.8</html>',False),
               (('ipify','https://api.ipify.org','json'),b'{"ip":134744072}',False),
               (('ipify','https://api.ipify.org','json'),b'{"ip":"127.0.0.1"}',False),
               (('ipify','https://api.ipify.org','json'),b'{"ip":"2606:4700::1111%eth0"}',False)]
        for service,body,healthy in cases:
            with patch.object(t,'request',return_value=(good,body)):
                observation=t.ip_observation(service)
            self.assertEqual(observation['healthy'],healthy)
            self.assertNotIn('loc',observation)
            self.assertNotIn('body',observation)
    def test_two_independent_cloud_services_required(self):
        bad={'healthy':False,'reason':'timeout'}
        variants=[([bad,bad,bad,bad],None),
                  ([{'healthy':True,'ip':'8.8.8.8'},bad,bad,bad],None),
                  ([{'healthy':True,'ip':'8.8.8.8'},{'healthy':True,'ip':'1.1.1.1'},bad,bad],None),
                  ([{'healthy':True,'ip':'8.8.8.8'},{'healthy':True,'ip':'8.8.8.8'},bad,bad],'8.8.8.8')]
        for observations,expected in variants:
            with patch.object(t,'ip_observation',side_effect=observations):
                controls,cloud=t.establish_egress_controls()
            self.assertEqual(cloud,expected)
            self.assertEqual(len(t.ACTIVE_EGRESS),2 if expected else 0)
    def test_neutral_hop_failure_prevents_ip_attribution(self):
        import contextlib
        with patch.object(t,'prepare_outbound',return_value=(SS,{})),\
             patch.object(t,'core_session',return_value=contextlib.nullcontext((1,'temporary'))),\
             patch.object(t,'request',return_value=({'http_status':0,'error':'timeout'},b'')),\
             patch.object(t,'egress') as attribution:
            record,out=t.validate_hop({'id':'synthetic','uri':'synthetic','source_indexes':[]})
        self.assertIsNone(out);self.assertEqual(record['stage'],'neutral-https')
        self.assertEqual(record['state'],'unknown');attribution.assert_not_called()
    def test_failed_controls_explicitly_block_all24_without_proxy_attempt(self):
        rows=json.loads((t.OUT/'selection.json').read_text())
        candidates=[{**row,'uri':'synthetic'} for row in rows]
        with patch.object(t.c,'core_metadata',return_value={}),\
             patch.object(t,'load_inputs',return_value=(candidates,[],{})),\
             patch.object(t,'cloud_control',return_value={'healthy':True}),\
             patch.object(t,'establish_egress_controls',return_value=([],None)),\
             patch.object(t,'save'),patch.object(t,'validate_hop') as hop,\
             patch.object(t,'BUDGET',t.Budget()),patch.object(t,'ACTIVE_EGRESS',[]):
            report=t.run()
        self.assertEqual(report['status'],'probe-controls-not-established')
        self.assertEqual(len(report['not_run']),24)
        self.assertEqual(report['candidate_unique_not_tested'],24)
        self.assertEqual(report['candidate_probe_attempts'],0);hop.assert_not_called()
    def test_refund_only_measured_complete_requests(self):
        budget=t.Budget(payload=20)
        budget.claim(15);budget.observe(3,15)
        self.assertEqual(budget.reserved,3)
        budget.claim(15)
        self.assertEqual(budget.reserved,18)
        with self.assertRaises(t.Unknown):budget.claim(3)
    def test_oversize_accounting_is_truthful_and_stops(self):
        budget=t.Budget(payload=20);budget.claim(10);budget.observe(30,10)
        self.assertEqual(budget.reserved,30);self.assertTrue(budget.exhausted)
    def test_concurrent_reservations_and_refunds(self):
        import concurrent.futures,threading
        budget=t.Budget(payload=100);barrier=threading.Barrier(8)
        def consume(_):
            budget.claim(10);barrier.wait();budget.observe(2,10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(consume,range(8)))
        self.assertEqual(budget.reserved,16);self.assertEqual(budget.observed,16)
    def test_process_timeout_retains_full_reservation(self):
        budget=t.Budget()
        with patch.object(t,'BUDGET',budget),patch.object(t,'endpoint',return_value=('www.gstatic.com','8.8.8.8')),\
             patch.object(t.subprocess,'run',side_effect=t.subprocess.TimeoutExpired('curl',1)):
            with self.assertRaises(t.Unknown):t.request(t.NEUTRAL,limit=100)
        self.assertEqual(budget.reserved,100);self.assertEqual(budget.observed,0)
    def test_input_failure_still_blocks_frozen24(self):
        with patch.object(t.c,'core_metadata',return_value={}),\
             patch.object(t,'load_inputs',side_effect=t.Unknown('checked-snapshot-unavailable')),\
             patch.object(t,'save'),patch.object(t,'BUDGET',t.Budget()):
            report=t.run()
        self.assertEqual(len(report['not_run']),24)
        self.assertEqual(report['candidate_probe_attempts'],0)
        self.assertEqual(report['candidate_unique_not_tested'],24)
    def test_healthy_hop_matrix_finalization_keeps_expected_cohort(self):
        rows=json.loads((t.OUT/'selection.json').read_text())
        candidates=[{**row,'uri':'synthetic'} for row in rows]
        record={'id':'synthetic-hop','state':'apparently-ru-healthy','asn':'AS1','egress':[{'ip':'8.8.4.4'}]}
        def assessed(item,hop=None):return {'id':item['id'],'group':item['group'],'state':'passed'}
        with patch.object(t.c,'core_metadata',return_value={}),\
             patch.object(t,'load_inputs',return_value=(candidates,[{'id':'synthetic-hop'}],{})),\
             patch.object(t,'cloud_control',return_value={'healthy':True}),\
             patch.object(t,'establish_egress_controls',return_value=([],'1.1.1.1')),\
             patch.object(t,'validate_hop',return_value=(record,SS)),\
             patch.object(t,'hop_control',return_value={'healthy':True}),\
             patch.object(t,'assess',side_effect=assessed),patch.object(t.time,'sleep'),\
             patch.object(t,'save'),patch.object(t,'BUDGET',t.Budget()):
            report=t.run()
        self.assertEqual(report['status'],'completed')
        self.assertEqual(report['candidate_probe_attempts'],96)
        self.assertEqual(report['candidate_unique_tested'],24)
        self.assertEqual(report['candidate_unique_not_tested'],0)
        self.assertEqual(report['not_run'],[])
    def test_repair_pool_and_cumulative_caps(self):
        self.assertEqual(len(t.RECHECK_HOP_IDS),10)
        self.assertEqual(t.PAYLOAD_LIMIT+t.PREVIOUS_RESERVED_BYTES,196*1024*1024)
        self.assertLessEqual(t.TOTAL_SECONDS+t.PREVIOUS_LIVE_SECONDS,24*60)
    def test_selection_is_bounded_unique(self):
        path=t.OUT/'selection.json'
        if not path.exists():self.skipTest('selection pending')
        data=json.loads(path.read_text())
        self.assertLessEqual(len(data),24)
        self.assertEqual(len(data),len({x['id'] for x in data}))
        self.assertTrue(any(x['group']=='prior-local-positive' and x['id']=='e606956b7e70d0d2' for x in data))
        self.assertTrue(any(x['group']=='stable-local-negative' for x in data))

if __name__=='__main__':unittest.main()

class PinnedCoreTests(unittest.TestCase):
    @unittest.skipUnless(t.os.environ.get('RUN_CORE_SMOKE')=='1', 'runtime smoke requires CI network namespace support')
    def test_actual_core_baseline_detour_and_dead_hop(self):
        import socket,threading,time
        self.assertTrue(t.CORE.exists(), 'Mandatory runtime smoke requires pinned core')
        variants=[copy.deepcopy(SS),copy.deepcopy(VLESS),
                  {**copy.deepcopy(SS),'plugin':'obfs-local','plugin_opts':'obfs=tls;obfs-host=example.com'},
                  {'type':'trojan','password':'synthetic-test-only','tls':{'enabled':True,'server_name':'example.com'},'network':'tcp'},
                  {'type':'vmess','uuid':VLESS['uuid'],'security':'auto','tls':{'enabled':True,'server_name':'example.com'},'network':'tcp'}]
        for variant in variants:
            for mode in ('baseline','detour','dead-hop'):
                with self.subTest(protocol=variant['type'],plugin=variant.get('plugin'),mode=mode):
                    hits=[0,0];listeners=[];threads=[]
                    def watch(index,listener):
                        listener.settimeout(.8)
                        try:
                            conn,_=listener.accept()
                            with conn:
                                conn.settimeout(.5)
                                if conn.recv(256):hits[index]+=1
                        except (OSError,TimeoutError):pass
                    for i in range(2):
                        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(2)
                        listeners.append(listener)
                        if mode!='dead-hop' or i==0:
                            thread=threading.Thread(target=watch,args=(i,listener));thread.start();threads.append(thread)
                    candidate=copy.deepcopy(variant);candidate.update(server='127.0.0.1',server_port=listeners[0].getsockname()[1])
                    hop=copy.deepcopy(SS);hop.update(server='127.0.0.1',server_port=listeners[1].getsockname()[1])
                    if mode=='dead-hop':listeners[1].close()
                    try:
                        with t.core_session(candidate,hop if mode!='baseline' else None) as (port,password):
                            with socket.create_connection(('127.0.0.1',port),timeout=2) as sock:
                                sock.settimeout(1)
                                sock.sendall(b'\x05\x01\x02');self.assertEqual(sock.recv(2),b'\x05\x02')
                                user=b'trial';secret=password.encode()
                                sock.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(secret)])+secret)
                                self.assertEqual(sock.recv(2),b'\x01\x00')
                                sock.sendall(b'\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb')
                                try:sock.recv(10);sock.sendall(b'synthetic-public-payload')
                                except OSError:pass
                                time.sleep(.1)
                        for thread in threads:thread.join(2)
                        self.assertEqual(hits, {'baseline':[1,0],'detour':[0,1],'dead-hop':[0,0]}[mode])
                    finally:
                        for listener in listeners:listener.close()
