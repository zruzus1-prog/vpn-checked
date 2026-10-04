"""Retries recover transient failures without changing TLS or qualification rules."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import checker as c
from validate_output import validate

URI='vless://12345678-1234-1234-1234-123456789abc@example.org:443?security=tls&sni=example.org'
YT='<title>YouTube</title>ytInitialData ytcfg.set'

class Clock:
    def __init__(self): self.t=100.
    def monotonic(self): return self.t
    def sleep(self,seconds): self.t+=seconds

def deep():
    return [(200,c.DOWNLOAD_BYTES,4)]+[(204,0,.1)]*3+[(200,c.DOWNLOAD_BYTES,4),
        (200,len(YT),.5,YT),(403,0,.1,'Forbidden')]

class DiagnosticTests(unittest.TestCase):
    def run_probe(self,responses,addresses=None):
        clock=Clock();utc_base=datetime.now(timezone.utc)-timedelta(minutes=5);process=Mock();process.poll.return_value=None
        with patch('checker.utc_now',side_effect=lambda:(utc_base+timedelta(seconds=clock.t-100)).isoformat()), \
             patch('checker.resolve_public',return_value=addresses or ['8.8.8.8']), \
             patch('checker.subprocess.Popen',return_value=process) as launch, \
             patch('checker.time.monotonic',side_effect=clock.monotonic), \
             patch('checker.time.sleep',side_effect=clock.sleep), \
             patch('checker.curl',side_effect=responses) as request:
            row,line=c.probe(URI,'/fake/core',1000,c.DeepBudget(1))
        return row,line,request,launch,process

    def test_mid_quick_core_crash_is_infrastructure_failure(self):
        process=Mock();process.poll.side_effect=[None,None,1]
        with patch('checker.resolve_public',return_value=['8.8.8.8']), \
             patch('checker.subprocess.Popen',return_value=process), \
             patch('checker.time.sleep'),patch('checker.curl',return_value=(204,0,.1)):
            row,line=c.probe(URI,'/fake/core',c.time.monotonic()+1000,c.DeepBudget(1))
        self.assertEqual(row['reason'],'core-stopped')
        self.assertNotIn('deep_tested',row)
        self.assertIsNone(line)

    def test_core_crash_during_service_does_not_become_unconfirmed(self):
        process=Mock();process.poll.return_value=None
        responses=iter([(204,0,.1)]*2+deep())
        def request(*args,**kwargs):
            answer=next(responses)
            if args[0]=='https://www.youtube.com/':process.poll.return_value=1
            return answer
        with patch('checker.resolve_public',return_value=['8.8.8.8']), \
             patch('checker.subprocess.Popen',return_value=process), \
             patch('checker.time.sleep'),patch('checker.curl',side_effect=request):
            row,line=c.probe(URI,'/fake/core',c.time.monotonic()+1000,c.DeepBudget(1))
        self.assertEqual(row['reason'],'core-stopped')
        self.assertIsNone(line)
        self.assertFalse(any(row['service_qualified'].values()))

    def test_transient_timeout_gets_one_retry_and_keeps_evidence(self):
        row,line,*_=self.run_probe([c.RequestFailed('timeout',True),(204,0,.1),(204,0,.1)]+deep())
        self.assertTrue(row['service_qualified']['youtube']);self.assertIsNotNone(line)
        self.assertFalse(row['service_qualified']['chatgpt'])
        self.assertEqual([a['attempt'] for a in row['attempts'][:3]],[1,2,1])
        self.assertFalse(row['attempts'][0]['passed'])
        self.assertTrue(row['attempts'][1]['passed'])
        self.assertFalse(row['youtube_evidence']['video_playback_tested'])

    def test_auxiliary_site_failure_does_not_disqualify_stable_proxy(self):
        row,line,*_=self.run_probe([(204,0,.1),(403,0,.1)]+deep())
        self.assertIsNotNone(line)
        self.assertEqual(row['quick_endpoints_passed'],[c.QUICK_ENDPOINTS[0]])
        stable=[a for a in row['attempts'] if a['stage'].startswith('stability')]
        self.assertEqual([a['endpoint'] for a in stable],[c.QUICK_ENDPOINTS[0]]*3)

    def test_bad_certificate_not_retried_or_accepted(self):
        row,line,request,*_=self.run_probe([c.RequestFailed('tls-certificate'),c.RequestFailed('tls-certificate')])
        self.assertIsNone(line);self.assertEqual(request.call_count,2)
        self.assertEqual(row['reason'],'quick-https-failed')

    def test_retries_bounded(self):
        row,line,request,*_=self.run_probe([c.RequestFailed('timeout',True)]*4)
        self.assertIsNone(line);self.assertEqual(request.call_count,4)
        self.assertEqual(row['reason'],'quick-https-failed')

    def test_alternate_public_address_rechecks_quick_gate(self):
        row,line,request,launch,process=self.run_probe(
            [(403,0,.1)]*2+[(204,0,.1)]*2+deep(),['8.8.8.8','1.1.1.1'])
        self.assertIsNotNone(line);self.assertEqual(launch.call_count,2)
        self.assertEqual(process.terminate.call_count,2)
        self.assertEqual(row['tested_address'],'1.1.1.1')
        self.assertEqual({a['address'] for a in row['attempts']},{'8.8.8.8','1.1.1.1'})

    def test_slow_download_retried_then_still_requires_exact_good_two_samples(self):
        row,line,*_=self.run_probe([(204,0,.1)]*2+[(200,c.DOWNLOAD_BYTES,9)]+deep())
        self.assertIsNotNone(line)
        samples=[a for a in row['attempts'] if a['stage']=='download-1']
        self.assertEqual([a['passed'] for a in samples],[False,True])
        self.assertEqual(row['download_kib_s'],[512,512])

    def test_identity_stable_on_display_rename_but_not_connection_change(self):
        self.assertEqual(c.node_id(URI+'#one'),c.node_id(URI+'#two'))
        self.assertNotEqual(c.node_id(URI),c.node_id(URI+'&fp=firefox'))
        row,line,*_=self.run_probe([(204,0,.1)]*2+deep())
        self.assertEqual(line.split('#')[0],URI)
        self.assertEqual(row['id'],c.node_id(line))

    def test_curl_stderr_never_enters_diagnostic(self):
        diagnostic={}
        proc=Mock(returncode=60,stdout=b'000 0 0.2 0.1 0 0',stderr=b'RAW_PASSWORD_DO_NOT_LOG')
        with patch('checker.subprocess.run',return_value=proc):
            with self.assertRaises(c.RequestFailed) as error:
                c.curl('https://www.gstatic.com/generate_204',1080,diagnostic=diagnostic)
        self.assertFalse(error.exception.transient)
        self.assertEqual(diagnostic['error'],'tls-certificate')
        self.assertNotIn('RAW_PASSWORD',json.dumps(diagnostic))

    def test_all_dns_answers_checked_before_alternative_selection(self):
        proc=Mock(stdout=json.dumps(['8.8.8.8','1.1.1.1','9.9.9.9','10.0.0.1']))
        with patch('checker.subprocess.run',return_value=proc):
            with self.assertRaises(c.Rejected): c.resolve_public('example.org',all_addresses=True)

    def test_report_requires_fresh_proof_not_just_success_flags(self):
        row,line,*_=self.run_probe([(204,0,.1)]*2+deep())
        with patch('checker.download_feed',return_value=URI):
            _,_,sources,stats=c.collect_candidates()
        accepted={'both':[],'chatgpt':[],'youtube':[line]}
        with tempfile.TemporaryDirectory() as td:
            report=c.write_report(td,sources,stats,[row],accepted,c.utc_now())
            validate(td)
            mutations=[lambda r:r['results'][0].update(checked_at='2000-01-01T00:00:00+00:00'),
                lambda r:r['results'][0].update(attempts=[]),
                lambda r:r['probe_origin'].update(russia_verified=True),
                lambda r:r['results'][0]['attempts'][0].update(address='127.0.0.1'),
                lambda r:r['results'][0]['attempts'][0].update(error='RAW_PASSWORD')]
            for mutate in mutations:
                candidate=copy.deepcopy(report);mutate(candidate)
                (Path(td)/'report.json').write_text(json.dumps(candidate))
                with self.assertRaises(ValueError):validate(td)

if __name__=='__main__':unittest.main()
