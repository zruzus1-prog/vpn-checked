"""Offline staged-check, content-gating, budgets and output-integrity tests."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import checker as c
from validate_output import validate

URI='vless://12345678-1234-1234-1234-123456789abc@example.org:443?security=tls&sni=example.org'
YOUTUBE='<html><title>YouTube</title><script>var ytInitialData={};ytcfg.set({})</script></html>'
CHATGPT='<html><title>ChatGPT</title><script>window.__reactRouterContext={}</script></html>'


class Clock:
    def __init__(self): self.now=100.
    def monotonic(self): return self.now
    def sleep(self,seconds): self.now+=seconds


def success_responses(yt=YOUTUBE,gpt=CHATGPT):
    return [(204,0,.1)]*2+[(200,c.DOWNLOAD_BYTES,4)]+[(204,0,.2)]*3+[(200,c.DOWNLOAD_BYTES,4),
            (200,len(yt),.5,yt),(200,len(gpt),.5,gpt)]


class StrengthenedTests(unittest.TestCase):
    def run_probe(self,responses=None,budget=None):
        process=Mock(); process.poll.return_value=None
        clock=Clock()
        with patch('checker.resolve_public',return_value='8.8.8.8'), \
             patch('checker.subprocess.Popen',return_value=process) as launch, \
             patch('checker.time.monotonic',side_effect=clock.monotonic), \
             patch('checker.time.sleep',side_effect=clock.sleep), \
             patch('checker.curl',side_effect=responses or success_responses()) as request:
            result,line=c.probe(URI,'/fake/core',300,budget)
        return result,line,process,launch,request

    def test_both_services_and_45_seconds_required(self):
        result,line,process,launch,request=self.run_probe()
        self.assertTrue(result['qualified'])
        self.assertEqual(result['stability_seconds'],45)
        self.assertEqual(result['download_kib_s'],[512,512])
        self.assertEqual(result['min_kib_s'],512)
        self.assertEqual(len(request.call_args_list),9)
        launch.assert_called_once()
        process.terminate.assert_called_once()
        self.assertEqual(result['subscription_sha256'],hashlib.sha256(line.encode()).hexdigest())
        self.assertTrue(all(row.args[1]==request.call_args_list[0].args[1] for row in request.call_args_list))

    def test_mid_window_disconnect_is_rejected(self):
        responses=success_responses()
        responses[4]=c.Rejected('dropped after 30 seconds')
        result,line,*_=self.run_probe(responses)
        self.assertFalse(result['qualified']); self.assertIsNone(line)
        self.assertEqual(result['reason'],'stability-failed')

    def test_second_download_slow_is_rejected(self):
        responses=success_responses(); responses[6]=(200,c.DOWNLOAD_BYTES,9)
        result,line,*_=self.run_probe(responses)
        self.assertFalse(result['qualified']); self.assertIsNone(line)
        self.assertEqual(result['reason'],'throughput-failed')

    def test_no_service_downgrade(self):
        result,line,*_=self.run_probe(success_responses(gpt='<title>Just a moment</title>'))
        self.assertFalse(result['qualified'])
        self.assertTrue(result['service_qualified']['youtube'])
        self.assertFalse(result['service_qualified']['chatgpt'])
        self.assertIsNotNone(line)  # service-only feed, never primary

    def test_deep_cap_stops_before_bulk_download(self):
        result,line,_,_,request=self.run_probe(budget=c.DeepBudget(0))
        self.assertEqual(result['reason'],'deep-budget')
        self.assertIsNone(line); self.assertEqual(request.call_count,2)

    def test_global_deadline_rejects_before_core_start(self):
        with patch('checker.time.monotonic',return_value=100), patch('checker.resolve_public',return_value='8.8.8.8'), patch('checker.subprocess.Popen') as core:
            result,line=c.probe(URI,'/fake/core',105)
        core.assert_not_called(); self.assertIsNone(line)

    def test_deep_budget_thread_safe(self):
        from concurrent.futures import ThreadPoolExecutor
        budget=c.DeepBudget(7)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:budget.claim(),range(100)))
        self.assertEqual(sum(results),7); self.assertEqual(budget.used,7)

    def test_bounded_dns_timeout(self):
        with patch('checker.subprocess.run',side_effect=subprocess.TimeoutExpired('dns',5)) as run:
            with self.assertRaises(c.Rejected): c.resolve_public('example.org')
        self.assertEqual(run.call_args.kwargs['timeout'],5)

    def test_malformed_vmess_types_rejected(self):
        data={'add':'example.org','port':443,'id':'12345678-1234-1234-1234-123456789abc','tls':'tls'}
        for key,value in [('alpn',5),('port',float('inf')),('fp',[]),('path',None),('host',{}),('sni',False)]:
            case={**data,key:value}
            uri='vmess://'+base64.b64encode(json.dumps(case).encode()).decode()
            with self.subTest(key=key),self.assertRaises(ValueError): c.parse_uri(uri)

    def test_strict_service_content(self):
        self.assertEqual(c.service_label('youtube',200,YOUTUBE),'page-confirmed')
        self.assertEqual(c.service_label('chatgpt',200,CHATGPT),'page-confirmed')
        for name,page in [('youtube',YOUTUBE),('chatgpt',CHATGPT)]:
            for code in (204,301,302,403,429,500):
                with self.subTest(name=name,code=code):
                    self.assertNotEqual(c.service_label(name,code,page),'page-confirmed')
            for extra in ('Just a moment','Before you continue','cf-chl-foo','CAPTCHA','Verify you are human'):
                with self.subTest(name=name,extra=extra):
                    self.assertNotEqual(c.service_label(name,200,page+extra),'page-confirmed')
            self.assertNotEqual(c.service_label(name,200,'<html>OK</html>'),'page-confirmed')

    def artifact(self,path):
        result,line,*_=self.run_probe()
        for filename in c.FEEDS.values(): (path/filename).write_text(line+'\n')
        report={'schema_version':2,'completed_at':datetime.now(timezone.utc).isoformat(),
                'sampled':1,'deep_tested':1,'qualified':1,
                'feed_counts':{key:1 for key in c.FEEDS},'results':[result]}
        (path/'report.json').write_text(json.dumps(report))
        return report

    def test_fresh_three_feed_artifact_valid(self):
        with tempfile.TemporaryDirectory() as td:
            self.artifact(Path(td)); validate(td)

    def test_primary_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td);self.artifact(path)
            (path/'subscription.txt').write_text(URI+'#unrelated\n')
            with self.assertRaises(ValueError): validate(path)

    def test_primary_cannot_include_only_one_service(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td);report=self.artifact(path)
            report['results'][0]['service_qualified']['chatgpt']=False
            (path/'report.json').write_text(json.dumps(report))
            with self.assertRaises(ValueError): validate(path)

    def test_weak_or_inconsistent_report_rejected(self):
        mutations=[lambda r:r['results'][0].update(stability_seconds=44),
                   lambda r:r['results'][0].update(min_kib_s=255),
                   lambda r:r['results'][0].update(download_kib_s=[300]),
                   lambda r:r['results'][0].update(stability_seconds=float('nan')),
                   lambda r:r['results'][0].update(min_kib_s=True),
                   lambda r:r.update(sampled=True),lambda r:r.update(deep_tested=2),
                   lambda r:r['results'].append(copy.deepcopy(r['results'][0]))]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as td:
                path=Path(td);report=self.artifact(path);mutate(report)
                (path/'report.json').write_text(json.dumps(report))
                with self.assertRaises(ValueError): validate(path)

    def test_main_produces_separate_service_feeds(self):
        result,line,*_=self.run_probe(success_responses(gpt='<title>Just a moment</title>'))
        cwd=os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as td:
                os.chdir(td)
                def fake_probe(*args):
                    args[3].claim()
                    return result,line
                with patch('checker.download_feed',return_value=URI),patch('checker.probe',side_effect=fake_probe):
                    c.main()
                path=Path('public'); validate(path)
                self.assertEqual((path/'subscription.txt').read_text(),'')
                self.assertEqual((path/'subscription-gpt.txt').read_text(),'')
                self.assertEqual((path/'subscription-youtube.txt').read_text(),line+'\n')
        finally: os.chdir(cwd)


if __name__=='__main__': unittest.main()
