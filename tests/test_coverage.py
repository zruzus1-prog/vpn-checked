"""Offline coverage/accounting and bounded built-in obfs compatibility tests."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.parse as U
import uuid
from unittest.mock import Mock, patch

import checker as c
from validate_output import validate


def vless(index=1,extra=''):
    return f'vless://{uuid.UUID(int=index)}@example.org:443?security=tls&sni=example.org'+extra


def ss(plugin,method='chacha20-ietf-poly1305'):
    auth=base64.urlsafe_b64encode((method+':synthetic-secret').encode()).decode().rstrip('=')
    return 'ss://'+auth+'@example.org:2377?plugin='+U.quote(plugin,safe='')


class PluginTests(unittest.TestCase):
    def test_builtin_tls_obfs_keeps_opaque_host_and_connection_uri(self):
        camouflage='(Notice🇨🇦 @example)opaque:137563'
        uri=ss('obfs-local;obfs=tls;obfs-host='+camouflage)+'#'+U.quote('🇺🇸 Source label')
        parsed=c.parse_uri(uri)
        self.assertEqual(parsed['plugin'],'obfs-local')
        self.assertEqual(parsed['plugin_opts'],'obfs=tls;obfs-host='+camouflage)
        self.assertNotIn('tls',parsed)  # camouflage is not certificate-verified TLS
        self.assertEqual(parsed['server'],'example.org')
        self.assertEqual(parsed['server_port'],2377)
        exported=c.export_with_label(uri,{'id':'a'*16})
        self.assertEqual(uri.split('#')[0],exported.split('#')[0])
        self.assertEqual(c.parse_uri(exported),parsed)

    def test_plugin_option_order_is_canonical(self):
        self.assertEqual(c.parse_uri(ss('obfs-local;obfs=tls;obfs-host=example.org')),
                         c.parse_uri(ss('obfs-local;obfs-host=example.org;obfs=tls')))

    def test_rejects_other_plugins_modes_commands_and_ambiguous_options(self):
        values=['','/bin/sh;obfs=tls;obfs-host=x','v2ray-plugin;obfs=tls;obfs-host=x',
                'obfs-local;obfs=http;obfs-host=x','obfs-local;obfs=tls',
                'obfs-local;obfs=tls;obfs=tls','obfs-local;obfs=tls;obfs-host=x;exec=bad',
                'obfs-local;obfs=tls;obfs-host=x\\;exec=bad',
                'obfs-local;obfs=tls;obfs-host=x=y',
                'obfs-local;obfs=tls;obfs-host=',
                'obfs-local;obfs=tls;obfs-host=x\r\nInjected: value',
                'obfs-local;obfs=tls;obfs-host=\u202ex',
                'obfs-local;obfs=tls;obfs-host=x\u2028injected',
                'obfs-local;obfs=tls;obfs-host='+'🇨🇦'*40]
        for value in values:
            with self.subTest(value=value),self.assertRaises(ValueError): c.parse_uri(ss(value))

    def test_plugin_cannot_relax_cipher_tls_or_other_protocols(self):
        plugin='obfs-local;obfs=tls;obfs-host=x'
        for uri in (ss(plugin,'none'),ss(plugin)+'&insecure=1',
                    vless()+'&plugin='+U.quote(plugin,safe='')):
            with self.subTest(uri=uri),self.assertRaises(ValueError): c.parse_uri(uri)

    def test_legacy_ss_authority_with_plugin(self):
        auth=base64.urlsafe_b64encode(b'aes-256-gcm:synthetic@example.org:443').decode()
        parsed=c.parse_uri('ss://'+auth+'?plugin='+U.quote('obfs-local;obfs=tls;obfs-host=x'))
        self.assertEqual(parsed['plugin'],'obfs-local')
        self.assertEqual(parsed['server_port'],443)


class CoverageTests(unittest.TestCase):
    def collect(self,feeds):
        with patch('checker.download_feed',side_effect=feeds+['']*(len(c.SOURCES)-len(feeds))):
            return c.collect_candidates()

    def test_source_counts_dedup_endpoints_and_no_secret_diagnostics(self):
        first=vless()+'#name-one'
        duplicate=vless()+'#name-two'
        alternate=vless(extra='&fp=firefox')
        unsafe=vless(2)+'&insecure=1'
        unsupported=vless(3)+'&unknownOption=none'
        malformed='vless://SECRET_INVALID_UUID@example.org:443?security=tls'
        normalized,provenance,sources,stats=self.collect([
            '\n'.join([first,duplicate,alternate,unsafe]),
            '\n'.join([duplicate,unsupported,malformed]),c.Rejected('unavailable')])
        self.assertEqual(stats['raw_lines'],7)
        self.assertEqual(stats['supported_lines'],4)
        self.assertEqual(stats['unique_candidates'],2)
        self.assertEqual(stats['unique_endpoints'],1)
        self.assertEqual(stats['duplicate_supported_lines'],2)
        self.assertEqual(stats['cross_source_duplicate_candidates'],1)
        self.assertEqual(sources[0]['rejection_categories'],{'insecure-tls-requested':1})
        self.assertEqual(sources[1]['rejection_categories'],{'unsupported-option':1,'malformed':1})
        self.assertEqual(sorted(len(v) for v in provenance.values()),[1,2])
        self.assertNotIn('SECRET_INVALID_UUID',json.dumps([sources,stats]))
        self.assertFalse(c.coverage_summary(sources,2,[{},{}])['complete_supported'])

    def test_disabled_insecure_flags_are_not_reported_as_enabled(self):
        for flag in ('insecure=0','allowInsecure=false'):
            uri=vless()+'&'+flag
            self.assertEqual(c.parse_uri(uri),c.parse_uri(vless()))

    def test_selection_is_deterministic_and_does_not_randomly_omit_under_cap(self):
        normalized={json.dumps(c.parse_uri(vless(i)),sort_keys=True,separators=(',',':')):vless(i)
                    for i in range(1,173)}
        self.assertEqual(len(c.select_candidates(normalized)),172)
        self.assertEqual(c.select_candidates(normalized),c.select_candidates(dict(reversed(list(normalized.items())))))

    def test_line_cap_is_a_source_failure_not_silent_truncation(self):
        with patch('checker.MAX_FEED_LINES',2):
            with self.assertRaises(c.Rejected): c.feed_lines('\n'.join([vless()]*3))

    def main_artifact(self,root,total=172,reason='throughput-failed',source_failure=False):
        feed='\n'.join(vless(i) for i in range(1,total+1))
        calls=[]
        def fake_probe(uri,core,deadline,budget):
            calls.append(uri)
            deep=reason not in ('budget','deep-budget','quick-https-failed')
            if deep: self.assertTrue(budget.claim())
            return {'id':c.node_id(uri),'identity_version':c.CANONICALIZATION_VERSION,
                    'checked_at':c.utc_now(),'completed_at':c.utc_now(),'attempts':[],
                    'qualified':False,'baseline_qualified':False,'deep_tested':deep,
                    'service_qualified':{'youtube':False,'chatgpt':False},'reason':reason},None
        cwd=os.getcwd()
        try:
            os.chdir(root)
            feeds=[feed,feed,c.Rejected('unavailable') if source_failure else feed]+['']*(len(c.SOURCES)-3)
            with patch('checker.download_feed',side_effect=feeds),patch('checker.probe',side_effect=fake_probe):
                c.main()
            validate(Path(root)/'public')
            report=json.loads((Path(root)/'public/report.json').read_text())
        finally: os.chdir(cwd)
        return report,calls

    def test_all_172_candidates_can_receive_deep_checks(self):
        with tempfile.TemporaryDirectory() as td:
            report,calls=self.main_artifact(td)
        self.assertEqual(len(set(calls)),172)
        self.assertEqual(report['deep_tested'],172)
        self.assertTrue(report['coverage']['complete_supported'])
        self.assertEqual(report['coverage']['completed_assessments'],172)

    def test_above_cap_fails_without_silent_sampling(self):
        with tempfile.TemporaryDirectory() as td, self.assertRaises(RuntimeError):
            self.main_artifact(td,c.MAX_CANDIDATES+1)

    def test_deadline_deep_cap_and_missing_source_prevent_publication(self):
        for reason,missing in [('budget',False),('deep-budget',False),('quick-https-failed',True)]:
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as td,self.assertRaises(RuntimeError):
                self.main_artifact(td,2,reason,missing)

    def test_publisher_rejects_tampered_complete_and_counts(self):
        with tempfile.TemporaryDirectory() as td:
            report,_=self.main_artifact(td,2)
            mutations=[lambda r:r['coverage'].update(complete_supported=False),
                       lambda r:r['coverage'].update(candidate_cap_skipped=1),
                       lambda r:r['coverage'].update(deadline_skipped=False),
                       lambda r:r['sources'][0].update(supported_lines=1),
                       lambda r:r['sources'][0]['rejection_categories'].update(SECRET=1),
                       lambda r:r.update(unique_candidates=1)]
            path=Path(td)/'public'
            for mutate in mutations:
                case=copy.deepcopy(report);mutate(case)
                (path/'report.json').write_text(json.dumps(case))
                with self.assertRaises(ValueError): validate(path)

    def test_deadline_during_service_is_not_misreported_as_network_failure(self):
        process=Mock();process.poll.return_value=None
        responses=[(204,0,.1)]*2+[(200,c.DOWNLOAD_BYTES,4)]+[(204,0,.1)]*3+[(200,c.DOWNLOAD_BYTES,4),c.BudgetExceeded('deadline')]
        with patch('checker.resolve_public',return_value='8.8.8.8'),patch('checker.subprocess.Popen',return_value=process),patch('checker.time.sleep'),patch('checker.curl',side_effect=responses):
            result,line=c.probe(vless(),'/fake/core',c.time.monotonic()+180)
        self.assertEqual(result['reason'],'budget')
        self.assertFalse(result['qualified']);self.assertIsNone(line)
        self.assertFalse(any(result['service_qualified'].values()))


class CompatibilityTests(unittest.TestCase):
    def test_vless_packet_encoding_preserves_explicit_empty(self):
        self.assertEqual(c.parse_uri(vless())['packet_encoding'],'xudp')
        self.assertEqual(c.parse_uri(vless(extra='&packetEncoding=xudp')),c.parse_uri(vless()))
        self.assertEqual(c.parse_uri(vless(extra='&packetEncoding='))['packet_encoding'],'')
        self.assertEqual(c.parse_uri(vless(extra='&packetEncoding=packetaddr'))['packet_encoding'],'packetaddr')
        with self.assertRaises(ValueError): c.parse_uri(vless(extra='&packetEncoding=unknown'))

    def test_raw_tcp_and_none_header_have_equal_effective_config(self):
        baseline=c.parse_uri(vless())
        for options in ('&type=raw','&type=tcp&headerType=none','&type=raw&headertype=none'):
            self.assertEqual(c.parse_uri(vless(extra=options)),baseline)
        for options in ('&headerType=http','&headerType=none&headertype=none',
                        '&type=ws&headerType=none','&headerType=',
                        '&type=xhttp&headerType=none'):
            with self.subTest(options=options),self.assertRaises(ValueError): c.parse_uri(vless(extra=options))

    def test_hy2_zero_only_bandwidth_and_no_tls_downgrade(self):
        uri='hysteria2://synthetic@example.org:443?sni=example.org'
        self.assertEqual(c.parse_uri(uri),c.parse_uri(uri+'&upmbps=0'))
        self.assertEqual(c.parse_uri(uri)['up_mbps'],0)
        for option in ('upmbps=10','upmbps=-1','upmbps=unlimited','upmbps=0&insecure=1'):
            with self.subTest(option=option),self.assertRaises(ValueError): c.parse_uri(uri+'&'+option)

    def test_new_options_cannot_be_silently_ignored_on_other_protocols(self):
        for option in ('packetEncoding=xudp','headerType=none','upmbps=0'):
            with self.subTest(option=option),self.assertRaises(ValueError):
                c.parse_uri('trojan://synthetic@example.org:443?'+option)

    def test_capacity_and_probe_gates_remain_bounded(self):
        self.assertEqual((c.MAX_CANDIDATES,c.MAX_DEEP,c.WORKERS,c.BUDGET),(2048,2048,4,5400))
        self.assertEqual((c.STABILITY_SECONDS,c.DOWNLOAD_BYTES,c.MIN_BYTES_PER_SECOND),(45,2*1024*1024,256*1024))


if __name__=='__main__': unittest.main()
