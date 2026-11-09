"""Offline integration: real prepare/manifest validation, synthetic remote history."""
import copy
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import cadence_limiter as l
import history as h
import production as p
import checker as c
from test_pipeline import feed, uri

NOW=datetime.now(timezone.utc)-timedelta(minutes=1)
HEAD='b'*40
ENV={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'100','GITHUB_RUN_ATTEMPT':'1','GITHUB_ACTIONS':'true',
     'GITHUB_EVENT_NAME':'schedule','GITHUB_REF':'refs/heads/main','GITHUB_REPOSITORY':'owner/repo','CADENCE_PUBLISH':'true'}
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name); self.ticket=self.root/'ticket.json'; self.manifest=self.root/'frozen/manifest.json'; self.output=self.root/'outputs'
        self.env=patch.dict(os.environ,{**ENV,'GITHUB_OUTPUT':str(self.output)},clear=True);self.env.start();self.addCleanup(self.env.stop)
        for target in ('checker.utc_now','production.now_iso'):
            mock=patch(target,return_value=NOW.isoformat());mock.start();self.addCleanup(mock.stop)
        self.state=h.empty(NOW.isoformat());self.provenance={'checked_commit':HEAD,'authenticated_snapshots':0,'mode':'expired-history'}
    def state_with(self,age=3600,run_id='90'):
        state=h.empty(NOW.isoformat())
        state['runs']=[{'run_id':run_id,'run_attempt':'1','implementation_sha':'a'*40,'snapshot_at':(NOW-timedelta(seconds=age)).isoformat(),'event':'schedule'}]
        return state
    def reserve(self,state=None,provenance=None):
        loader=Mock(return_value=(state or self.state,provenance or self.provenance))
        result=l.reserve(self.ticket,clock=lambda:NOW,loader=loader)
        return result,loader
    def prepare(self,state=None,provenance=None):
        with patch('history.load_remote',return_value=(state or self.state,provenance or self.provenance)) as load, patch('checker.download_feed',side_effect=lambda _:feed(uri())):
            result=l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW)
        self.assertEqual(load.call_count,1)
        return result
    def assert_no_outputs(self): self.assertFalse(self.output.exists())
    def test_full_real_prepare_and_digest_outputs(self):
        ticket,loader=self.reserve(self.state_with())
        self.assertEqual(loader.call_count,1)
        manifest=self.prepare(self.state_with())
        self.assertEqual(manifest['history']['provenance']['checked_commit'],HEAD)
        values=dict(line.split('=',1) for line in self.output.read_text().splitlines())
        self.assertEqual(values['history_commit'],HEAD)
        self.assertEqual(values['manifest_sha256'],p.digest(self.manifest.read_bytes()))
        self.assertEqual(json.loads(values['matrix']),{'include':[{'shard':'000'}]})
    def test_clock_before_slot_never_collects(self):
        self.reserve(self.state_with(age=1800))
        prepare=Mock()
        with self.assertRaises(ValueError): l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW,prepare=prepare)
        prepare.assert_not_called();self.assert_no_outputs()
    def test_intervening_checked_writer_fails_before_outputs(self):
        self.reserve()
        changed={**self.provenance,'checked_commit':'c'*40}
        with self.assertRaises(ValueError): self.prepare(provenance=changed)
        self.assert_no_outputs()
    def test_same_head_but_too_recent_final_history_fails(self):
        self.reserve()
        with self.assertRaises(ValueError): self.prepare(self.state_with(age=60))
        self.assert_no_outputs()
    def test_final_capacity_rechecked(self):
        self.reserve()
        state=h.empty(NOW.isoformat())
        state['runs']=[{'run_id':str(i+1),'run_attempt':'1','implementation_sha':'a'*40,'snapshot_at':(NOW-timedelta(seconds=(64-i)*61)).isoformat(),'event':'schedule'} for i in range(64)]
        # Latest is too recent AND64 slots are occupied; direct final verifier must reject.
        manifest={'created_at':NOW.isoformat(),'run_id':'100','history':{'state':state,'provenance':self.provenance}}
        with self.assertRaises(ValueError): l.verify_final(manifest,l.read_ticket(self.ticket))
    def test_initial_history_error_is_fatal(self):
        loader=Mock(side_effect=ValueError('secret-content'))
        with self.assertRaises(ValueError): l.reserve(self.ticket,clock=lambda:NOW,loader=loader)
        self.assertFalse(self.ticket.exists());self.assert_no_outputs()
    def test_final_history_error_is_fatal_and_environment_restored(self):
        self.reserve()
        with patch('history.load_remote',side_effect=ValueError('bad history')),patch('checker.download_feed',side_effect=lambda _:feed(uri())):
            with self.assertRaises(ValueError): l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW)
        self.assertEqual(os.environ['GITHUB_OUTPUT'],str(self.output));self.assert_no_outputs()
    def test_sources_fail_no_fallback_to_existing_publication(self):
        self.reserve()
        with patch('checker.download_feed',side_effect=OSError('offline')):
            with self.assertRaises((OSError,ValueError)): l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW)
        self.assert_no_outputs()
    def test_manual_publish_waits(self):
        os.environ['GITHUB_EVENT_NAME']='workflow_dispatch'
        ticket,loader=self.reserve(self.state_with(age=60))
        self.assertTrue(ticket['publishing']);self.assertEqual(loader.call_count,1)
        self.assertEqual(h.stamp(ticket['not_before']),NOW+timedelta(seconds=3540))
    def test_manual_dryrun_no_wait_but_final_history_still_mandatory(self):
        os.environ.update(GITHUB_EVENT_NAME='workflow_dispatch',CADENCE_PUBLISH='false')
        ticket,loader=self.reserve(self.state_with(age=60))
        loader.assert_not_called();self.assertFalse(ticket['publishing'])
        self.prepare(self.state_with(age=60))
    def test_schedule_cannot_disable_limiter(self):
        os.environ['CADENCE_PUBLISH']='false'
        with self.assertRaises(ValueError):self.reserve()
    def test_nonmain_cannot_publish(self):
        os.environ.update(GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/other')
        with self.assertRaises(ValueError):self.reserve()
    def test_ticket_cannot_cross_runs_attempts_or_implementations(self):
        self.reserve()
        for key,value in [('GITHUB_RUN_ID','101'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_SHA','d'*40)]:
            with patch.dict(os.environ,{key:value}):
                with self.assertRaises(ValueError):l.read_ticket(self.ticket)
    def test_crash_before_publication_rerun_not_reserved_forever(self):
        self.reserve(self.state_with(age=3600))
        os.environ['GITHUB_RUN_ATTEMPT']='2'
        # New ticket re-reads unchanged successful history; prior ticket is not a durable lease.
        ticket,_=self.reserve(self.state_with(age=3600))
        self.assertEqual(ticket['run_attempt'],'2');self.assertEqual(h.stamp(ticket['not_before']),NOW)
    def test_crash_after_publication_same_run_id_rejected(self):
        os.environ['GITHUB_RUN_ATTEMPT']='2'
        with self.assertRaises(ValueError):self.reserve(self.state_with(age=3600,run_id='100'))
        self.assert_no_outputs()
    def test_final_same_run_id_rejected(self):
        self.reserve()
        manifest={'created_at':NOW.isoformat(),'run_id':'100','history':{'state':self.state_with(run_id='100'),'provenance':self.provenance}}
        with self.assertRaises(ValueError):l.verify_final(manifest,l.read_ticket(self.ticket))
    def test_malformed_ticket_fails_closed(self):
        self.ticket.write_text('{not-json')
        with self.assertRaises(ValueError):l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW)
        self.assert_no_outputs()
    def test_backward_clock_fails_before_wait(self):
        self.reserve()
        with self.assertRaises(ValueError):l.wait_ticket(self.ticket,clock=lambda:NOW-timedelta(seconds=1))
    def test_forward_clock_cannot_override_final_manifest_timestamp(self):
        self.reserve(self.state_with(age=1800))
        with patch('history.load_remote',return_value=(self.state,self.provenance)),patch('checker.download_feed',side_effect=lambda _:feed(uri())):
            with self.assertRaises(ValueError):l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW+timedelta(hours=2))
        self.assert_no_outputs()
    def test_sanitized_cli_failure(self):
        with patch('cadence_limiter.main',side_effect=ValueError('SECRET')),patch('production.emit_diagnostic') as emit:
            self.assertEqual(l.run_cli(),1)
            record=p.diagnostic_record('failure',emit.call_args.args[1]);self.assertNotIn('SECRET',json.dumps(record))
    def test_workflow_structure_and_unchanged_publication_lease(self):
        text=(Path(l.__file__).parent/'.github/workflows/check.yml').read_text()
        self.assertIn("- cron: '23 * * * *'",text);self.assertIn("- cron: '53 * * * *'",text)
        self.assertIn('group: checked-subscription\n  cancel-in-progress: false',text)
        self.assertIn('timeout-minutes: 111',text)
        self.assertIn('timeout-minutes: 62',text)
        self.assertEqual(text.count('continue-on-error: true'),4)
        self.assertIn('git push --force-with-lease="refs/heads/checked:$expected"',text)
        self.assertIn('test "$expected" = "$HISTORY_COMMIT"',text)
        self.assertIn("(github.event_name == 'workflow_dispatch' && inputs.publish == true)",text)
    def test_real_history_update_survives_adversarial_half_hour_requests(self):
        start=NOW-timedelta(days=10)
        state=h.empty(start.isoformat())
        last=start
        for index in range(240):
            requested=max(start+timedelta(minutes=30*index),last)
            state=h.prune(state,requested)
            due=l.not_before(state,now=requested)
            state=h.update(state,[],[],at=due.isoformat(),implementation_sha='a'*40,
                           run_id=str(index+1),run_attempt='1',event='schedule')
            self.assertLessEqual(len(state['runs']),49)
            self.assertLessEqual(len(h.encoded(state)),h.MAX_BYTES)
            last=due
        self.assertEqual(len(state['runs']),49)
    def test_failed_attempt_does_not_advance_success_history(self):
        ticket,_=self.reserve(self.state_with(age=3600))
        with patch('checker.download_feed',side_effect=OSError('offline')):
            with self.assertRaises((OSError,ValueError)):l.prepare_slot(self.ticket,self.manifest,clock=lambda:NOW)
        next_ticket,_=self.reserve(self.state_with(age=3600))
        self.assertEqual(ticket['not_before'],next_ticket['not_before'])
        self.assert_no_outputs()
    def test_predecessor_explicitly_trusted_without_cap_changes(self):
        self.assertIn('efbc10a5eb4b7f0d3b67934b4c971f7bbe6beb6e',h.BOOTSTRAP_IMPLEMENTATIONS)
        self.assertEqual((h.MAX_RUNS,h.MAX_ANCHOR_RUNS,h.MAX_BYTES),(64,64,48*1024*1024))
if __name__=='__main__':unittest.main()
