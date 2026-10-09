"""Scheduling/capacity change keeps measurements intact and metadata bounded."""
import copy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import history as h
import publish_status as status
from test_history import history_for, NOW


class SpeedTrialTests(unittest.TestCase):
    def test_exact_live_run_budget(self):
        state, _, _ = history_for(hours=tuple(reversed([i / 2 for i in range(64)])))
        self.assertEqual(len(state['runs']), 64)
        h.validate(state, now=NOW)
        bad = copy.deepcopy(state)
        extra = dict(bad['runs'][-1], run_id='999', snapshot_at=(NOW+timedelta(seconds=1)).isoformat())
        bad['runs'].append(extra)
        bad['created_at'] = extra['snapshot_at']
        with self.assertRaises(ValueError):
            h.validate(bad, now=NOW+timedelta(seconds=1))
        self.assertEqual(h.MAX_BYTES, 48*1024*1024)
        self.assertEqual(h.MAX_AGE_SECONDS, 48*3600)
        self.assertEqual(h.MIN_RUN_GAP_SECONDS, 90*60)

    def test_commit_metadata_fetch_is_bounded_to_four_pages(self):
        calls = []
        commit = {'sha': 'a'*40, 'commit': {'committer': {'date': NOW.isoformat()}}}
        class ReachedReport(Exception): pass
        def read(url, maximum, token=None):
            calls.append(url)
            if '/commits?' in url:
                return h.encoded([commit] * 32)
            raise ReachedReport()
        with patch.object(h, 'remote_read', side_effect=read), self.assertRaises(ReachedReport):
            h.load_remote('owner/repo', None, now=NOW)
        pages = [u for u in calls if '/commits?' in u]
        self.assertEqual(len(pages), 4)
        self.assertTrue(pages[-1].endswith('page=4'))

    def test_status_separates_times_without_changing_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {'started_at':'2026-10-09T00:00:00+00:00',
                      'completed_at':'2026-10-09T00:30:00+00:00',
                      'production':{'run_id':'123'}}
            originals = {'report.json':json.dumps(report).encode(),
                         'subscription-youtube-stable.txt':b'ss://unchanged#label\n',
                         'subscription-youtube-reserve.txt':b''}
            for name, data in originals.items(): (root/name).write_bytes(data)
            text = status.write_status(root, '2026-10-09T00:31:00Z')
            for name, data in originals.items(): self.assertEqual((root/name).read_bytes(), data)
            self.assertIn('00:31:00Z', text)
            self.assertIn('00:30:00+00:00', text)
            self.assertIn('00:00:00+00:00', text)
            self.assertIn('**1**; резерв: **0**', text)
            with self.assertRaises(ValueError): status.write_status(root, '2026-10-09T00:01:00Z')
            with self.assertRaises(ValueError): status.write_status(root, '2026-10-09T00:31:00+03:00')

    def test_workflow_scope(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/check.yml').read_text()
        self.assertIn("cron: '23 * * * *'", workflow)
        self.assertIn('max-parallel: 8', workflow)
        self.assertIn('export GIT_AUTHOR_DATE="$publication_at" GIT_COMMITTER_DATE="$publication_at"', workflow)
        self.assertLess(workflow.index('production.py verify-public'), workflow.index('python3 publish_status.py'))
        self.assertIn('history.json report.json STATUS.md LICENSE', workflow)
        self.assertIn('144c2dea096443d2db6829fe0a8e61e88abdf6b2', h.BOOTSTRAP_IMPLEMENTATIONS)
