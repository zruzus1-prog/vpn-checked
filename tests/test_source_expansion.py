"""Seventh-source rollout without relaxing historical or current inventories."""
from datetime import datetime,timezone
import copy
import unittest
from unittest.mock import patch

import checker as c
import history as h
import validate_output as v
import test_history as fixtures


RADIKAL='https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt'


class SourceExpansionTests(unittest.TestCase):
    def test_exact_seventh_source_and_legacy_allowlists(self):
        self.assertEqual(len(c.SOURCES),7)
        self.assertEqual(c.SOURCES[-1],RADIKAL)
        self.assertEqual(h.CURRENT_SOURCE_INVENTORY,tuple(c.SOURCES))
        self.assertEqual(h.LEGACY_SOURCE_INVENTORY,tuple(c.SOURCES[:6]))

    def test_archival_scope_restores_current_inventory_even_after_failure(self):
        before=c.SOURCES,v.SOURCES
        with self.assertRaisesRegex(RuntimeError,'fixture'):
            with h.archived_source_inventory({'sources':[{'url':url} for url in c.SOURCES[:6]]}):
                self.assertEqual(len(c.SOURCES),6)
                self.assertIs(v.SOURCES,c.SOURCES)
                raise RuntimeError('fixture')
        self.assertIs(c.SOURCES,before[0]);self.assertIs(v.SOURCES,before[1])
        self.assertEqual(len(c.SOURCES),7)

    def test_arbitrary_or_partial_archive_source_inventory_rejected(self):
        inventories=[c.SOURCES[:5],list(reversed(c.SOURCES)),c.SOURCES[:6]+['https://attacker.invalid/feed']]
        for inventory in inventories:
            with self.subTest(inventory=inventory),self.assertRaises(ValueError):
                with h.archived_source_inventory({'sources':[{'url':url} for url in inventory]}):
                    self.fail('untrusted source inventory admitted')

    def test_new_identity_only_enters_reserve_after_one_fresh_pass(self):
        item=fixtures.candidate(900);item['sources']=[RADIKAL]
        state=h.empty(fixtures.NOW.isoformat())
        result=fixtures.row(item)
        state=h.update(state,[item],[result],at=fixtures.NOW.isoformat(),implementation_sha='1'*40,
                       run_id='1234',run_attempt='1',event='schedule')
        split,_=h.split(state,[result],{item['id']:item['uri']})
        self.assertEqual(split,{'stable':[],'reserve':[item['uri']]})

    def test_experimental_run_cannot_authenticate_production_history(self):
        report,commit,run,jobs=fixtures.AuthenticationTests().fixtures()
        run['path']='.github/workflows/radikal-trial.yml'
        with patch('history.remote_read',side_effect=[h.encoded(run),h.encoded(jobs)]),self.assertRaises(ValueError):
            h.authenticate_publication('owner/repo',commit,report,None,now=fixtures.NOW)
