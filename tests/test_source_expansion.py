"""Explicit source retirement with strict current coverage and authenticated replay."""
from datetime import datetime,timedelta,timezone
import json
import copy
import unittest
from unittest.mock import patch

import checker as c
import history as h
import validate_output as v
import test_history as fixtures
import test_pipeline as pipeline
import production as p


RADIKAL='https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt'


class SourceExpansionTests(unittest.TestCase):
    def test_exact_six_active_sources_and_fixed_legacy_allowlists(self):
        self.assertEqual(len(c.SOURCES),6)
        self.assertNotIn(h.RETIRED_SOURCE,c.SOURCES)
        self.assertEqual(c.SOURCES[-1],RADIKAL)
        self.assertEqual(h.CURRENT_SOURCE_INVENTORY,tuple(c.SOURCES))
        self.assertEqual(h.LEGACY_SOURCE_INVENTORY,h.HISTORICAL_SOURCE_INVENTORY[:-1])
        self.assertEqual(len(h.LEGACY_SOURCE_INVENTORY),6)
        self.assertEqual(len(h.HISTORICAL_SOURCE_INVENTORY),7)
        self.assertIn(h.RETIRED_SOURCE,h.LEGACY_SOURCE_INVENTORY)
        self.assertIn('2e555fd711f2d3fdcc1f9ff2c3f2b2e37d106d77',h.BOOTSTRAP_IMPLEMENTATIONS)

    def test_archival_scope_restores_current_inventory_even_after_failure(self):
        before=c.SOURCES,v.SOURCES
        with self.assertRaisesRegex(RuntimeError,'fixture'):
            with h.archived_source_inventory({'sources':[{'url':url} for url in h.HISTORICAL_SOURCE_INVENTORY]}):
                self.assertEqual(len(c.SOURCES),7)
                self.assertIs(v.SOURCES,c.SOURCES)
                raise RuntimeError('fixture')
        self.assertIs(c.SOURCES,before[0]);self.assertIs(v.SOURCES,before[1])
        self.assertEqual(len(c.SOURCES),6)

    def test_arbitrary_or_partial_archive_source_inventory_rejected(self):
        inventories=[c.SOURCES[:5],list(reversed(c.SOURCES)),c.SOURCES[:6]+['https://attacker.invalid/feed']]
        for inventory in inventories:
            with self.subTest(inventory=inventory),self.assertRaises(ValueError):
                with h.archived_source_inventory({'sources':[{'url':url} for url in inventory]}):
                    self.fail('untrusted source inventory admitted')

    def test_new_identity_is_explicit_diversity_trial_after_one_fresh_pass(self):
        item=fixtures.candidate(900);item['sources']=[RADIKAL]
        state=h.empty(fixtures.NOW.isoformat())
        result=fixtures.row(item)
        state=h.update(state,[item],[result],at=fixtures.NOW.isoformat(),implementation_sha='1'*40,
                       run_id='1234',run_attempt='1',event='schedule')
        split,proof=h.split(state,[result],{item['id']:item['uri']})
        self.assertEqual(split,{'stable':[item['uri']],'reserve':[]})
        self.assertFalse(proof['evidence'][item['id']]['eligible'])
        self.assertEqual(proof['evidence'][item['id']]['tier'],'fresh-diversity')
        self.assertEqual(proof['selection']['selected_tier_counts']['fresh-diversity'],1)

    def test_experimental_run_cannot_authenticate_production_history(self):
        report,commit,run,jobs=fixtures.AuthenticationTests().fixtures()
        run['path']='.github/workflows/radikal-trial.yml'
        with patch('history.remote_read',side_effect=[h.encoded(run),h.encoded(jobs)]),self.assertRaises(ValueError):
            h.authenticate_publication('owner/repo',commit,report,None,now=fixtures.NOW)


class RetiredSourceReplayTests(unittest.TestCase):
    setUp = pipeline.PipelineTests.setUp
    run_shards = pipeline.PipelineTests.run_shards

    def publications(self):
        """Real old-six -> old-seven -> active-six -> next-active-six artifacts."""
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return pipeline.TEST_CLOCK[0] + timedelta(seconds=5)
        now = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
        api = 'https://api.github.com/repos/owner/repo'
        commits, remote, manifests = [], {}, []
        previous = 'f' * 40
        def read(url, maximum, token=None):
            data = remote[url]
            self.assertLessEqual(len(data), maximum)
            return data
        inventories = (h.LEGACY_SOURCE_INVENTORY, h.HISTORICAL_SOURCE_INVENTORY,
                       h.CURRENT_SOURCE_INVENTORY, h.CURRENT_SOURCE_INVENTORY)
        for index, (hours, inventory) in enumerate(zip((36, 30, 4, 1), inventories)):
            pipeline.TEST_CLOCK[0] = now - timedelta(hours=hours)
            implementation = '2e555fd711f2d3fdcc1f9ff2c3f2b2e37d106d77' if index < 2 else '1' * 40
            def download(url):
                if index >= 2:
                    self.assertNotEqual(url, h.RETIRED_SOURCE)
                # One retired-only, one mixed, one active-only identity.
                values = (900, 901) if url == h.RETIRED_SOURCE else (1, 901)
                return pipeline.feed('\n'.join(pipeline.uri(i) for i in values))
            if not index:
                state = h.empty(pipeline.TEST_CLOCK[0].isoformat())
                provenance = {'checked_commit': previous, 'authenticated_snapshots': 0,
                              'mode': 'expired-history'}
            else:
                with patch('history.remote_read', side_effect=read):
                    state, provenance = h.load_remote('owner/repo', None, now=pipeline.TEST_CLOCK[0])
            with h.archived_source_inventory({'sources': [{'url': u} for u in inventory]}), \
                 patch.object(p, 'datetime', Clock), patch.object(v, 'datetime', Clock), \
                 patch('history.load_remote', return_value=(state, provenance)), \
                 patch('checker.download_feed', side_effect=download) as downloaded, \
                 patch.dict('os.environ', {'GITHUB_RUN_ID': str(100 + index),
                                          'GITHUB_SHA': implementation,
                                          'GITHUB_EVENT_NAME': 'schedule'}):
                manifest = p.prepare(self.manifest_path, use_history=True)
                manifests.append(copy.deepcopy(manifest))
                self.run_shards(manifest, pipeline.successful_probe)
                p.merge(self.manifest_path, self.shards, self.output)
                report = p.verify_public(self.manifest_path, self.output)
                self.assertEqual(downloaded.call_count, len(inventory))
                self.assertEqual(report['coverage']['sources_expected'], len(inventory))
                self.assertTrue(report['coverage']['complete_supported'])
            done = p.instant(report['completed_at'])
            sha = f'{index + 1:040x}'
            commit = {'sha': sha, 'parents': [{'sha': previous}], 'commit': {
                'committer': {'name': 'github-actions[bot]',
                              'email': '41898282+github-actions[bot]@users.noreply.github.com',
                              'date': (done + timedelta(seconds=1)).isoformat()}}}
            run = {'id': 100 + index, 'run_attempt': 1, 'conclusion': 'success',
                   'status': 'completed', 'repository': {'full_name': 'owner/repo'},
                   'head_repository': {'full_name': 'owner/repo'}, 'head_branch': 'main',
                   'head_sha': implementation, 'path': '.github/workflows/check.yml',
                   'event': 'schedule', 'run_started_at': report['started_at'],
                   'updated_at': (done + timedelta(seconds=2)).isoformat()}
            root = 'https://raw.githubusercontent.com/owner/repo/' + sha + '/'
            remote.update({root + path.name: path.read_bytes() for path in self.output.iterdir()})
            remote[api + '/actions/runs/' + str(100 + index) + '/attempts/1'] = h.encoded(run)
            remote[api + '/actions/runs/' + str(100 + index) + '/attempts/1/jobs?per_page=100'] = h.encoded({
                'total_count': 1, 'jobs': [{'name': 'publish', 'conclusion': 'success',
                                         'started_at': report['completed_at'], 'completed_at': run['updated_at']}]})
            commits.insert(0, commit)
            remote[api + '/commits?sha=checked&per_page=32'] = h.encoded(commits)
            previous = sha
        return now, remote, root, manifests, read

    def test_retirement_and_next_publication_replay_preserve_bounded_provenance(self):
        now, remote, root, manifests, read = self.publications()
        retired_id = c.node_id(pipeline.uri(900))
        mixed_id = c.node_id(pipeline.uri(901))
        for manifest in manifests[2:]:
            self.assertEqual([x['url'] for x in manifest['sources']], c.SOURCES)
            self.assertNotIn(retired_id, manifest['history']['current_ids'])
            retired = next(x for x in manifest['candidates'] if x['id'] == retired_id)
            self.assertEqual(retired['sources'], [h.RETIRED_SOURCE])
            mixed = next(x for x in manifest['candidates'] if x['id'] == mixed_id)
            self.assertNotIn(h.RETIRED_SOURCE, mixed['sources'])
        published = h.strict_json(remote[root + 'history.json'])
        for extra_hours in (0, 15.999, 16.001, 17.999, 18.001, 48):
            at = now + timedelta(hours=extra_hours)
            with patch('history.remote_read', side_effect=read):
                replayed, _ = h.load_remote('owner/repo', None, now=at)
            self.assertEqual(replayed, h.prune(published, at))
        retired = next(x for x in published['entries'] if x['id'] == retired_id)
        self.assertEqual(retired['last_upstream_seen_at'], (now - timedelta(hours=30)).isoformat())
        self.assertEqual(len(retired['observations']), 4)
        nominated, _ = h.nominate(published, [], (now + timedelta(hours=16, seconds=1)).isoformat())
        self.assertNotIn(retired_id, {x['id'] for x in nominated})

    def test_retired_source_cannot_be_claimed_as_current_or_change_retained_provenance(self):
        _, _, _, manifests, _ = self.publications()
        manifest = manifests[-1]
        retired_id = c.node_id(pipeline.uri(900))
        changed = copy.deepcopy(manifest)
        changed['history']['current_ids'].append(retired_id)
        with self.assertRaisesRegex(ValueError, 'invalid candidate provenance'):
            p.validate_inventory(changed)
        changed = copy.deepcopy(manifest)
        next(x for x in changed['candidates'] if x['id'] == retired_id)['sources'] = [c.SOURCES[0]]
        with self.assertRaisesRegex(ValueError, 'historical candidate altered'):
            p.validate_history_manifest(changed, p.instant(changed['created_at']))
        report_path = self.output / 'report.json'
        report = json.loads(report_path.read_text())
        next(x for x in report['results'] if x['id'] == retired_id)['sources'] = [c.SOURCES[0]]
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'history source provenance mismatch'):
            v.validate(self.output, as_of=p.instant(report['completed_at']))

    def test_unknown_historical_provenance_is_never_admitted(self):
        state, _, _ = fixtures.history_for()
        state['entries'][0]['sources'] = ['https://attacker.invalid/feed']
        with self.assertRaises(ValueError):
            h.validate(state, now=fixtures.NOW)

    def test_intermediate_retained_provenance_cannot_be_rewritten(self):
        from pathlib import Path
        import tempfile
        now, remote, _, _, read = self.publications()
        # Alter the first active-six publication, not the latest cumulative
        # claim. Rehash and rerank its matching row/state claims so standalone
        # validation succeeds; replay must still bind to the earlier source.
        root = 'https://raw.githubusercontent.com/owner/repo/' + f'{3:040x}' + '/'
        report = h.strict_json(remote[root + 'report.json'])
        state = h.strict_json(remote[root + 'history.json'])
        retired_id = c.node_id(pipeline.uri(900))
        next(row for row in report['results'] if row['id'] == retired_id)['sources'] = [c.SOURCES[0]]
        next(entry for entry in state['entries'] if entry['id'] == retired_id)['sources'] = [c.SOURCES[0]]
        exports = {c.node_id(line): line for line in remote[root + c.FEEDS['youtube']].decode().splitlines()}
        feeds, ranking = h.split(state, report['results'], exports)
        data = h.encoded(state)
        report['history'].update(ranking)
        report['history']['state_sha256'] = p.digest(data)
        report['history']['split_counts'] = {key: len(lines) for key, lines in feeds.items()}
        remote[root + 'history.json'] = data
        for key, filename in h.SPLIT_FEEDS.items():
            remote[root + filename] = ('\n'.join(feeds[key]) + ('\n' if feeds[key] else '')).encode()
        remote[root + 'report.json'] = h.encoded(report)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for url, payload in remote.items():
                if url.startswith(root):
                    (folder / url.removeprefix(root)).write_bytes(payload)
            v.validate(folder, as_of=p.instant(report['completed_at']))
        with patch('history.remote_read', side_effect=read), self.assertRaisesRegex(ValueError, 'invalid trusted history'):
            h.load_remote('owner/repo', None, now=now)
