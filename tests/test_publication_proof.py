"""Adversarial publication proof checks; all credentials and records are synthetic.

The producer is trusted code, but publication must reject corrupted proof and
accidental diagnostic expansion rather than silently release it as verified.
"""
import unittest

import checker as c
import production as p
import test_pipeline as fixtures


class PublicationProofTests(unittest.TestCase):
    # Reuse the same isolated temporary inventory without inheriting its tests.
    setUp = fixtures.PipelineTests.setUp
    prepare = fixtures.PipelineTests.prepare
    run_shards = fixtures.PipelineTests.run_shards
    mutate_shard = fixtures.PipelineTests.mutate_shard

    def assert_invalid_proof(self, mutate):
        manifest = self.prepare(1)
        self.run_shards(manifest, fixtures.successful_probe)
        self.mutate_shard(lambda payload: mutate(payload['results'][0]))
        with self.assertRaises(ValueError):
            p.merge(self.manifest_path, self.shards, self.output)

    def test_complete_synthetic_proof_is_accepted(self):
        manifest = self.prepare(1)
        self.run_shards(manifest, fixtures.successful_probe)
        p.merge(self.manifest_path, self.shards, self.output)
        self.assertEqual(p.verify_public(self.manifest_path, self.output)['feed_counts'],
                         {'both': 1, 'youtube': 1, 'chatgpt': 1})

    def test_unknown_result_field_cannot_leak_configuration(self):
        self.assert_invalid_proof(lambda row: row.update(
            private_config={'password': 'synthetic-private-value'}))

    def test_unknown_attempt_field_cannot_leak_stderr(self):
        self.assert_invalid_proof(lambda row: row['attempts'][0].update(
            raw_stderr='synthetic-private-value'))

    def test_qualified_services_require_request_evidence(self):
        self.assert_invalid_proof(lambda row: row.update(
            attempts=[a for a in row['attempts'] if not a['stage'].startswith('service-')]))

    def test_qualified_services_require_page_assessment(self):
        self.assert_invalid_proof(lambda row: row.pop('service_diagnostics', None))

    def test_claimed_stability_cannot_replace_elapsed_time(self):
        def mutate(row):
            instant = row['attempts'][0]['started_at']
            for attempt in row['attempts']:
                attempt['started_at'] = instant
            row['stability_seconds'] = c.STABILITY_SECONDS
        self.assert_invalid_proof(mutate)

    def test_failed_curl_cannot_be_marked_successful(self):
        def mutate(row):
            attempt = next(a for a in row['attempts'] if a['stage'] == 'download-1')
            attempt.update(passed=True, curl_exit=60, error='tls-certificate')
        self.assert_invalid_proof(mutate)

    def test_qualified_service_cannot_borrow_another_endpoint(self):
        def mutate(row):
            attempt = next(a for a in row['attempts'] if a['stage'] == 'service-youtube')
            attempt['endpoint'] = 'https://chatgpt.com/'
        self.assert_invalid_proof(mutate)


if __name__ == '__main__':
    unittest.main()
