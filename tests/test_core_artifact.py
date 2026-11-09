"""Offline proof of one pinned download and fail-closed per-shard installation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import unittest
from unittest.mock import patch

import fetch_core
import test_fetch_core as fixtures


class SharedCoreTests(unittest.TestCase):
    VERSION = fixtures.FetchCoreTests.VERSION
    BINARY = fixtures.FetchCoreTests.BINARY
    setUp = fixtures.FetchCoreTests.setUp
    make_archive = fixtures.FetchCoreTests.make_archive
    write_lock = fixtures.FetchCoreTests.write_lock
    download = fixtures.FetchCoreTests.download
    responses = fixtures.FetchCoreTests.responses
    assert_no_install = fixtures.FetchCoreTests.assert_no_install

    def local_archive(self):
        path = Path('artifact/core.tar.gz')
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(self.archive)
        return path

    def test_download_only_exports_exact_pinned_archive_without_extraction(self):
        output = Path('artifact/core.tar.gz')
        with patch('fetch_core.tarfile.open') as opened:
            fetch_core.main(['--download-only', str(output)])
            opened.assert_not_called()
        self.assertEqual(output.read_bytes(), self.archive)
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), self.lock['sha256'])
        self.assertEqual(self.run.call_count, 1)
        self.assert_no_install()

    def test_local_install_rechecks_pin_and_generates_binary_proof_without_network(self):
        path = self.local_archive()
        # Artifacts do not get to supply their own trusted checksum or proof.
        path.with_name('core-verification.json').write_text('{"archive_sha256":"untrusted"}')
        fetch_core.main(['--archive', str(path)])
        self.run.assert_not_called()
        self.assertEqual(Path('bin/sing-box').read_bytes(), self.BINARY)
        proof = json.loads(Path('bin/core-verification.json').read_text())
        self.assertEqual(proof['archive_sha256'], self.lock['sha256'])
        self.assertEqual(proof['binary_sha256'], hashlib.sha256(self.BINARY).hexdigest())

    def test_one_download_serves_eight_independently_verified_shards(self):
        path = Path('artifact/core.tar.gz')
        fetch_core.install(download_only=path)
        with patch('fetch_core.verified_archive', wraps=fetch_core.verified_archive) as verify:
            for _ in range(8):
                fetch_core.install(archive_path=path)
                self.assertEqual(Path('bin/sing-box').read_bytes(), self.BINARY)
            self.assertEqual(verify.call_count, 8)
        self.assertEqual(self.run.call_count, 1)

    def test_cli_modes_are_exclusive_and_default_remains_compatible(self):
        with patch('sys.stderr'), self.assertRaises(SystemExit) as raised:
            fetch_core.main(['--archive', 'input', '--download-only', 'output'])
        self.assertEqual(raised.exception.code, 2)
        self.run.assert_not_called()
        with self.assertRaises(ValueError):
            fetch_core.install(archive_path='input', download_only='output')
        self.run.assert_not_called()
        fetch_core.main([])
        self.assertEqual(self.run.call_count, 1)
        self.assertEqual(Path('bin/sing-box').read_bytes(), self.BINARY)

    def test_download_only_bad_pin_never_creates_artifact_or_extracts(self):
        self.write_lock(sha256='0' * 64)
        output = Path('artifact/core.tar.gz')
        with patch('fetch_core.tarfile.open') as opened, \
             self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            fetch_core.install(download_only=output)
        opened.assert_not_called()
        self.assertFalse(output.exists())
        self.assert_no_install()

    def test_download_only_exhausted_504s_never_export_partial_or_stale_bytes(self):
        path = self.local_archive()
        path.write_bytes(b'previous artifact')
        self.responses(*[(22, '504\n')] * 3)
        with self.assertRaises(subprocess.CalledProcessError):
            fetch_core.install(download_only=path)
        self.assertEqual(self.run.call_count, 3)
        self.assertEqual(path.read_bytes(), b'previous artifact')
        self.assert_no_install()

    def test_missing_local_artifact_has_no_network_fallback(self):
        with self.assertRaises(FileNotFoundError):
            fetch_core.install(archive_path='missing.tar.gz')
        self.run.assert_not_called()
        self.assert_no_install()

    def test_tampered_local_artifact_is_rejected_before_extraction(self):
        path = self.local_archive()
        path.write_bytes(self.archive + b'tampered')
        with patch('fetch_core.tarfile.open') as opened, \
             self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            fetch_core.install(archive_path=path)
        opened.assert_not_called()
        self.run.assert_not_called()
        self.assert_no_install()

    def test_wrong_local_lock_is_rejected_even_for_a_previously_valid_archive(self):
        path = self.local_archive()
        self.write_lock(sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            fetch_core.install(archive_path=path)
        self.run.assert_not_called()
        self.assert_no_install()

    def test_invalid_local_lock_is_rejected_before_archive_read(self):
        self.write_lock(version='../latest')
        with patch('fetch_core.verified_archive') as verify, \
             self.assertRaisesRegex(ValueError, 'invalid core lock'):
            fetch_core.install(archive_path='missing.tar.gz')
        verify.assert_not_called()
        self.run.assert_not_called()

    def test_oversized_local_artifact_is_rejected_before_hash_or_extraction(self):
        path = self.local_archive()
        with path.open('wb') as stream:
            stream.truncate(80000001)
        with patch('fetch_core.hashlib.sha256') as hashed, \
             patch('fetch_core.tarfile.open') as opened, \
             self.assertRaisesRegex(ValueError, 'invalid core archive'):
            fetch_core.install(archive_path=path)
        hashed.assert_not_called()
        opened.assert_not_called()
        self.run.assert_not_called()
        self.assert_no_install()

    def test_symlink_directory_and_fifo_are_not_accepted_as_archives(self):
        path = self.local_archive()
        link = Path('link'); link.symlink_to(path)
        fifo = Path('fifo'); os.mkfifo(fifo)
        for item in (link, path.parent, fifo):
            with self.subTest(item=item), \
                 self.assertRaises((OSError, ValueError)):
                fetch_core.install(archive_path=item)
        self.run.assert_not_called()
        self.assert_no_install()

    def test_extraction_uses_verified_bytes_even_if_input_path_changes(self):
        path = self.local_archive()
        original_open = tarfile.open

        def replace_input(*args, **kwargs):
            path.write_bytes(b'replacement after verification')
            return original_open(*args, **kwargs)

        with patch('fetch_core.tarfile.open', side_effect=replace_input):
            fetch_core.install(archive_path=path)
        self.assertEqual(Path('bin/sing-box').read_bytes(), self.BINARY)
        self.run.assert_not_called()

    def test_corrupt_or_wrong_member_local_archive_never_installs(self):
        for content, error in ((b'not gzip', tarfile.ReadError),
                               (self.make_archive('other-version/sing-box'), KeyError)):
            with self.subTest(error=error):
                self.archive = content
                self.write_lock()
                path = self.local_archive()
                with self.assertRaises(error):
                    fetch_core.install(archive_path=path)
                self.run.assert_not_called()
                self.assert_no_install()

    def test_tampered_artifact_preserves_existing_binary_and_proof(self):
        path = self.local_archive()
        fetch_core.install(archive_path=path)
        proof = Path('bin/core-verification.json').read_bytes()
        path.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            fetch_core.install(archive_path=path)
        self.assertEqual(Path('bin/sing-box').read_bytes(), self.BINARY)
        self.assertEqual(Path('bin/core-verification.json').read_bytes(), proof)
        self.run.assert_not_called()


class SharedCoreWorkflowTests(unittest.TestCase):
    def test_artifact_id_guard_rejects_empty_multiple_and_untrusted_values(self):
        guard = '[[ "$CORE_ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]]'
        for value in ('1', '1234567890', '', '0', '-1', '1,2', '1 2', '1\n2',
                      '1oops', 'latest', '$(false)', '1; false'):
            with self.subTest(value=value):
                result = subprocess.run(['bash', '-c', guard],
                                        env={'CORE_ARTIFACT_ID': value})
                self.assertEqual(result.returncode == 0, value in ('1', '1234567890'))

    def test_one_download_precedes_freeze_and_shards_use_exact_immutable_artifact(self):
        text = (Path(fetch_core.__file__).parent / '.github/workflows/check.yml').read_text()
        prepare, rest = text.split('\n  shard:\n', 1)
        shard, rest = rest.split('\n  merge:\n', 1)
        self.assertEqual(text.count('fetch_core.py --download-only'), 1)
        self.assertEqual(text.count('fetch_core.py --archive'), 1)
        self.assertLess(prepare.index('cadence_limiter.py wait'), prepare.index('fetch_core.py --download-only'))
        self.assertLess(prepare.index('fetch_core.py --download-only'), prepare.index('id: core-artifact'))
        self.assertLess(prepare.index('id: core-artifact'), prepare.index('id: freeze'))
        self.assertIn('core_artifact_id: ${{ steps.core-artifact.outputs.artifact-id }}', prepare)
        self.assertIn('name: pinned-core-${{ github.run_attempt }}', prepare)
        self.assertIn('path: /tmp/pinned-core/core.tar.gz', prepare)
        # Preserve the former eight-minute job overhead allowance after adding
        # the bounded four-minute download and two-minute artifact upload.
        self.assertIn('timeout-minutes: 111', prepare)
        self.assertIn('timeout-minutes: 4\n        run: python3 fetch_core.py --download-only', prepare)
        self.assertIn('id: core-artifact\n        timeout-minutes: 2', prepare)
        self.assertIn('artifact-ids: ${{ needs.prepare.outputs.core_artifact_id }}', shard)
        self.assertIn('CORE_ARTIFACT_ID: ${{ needs.prepare.outputs.core_artifact_id }}', shard)
        self.assertIn('[[ "$CORE_ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]]', shard)
        self.assertLess(shard.index('[[ "$CORE_ARTIFACT_ID"'), shard.index('artifact-ids:'))
        self.assertIn('merge-multiple: true', shard)
        self.assertIn('run: python3 fetch_core.py --archive /tmp/pinned-core/core.tar.gz', shard)
        self.assertNotIn('run-id:', shard)
        self.assertNotIn('repository:', shard)
        self.assertNotIn('github-token:', shard)
        self.assertNotIn('fetch_core.py\n', shard)
        self.assertNotIn('fetch_core.py', rest)
        self.assertLess(shard.index('fetch_core.py --archive'), shard.index('SING_BOX_TEST_BIN='))
        self.assertLess(shard.index('SING_BOX_TEST_BIN='), shard.index('production.py shard'))


if __name__ == '__main__':
    unittest.main()
