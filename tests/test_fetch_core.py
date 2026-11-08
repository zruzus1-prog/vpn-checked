"""Offline installer checks: curl retry policy and fail-closed verification."""
import hashlib
import io
import json
import os
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

import fetch_core


class FetchCoreTests(unittest.TestCase):
    VERSION = '1.14.2'
    BINARY = b'fixture core; never executed\n'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        old_cwd = Path.cwd()
        os.chdir(temporary.name)
        self.addCleanup(os.chdir, old_cwd)
        self.archive = self.make_archive()
        self.write_lock()
        self.commands = []
        self.archives = []
        runner = patch('fetch_core.subprocess.run', side_effect=self.download)
        self.run = runner.start()
        self.addCleanup(runner.stop)
        sleeper = patch('fetch_core.time.sleep')
        self.sleep = sleeper.start()
        self.addCleanup(sleeper.stop)
        quiet = patch('builtins.print')
        quiet.start()
        self.addCleanup(quiet.stop)

    def make_archive(self, name=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            member = tarfile.TarInfo(name or f'sing-box-{self.VERSION}-linux-amd64/sing-box')
            member.size = len(self.BINARY)
            archive.addfile(member, io.BytesIO(self.BINARY))
        return output.getvalue()

    def write_lock(self, **changes):
        self.lock = {'version': self.VERSION,
                     'sha256': hashlib.sha256(self.archive).hexdigest()}
        self.lock.update(changes)
        Path('core-lock.json').write_text(json.dumps(self.lock))

    def download(self, command, **kwargs):
        self.commands.append((command, kwargs))
        archive = Path(command[command.index('--output') + 1])
        self.archives.append(archive)
        self.assertFalse(archive.exists(), 'partial output must be removed before retry')
        archive.write_bytes(self.archive)
        return subprocess.CompletedProcess(command, 0)

    def assert_no_install(self):
        self.assertFalse(Path('bin').exists())
        self.assertTrue(all(not archive.exists() for archive in self.archives))

    def test_verified_archive_installs_and_records_exact_hashes(self):
        fetch_core.install()
        binary = Path('bin/sing-box')
        self.assertEqual(binary.read_bytes(), self.BINARY)
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual(json.loads(Path('bin/core-verification.json').read_text()), {
            'version': self.VERSION,
            'archive_sha256': self.lock['sha256'],
            'binary_sha256': hashlib.sha256(self.BINARY).hexdigest(),
        })
        self.assertEqual(self.run.call_count, 1)
        self.assertTrue(all(not archive.exists() for archive in self.archives))

    def test_pinned_https_command_has_bounded_transient_only_retries(self):
        fetch_core.install()
        command, kwargs = self.commands[0]
        # Exact command protects the pin, TLS, proxy/config isolation, archive
        # size and time limits; no retry-all-errors or retry-connrefused.
        self.assertEqual(command, [
            'curl', '--disable', '--fail', '--silent', '--show-error',
            '--location', '--proto', '=https', '--proto-redir', '=https',
            '--proxy', '', '--max-time', '60', '--max-filesize', '80000000',
            '--write-out', '%{http_code}\n%header{retry-after}',
            '--output', str(self.archives[0]),
            f'https://github.com/SagerNet/sing-box/releases/download/v{self.VERSION}/'
            f'sing-box-{self.VERSION}-linux-amd64.tar.gz',
        ])
        self.assertEqual(kwargs, {'check': True, 'stdout': subprocess.PIPE,
                                  'text': True, 'timeout': 65})
        self.sleep.assert_not_called()

    def test_invalid_pin_refuses_before_any_download_or_extraction(self):
        invalid = ({'version': 'latest'}, {'version': '../1.14.2'},
                   {'sha256': 'a' * 63}, {'sha256': 'A' * 64})
        for changes in invalid:
            with self.subTest(changes=changes):
                self.write_lock(**changes)
                with patch('fetch_core.tarfile.open') as opened:
                    with self.assertRaisesRegex(ValueError, 'invalid core lock'):
                        fetch_core.install()
                    opened.assert_not_called()
                self.run.assert_not_called()
                self.assert_no_install()

    def test_checksum_mismatch_never_extracts_or_retries(self):
        self.write_lock(sha256='0' * 64)
        with patch('fetch_core.tarfile.open') as opened:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                fetch_core.install()
            opened.assert_not_called()
        self.assertEqual(self.run.call_count, 1)
        self.assert_no_install()

    def test_permanent_curl_failure_never_extracts_partial_output_or_retries(self):
        # Errors outside the exact transient allowlist remain terminal even if
        # an archive/partial file was left behind.
        for code in (1, 6, 7, 18, 22, 23, 35, 47, 60, 63):
            with self.subTest(curl_exit=code):
                self.run.reset_mock()
                error = subprocess.CalledProcessError(code, ['curl'], output='404\n')

                def fail(command, **kwargs):
                    self.download(command, **kwargs)
                    raise error

                self.run.side_effect = fail
                with patch('fetch_core.tarfile.open') as opened:
                    with self.assertRaises(subprocess.CalledProcessError) as raised:
                        fetch_core.install()
                    self.assertIs(raised.exception, error)
                    opened.assert_not_called()
                self.assertEqual(self.run.call_count, 1)
                self.assert_no_install()

    def test_hard_process_timeout_is_terminal_and_cleans_partial_archive(self):
        def stall(command, **kwargs):
            self.download(command, **kwargs)
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])

        self.run.side_effect = stall
        with patch('fetch_core.tarfile.open') as opened:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                fetch_core.install()
            opened.assert_not_called()
        self.assertEqual(raised.exception.timeout, 65)
        self.assertEqual(self.run.call_count, 1)
        self.assert_no_install()

    def responses(self, *failures):
        outcomes = iter(failures)

        def respond(command, **kwargs):
            result = self.download(command, **kwargs)
            failure = next(outcomes, None)
            if failure is not None:
                code, metadata = failure
                raise subprocess.CalledProcessError(code, command, output=metadata)
            return result

        self.run.side_effect = respond

    def test_transient_http_timeout_and_receive_errors_retry_once_then_verify(self):
        for failure in ([(22, str(status) + '\n') for status in (408, 429, 500, 502, 503, 504)] +
                        [(28, '000\n'), (56, '000\n'), (56, '200\n')]):
            with self.subTest(failure=failure):
                self.run.reset_mock()
                self.sleep.reset_mock()
                self.responses(failure)
                fetch_core.install()
                self.assertEqual(self.run.call_count, 2)
                self.sleep.assert_called_once_with(1)
                self.assertEqual(Path('bin/sing-box').read_bytes(), self.BINARY)

    def test_mixed_503_timeout_and_receive_failure_stop_at_three_attempts(self):
        self.responses((22, '503\n'), (28, '200\n'), (56, '000\n'))
        with patch('fetch_core.tarfile.open') as opened:
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                fetch_core.install()
            opened.assert_not_called()
        self.assertEqual(raised.exception.returncode, 56)
        self.assertEqual(self.run.call_count, 3)
        self.assertEqual([call.args for call in self.sleep.call_args_list], [(1,), (2,)])
        self.assert_no_install()

    def test_persistent_receive_error_is_limited_to_three_attempts(self):
        self.responses(*[(56, '000\n')] * 3)
        with self.assertRaises(subprocess.CalledProcessError):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 3)
        self.assertEqual([call.args for call in self.sleep.call_args_list], [(1,), (2,)])
        self.assert_no_install()

    def test_permanent_error_after_transient_is_not_retried_even_with_503_status(self):
        for code, status in ((60, '503'), (35, '503'), (23, '503'), (63, '503'), (22, '404')):
            with self.subTest(code=code):
                self.run.reset_mock()
                self.sleep.reset_mock()
                self.responses((56, '000\n'), (code, status + '\n'))
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    fetch_core.install()
                self.assertEqual(raised.exception.returncode, code)
                self.assertEqual(self.run.call_count, 2)
                self.sleep.assert_called_once_with(1)
                self.assert_no_install()

    def test_malformed_status_or_retry_after_is_terminal(self):
        for metadata in ('', '503garbage\n', '٥٠٣\n', '503\nnot a date', '503\n-1',
                         '503\n' + '9' * 30):
            with self.subTest(metadata=metadata):
                self.run.reset_mock()
                self.responses((22, metadata))
                with self.assertRaises(subprocess.CalledProcessError):
                    fetch_core.install()
                self.assertEqual(self.run.call_count, 1)
                self.sleep.assert_not_called()
                self.assert_no_install()

    def test_retry_after_seconds_and_date_are_honored(self):
        date = format_datetime(datetime.fromtimestamp(1007, timezone.utc), usegmt=True)
        for header in ('7', date):
            with self.subTest(header=header):
                self.run.reset_mock()
                self.sleep.reset_mock()
                self.responses((22, '503\n' + header))
                with patch('fetch_core.time.time', return_value=1000):
                    fetch_core.install()
                self.sleep.assert_called_once_with(7)
                self.assertEqual(self.run.call_count, 2)

    def test_retry_after_beyond_deadline_fails_without_early_retry(self):
        self.responses((22, '503\n600'))
        with self.assertRaises(subprocess.CalledProcessError):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 1)
        self.sleep.assert_not_called()
        self.assert_no_install()

    def test_deadline_insufficient_for_backoff_is_terminal(self):
        self.responses((56, '000\n'))
        with patch('fetch_core.time.monotonic', side_effect=[0, 0, 189.5]), \
             self.assertRaises(subprocess.CalledProcessError):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 1)
        self.sleep.assert_not_called()
        self.assert_no_install()

    def test_deadline_expiring_during_sleep_does_not_start_another_process(self):
        self.responses((56, '000\n'))
        with patch('fetch_core.time.monotonic', side_effect=[0, 0, 1, 190.1]), \
             self.assertRaises(subprocess.TimeoutExpired):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 1)
        self.sleep.assert_called_once_with(1)
        self.assert_no_install()

    def test_subprocess_timeout_is_capped_to_remaining_global_budget(self):
        with patch('fetch_core.time.monotonic', side_effect=[0, 188]):
            fetch_core.install()
        self.assertEqual(self.commands[0][1]['timeout'], 2)

    def test_three_attempt_timeline_does_not_reset_global_budget(self):
        self.responses((56, '000\n'), (56, '000\n'))
        with patch('fetch_core.time.monotonic', side_effect=[0, 0, 64, 65, 129, 131]):
            fetch_core.install()
        self.assertEqual([kwargs['timeout'] for _, kwargs in self.commands], [65, 65, 59])
        self.assertEqual([call.args for call in self.sleep.call_args_list], [(1,), (2,)])

    def test_checksum_failure_after_receive_retry_remains_terminal(self):
        self.write_lock(sha256='0' * 64)
        self.responses((56, '000\n'))
        with patch('fetch_core.tarfile.open') as opened:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                fetch_core.install()
            opened.assert_not_called()
        self.assertEqual(self.run.call_count, 2)
        self.sleep.assert_called_once_with(1)
        self.assert_no_install()

    def test_missing_curl_is_not_retried(self):
        self.run.side_effect = FileNotFoundError('curl unavailable')
        with self.assertRaises(FileNotFoundError):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 1)
        self.assert_no_install()

    def test_checksum_valid_but_corrupt_tar_is_not_retried(self):
        self.archive = b'not a gzip archive'
        self.write_lock()
        with self.assertRaises(tarfile.ReadError):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 1)
        self.assert_no_install()

    def test_wrong_archive_member_is_not_installed_or_retried(self):
        self.archive = self.make_archive('other-version/sing-box')
        self.write_lock()
        with self.assertRaises(KeyError):
            fetch_core.install()
        self.assertEqual(self.run.call_count, 1)
        self.assert_no_install()

    def test_nonregular_and_oversized_members_are_rejected(self):
        for regular, size in ((False, 10), (True, 100000001)):
            with self.subTest(regular=regular, size=size):
                self.run.reset_mock()
                member = Mock(size=size)
                member.isfile.return_value = regular
                with patch('fetch_core.tarfile.open') as opened:
                    archive = opened.return_value.__enter__.return_value
                    archive.getmember.return_value = member
                    with self.assertRaisesRegex(ValueError, 'invalid core member'):
                        fetch_core.install()
                    archive.extractfile.assert_not_called()
                self.assertEqual(self.run.call_count, 1)
                self.assert_no_install()

    def test_bad_download_does_not_replace_an_existing_verified_install(self):
        Path('bin').mkdir()
        Path('bin/sing-box').write_bytes(b'previous binary')
        Path('bin/core-verification.json').write_bytes(b'previous proof')
        self.write_lock(sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            fetch_core.install()
        self.assertEqual(Path('bin/sing-box').read_bytes(), b'previous binary')
        self.assertEqual(Path('bin/core-verification.json').read_bytes(), b'previous proof')
        self.assertEqual(self.run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
