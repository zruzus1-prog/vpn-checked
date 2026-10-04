"""Offline regression coverage for safety boundaries and probe failure cleanup."""
import socket
import subprocess
import unittest
from unittest.mock import Mock, patch

import checker as c

VLESS = 'vless://12345678-1234-1234-1234-123456789abc@example.org:443?security=tls&sni=example.org'


class ReviewTests(unittest.TestCase):
    def probe_with(self, process, responses):
        with patch('checker.resolve_public', return_value='8.8.8.8'), \
             patch('checker.subprocess.Popen', return_value=process), \
             patch('checker.time.sleep'), patch('checker.MAX_ATTEMPTS',1), \
             patch('checker.curl', side_effect=responses):
            return c.probe(VLESS, '/fake/core', c.time.monotonic() + 180)

    def test_dns_failure_never_launches_core(self):
        with patch('checker.resolve_public', side_effect=socket.gaierror('offline')), \
             patch('checker.subprocess.Popen') as launch:
            result, line = c.probe(VLESS, '/fake/core', c.time.monotonic() + 180)
        launch.assert_not_called()
        self.assertEqual(result['reason'], 'endpoint-rejected')
        self.assertIsNone(line)

    def test_missing_core_never_qualifies(self):
        with patch('checker.resolve_public', return_value='8.8.8.8'), \
             patch('checker.subprocess.Popen', side_effect=FileNotFoundError):
            result, line = c.probe(VLESS, '/fake/core', c.time.monotonic() + 180)
        self.assertEqual(result['reason'], 'core-start-failed')
        self.assertIsNone(line)

    def test_early_core_exit_never_qualifies(self):
        process = Mock()
        process.poll.return_value = 1
        result, line = self.probe_with(process, [])
        self.assertFalse(result['qualified'])
        self.assertEqual(result['reason'], 'core-start-failed')
        self.assertIsNone(line)
        process.terminate.assert_called_once()

    def test_timeout_terminates_core(self):
        process = Mock()
        process.poll.return_value = None
        result, line = self.probe_with(process, [subprocess.TimeoutExpired('curl', 5)]*2)
        self.assertFalse(result['qualified'])
        self.assertIsNone(line)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=2)

    def test_unresponsive_core_is_killed(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('core', 2), 0]
        result, line = self.probe_with(process, [c.Rejected('failed')]*2)
        self.assertFalse(result['qualified'])
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_slow_or_wrong_size_download_never_qualifies(self):
        for download in [(200, c.DOWNLOAD_BYTES, 8.1), (200, c.DOWNLOAD_BYTES-1, 1), (206, c.DOWNLOAD_BYTES, 1), (200, c.DOWNLOAD_BYTES, 0)]:
            with self.subTest(download=download):
                process = Mock()
                process.poll.return_value = None
                result, line = self.probe_with(process, [(204, 0, .1)] * 2 + [download])
                self.assertFalse(result['qualified'])
                self.assertIsNone(line)

    def test_service_failures_are_labels_not_full_service_claims(self):
        process = Mock()
        process.poll.return_value = None
        result, line = self.probe_with(process, [(204, 0, .1)] * 2 + [(200, c.DOWNLOAD_BYTES, 4)] + [(204, 0, .1)] * 3 + [(200, c.DOWNLOAD_BYTES, 4), c.Rejected('unreachable'), (302, 100, .1, '')])
        self.assertFalse(result['qualified'])
        self.assertEqual(result['reachability'], {'youtube': 'not-confirmed', 'chatgpt': 'http-302'})
        self.assertIsNone(line)

    def test_socks_auth_and_empty_proxy_environment(self):
        with patch('checker.subprocess.run', return_value=Mock(returncode=0, stdout=b'204 0 0.1')) as run:
            c.curl('https://example.org/', 1080, password='local-test-secret')
        args = run.call_args.args[0]
        self.assertEqual(args[args.index('--proxy-user') + 1], 'checker:local-test-secret')
        self.assertNotIn('HTTPS_PROXY', run.call_args.kwargs['env'])
        self.assertNotIn('ALL_PROXY', run.call_args.kwargs['env'])
        self.assertEqual(args[1], '--disable')


if __name__ == '__main__':
    unittest.main()
