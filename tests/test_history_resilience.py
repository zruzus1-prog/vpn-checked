"""Source-lifetime nomination margins and bounded, secret-safe historical GETs."""
import copy
from datetime import timedelta
import errno
import http.client
import io
import os
import socket
import ssl
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

import checker as c
import history as h
import test_history as histories
import test_history_rollover as rollover
import test_pipeline as pipeline


class RetainedLifetimeTests(unittest.TestCase):
    def state_with_remaining(self, remaining):
        state, _, _ = histories.history_for()
        state['entries'][0]['last_upstream_seen_at'] = (
            histories.NOW - timedelta(seconds=h.MAX_AGE_SECONDS) + remaining).isoformat()
        return state

    def test_exact_margin_and_one_microsecond_on_each_side(self):
        for offset, expected in ((-1, False), (0, True), (1, True)):
            remaining = timedelta(seconds=c.MAX_RESULT_AGE_SECONDS, microseconds=offset)
            state = self.state_with_remaining(remaining)
            original = copy.deepcopy(state)
            with self.subTest(microseconds=offset):
                rows, kept = h.nominate(state, [], histories.NOW.isoformat())
                self.assertEqual(bool(rows), expected)
                self.assertEqual(kept, original)
                self.assertEqual(state, original)
                self.assertEqual(rows, h.eligible_retained(state, [], histories.NOW))

    def test_current_source_is_never_excluded_by_history_margin(self):
        state = self.state_with_remaining(timedelta(seconds=1))
        current = histories.candidate()
        current['uri'] += '-fresh-label'
        rows, kept = h.nominate(state, [current], histories.NOW.isoformat())
        self.assertEqual(rows, [current])
        self.assertEqual(kept, state)
        self.assertEqual(h.eligible_retained(state, {current['id']}, histories.NOW), [])

    def test_fully_valid_retained_candidates_remain_sorted_and_inputs_unchanged(self):
        items = [histories.candidate(i) for i in (1, 2, 3)]
        state, _, _ = histories.history_for(items)
        current = [items[1]]
        original_state, original_current = copy.deepcopy(state), copy.deepcopy(current)
        rows, _ = h.nominate(state, current, histories.NOW.isoformat())
        self.assertEqual(rows, sorted(items, key=lambda row: row['id']))
        self.assertEqual(state, original_state)
        self.assertEqual(current, original_current)
        selected = h.eligible_retained(state, [items[1]['id']], histories.NOW)
        selected[0]['sources'].append('not-a-real-source')
        self.assertEqual(state, original_state)

    def test_failed_only_or_expired_observations_cannot_nominate(self):
        state, _, _ = histories.history_for(passed=[False, False, False])
        self.assertEqual(h.eligible_retained(state, [], histories.NOW), [])
        state, _, _ = histories.history_for(hours=(48,))
        self.assertEqual(h.eligible_retained(state, [], histories.NOW + timedelta(microseconds=1)), [])


class MarginReplayTests(unittest.TestCase):
    setUp = pipeline.PipelineTests.setUp
    run_shards = pipeline.PipelineTests.run_shards
    publications = rollover.RolloverTests.publications
    commit_pages = rollover.RolloverTests.commit_pages
    replay = rollover.RolloverTests.replay

    def test_omitted_near_expiry_rows_preserve_truthful_metadata_and_next_replay(self):
        now, remote, root = self.publications(
            hours=(47.5, 46.5, 1, .5), current_indexes={0}, replay_seed=True)
        state = h.strict_json(remote[root + 'history.json'])
        report = h.strict_json(remote[root + 'report.json'])
        rid = c.node_id(pipeline.uri(1))
        entry = next(item for item in state['entries'] if item['id'] == rid)
        self.assertEqual([obs['run_id'] for obs in entry['observations']], ['100', '101'])
        self.assertNotIn(rid, {row['id'] for row in report['results']})
        self.assertEqual(entry['last_upstream_seen_at'], (now - timedelta(hours=47.5)).isoformat())
        self.assertEqual(self.replay(remote, now), h.prune(state, now))


class Response(io.BytesIO):
    status = 200


class HistoricalReadTests(unittest.TestCase):
    url = 'https://api.github.com/repos/owner/repo/commits?sha=checked&private=URL-SECRET'

    def setUp(self):
        self.clock = 0.0
        self.times = patch('history.time.monotonic', side_effect=lambda: self.clock)
        self.times.start()
        self.addCleanup(self.times.stop)
        self.sleep = patch('history.time.sleep', side_effect=self.advance)
        self.sleeps = self.sleep.start()
        self.addCleanup(self.sleep.stop)
        self.openers = patch('history.urllib.request.build_opener')
        self.build_opener = self.openers.start()
        self.addCleanup(self.openers.stop)
        self.opener = self.build_opener.return_value

    def advance(self, seconds):
        self.clock += seconds

    def http_error(self, status):
        return urllib.error.HTTPError(self.url, status, 'SERVER-SECRET', {'X-Secret': 'HEADER-SECRET'}, None)

    def assert_safe(self, error):
        rendered = ''.join(traceback.format_exception(error))
        for secret in ('URL-SECRET', 'SERVER-SECRET', 'HEADER-SECRET', 'TOKEN-SECRET',
                       'TRANSPORT-SECRET', 'https://', 'owner/repo'):
            self.assertNotIn(secret, str(error))
            self.assertNotIn(secret, repr(error))
            self.assertNotIn(secret, rendered)
        self.assertIn(error.reason, h.REMOTE_READ_REASONS)
        self.assertTrue(error.status is None or type(error.status) is int)
        self.assertIn(error.attempts, range(h.REMOTE_MAX_ATTEMPTS + 1))

    def test_retryable_statuses_recover_with_same_get_and_auth(self):
        for status in sorted(h.REMOTE_RETRY_STATUSES):
            self.opener.reset_mock()
            self.opener.open.side_effect = [self.http_error(status), Response(b'ok')]
            with self.subTest(status=status):
                self.assertEqual(h.remote_read(self.url, 2, 'TOKEN-SECRET'), b'ok')
                self.assertEqual(self.opener.open.call_count, 2)
                first, second = self.opener.open.call_args_list
                self.assertIs(first.args[0], second.args[0])
                self.assertEqual(first.args[0].get_method(), 'GET')
                self.assertEqual(first.args[0].get_header('Authorization'), 'Bearer TOKEN-SECRET')

    def test_timeout_and_connection_errors_retry_to_success(self):
        errors = [TimeoutError('TRANSPORT-SECRET'), ConnectionResetError('TRANSPORT-SECRET'),
                  urllib.error.URLError(TimeoutError('TRANSPORT-SECRET')),
                  urllib.error.URLError(ConnectionRefusedError('TRANSPORT-SECRET')),
                  urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, 'TRANSPORT-SECRET')),
                  OSError(errno.ENETUNREACH, 'TRANSPORT-SECRET'), http.client.IncompleteRead(b'secret')]
        for error in errors:
            self.opener.reset_mock()
            self.opener.open.side_effect = [error, Response(b'ok')]
            with self.subTest(kind=type(error)):
                self.assertEqual(h.remote_read(self.url, 2), b'ok')
                self.assertEqual(self.opener.open.call_count, 2)

    def test_retry_exhaustion_is_exactly_three_attempts_and_secret_safe(self):
        for error, reason, status in ((self.http_error(503), 'http_status', 503),
                                     (TimeoutError('TRANSPORT-SECRET'), 'timeout', None)):
            self.opener.reset_mock()
            self.opener.open.side_effect = error
            with self.subTest(reason=reason), self.assertRaises(h.RemoteReadError) as raised:
                h.remote_read(self.url, 2, 'TOKEN-SECRET')
            self.assertEqual((raised.exception.reason, raised.exception.status, raised.exception.attempts),
                             (reason, status, 3))
            self.assertEqual(self.opener.open.call_count, 3)
            self.assert_safe(raised.exception)

    def test_nontransient_statuses_are_never_retried(self):
        for status in (301, 302, 307, 308, 400, 401, 403, 404, 410, 501):
            self.opener.reset_mock()
            self.opener.open.side_effect = self.http_error(status)
            with self.subTest(status=status), self.assertRaises(h.RemoteReadError) as raised:
                h.remote_read(self.url, 2, 'TOKEN-SECRET')
            self.assertEqual(raised.exception.status, status)
            self.assertEqual(raised.exception.attempts, 1)
            self.assertEqual(self.opener.open.call_count, 1)
            self.assert_safe(raised.exception)

    def test_tls_and_unknown_transport_errors_are_never_retried(self):
        errors = [(ssl.SSLCertVerificationError('TRANSPORT-SECRET'), 'tls'),
                  (ssl.SSLError('TRANSPORT-SECRET'), 'tls'),
                  (urllib.error.URLError(ssl.SSLCertVerificationError('TRANSPORT-SECRET')), 'tls'),
                  (urllib.error.URLError('TRANSPORT-SECRET'), 'transport'),
                  (socket.gaierror(socket.EAI_NONAME, 'TRANSPORT-SECRET'), 'connection')]
        for error, reason in errors:
            self.opener.reset_mock()
            self.opener.open.side_effect = error
            with self.subTest(reason=reason), self.assertRaises(h.RemoteReadError) as raised:
                h.remote_read(self.url, 2)
            self.assertEqual((raised.exception.reason, raised.exception.attempts), (reason, 1))
            self.assertEqual(self.opener.open.call_count, 1)
            self.assert_safe(raised.exception)

    def test_redirect_handler_blocks_before_redirected_request_or_auth_leak(self):
        def redirect(request, **kwargs):
            handler = self.build_opener.call_args.args[0]()
            return handler.redirect_request(request, None, 302, 'SERVER-SECRET', {},
                                            'https://evil.example/URL-SECRET')
        self.opener.open.side_effect = redirect
        with self.assertRaises(h.RemoteReadError) as raised:
            h.remote_read(self.url, 2, 'TOKEN-SECRET')
        self.assertEqual((raised.exception.reason, raised.exception.attempts), ('redirect', 1))
        self.assertEqual(self.opener.open.call_count, 1)
        self.assert_safe(raised.exception)

    def test_raw_host_never_receives_api_auth(self):
        self.opener.open.return_value = Response(b'ok')
        h.remote_read('https://raw.githubusercontent.com/owner/repo/sha/report.json', 2, 'TOKEN-SECRET')
        self.assertIsNone(self.opener.open.call_args.args[0].get_header('Authorization'))

    def test_byte_cap_and_schema_errors_never_retry(self):
        self.opener.open.return_value = Response(b'123')
        with self.assertRaises(h.RemoteReadError) as raised:
            h.remote_read(self.url, 2)
        self.assertEqual((raised.exception.reason, raised.exception.attempts), ('oversize', 1))
        self.assertEqual(self.opener.open.call_count, 1)
        self.assert_safe(raised.exception)
        self.opener.reset_mock()
        self.opener.open.return_value = Response(b'{"duplicate":1,"duplicate":2}')
        with self.assertRaises(ValueError):
            h.strict_json(h.remote_read(self.url, 1024))
        self.assertEqual(self.opener.open.call_count, 1)

    def test_trust_failure_does_not_start_any_fetch(self):
        with self.assertRaises(ValueError):
            h.remote_read('https://evil.example/URL-SECRET', 2, 'TOKEN-SECRET')
        self.opener.open.assert_not_called()

    def test_deadline_caps_later_timeouts_and_does_not_accept_late_body(self):
        timeouts = []
        def timeout(request, *, timeout):
            timeouts.append(timeout)
            self.advance(timeout)
            raise TimeoutError('TRANSPORT-SECRET')
        self.opener.open.side_effect = timeout
        with self.assertRaises(h.RemoteReadError) as raised:
            h.remote_read(self.url, 2)
        self.assertEqual(timeouts, [30, 30, 27])
        self.assertEqual(self.clock, 90)
        self.assertEqual(raised.exception.attempts, 3)
        self.assert_safe(raised.exception)
        self.opener.reset_mock()
        def late(request, *, timeout):
            self.advance(90)
            return Response(b'ok')
        self.opener.open.side_effect = late
        with self.assertRaises(h.RemoteReadError) as raised:
            h.remote_read(self.url, 2)
        self.assertEqual((raised.exception.reason, raised.exception.attempts), ('deadline', 1))
        self.assertEqual(self.opener.open.call_count, 1)

    def test_deadline_does_not_sleep_or_retry_when_budget_is_exhausted(self):
        def late_failure(request, *, timeout):
            self.advance(89)
            raise TimeoutError('TRANSPORT-SECRET')
        self.opener.open.side_effect = late_failure
        with self.assertRaises(h.RemoteReadError) as raised:
            h.remote_read(self.url, 2)
        self.assertEqual((raised.exception.reason, raised.exception.attempts), ('deadline', 1))
        self.opener.open.assert_called_once()
        self.sleeps.assert_not_called()

    def test_streaming_reads_shrink_socket_timeout_with_the_shared_deadline(self):
        transport = Mock()
        owner = self
        class SlowResponse(Response):
            fp = SimpleNamespace(raw=SimpleNamespace(_sock=transport))
            def read1(self, maximum):
                timeout = transport.settimeout.call_args.args[0]
                owner.advance(min(25, timeout))
                if timeout < 25:
                    raise TimeoutError('TRANSPORT-SECRET')
                return super().read1(min(1, maximum))
        self.opener.open.return_value = SlowResponse(b'abc')
        with self.assertRaises(h.RemoteReadError) as raised:
            h.remote_read(self.url, 3)
        self.assertEqual([call.args[0] for call in transport.settimeout.call_args_list], [30, 30, 30, 15])
        self.assertEqual(self.clock, 90)
        self.assertEqual((raised.exception.reason, raised.exception.attempts), ('deadline', 1))
        self.opener.open.assert_called_once()
        self.assert_safe(raised.exception)

    def test_partial_body_connection_failure_retries_without_returning_stale_bytes(self):
        class TruncatedResponse(Response):
            length = 10  # HTTPResponse retains a nonzero length on early EOF.
        self.opener.open.side_effect = [TruncatedResponse(b'old'), Response(b'new')]
        self.assertEqual(h.remote_read(self.url, 10), b'new')
        self.assertEqual(self.opener.open.call_count, 2)

    def test_only_initial_missing_checked_branch_is_cold_start(self):
        self.opener.open.side_effect = self.http_error(404)
        state, provenance = h.load_remote('owner/repo', None, now=histories.NOW)
        self.assertEqual(state, h.empty(histories.NOW.isoformat()))
        self.assertEqual(provenance['mode'], 'cold-start')
        self.assertEqual(self.opener.open.call_count, 1)
        self.opener.reset_mock()
        commit = {'sha': 'a' * 40, 'commit': {'committer': {'date': histories.NOW.isoformat()}}}
        self.opener.open.side_effect = [Response(h.encoded([commit])), self.http_error(404)]
        with self.assertRaises(h.RemoteReadError) as raised:
            h.load_remote('owner/repo', None, now=histories.NOW)
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(self.opener.open.call_count, 2)


class BaselineCompatibilityTests(unittest.TestCase):
    def test_previous_main_remains_explicitly_authenticated_after_upgrade(self):
        previous = '5d771ea965937d6ee7db1f305f9c5680a78a35b3'
        report, commit, run, jobs = histories.AuthenticationTests().fixtures()
        report['production']['implementation_sha'] = previous
        run['head_sha'] = previous
        with patch.dict(os.environ, {'GITHUB_SHA': 'f' * 40}), \
                patch('history.remote_read', side_effect=[h.encoded(run), h.encoded(jobs)]):
            self.assertEqual(h.authenticate_publication('owner/repo', commit, report, None,
                                                       now=histories.NOW), 'schedule')


if __name__ == '__main__':
    unittest.main()
