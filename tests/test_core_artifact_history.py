"""Replay the unchanged history proofs across the exact shared-archive upgrade."""
from unittest.mock import patch

import test_core_retry_history as predecessor


class SharedCoreHistoryTrustTests(predecessor.CoreRetryHistoryTrustTests):
    def setUp(self):
        pin = patch.object(predecessor, 'PREDECESSOR',
                           'b4d1581f5b035acac4d5dc08aca373d4d0aecf09')
        pin.start()
        self.addCleanup(pin.stop)


class SharedCoreHistoryReplayTests(predecessor.CoreRetryHistoryReplayTests):
    def setUp(self):
        super().setUp()
        pin = patch.object(predecessor, 'PREDECESSOR',
                           'b4d1581f5b035acac4d5dc08aca373d4d0aecf09')
        pin.start()
        self.addCleanup(pin.stop)
