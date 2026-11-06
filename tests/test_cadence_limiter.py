import sys
from datetime import datetime, timezone, timedelta
import unittest
import history as h
from cadence_limiter import not_before, wait_until, verify_snapshot_slot
NOW=datetime(2026,11,6,12,tzinfo=timezone.utc)
class LimiterTests(unittest.TestCase):
    def state(self, offsets):
        state=h.empty(NOW.isoformat())
        state['runs']=[{'run_id':str(i+1),'run_attempt':'1','implementation_sha':'a'*40,'snapshot_at':(NOW-timedelta(seconds=offset)).isoformat(),'event':'schedule'} for i,offset in enumerate(offsets)]
        return state
    def test_cold_start(self): self.assertEqual(not_before(self.state([]),now=NOW),NOW)
    def test_recent_requires_wait(self): self.assertEqual(not_before(self.state([1800]),now=NOW),NOW+timedelta(seconds=1800))
    def test_old_no_wait(self): self.assertEqual(not_before(self.state([3600]),now=NOW),NOW)
    def test_corrupt_history_is_fatal(self):
        state=self.state([0]); state['runs'][0]['run_id']='bad'
        with self.assertRaises(ValueError): not_before(state,now=NOW)
    def test_legacy_burst_cannot_admit_a_65th_live_snapshot(self):
        state=self.state(list(reversed([i*60 for i in range(64)])))
        due=not_before(state,now=NOW)
        self.assertGreater(due,NOW+timedelta(hours=1))
        with self.assertRaises(ValueError): wait_until(due,clock=lambda:NOW)
    def test_wait_and_verify(self):
        elapsed=[0]
        def sleep(s): elapsed[0]+=s
        due=NOW+timedelta(seconds=3600)
        wait_until(due,clock=lambda:NOW+timedelta(seconds=elapsed[0]),sleep=sleep,monotonic=lambda:elapsed[0])
        self.assertEqual(elapsed[0],3600)
        verify_snapshot_slot({'created_at':due.isoformat()},due)
        with self.assertRaises(ValueError): verify_snapshot_slot({'created_at':NOW.isoformat()},due)
    def test_frozen_wallclock_is_bounded(self):
        elapsed=[0]
        def sleep(s): elapsed[0]+=s
        with self.assertRaises(ValueError): wait_until(NOW+timedelta(seconds=1),clock=lambda:NOW,sleep=sleep,monotonic=lambda:elapsed[0])
        self.assertLessEqual(elapsed[0],3660)
    def test_no_success_after_monotonic_budget(self):
        samples=iter([0,3661])
        with self.assertRaises(ValueError):wait_until(NOW,clock=lambda:NOW,monotonic=lambda:next(samples))
    def test_sleep_capped_at_remaining_budget(self):
        elapsed=[3645];first=[True];sleeps=[]
        def monotonic():
            if first[0]:first[0]=False;return 0
            return elapsed[0]
        def sleep(seconds):sleeps.append(seconds);elapsed[0]+=seconds
        with self.assertRaises(ValueError):wait_until(NOW+timedelta(seconds=100),clock=lambda:NOW,sleep=sleep,monotonic=monotonic)
        self.assertEqual(sleeps,[15])
    def test_inclusive_48h_slot_bound(self):
        # Adversarial infinitely frequent requests cannot create a new slot early.
        start=NOW-timedelta(hours=100)
        slots=[]
        for index in range(240):
            now=start+timedelta(minutes=index)
            if slots: now=max(now,slots[-1]+timedelta(hours=1))
            slots.append(now)
            live=[s for s in slots if (now-s).total_seconds()<=h.MAX_AGE_SECONDS]
            self.assertLessEqual(len(live),49)
            self.assertLessEqual(len(live),h.MAX_RUNS)
if __name__=='__main__': unittest.main()
