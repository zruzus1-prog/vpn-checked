import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from validate_output import validate
from checker import FEEDS

class OutputTests(unittest.TestCase):
    def write(self, path, age=0):
        for filename in FEEDS.values(): (path/filename).write_text('')
        (path/'report.json').write_text(json.dumps({'schema_version':2,'deep_tested':0,'feed_counts':{key:0 for key in FEEDS},'completed_at':(datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat(),'qualified':0,'sampled':0,'results':[]}))
    def test_fresh_empty_valid(self):
        with tempfile.TemporaryDirectory() as td:
            self.write(Path(td)); validate(td)
    def test_stale_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            self.write(Path(td),7200)
            with self.assertRaises(ValueError): validate(td)
    def test_extra_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            self.write(Path(td)); (Path(td)/'evil.sh').write_text('false')
            with self.assertRaises(ValueError): validate(td)
    def test_inconsistent_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            self.write(Path(td)); (Path(td)/'subscription.txt').write_text('trojan://p@example.org:443\n')
            with self.assertRaises(ValueError): validate(td)
