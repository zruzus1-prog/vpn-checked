"""Validate data-only feeds before the isolated write-token publishing job."""
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
from checker import FEEDS, MAX_CANDIDATES, MAX_DEEP, MIN_BYTES_PER_SECOND, STABILITY_SECONDS, parse_uri


def count(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('invalid count')
    return value


def number(value):
    if type(value) not in (int,float) or not math.isfinite(value):
        raise ValueError('invalid numeric measurement')
    return value


def validate(root):
    root=Path(root)
    if {p.name for p in root.iterdir()} != {*FEEDS.values(), 'report.json'}:
        raise ValueError('unexpected output files')
    for p in root.iterdir():
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
            raise ValueError('invalid output file')
    report=json.loads((root/'report.json').read_text())
    if report.get('schema_version') != 2: raise ValueError('unknown schema')
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(report['completed_at'])).total_seconds()
    if not 0 <= age < 3600: raise ValueError('stale output')
    sampled=count(report['sampled'],MAX_CANDIDATES)
    deep=count(report['deep_tested'],min(MAX_DEEP,sampled))
    results=report['results']
    if not isinstance(results,list) or len(results)!=sampled: raise ValueError('inconsistent results')
    expected={key:set() for key in FEEDS}
    ids=set()
    actual_deep=0
    for row in results:
        rid=row['id']
        if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{16}',rid) or rid in ids:
            raise ValueError('invalid result identity')
        ids.add(rid)
        if row.get('deep_tested') is True: actual_deep+=1
        services=row['service_qualified']
        if set(services)!={'youtube','chatgpt'} or any(type(x) is not bool for x in services.values()):
            raise ValueError('invalid service results')
        qualified=row['qualified']
        if type(qualified) is not bool or qualified != all(services.values()):
            raise ValueError('invalid combined qualification')
        if any(services.values()):
            if row.get('baseline_qualified') is not True or row.get('deep_tested') is not True:
                raise ValueError('missing baseline proof')
            if number(row['stability_seconds']) < STABILITY_SECONDS or number(row['min_kib_s']) < MIN_BYTES_PER_SECOND/1024:
                raise ValueError('weak baseline')
            speeds=row['download_kib_s']
            if not isinstance(speeds,list) or len(speeds)!=2 or min(number(x) for x in speeds)<MIN_BYTES_PER_SECOND/1024:
                raise ValueError('weak downloads')
            digest=row['subscription_sha256']
            if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):
                raise ValueError('invalid subscription digest')
            for name,passed in services.items():
                if passed:
                    if row['reachability'][name]!='page-confirmed': raise ValueError('unconfirmed service')
                    expected[name].add(digest)
            if qualified: expected['both'].add(digest)
    if actual_deep != deep: raise ValueError('inconsistent deep count')
    if set(report['feed_counts']) != set(FEEDS): raise ValueError('invalid feed counts')
    for key,filename in FEEDS.items():
        lines=(root/filename).read_text().splitlines()
        if len(lines) != count(report['feed_counts'][key],deep): raise ValueError('inconsistent feed count')
        for line in lines: parse_uri(line)
        hashes={hashlib.sha256(line.encode()).hexdigest() for line in lines}
        if len(hashes)!=len(lines) or hashes!=expected[key]: raise ValueError('inconsistent feed contents')
    if count(report['qualified'],deep) != report['feed_counts']['both']:
        raise ValueError('inconsistent primary count')


if __name__=='__main__': validate(sys.argv[1])
