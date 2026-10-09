"""Validate data-only feeds before the isolated write-token publishing job."""
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
from checker import (FEEDS, SOURCES, MAX_FEED_LINES, MAX_CANDIDATES, MAX_DEEP,
                     MIN_BYTES_PER_SECOND, STABILITY_SECONDS, PROTOCOLS,
                     REJECTION_CATEGORIES, RESULT_FAILURE_REASONS,
                     coverage_summary, parse_uri, node_id, public_ip, CANONICALIZATION_VERSION,
                     MAX_RESULT_AGE_SECONDS, QUICK_ENDPOINTS, SPEED_ENDPOINT,
                     DOWNLOAD_BYTES, QUICK_TIMEOUT, MAX_ENDPOINT_ADDRESSES, MAX_ATTEMPTS,
                     CURL_ERROR_CATEGORIES)


def count(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('invalid count')
    return value


def number(value):
    if type(value) not in (int,float) or not math.isfinite(value):
        raise ValueError('invalid numeric measurement')
    return value


def histogram(value, allowed, total):
    if not isinstance(value,dict) or set(value)-allowed:
        raise ValueError('invalid histogram keys')
    if sum(count(item,total) for item in value.values())!=total:
        raise ValueError('inconsistent histogram')


def timestamp(value):
    if not isinstance(value,str): raise ValueError('invalid timestamp')
    result=datetime.fromisoformat(value)
    if result.tzinfo is None or result>datetime.now(timezone.utc): raise ValueError('invalid timestamp')
    return result


ROW_KEYS = {'id','identity_version','original_uri_sha256','checked_at','completed_at',
    'qualified','baseline_qualified','service_qualified','attempts','protocol','sources',
    'resolved_addresses','address_limit','resolved_address_count','tested_address',
    'core_started','quick_endpoints_passed','deep_tested','baseline_started_at',
    'median_ms','min_kib_s','download_kib_s','stability_seconds','reachability',
    'service_diagnostics','youtube_evidence','reason','subscription_sha256'}
ATTEMPT_KEYS = {'stage','endpoint','address','attempt','started_at','curl_exit','http_status',
    'bytes','elapsed_seconds','connect_seconds','tls_seconds','first_byte_seconds',
    'error','duration_seconds','passed'}
SERVICE_KEYS = {'label','http_status','blocking_signals','recognized_page','interpretation'}
BLOCKING_SIGNALS = {'challenge-element','consent-form','traffic-verification-form','challenge-frame',
    'malformed-html'} | {'title-or-heading:'+item.replace(' ','-') for item in
    ('just a moment','attention required','before you continue','access denied','captcha','unsupported_country')} | {
    'page-text:'+item.replace(' ','-') for item in ('verify you are human','checking your browser',
    'our systems have detected unusual traffic','enable javascript and cookies to continue',
    'service is not available in your country')}


def validate_attempts(row):
    if not isinstance(row,dict) or set(row)-ROW_KEYS: raise ValueError('unexpected result fields')
    for name in ('qualified','baseline_qualified','deep_tested','core_started'):
        if name in row and type(row[name]) is not bool: raise ValueError('invalid result flag')
    if 'original_uri_sha256' in row and not re.fullmatch('[0-9a-f]{64}',str(row['original_uri_sha256'])):
        raise ValueError('invalid original URI digest')
    if 'sources' in row and (not isinstance(row['sources'],list) or not row['sources'] or
                            any(url not in SOURCES for url in row['sources'])):
        raise ValueError('invalid result sources')
    if 'address_limit' in row and (type(row['address_limit']) is not int or row['address_limit']!=MAX_ENDPOINT_ADDRESSES):
        raise ValueError('invalid address limit')
    if 'resolved_address_count' in row: count(row['resolved_address_count'],65536)
    if 'median_ms' in row: count(row['median_ms'],120000)
    for name in ('min_kib_s','stability_seconds'):
        if name in row and number(row[name])<0: raise ValueError('invalid result measurement')
    if 'download_kib_s' in row and (not isinstance(row['download_kib_s'],list) or
        len(row['download_kib_s'])!=2 or any(number(value)<0 for value in row['download_kib_s'])):
        raise ValueError('invalid download measurements')
    if 'quick_endpoints_passed' in row and (not isinstance(row['quick_endpoints_passed'],list) or
        not row['quick_endpoints_passed'] or any(value not in QUICK_ENDPOINTS for value in row['quick_endpoints_passed'])):
        raise ValueError('invalid quick endpoint results')
    attempts=row.get('attempts')
    if not isinstance(attempts,list) or len(attempts)>32: raise ValueError('invalid attempts')
    checked=timestamp(row['checked_at']);completed=timestamp(row['completed_at'])
    allowed_endpoints=set(QUICK_ENDPOINTS)|{SPEED_ENDPOINT,'https://www.youtube.com/','https://chatgpt.com/'}
    stages={'quick-https','stability-15','stability-30','stability-45','download-1','download-2','service-youtube','service-chatgpt'}
    errors=set(CURL_ERROR_CATEGORIES.values())|{'curl-error','invalid-curl-metrics','process-timeout',
        'request-failed','http-status','response-shape-or-speed',None}
    last_time=checked
    for attempt in attempts:
        if not isinstance(attempt,dict) or set(attempt)-ATTEMPT_KEYS: raise ValueError('unexpected attempt fields')
        if attempt.get('stage') not in stages or attempt.get('endpoint') not in allowed_endpoints:
            raise ValueError('invalid diagnostic stage/endpoint')
        if not public_ip(attempt['address']): raise ValueError('unsafe diagnostic endpoint')
        if type(attempt['attempt']) is not int or not 1<=attempt['attempt']<=MAX_ATTEMPTS:
            raise ValueError('invalid attempt number')
        at=timestamp(attempt['started_at'])
        if not last_time<=at<=completed: raise ValueError('invalid attempt time order')
        last_time=at
        if attempt.get('error') not in errors: raise ValueError('unsafe diagnostic error')
        for name in ('duration_seconds','elapsed_seconds','connect_seconds','tls_seconds','first_byte_seconds'):
            if name in attempt and not 0<=number(attempt[name])<=120: raise ValueError('invalid request timing')
        if 'http_status' in attempt: count(attempt['http_status'],599)
        if 'bytes' in attempt: count(attempt['bytes'],max(DOWNLOAD_BYTES,2*1024*1024))
        if 'curl_exit' in attempt and attempt['curl_exit'] is not None: count(attempt['curl_exit'],255)
        if 'passed' in attempt and type(attempt['passed']) is not bool: raise ValueError('invalid attempt outcome')
        if attempt.get('passed') is True and (attempt.get('error') is not None or attempt.get('curl_exit',0)!=0):
            raise ValueError('contradictory successful attempt')
    addresses=row.get('resolved_addresses',[])
    if not isinstance(addresses,list) or len(addresses)>MAX_ENDPOINT_ADDRESSES or any(not public_ip(a) for a in addresses):
        raise ValueError('unsafe resolved addresses')
    if 'youtube_evidence' in row and row['youtube_evidence']!={'scope':'homepage-html-only',
            'video_playback_tested':False,'googlevideo_media_tested':False}:
        raise ValueError('unsupported YouTube evidence claim')
    diagnostics=row.get('service_diagnostics',{})
    reachability=row.get('reachability',{})
    if not isinstance(diagnostics,dict) or set(diagnostics)-{'youtube','chatgpt'} or not isinstance(reachability,dict) or set(reachability)-{'youtube','chatgpt'}:
        raise ValueError('invalid service diagnostics')
    for name,proof in diagnostics.items():
        if not isinstance(proof,dict) or set(proof)!=SERVICE_KEYS: raise ValueError('unexpected service fields')
        label=proof['label']
        if label not in ('page-confirmed','not-confirmed','unrecognized-page','challenge-or-blocked') and not re.fullmatch(r'http-[1-5][0-9]{2}',str(label)):
            raise ValueError('invalid service label')
        if proof['http_status'] is not None: count(proof['http_status'],599)
        if proof['interpretation']!='automated-http-test-only' or type(proof['recognized_page']) is not bool:
            raise ValueError('invalid service evidence scope')
        if not isinstance(proof['blocking_signals'],list) or any(item not in BLOCKING_SIGNALS for item in proof['blocking_signals']):
            raise ValueError('unsafe blocking signals')
        if reachability.get(name)!=label: raise ValueError('inconsistent service labels')
    if 'tested_address' in row and row['tested_address'] not in addresses: raise ValueError('unexpected tested address')
    if set(reachability)!=set(diagnostics): raise ValueError('missing service diagnostics')
    if not row.get('baseline_qualified'): return
    tested=row.get('tested_address')
    if tested not in addresses: raise ValueError('unverified tested address')
    baseline=timestamp(row['baseline_started_at'])
    if not checked<=baseline<=completed: raise ValueError('invalid baseline start')
    if (completed-baseline).total_seconds()<STABILITY_SECONDS-.01: raise ValueError('insufficient observed stability')
    final_proofs={}
    for stage in ('quick-https','stability-15','stability-30','stability-45','download-1','download-2'):
        matching=[a for a in attempts if a['stage']==stage and a['address']==tested and a.get('passed') is True]
        if not matching: raise ValueError('missing successful baseline diagnostic')
        a=matching[-1];final_proofs[stage]=a
        if stage.startswith('download'):
            if a['endpoint']!=SPEED_ENDPOINT or a.get('http_status')!=200 or a.get('bytes')!=DOWNLOAD_BYTES or not 0<number(a['elapsed_seconds'])<=DOWNLOAD_BYTES/MIN_BYTES_PER_SECOND:
                raise ValueError('weak download diagnostic')
        elif a['endpoint'] not in QUICK_ENDPOINTS or a.get('http_status')!=204 or a.get('bytes')!=0 or not 0<number(a['elapsed_seconds'])<=QUICK_TIMEOUT:
            raise ValueError('weak HTTPS diagnostic')
        if stage.startswith('stability-'):
            minimum=int(stage.split('-')[1])
            if (timestamp(a['started_at'])-baseline).total_seconds()<minimum-.01:
                raise ValueError('stability checkpoints compressed')
    if not timestamp(final_proofs['quick-https']['started_at'])<=baseline<=timestamp(final_proofs['download-1']['started_at'])<=timestamp(final_proofs['stability-15']['started_at'])<=timestamp(final_proofs['stability-30']['started_at'])<=timestamp(final_proofs['stability-45']['started_at'])<=timestamp(final_proofs['download-2']['started_at']):
        raise ValueError('baseline stage order mismatch')
    measured=[round(DOWNLOAD_BYTES/number(final_proofs['download-'+str(i)]['elapsed_seconds'])/1024,1) for i in (1,2)]
    if row.get('download_kib_s')!=measured or row.get('min_kib_s')!=min(measured):
        raise ValueError('download summary differs from attempt proof')
    for name,passed in row.get('service_qualified',{}).items():
        if not passed: continue
        proof=diagnostics.get(name)
        if not proof or proof['label']!='page-confirmed' or proof['http_status']!=200 or proof['recognized_page'] is not True or proof['blocking_signals']:
            raise ValueError('missing recognized service evidence')
        matching=[a for a in attempts if a['stage']=='service-'+name and a['address']==tested]
        if not matching: raise ValueError('missing service HTTP evidence')
        final=matching[-1]
        expected='https://www.youtube.com/' if name=='youtube' else 'https://chatgpt.com/'
        if final['endpoint']!=expected or final.get('http_status')!=200 or final.get('error') is not None or final.get('curl_exit',0)!=0 or not 0<count(final.get('bytes'),2*1024*1024) or timestamp(final['started_at'])<timestamp(final_proofs['download-2']['started_at']):
            raise ValueError('invalid successful service HTTP evidence')


def validate_coverage(report, results):
    sources=report['sources']
    if not isinstance(sources,list) or len(sources)!=len(SOURCES):
        raise ValueError('invalid source inventory')
    if [s['url'] for s in sources]!=SOURCES:
        raise ValueError('unexpected sources')
    totals={key:0 for key in ('lines','supported_lines','unique_candidates',
                             'unsupported_or_rejected_lines')}
    available=[]
    for source in sources:
        if type(source['downloaded']) is not bool: raise ValueError('invalid source status')
        if not source['downloaded']:
            if set(source)!={'url','downloaded','reason'} or source['reason']!='source-unavailable-or-invalid':
                raise ValueError('invalid source failure')
            continue
        available.append(source)
        timestamp(source['fetched_at'])
        if not isinstance(source.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',source['sha256']):
            raise ValueError('invalid source digest')
        if source.get('hash_scope') not in ('downloaded-source-bytes','utf8-text'):
            raise ValueError('invalid source hash scope')
        raw=count(source['lines'],MAX_FEED_LINES)
        count(source['raw_unique_lines'],raw)
        supported=count(source['supported_lines'],raw)
        unique=count(source['unique_candidates'],supported)
        count(source['unique_endpoints'],unique)
        if count(source['duplicate_supported_lines'],supported)!=supported-unique:
            raise ValueError('inconsistent source duplicates')
        rejected=count(source['unsupported_or_rejected_lines'],raw)
        if supported+rejected!=raw: raise ValueError('inconsistent source totals')
        histogram(source['raw_protocol_counts'],PROTOCOLS|{'other'},raw)
        histogram(source['supported_protocol_counts'],PROTOCOLS,unique)
        histogram(source['rejection_categories'],REJECTION_CATEGORIES,rejected)
        for key in totals: totals[key]+=source[key]
    maximum=MAX_FEED_LINES*len(SOURCES)
    for global_key,source_key in (('raw_lines','lines'),('supported_lines','supported_lines'),
                                 ('unsupported_or_rejected_lines','unsupported_or_rejected_lines')):
        if count(report[global_key],maximum)!=totals[source_key]:
            raise ValueError('inconsistent input totals')
    raw_unique=count(report['raw_unique_lines'],report['raw_lines'])
    if raw_unique<max((s['raw_unique_lines'] for s in available),default=0):
        raise ValueError('inconsistent unique input count')
    unique=count(report['unique_candidates'],report['supported_lines'])
    if unique<max((s['unique_candidates'] for s in available),default=0):
        raise ValueError('inconsistent supported unique count')
    count(report['unique_endpoints'],unique)
    if count(report['duplicate_supported_lines'],maximum)!=report['supported_lines']-unique:
        raise ValueError('inconsistent global duplicates')
    if count(report['cross_source_duplicate_candidates'],maximum)!=totals['unique_candidates']-unique:
        raise ValueError('inconsistent cross-source duplicates')
    histogram(report['candidate_protocol_counts'],PROTOCOLS,unique)
    history=report.get('history')
    assessed=unique
    if history is not None:
        current_ids=history.get('current_ids')
        if not isinstance(current_ids,list) or len(current_ids)!=unique or len(set(current_ids))!=unique:
            raise ValueError('invalid current upstream inventory')
        result_ids={row['id'] for row in results}
        if not set(current_ids)<=result_ids: raise ValueError('missing upstream assessment')
        if history.get('current_candidates')!=unique: raise ValueError('inconsistent current inventory')
        retained=count(history['retained_candidates'],MAX_CANDIDATES)
        assessed=unique+retained
        if history['assessed_candidates']!=assessed: raise ValueError('inconsistent retained coverage')
    if assessed>MAX_CANDIDATES or len(results)!=assessed:
        raise ValueError('incomplete candidate selection')
    expected=coverage_summary(sources,assessed,results)
    actual=report['coverage']
    if not expected['complete_supported']: raise ValueError('incomplete supported coverage')
    if not isinstance(actual,dict) or actual!=expected:
        raise ValueError('inconsistent coverage')
    for key,value in expected.items():
        if type(actual[key]) is not type(value): raise ValueError('invalid coverage types')


def validate(root, *, as_of=None, allow_legacy_split=False):
    root=Path(root)
    now=as_of or datetime.now(timezone.utc)
    from history import strict_json
    report_path=root/'report.json'
    if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size>64_000_000:
        raise ValueError('invalid report file')
    report=strict_json(report_path.read_bytes())
    extra_files=set()
    if isinstance(report,dict) and 'history' in report:
        from history import SPLIT_FEEDS, MAX_BYTES as MAX_HISTORY_BYTES
        extra_files={*SPLIT_FEEDS.values(),'history.json'}
    if {p.name for p in root.iterdir()} != {*FEEDS.values(), 'report.json'}|extra_files:
        raise ValueError('unexpected output files')
    for p in root.iterdir():
        if p.is_symlink() or not p.is_file() or p.stat().st_size > (64_000_000 if p.name=='report.json' else MAX_HISTORY_BYTES if p.name=='history.json' else 4_000_000):
            raise ValueError('invalid output file')
    allowed={'schema_version','started_at','completed_at','vantage','probe_origin','identity_version',
        'identity_scope','core','sources','raw_lines','raw_unique_lines','supported_lines','unique_candidates',
        'unique_endpoints','duplicate_supported_lines','cross_source_duplicate_candidates',
        'unsupported_or_rejected_lines','candidate_protocol_counts','sampled','coverage','deep_tested',
        'qualified','feed_counts','results','method','interpretation','diagnostics','limits','max_age_hours',
        'freshness_note','production','history','resources'}
    if not isinstance(report,dict) or set(report)-allowed: raise ValueError('unexpected public report fields')
    if report.get('schema_version') != 4: raise ValueError('unknown schema')
    age=(now-datetime.fromisoformat(report['completed_at'])).total_seconds()
    if not 0 <= age < 3600: raise ValueError('stale output')
    if report.get('identity_version')!=CANONICALIZATION_VERSION: raise ValueError('unknown identity version')
    origin=report.get('probe_origin',{})
    if origin.get('russia_verified') is not False or origin.get('country')!='unknown':
        raise ValueError('unverified geographic claim')
    if origin.get('provider') not in ('github-actions','local') or origin.get('path_status')!='unknown':
        raise ValueError('invalid probe origin')
    sampled=count(report['sampled'],MAX_CANDIDATES)
    deep=count(report['deep_tested'],min(MAX_DEEP,sampled))
    results=report['results']
    if not isinstance(results,list) or len(results)!=sampled: raise ValueError('inconsistent results')
    expected={key:set() for key in FEEDS}
    ids=set();results_by_id={}
    actual_deep=0
    for row in results:
        rid=row['id']
        if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{16}',rid) or rid in ids:
            raise ValueError('invalid result identity')
        ids.add(rid);results_by_id[rid]=row
        if row.get('identity_version')!=CANONICALIZATION_VERSION: raise ValueError('bad node identity version')
        checked=timestamp(row['checked_at']);completed=timestamp(row['completed_at'])
        if completed<checked or (now-checked).total_seconds()>MAX_RESULT_AGE_SECONDS:
            raise ValueError('stale node measurement')
        if row.get('reason') in ('budget','deep-budget','core-start-failed','core-stopped'):
            raise ValueError('incomplete/infrastructure failure')
        validate_attempts(row)
        if row.get('protocol') not in PROTOCOLS: raise ValueError('invalid result protocol')
        if 'reason' in row and row['reason'] not in RESULT_FAILURE_REASONS:
            raise ValueError('invalid result reason')
        if row.get('deep_tested') is True: actual_deep+=1
        services=row['service_qualified']
        if set(services)!={'youtube','chatgpt'} or any(type(x) is not bool for x in services.values()):
            raise ValueError('invalid service results')
        qualified=row['qualified']
        if type(qualified) is not bool or qualified != all(services.values()):
            raise ValueError('invalid combined qualification')
        if any(services.values()):
            if row.get('reason') in ('budget','deep-budget'):
                raise ValueError('incomplete node cannot qualify')
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
        for line in lines:
            parse_uri(line)
            if node_id(line) not in results_by_id: raise ValueError('feed identity has no measurement')
            row=results_by_id[node_id(line)]
            if row.get('subscription_sha256')!=hashlib.sha256(line.encode()).hexdigest():
                raise ValueError('feed identity/digest mismatch')
        hashes={hashlib.sha256(line.encode()).hexdigest() for line in lines}
        if len(hashes)!=len(lines) or hashes!=expected[key]: raise ValueError('inconsistent feed contents')
    if count(report['qualified'],deep) != report['feed_counts']['both']:
        raise ValueError('inconsistent primary count')
    validate_coverage(report,results)
    if 'history' in report:
        validate_history_outputs(root,report,results,now,allow_legacy_split=allow_legacy_split)


def validate_history_outputs(root, report, results, now, *, allow_legacy_split=False):
    import history as h
    metadata=report['history']
    allowed={'state_sha256','provenance','current_candidates','retained_candidates',
             'assessed_candidates','current_ids','split_counts','policy','eligible_before_diversity',
             'stable_ids','reserve_ids','evidence'}
    if not isinstance(metadata,dict): raise ValueError('invalid history metadata')
    if metadata.get('policy') != h.LEGACY_POLICY:
        allowed.add('selection')
    if not isinstance(metadata,dict) or set(metadata)!=allowed: raise ValueError('invalid history metadata')
    data=(root/'history.json').read_bytes()
    if hashlib.sha256(data).hexdigest()!=metadata['state_sha256']: raise ValueError('history digest mismatch')
    state=h.validate(h.strict_json(data),now=now,require_recent=True)
    if state['created_at']!=report['started_at']: raise ValueError('history snapshot mismatch')
    production=report['production']
    run=state['runs'][-1] if state['runs'] else {}
    if (run.get('run_id'),run.get('run_attempt'),run.get('implementation_sha'))!=(production['run_id'],production['run_attempt'],production['implementation_sha']):
        raise ValueError('history run mismatch')
    exports={node_id(line):line for line in (root/FEEDS['youtube']).read_text().splitlines()}
    feeds,ranking=h.split_for_report(state,results,exports,report,allow_legacy=allow_legacy_split)
    if any(metadata.get(k)!=v for k,v in ranking.items()): raise ValueError('history ranking mismatch')
    if metadata['split_counts']!={key:len(lines) for key,lines in feeds.items()}:
        raise ValueError('split count mismatch')
    for key,filename in h.SPLIT_FEEDS.items():
        if (root/filename).read_text().splitlines()!=feeds[key]: raise ValueError('split feed mismatch')
    entries={entry['id']:entry for entry in state['entries']}
    current=set(metadata['current_ids'])
    source_times={source['url']:timestamp(source['fetched_at']) for source in report['sources']}
    for row in results:
        entry=entries.get(row['id'])
        if entry is None: raise ValueError('missing history assessment')
        observation=entry['observations'][-1]
        passed=row['service_qualified']['youtube']
        expected={'run_id':production['run_id'],'youtube':passed,
                  'min_kib_s':h.measured_min_speed(row) if passed else None,
                  'median_ms':row.get('median_ms') if passed else None,
                  'tested_address':row.get('tested_address') if passed else None}
        if observation!=expected: raise ValueError('history outcome mismatch')
        seen=timestamp(entry['last_upstream_seen_at'])
        if row['id'] in current:
            if seen!=max(source_times[u] for u in row['sources']): raise ValueError('source presence time mismatch')
        elif (now-seen).total_seconds()>h.MAX_AGE_SECONDS:
            raise ValueError('historical candidate expired before publication')


if __name__=='__main__': validate(sys.argv[1])
