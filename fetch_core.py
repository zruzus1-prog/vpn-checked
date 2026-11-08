#!/usr/bin/env python3
"""Download only a fixed official archive and verify its pinned digest before extraction."""
import hashlib
import json
from email.utils import parsedate_to_datetime
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time


def retry_delay(error, attempt):
    """Only retry selected transport/HTTP failures, never TLS or local errors."""
    status, _, retry_after = (error.stdout or '').partition('\n')
    if not (len(status) == 3 and status.isascii() and status.isdigit()):
        return None
    if not (error.returncode in (28, 56) or
            (error.returncode == 22 and status in {'408', '429', '500', '502', '503', '504'})):
        return None
    delay = 2 ** attempt
    retry_after = retry_after.strip()
    if retry_after:
        if retry_after.isascii() and retry_after.isdigit():
            if len(retry_after) > 10:
                return None
            delay = max(delay, int(retry_after))
        else:
            try:
                date = parsedate_to_datetime(retry_after)
                if date.tzinfo is None:
                    return None
                delay = max(delay, date.timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                return None
    return delay


def download(url, archive):
    # Python owns the only retry loop: three attempts total, with one deadline.
    # Capture only final response metadata; the archive still goes to its file.
    command = ['curl','--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--proxy','','--max-time','60','--max-filesize','80000000','--write-out','%{http_code}\n%header{retry-after}','--output',str(archive),url]
    deadline = time.monotonic() + 190
    for attempt in range(3):
        archive.unlink(missing_ok=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, 190)
        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True,
                           timeout=min(65, remaining))
            return
        except subprocess.CalledProcessError as error:
            delay = retry_delay(error, attempt)
            if attempt == 2 or delay is None or time.monotonic() + delay >= deadline:
                raise
            time.sleep(delay)


def install():
    lock=json.loads(Path('core-lock.json').read_text())
    version=lock['version']; digest=lock['sha256']
    import re
    if not re.fullmatch(r'\d+\.\d+\.\d+',version) or not re.fullmatch(r'[0-9a-f]{64}',digest):
        raise ValueError('invalid core lock; refuse download')
    filename=f'sing-box-{version}-linux-amd64.tar.gz'
    url=f'https://github.com/SagerNet/sing-box/releases/download/v{version}/{filename}'
    with tempfile.TemporaryDirectory() as td:
        archive=Path(td)/'core.tar.gz'
        download(url, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=digest:
            raise ValueError('core checksum mismatch')
        with tarfile.open(archive,'r:gz') as tar:
            member=tar.getmember(f'sing-box-{version}-linux-amd64/sing-box')
            if not member.isfile() or member.size>100000000: raise ValueError('invalid core member')
            data=tar.extractfile(member).read()
        Path('bin').mkdir(exist_ok=True)
        target=Path('bin/sing-box'); target.write_bytes(data); target.chmod(0o755)
        (target.parent/'core-verification.json').write_text(json.dumps({
            'version':version,'archive_sha256':digest,
            'binary_sha256':hashlib.sha256(data).hexdigest()},sort_keys=True)+'\n')
    print('Official core archive verified; no proxy connections made by installer.')

if __name__=='__main__': install()
