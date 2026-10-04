#!/usr/bin/env python3
"""Download only a fixed official archive and verify its pinned digest before extraction."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


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
        subprocess.run(['curl','--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--proxy','','--max-time','60','--max-filesize','80000000','--output',str(archive),url],check=True,timeout=65)
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
