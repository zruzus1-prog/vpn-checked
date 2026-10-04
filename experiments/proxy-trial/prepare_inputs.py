#!/usr/bin/env python3
"""Fetch six allowlisted public feeds and one official SHA-verified binary.

No configuration URI is used as a download URL or executable argument here.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import trial

ROOT=Path(__file__).resolve().parent
CORE_URL='https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz'
CORE_SHA='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6'
ALLOWED={
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt',
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt',
 'https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt',
 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt',
 'https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure/vless.txt',
 'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt',
}

def download(url,path,maximum,timeout,redirects=False):
    args=['curl','--disable','--silent','--show-error','--fail','--proxy','','--proto','=https','--proto-redir','=https',
          '--connect-timeout','8','--max-time',str(timeout),'--max-filesize',str(maximum),'--output',str(path)]
    if redirects:args+=['--location','--max-redirs','5']
    subprocess.run(args+[url],check=True,env=trial.ENV,timeout=timeout+2)
    if path.stat().st_size>maximum:raise ValueError('Downloaded file exceeds budget')

def main():
    manifest=json.loads((ROOT/'feeds.json').read_text())
    if len(manifest)>6 or len({x['url'] for x in manifest})!=len(manifest):raise ValueError('Invalid manifest')
    (ROOT/'inputs').mkdir(exist_ok=True)
    failures=[]
    for src in manifest:
        if src['url'] not in ALLOWED:raise ValueError('Unapproved source URL')
        path=(ROOT/src['file']).resolve()
        if path.parent!=ROOT/'inputs':raise ValueError('Unsafe local path')
        path.unlink(missing_ok=True)
        try:download(src['url'],path,trial.MAX_FEED,20)
        except (OSError,subprocess.SubprocessError):
            path.unlink(missing_ok=True);failures.append(src['id'])
    print(json.dumps({'feeds_attempted':len(manifest),'failed_source_ids':failures}))
    inventory=trial.prepare(manifest,'GitHub ubuntu-24.04 hosted runner; not Russia or the user network')
    if inventory['selected_unique']==0:raise ValueError('No supported candidates; live trial not started')
    archive=ROOT/'core.tar.gz'
    download(CORE_URL,archive,64*1024*1024,90,True)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=CORE_SHA:raise ValueError('Official core SHA-256 mismatch')
    with tarfile.open(archive,'r:gz') as tar:
        m=tar.getmember('sing-box-1.14.2-linux-amd64/sing-box')
        if not m.isfile() or m.size>100000000:raise ValueError('Unexpected core archive member')
        data=tar.extractfile(m).read()
    (ROOT/'bin').mkdir(exist_ok=True);binary=ROOT/'bin/sing-box';binary.write_bytes(data);binary.chmod(0o755)
    (ROOT/'core-verification.json').write_text(json.dumps({'version':'1.14.2','archive_sha256':CORE_SHA,'binary_sha256':hashlib.sha256(data).hexdigest(),'source':CORE_URL},indent=2)+'\n')
    subprocess.run([str(binary),'version'],check=True,env=trial.ENV,timeout=5)

if __name__=='__main__':main()
