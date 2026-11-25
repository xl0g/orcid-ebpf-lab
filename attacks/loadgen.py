# Benign traffic generator for the victim service.
import random, sys, time, urllib.request
seed, dur = int(sys.argv[1]), float(sys.argv[2]); rnd = random.Random(seed)
paths = [('/', 30), ('/items?m=%d', 30), ('/health', 15), ('POST', 10), ('/status', 8), ('/report', 4), ('/export', 3)]
end = time.time() + dur
while time.time() < end:
    p = rnd.choices([x for x, _ in paths], [w for _, w in paths])[0]
    try:
        if p == 'POST': urllib.request.urlopen(urllib.request.Request('http://victim:8000/log', data=b'x' * rnd.randint(10, 500)), timeout=10).read()
        else: urllib.request.urlopen('http://victim:8000' + (p % rnd.randint(2, 20) if '%d' in p else p), timeout=10).read()
    except Exception as e: print('err', e, file=sys.stderr)
    time.sleep(rnd.expovariate(20))
