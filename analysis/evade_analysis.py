# D2 (novelty) vs D3 (novelty + per-identity rate anomaly) across the evasion ladder.
import json, sys, glob, collections, statistics as st
SECRETS=('/app/.env','/root/.aws/credentials','/var/run/secrets/kubernetes.io/serviceaccount/token')
base=lambda p:(p or '').rsplit('/',1)[-1]; pref=lambda p:'/'.join((p or '').split('/')[:4])
class Ev:
    __slots__=('k','ns','cg','comm','file','port','ip')
    def __init__(s,p):
        s.k,s.ns,s.cg,s.comm=p[0],int(p[1]),int(p[2]),p[4]; s.file=s.port=s.ip=None
        if s.k in('X','F'):s.file=p[5]
        elif s.k=='O':s.file=p[6]
        elif s.k=='C':s.port,s.ip=p[5],p[6]
def load(run):
    O=f'results/{run}'; ids=json.load(open(f'{O}/identities.json'))
    vs=[json.loads(l) for l in open(f'{O}/campaign.jsonl')] if open(f'{O}/campaign.jsonl').read().strip() else []
    E=[]
    for l in open(f'{O}/events.tsv'):
        p=l.rstrip('\n').split('\t')
        if len(p)>=6 and p[0] in 'FXOC':
            try:E.append(Ev(p))
            except:pass
    E.sort(key=lambda e:e.ns); return ids,vs,E
is_secret=lambda e:e.k=='O' and any(s in (e.file or '') for s in SECRETS)
is_outb=lambda e:e.k=='C' and e.port!='53' and not (e.ip or '').startswith('127.')
W=2_000_000_000

def build(train):
    prof=collections.defaultdict(lambda:{'exe':set(),'op':set(),'dst':set()})
    sec_times=collections.defaultdict(list)
    for e in train:
        pr=prof[e.cg]
        if e.k=='X':pr['exe'].add(base(e.file))
        elif e.k=='O':
            pr['op'].add(pref(e.file))
            if is_secret(e):sec_times[e.cg].append(e.ns)
    # baseline: max secret-opens by a cgroup within any W-window during training
    base_rate={}
    for cg,ts in sec_times.items():
        ts.sort(); m=0; j=0
        for i in range(len(ts)):
            while ts[i]-ts[j]>W:j+=1
            m=max(m,i-j+1)
        base_rate[cg]=m
    for e in train:
        if e.k=='C':prof[e.cg]['dst'].add((e.port,e.ip))
    return prof,base_rate,sec_times

def d2(e,prof):
    pr=prof[e.cg]
    if e.k=='X' and base(e.file) not in pr['exe']:return 'novel-exec'
    if e.k=='O' and is_secret(e) and pref(e.file) not in pr['op']:return 'novel-path'
    if e.k=='C' and is_outb(e) and (e.port,e.ip) not in pr['dst']:return 'novel-dst'
    return None
# D3 adds a per-identity sliding-window rate anomaly on sensitive reads
def make_d3(prof,base_rate):
    recent=collections.defaultdict(collections.deque)
    def d3(e):
        s=d2(e,prof)
        if s:return s
        if is_secret(e):
            dq=recent[e.cg]; dq.append(e.ns)
            while dq and e.ns-dq[0]>W:dq.popleft()
            if len(dq)>base_rate.get(e.cg,0)+2:return 'rate-anomaly'
        return None
    return d3

def score_run(run):
    ids,vs,E=load(run); V=ids['victim']; cls=ids['cls']
    t0=min(v['t_start_ns'] for v in vs)
    train=[e for e in E if e.ns<t0]; test=[e for e in E if e.ns>=t0]
    prof,brate,_=build(train); d3=make_d3(prof,brate)
    def detect(fn):
        hit=set(); why=collections.Counter()
        for e in test:
            if e.cg!=V:continue
            s=fn(e)
            if not s:continue
            for v in vs:
                if v['t_start_ns']<=e.ns<=v['t_end_ns']+2e9:
                    hit.add(v['variant'])
                    if v['variant'] not in getattr(detect,'_seen',set()):why[s]+=1
        return len(hit)/len(vs),why
    r2,_=detect(lambda e:d2(e,prof)); r3,why3=detect(d3)
    return cls,r2,r3,why3

runs=[r.split('/')[-2] for r in glob.glob('results/A*_*/identities.json')]
agg=collections.defaultdict(lambda:{'d2':[],'d3':[],'why':collections.Counter()})
for run in sorted(runs):
    cls,r2,r3,why=score_run(run)
    agg[cls]['d2'].append(r2); agg[cls]['d3'].append(r3); agg[cls]['why']+=why
# FP on benign control: alerts per minute on victim+backup
ids,_,E=load('control2'); V,B=ids['victim'],ids['backup']
t0=min(e.ns for e in E)+45e9
train=[e for e in E if e.ns<t0]; test=[e for e in E if e.ns>=t0]
prof,brate,_=build(train); d3=make_d3(prof,brate)
cmin=(max(e.ns for e in test)-t0)/1e9/60
fp2=sum(1 for e in test if e.cg in(V,B) and d2(e,prof)); fp3=sum(1 for e in test if e.cg in(V,B) and d3(e))
order=['A1','A2','A3h','A3s']; lab={'A1':'A1 naif','A2':'A2 living-off-the-land','A3h':'A3 mimetisme (harvest)','A3s':'A3 mimetisme (furtif)'}
out={'per_class':[{'class':lab[c],'d2_detection':round(st.mean(agg[c]['d2']),3),'d3_detection':round(st.mean(agg[c]['d3']),3),'d3_signals':dict(agg[c]['why'])} for c in order if agg[c]['d2']],
     'control_fp_per_min':{'D2':round(fp2/cmin,2),'D3':round(fp3/cmin,2)},'control_minutes':round(cmin,1),'seeds':sorted(set(r.split('_')[-1] for r in runs))}
json.dump(out,open('results/evasion.json','w'),indent=2); print(json.dumps(out,indent=2,ensure_ascii=False))
