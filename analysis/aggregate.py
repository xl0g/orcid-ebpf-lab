import json, glob, statistics as st, collections
SECRETS=('/app/.env','/root/.aws/credentials','/var/run/secrets/kubernetes.io/serviceaccount/token')
ATTACK_EXE={'cat','head','dd','base64','od','xxd'}
IOC_EXE={'cat','head','dd','base64','od','xxd','curl','wget','nc','ncat'}
base=lambda p:(p or '').rsplit('/',1)[-1]; pref=lambda p:'/'.join((p or '').split('/')[:4])

class Ev:
    __slots__=('k','ns','cg','comm','file','port','ip')
    def __init__(s,p):
        s.k,s.ns,s.cg,s.comm=p[0],int(p[1]),int(p[2]),p[4]; s.file=s.port=s.ip=None
        if s.k in('X','F'): s.file=p[5]
        elif s.k=='O': s.file=p[6]
        elif s.k=='C': s.port,s.ip=p[5],p[6]

def load(run):
    O=f'results/{run}'; ids=json.load(open(f'{O}/identities.json'))
    variants=[json.loads(l) for l in open(f'{O}/campaign.jsonl')] if open(f'{O}/campaign.jsonl').read().strip() else []
    E=[]
    for line in open(f'{O}/events.tsv'):
        p=line.rstrip('\n').split('\t')
        if len(p)>=6 and p[0] in 'FXOC':
            try:E.append(Ev(p))
            except:pass
    E.sort(key=lambda e:e.ns)
    return ids,variants,E

is_secret=lambda e:e.k=='O' and any(s in (e.file or '') for s in SECRETS)
is_outb=lambda e:e.k=='C' and e.port!='53' and not (e.ip or '').startswith('127.')
def detectors(train):
    prof=collections.defaultdict(lambda:{'exe':set(),'op':set(),'dst':set()})
    for e in train:
        pr=prof[e.cg]
        if e.k=='X':pr['exe'].add(base(e.file))
        elif e.k=='O':pr['op'].add(pref(e.file))
        elif e.k=='C':pr['dst'].add((e.port,e.ip))
    d0=lambda e:e.k=='X' and (base(e.file) in IOC_EXE or '/dev/tcp' in (e.file or ''))
    d1=lambda e:is_secret(e) or (is_outb(e) and e.port=='8080')
    def d2(e):
        pr=prof[e.cg]
        if e.k=='X' and base(e.file) not in pr['exe']:return True
        if e.k=='O' and is_secret(e) and pref(e.file) not in pr['op']:return True
        if e.k=='C' and is_outb(e) and (e.port,e.ip) not in pr['dst']:return True
        return False
    return {'D0':d0,'D1':d1,'D2':d2},prof

def is_mal(e,V):
    if e.cg!=V:return False
    return is_secret(e) or (is_outb(e) and e.port=='8080') or (e.k=='X' and base(e.file) in ATTACK_EXE)

# ---- attack runs: detection + TTD + backup FP ----
det=collections.defaultdict(list); ttd=collections.defaultdict(list); bfp=collections.defaultdict(list); missed_all=[]
for run in ['att_7','att_11','att_23']:
    ids,variants,E=load(run); V,B=ids['victim'],ids['backup']
    t0=min(v['t_start_ns'] for v in variants)
    train=[e for e in E if e.ns<t0]; test=[e for e in E if e.ns>=t0]
    fns,_=detectors(train)
    tmin=(max(e.ns for e in test)-t0)/1e9/60
    for nm,fn in fns.items():
        hit={}; fb=0
        for e in test:
            if not fn(e):continue
            if is_mal(e,V):
                for v in variants:
                    if v['t_start_ns']<=e.ns<=v['t_end_ns']+2e9: hit.setdefault(v['variant'],e.ns-v['t_start_ns'])
            elif e.cg==B: fb+=1
        det[nm].append(len(hit)/len(variants)); bfp[nm].append(fb/tmin)
        if hit: ttd[nm].append(st.median(hit.values())/1e6)
        if nm=='D2': missed_all.append(sorted(set(v['variant'] for v in variants)-set(hit)))

# ---- control run: FP rate on benign victim+backup ----
ids,_,E=load('control'); V,B=ids['victim'],ids['backup']
t0=min(e.ns for e in E)+40e9  # 40s train
train=[e for e in E if e.ns<t0]; test=[e for e in E if e.ns>=t0]
fns,_=detectors(train); cmin=(max(e.ns for e in test)-t0)/1e9/60
cfp={}
for nm,fn in fns.items():
    v_fp=sum(1 for e in test if fn(e) and e.cg==V); b_fp=sum(1 for e in test if fn(e) and e.cg==B)
    cfp[nm]={'victim_fp':v_fp,'backup_fp':b_fp,'fp_per_min':round((v_fp+b_fp)/cmin,2)}

ms=lambda xs:(round(st.mean(xs),3),round(st.pstdev(xs),3))
summary={'attack_runs':['att_7','att_11','att_23'],'variants_each':40,
 'detection_rate_mean_std':{k:ms(det[k]) for k in ['D0','D1','D2']},
 'backup_fp_per_min_attackrun':{k:ms(bfp[k]) for k in ['D0','D1','D2']},
 'median_ttd_ms':{k:round(st.mean(ttd[k]),1) for k in ['D0','D1','D2'] if ttd[k]},
 'control_fp':cfp,'control_minutes':round(cmin,1),
 'd2_missed_variants_per_seed':missed_all}
json.dump(summary,open('results/summary.json','w'),indent=2); print(json.dumps(summary,indent=2))
