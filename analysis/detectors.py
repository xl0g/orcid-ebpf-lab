# Three detectors scored on the same captured eBPF event stream (per-type field layout fixed).
#   X ns cg pid comm FILE            (execve)
#   F ns cg child ppid pcomm         (fork/lineage)
#   O ns cg pid comm FLAGS FILE      (openat)
#   C ns cg pid comm PORT IP         (connect)
import json, sys, collections

RUN = sys.argv[1]; O = f'results/{RUN}'
ids = json.load(open(f'{O}/identities.json'))
VICTIM, BACKUP = ids['victim'], ids['backup']
variants = [json.loads(l) for l in open(f'{O}/campaign.jsonl')]
GRACE = 2_000_000_000
t_first = min(v['t_start_ns'] for v in variants)
SECRETS = ('/app/.env', '/root/.aws/credentials', '/var/run/secrets/kubernetes.io/serviceaccount/token')

class Ev:
    __slots__=('k','ns','cg','pid','comm','file','flags','port','ip')
    def __init__(s,p):
        s.k,s.ns,s.cg,s.pid,s.comm=p[0],int(p[1]),int(p[2]),int(p[3]),p[4]
        s.file=s.flags=s.port=s.ip=None
        if s.k=='X': s.file=p[5]
        elif s.k=='O': s.flags,s.file=p[5],p[6]
        elif s.k=='C': s.port,s.ip=p[5],p[6]
        elif s.k=='F': s.file=p[5]
E=[]
for line in open(f'{O}/events.tsv'):
    p=line.rstrip('\n').split('\t')
    if len(p)<6 or p[0] not in 'FXOC': continue
    try: E.append(Ev(p))
    except: pass
E.sort(key=lambda e:e.ns)
train=[e for e in E if e.ns<t_first]; test=[e for e in E if e.ns>=t_first]
base=lambda path:(path or '').rsplit('/',1)[-1]
pref=lambda path:'/'.join((path or '').split('/')[:4])
is_secret=lambda e: e.k=='O' and any(s in (e.file or '') for s in SECRETS)
is_outbound=lambda e: e.k=='C' and e.port!='53' and not (e.ip or '').startswith('127.')

# ground truth: semantic attack-induced victim events (detector-independent)
ATTACK_EXE={'cat','head','dd','base64','od','xxd'}
def is_mal(e):
    if e.cg!=VICTIM: return False
    if is_secret(e): return True
    if is_outbound(e) and e.port=='8080': return True
    if e.k=='X' and base(e.file) in ATTACK_EXE: return True
    return False
def vof(e):
    for v in variants:
        if v['t_start_ns']<=e.ns<=v['t_end_ns']+GRACE: return v['variant']
    return None

IOC_EXE={'cat','head','dd','base64','od','xxd','curl','wget','nc','ncat'}
d0=lambda e: e.k=='X' and (base(e.file) in IOC_EXE or '/dev/tcp' in (e.file or ''))
d1=lambda e: is_secret(e) or (is_outbound(e) and e.port=='8080')
prof=collections.defaultdict(lambda:{'exe':set(),'op':set(),'dst':set()})
for e in train:
    pr=prof[e.cg]
    if e.k=='X': pr['exe'].add(base(e.file))
    elif e.k=='O': pr['op'].add(pref(e.file))
    elif e.k=='C': pr['dst'].add((e.port,e.ip))
def d2(e):
    pr=prof[e.cg]
    if e.k=='X' and base(e.file) not in pr['exe']: return True
    if e.k=='O' and is_secret(e) and pref(e.file) not in pr['op']: return True
    if e.k=='C' and is_outbound(e) and (e.port,e.ip) not in pr['dst']: return True
    return False

def score(fn,name):
    det=set(); fpb=0; fpv=0; first={}
    for e in test:
        if not fn(e): continue
        if e.cg==VICTIM and is_mal(e):
            v=vof(e)
            if v is not None: det.add(v); first.setdefault(v,e.ns)
            else: fpv+=1
        elif e.cg==BACKUP: fpb+=1
        elif e.cg==VICTIM: fpv+=1
    ttd=sorted((first[v['variant']]-v['t_start_ns'])/1e6 for v in variants if v['variant'] in first)
    tmin=(max(e.ns for e in test)-t_first)/1e9/60
    return {'detector':name,'detection_rate':round(len(det)/len(variants),3),
            'variants_detected':len(det),'fp_backup_alerts':fpb,'fp_backup_per_min':round(fpb/tmin,2),
            'fp_victim_benign':fpv,'median_ttd_ms':round(ttd[len(ttd)//2],1) if ttd else None,
            'p90_ttd_ms':round(ttd[min(int(len(ttd)*0.9),len(ttd)-1)],1) if ttd else None}

res=[score(d0,'D0 signature'),score(d1,'D1 global-invariant'),score(d2,'D2 OrcID identity')]
missed=sorted(set(v['variant'] for v in variants)-set().union(*[{v['variant'] for v in variants if (lambda fn:any(fn(e) and e.cg==VICTIM and is_mal(e) and vof(e)==v['variant'] for e in test))(d2)} ]) ) if False else None
meta={'run':RUN,'events_total':len(E),'train_events':len(train),'test_events':len(test),
      'train_seconds':round((t_first-min(e.ns for e in E))/1e9,1),
      'victim_exe_profile':sorted(x for x in prof[VICTIM]['exe'] if x),
      'backup_exe_profile':sorted(x for x in prof[BACKUP]['exe'] if x),
      'backup_reads_creds':any(is_secret(e) for e in E if e.cg==BACKUP),
      'backup_outbound_8080':any(e.cg==BACKUP and is_outbound(e) and e.port=='8080' for e in E)}
out={'meta':meta,'results':res}; json.dump(out,open(f'{O}/detection.json','w'),indent=2); print(json.dumps(out,indent=2))
