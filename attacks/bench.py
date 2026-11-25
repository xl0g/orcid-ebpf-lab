import sys,time,urllib.request
host,n=sys.argv[1],int(sys.argv[2]); lat=[]
for i in range(n):
    t=time.monotonic_ns()
    urllib.request.urlopen(f'http://{host}:8000/items?m={i%17+2}',timeout=30).read()
    lat.append((time.monotonic_ns()-t)/1e6)
lat.sort(); import statistics as s
print(f'{n} reqs mean={s.mean(lat):.2f}ms p50={lat[n//2]:.2f} p99={lat[int(n*0.99)]:.2f}')
