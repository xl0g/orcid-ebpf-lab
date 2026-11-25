import os,sys,time
n=int(sys.argv[1]); t=time.monotonic_ns()
for i in range(n):
    try: fd=os.open('/etc/hostname',os.O_RDONLY); os.close(fd)
    except: pass
d=(time.monotonic_ns()-t)/1e9
print(f'{n} openat in {d:.3f}s = {n/d/1000:.1f}k/s, {d/n*1e9:.0f}ns/syscall')
