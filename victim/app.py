# Victim web service. Two deliberately vulnerable endpoints simulate an initial foothold:
#   /debug?cmd=  -> OS command injection (shell=True)
#   /calc?expr=  -> Python code injection (eval)
import http.server, json, os, random, sqlite3, subprocess, threading, time, urllib.parse
for line in open('/app/.env'):
    k, _, v = line.strip().partition('=')
    os.environ.setdefault(k, v)
DB = '/app/data.db'
con = sqlite3.connect(DB); con.execute('create table if not exists items(id integer primary key, name text)')
if not con.execute('select count(*) from items').fetchone()[0]:
    con.executemany('insert into items(name) values (?)', [(f'item{i}',) for i in range(200)])
con.commit(); con.close()
os.makedirs('/app/logs', exist_ok=True)

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ctype='text/plain'):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == '/':
            return self.send(200, open('/app/templates/index.html', 'rb').read(), 'text/html')
        if u.path == '/items':
            c = sqlite3.connect(DB); rows = c.execute('select id,name from items where id % ? = 0', (int(q.get('m', ['7'])[0]),)).fetchall(); c.close()
            return self.send(200, json.dumps(rows), 'application/json')
        if u.path == '/status':
            out = subprocess.run('df -h /app | tail -1', shell=True, capture_output=True, text=True).stdout
            return self.send(200, out)
        if u.path == '/report':
            with open('/app/logs/app.log', 'a') as f: f.write(f'{time.time()} report\n')
            subprocess.run(['gzip', '-kf', '/app/logs/app.log'])
            return self.send(200, 'ok')
        if u.path == '/export':
            p = f'/tmp/export-{random.randint(0, 1 << 30)}.csv'
            c = sqlite3.connect(DB)
            with open(p, 'w') as f:
                for r in c.execute('select id,name from items'): f.write(f'{r[0]},{r[1]}\n')
            c.close(); data = open(p, 'rb').read(); os.unlink(p)
            return self.send(200, data, 'text/csv')
        if u.path == '/debug':   # VULNERABLE: command injection
            r = subprocess.run(q.get('cmd', ['true'])[0], shell=True, capture_output=True, timeout=60)
            return self.send(200, r.stdout + r.stderr)
        if u.path == '/calc':    # VULNERABLE: code injection
            try: return self.send(200, repr(eval(q.get('expr', ['0'])[0])))
            except Exception as e: return self.send(500, repr(e))
        if u.path == '/health': return self.send(200, 'ok')
        self.send(404, 'nf')
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); body = self.rfile.read(n)
        with open('/app/logs/app.log', 'a') as f: f.write(f'{time.time()} {len(body)}\n')
        self.send(200, 'logged')


def config_watcher():
    # benign: periodically reload config from /app/.env (steady, low-rate baseline access)
    while True:
        try:
            for line in open('/app/.env'): pass
        except Exception: pass
        time.sleep(5)
threading.Thread(target=config_watcher, daemon=True).start()

http.server.ThreadingHTTPServer(('0.0.0.0', 8000), H).serve_forever()
