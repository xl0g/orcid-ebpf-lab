# Collection endpoint. Used legitimately by the backup job, abused by the attacker for exfiltration.
import http.server, json, time
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); b = self.rfile.read(n)
        with open('/out/received.jsonl', 'a') as f:
            f.write(json.dumps({'t': time.monotonic_ns(), 'src': self.client_address[0], 'path': self.path, 'bytes': len(b), 'marker': 'FAKE' in b.decode('latin1')}) + '\n')
        self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
    do_PUT = do_POST
http.server.ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()
