#!/usr/bin/env python3
"""Operator console for a running aicash mint.

A separate HTTP server, deliberately: the protocol implementation in
impl/aicash stays untouched, and nothing here is normative. The console
proxies to the mint so the browser talks to one origin, and it holds the
admin token server-side so the credential never reaches the page.

Loopback only. Anyone who reaches this port can mint.
"""
import base64, json, os, sys, http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl"))
from aicash.tokencodec import format_token, ledger_key, new_secret

PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aicash mint console</title><style>
:root{--bg:#f7f7f5;--card:#fff;--ink:#1a1a18;--dim:#6b6b66;--line:#e2e2dd;
--accent:#2f6f4f;--warn:#8a4b2a;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#16161a;--card:#1e1e23;--ink:#e8e8e4;
--dim:#9a9a94;--line:#30303a;--accent:#6bbf90;--warn:#d89a6a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:24px 18px 60px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:14px;text-transform:uppercase;
letter-spacing:.07em;color:var(--dim);margin:0 0 12px}
.sub{color:var(--dim);font-size:13px;margin-bottom:22px;font-family:var(--mono)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stat .n{font-size:24px;font-family:var(--mono);font-weight:600}
.stat .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim)}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
input,textarea{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:7px;
background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px}
textarea{min-height:70px;resize:vertical}
button{background:var(--accent);color:#fff;border:0;border-radius:7px;padding:9px 16px;
font-size:14px;cursor:pointer;margin-top:12px}button:hover{opacity:.9}
button.sec{background:transparent;color:var(--ink);border:1px solid var(--line)}
.row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:130px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:12px;
overflow-x:auto;font-size:12px;margin:12px 0 0;white-space:pre-wrap;word-break:break-all}
.tok{font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--line);
border-radius:6px;padding:9px;margin-top:8px;word-break:break-all;cursor:pointer}
.tok:hover{border-color:var(--accent)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent);
margin-right:6px;vertical-align:middle}.dot.off{background:var(--warn)}
.warn{color:var(--warn);font-size:12px;margin-top:8px}
details summary{cursor:pointer;color:var(--dim);font-size:13px}
.ok{color:var(--accent)}.bad{color:var(--warn)}
</style></head><body><div class="wrap">
<h1><span class="dot" id="dot"></span>aicash mint console</h1>
<div class="sub" id="hdr">connecting...</div>

<div class="grid" id="stats"></div>

<div class="card"><h2>Issue tokens</h2>
<div class="row">
<div><label>Amount each (millicredits)</label><input id="amt" value="1000"></div>
<div><label>How many</label><input id="qty" value="1"></div>
</div>
<button onclick="issue()">Issue</button>
<div class="warn">Issuing creates new money. It is signed into the supply snapshot and cannot be undone.</div>
<div id="issued"></div></div>

<div class="card"><h2>Check a token</h2>
<label>Paste a token string or a ledger key</label>
<textarea id="q" placeholder="aicash:v3:..."></textarea>
<button class="sec" onclick="check()">Check status</button>
<div id="status"></div></div>

<div class="card"><h2>Mint descriptor</h2>
<details><summary>Show raw JSON</summary><pre id="raw">...</pre></details></div>
</div><script>
const $=id=>document.getElementById(id);
async function api(p,b){const r=await fetch(p,b?{method:'POST',
 headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{});
 return {ok:r.ok,data:await r.json()};}
function fmt(n){return (n===undefined||n===null)?'-':n.toLocaleString();}
async function refresh(){
 const r=await api('/api/descriptor');
 if(!r.ok){$('dot').className='dot off';$('hdr').textContent='mint unreachable';return;}
 const d=r.data,s=d.supply||{};
 $('dot').className='dot';
 $('hdr').textContent=d.mint_id+'  ·  '+(d.denominations_mc||[]).join(', ')+' mc denominations';
 $('stats').innerHTML=[['Outstanding',s.outstanding_mc],['Issued',s.cumulative_issued_mc],
  ['Burned',s.cumulative_burned_mc],['Snapshot',s.snapshot_seq]]
  .map(([l,v])=>`<div class="stat"><div class="n">${fmt(v)}</div><div class="l">${l}</div></div>`).join('');
 $('raw').textContent=JSON.stringify(d,null,2);}
async function issue(){
 const amount=parseInt($('amt').value,10),count=parseInt($('qty').value,10);
 $('issued').innerHTML='<div class="warn">issuing...</div>';
 const r=await api('/api/issue',{amount_mc:amount,count:count});
 if(!r.ok){$('issued').innerHTML='<pre class="bad">'+JSON.stringify(r.data,null,2)+'</pre>';return;}
 $('issued').innerHTML='<div class="warn ok">'+r.data.tokens.length+
  ' token(s) issued. Click to copy — these are bearer tokens, anyone holding one can spend it.</div>'+
  r.data.tokens.map(t=>`<div class="tok" onclick="navigator.clipboard.writeText('${t}');this.textContent='copied — '+this.dataset.t" data-t="${t}">${t}</div>`).join('');
 refresh();}
async function check(){
 const r=await api('/api/status',{q:$('q').value.trim()});
 $('status').innerHTML='<pre>'+JSON.stringify(r.data,null,2)+'</pre>';}
refresh();setInterval(refresh,5000);
</script></body></html>"""


class Console(BaseHTTPRequestHandler):
    mint_port = 0
    mint_id = ""
    admin_token = None

    def log_message(self, *a):
        pass

    def _mint(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.mint_port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if self.admin_token:
            headers["X-Admin-Token"] = self.admin_token
        c.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"{}")

    def _send(self, code, obj, ctype="application/json"):
        payload = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if self.path == "/api/descriptor":
            code, obj = self._mint("GET", "/v3/mints")
            return self._send(code, obj)
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad_json"})

        if self.path == "/api/issue":
            amount, count = body.get("amount_mc"), body.get("count", 1)
            if not isinstance(amount, int) or amount <= 0 or not isinstance(count, int) \
                    or not 1 <= count <= 100:
                return self._send(400, {"error": "amount_mc must be a positive int, "
                                                 "count between 1 and 100"})
            secrets = [new_secret() for _ in range(count)]
            outputs = [{"amount_mc": amount,
                        "secret": base64.urlsafe_b64encode(s).decode().rstrip("=")}
                       for s in secrets]
            code, obj = self._mint("POST", "/admin/issue", {"outputs": outputs})
            if code != 200:
                return self._send(code, obj)
            # The token string only exists here: the mint stores hashes, never
            # secrets, so an unshown token is unrecoverable money.
            return self._send(200, {"tokens": [format_token(self.mint_id, amount, s)
                                               for s in secrets]})

        if self.path == "/api/status":
            q = (body.get("q") or "").strip()
            if not q:
                return self._send(400, {"error": "nothing to look up"})
            key = q
            if q.startswith("aicash:"):
                parts = q.split(":")
                if len(parts) != 5:
                    return self._send(400, {"error": "malformed token string"})
                pad = "=" * (-len(parts[4]) % 4)
                try:
                    key = ledger_key(base64.urlsafe_b64decode(parts[4] + pad))
                except Exception:
                    return self._send(400, {"error": "malformed token secret"})
            code, obj = self._mint("POST", "/v3/status", {"hashes": [key]})
            return self._send(code, obj)

        self._send(404, {"error": "not_found"})


def serve(port, mint_port, mint_id, admin_token):
    Console.mint_port, Console.mint_id, Console.admin_token = mint_port, mint_id, admin_token
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Console)
    httpd.daemon_threads = True
    return httpd
