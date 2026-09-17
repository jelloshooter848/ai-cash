# DEPLOYMENT.md — running a real AICash mint

This is the operator's guide for the v0.4 reference build: what the mint
process actually is, what you must put in front of it, how to back it up, and
what you are signing up for. It describes **this** code, not a generic service.
Where the implementation stops short of what an operator would want, it says so
rather than papering over it — read §10 before you commit to running anything
that holds other people's value.

Companion documents: `README.md` (what AICash is for), `aicash-spec-v0.4.md`
(the ratified protocol — the authority), `LOCKED-DESIGN-DECISIONS.md`
(especially **L17**, which scopes TLS, rate-limit enforcement and blind
signatures *out* of the reference build), `BOOTSTRAP.md` §1.1 (who runs mint #1
and the operator-exposure problem), `OPEN-QUESTIONS.md` (what is still open).

---

## 1. What the mint process actually is

One Python process. Concretely, when you run the launcher you get:

- **A stdlib `ThreadingHTTPServer`** (`aicash.mintapi._MintHTTPServer`) bound to
  `127.0.0.1:<port>`, speaking HTTP/1.1, one thread per connection, serving
  exactly four routes:

  | Route | Method | Auth | What it is |
  |---|---|---|---|
  | `/v3/mints` | GET | none | §3.6 descriptor + signed supply snapshot |
  | `/v3/status/<hash>`, `/v3/status` | GET / POST | none | §3.5 entry status |
  | `/v3/exchange` | POST | **none, by design** | §3.3 the one atomic operation |
  | `/admin/issue` | POST | `X-Admin-Token` | §7.1 operator funding, non-normative |

  The absence of authentication on `/v3/exchange` is **L2**, not an oversight:
  Layer 0 has no identities; authority is possession of a secret. Do not "fix"
  it with proxy auth — you would break every anonymous receive-first client
  (§3.7/§7.2), which is the whole product.

  `/admin/issue` is the opposite case, and it changed. `MintConfig.admin_token`
  has no default any more: it is one of three states, all of them named, and
  **saying nothing is an error rather than a state** — `MintConfig(...)` raises
  `ValueError` before a port is ever bound.

  | `admin_token=` | `/admin/issue` answers |
  |---|---|
  | `"<secret>"` | only a matching `X-Admin-Token` (constant-time compare) |
  | `ADMIN_ISSUANCE_DISABLED` | 401 to everyone, including you |
  | `ADMIN_ISSUANCE_OPEN` | everyone, unauthenticated — opt in by name |
  | unset, or `None` | nothing: the config refuses to build |

  It used to be that `admin_token=None` meant *allow everyone*, so any program
  that built a mint from a default config served money creation to whoever
  could reach the port — a credential whose absence was read as permission.
  `LOCKED-DESIGN-DECISIONS.md` **L19** records that change, deliberately
  breaking every caller that relied on the old default, including ones that
  never issue. Openness is still available and is now greppable: `grep -rn
  ADMIN_ISSUANCE_OPEN` enumerates every open mint in a tree, and a mint built
  that way logs a warning naming itself on every start.

  The launcher **in this tree** passes one of the three on every path, so
  `aicash-mint` as shipped here starts (§10.8). An **older** `aicash-mint`
  script does not, and that is the upgrade hazard: before this change
  `--open-issuance` passed `admin_token=None`, because `None` was the old
  spelling of *allow everyone*. Run the previous launcher against this
  library and it dies before binding a port — verified here: `ValueError:
  admin_token=None no longer means anything.` A `pip install` of the library
  over a checked-out launcher is the normal shape of this, so upgrade the
  launcher with it; the fix is one line (`--open-issuance` must now pass
  `ADMIN_ISSUANCE_OPEN`). An embedder that built its own `MintConfig` will
  likewise stop starting until it picks one, which is the intended outcome.

- **A SQLite file** (`--db`, default `mint.db`) holding the entire ledger:
  `entries` (keyed by *hash*, never by secret), `supply`, `idempotency`, plus
  the mint's own `mintapi_state` (snapshot sequence and day-windowed activity)
  and `mintapi_counted` (the idempotency keys already folded into that activity,
  so a retried call is not counted twice). Every write path runs under
  `BEGIN IMMEDIATE`, so SQLite's write lock serializes the critical section end
  to end. That is the concurrency model: **writes are serialized through one
  file on one host.** There is no replication and no second writer. A mint
  scales vertically or not at all.

- **An Ed25519 key file** (`--keys`, default `mint-keys.json`, mode 0600). It
  holds the signing key that signs every descriptor snapshot (L17: static key,
  published in the descriptor), and it *pins* `mint_id` and
  `baseline_model_class` for the life of the mint — the launcher refuses to
  start if either changes, because §4.1 makes the baseline the definition of
  the unit and changing it silently reprices every outstanding credit.

- **Optionally, a loopback operator console** (`--console-port`), a separate
  HTTP server that holds the admin token server-side and proxies to the mint.
  **It is OFF unless you ask for it**: `--console-port 0` is the default and
  `--console-port 8080` starts one. It used to default to 8080, which meant an
  operator who read the old "turn it off in production" line as advice rather
  than as an instruction was running it without deciding to. If you do start
  one, reach it only over an SSH tunnel.

  The console authenticates: on startup it prints one URL carrying a
  capability key (`http://127.0.0.1:<port>/?k=…`), generated fresh each start
  and held in memory only — never written to a file, a log line or any
  response body. Opening that URL once exchanges the key for an `HttpOnly;
  SameSite=Strict` session cookie, and every `/api/*` route requires that
  cookie; the bare `http://127.0.0.1:<port>/` answers 401, and the key is not
  accepted on an API route. It also refuses any `Host` that is not a loopback
  literal (the DNS-rebinding defence) and any foreign `Origin`/`Referer`. A
  `--no-auth` flag exists for automated tests only and shouts on every start.

  The console also **refuses to start with no operator credential**. It takes
  one from `--admin-token-file` (the file the launcher writes) or
  `--admin-token`; finding neither, it exits and names the three ways to
  supply one rather than starting a console whose Issue button cannot work.
  `--no-admin-token` starts it read-only on purpose — descriptor and status
  only, `POST /api/issue` answers 503 `no_admin_credential`, and it says so
  in the startup banner. That is the same rule as the mint's: an absent
  credential is something you ask for, never something that happens.

  **None of that makes the port safe to expose, and it is not a reason to
  relax anything above.** It is a second lock on a door that should still not
  face the street. Binding to loopback is a much weaker boundary than it
  sounds: it does not separate users on a shared machine, it does not stop
  another local process — including something installed for an unrelated
  reason — and it does not stop a web page open in the operator's own browser
  from posting to `127.0.0.1`, which is a routinely exploited class of attack
  and the whole reason the console checks `Host`, `Origin` and `Referer` at
  all. The admin token is still sitting in that process.
  `--console-port 0` in production remains the instruction.

The launcher (`run_mint.py`, installed as `aicash-mint`) is explicitly **not
protocol** — it is a wiring script, and its flags change faster than this
document. Run `aicash-mint --help` in your build and trust that over any flag
list written here.

**What the process is not:** it is not TLS-terminating, not rate-limiting, not
replicated, not failover-capable, and not a hardened public-facing HTTP server.
Everything in §4 exists because of that sentence.

---

## 2. Install

Python 3.12+, and `cryptography` (Ed25519). Nothing else.

```bash
adduser --system --home /var/lib/aicash --group aicash
python3 -m venv /opt/aicash/venv
install -d -o aicash -g aicash -m 0700 /var/lib/aicash
```

**Build out of the checkout, not in it.** `pip install /path/to/aicash` works
and is what you will reach for, but setuptools writes `build/` and
`aicash.egg-info/` next to `pyproject.toml` and the repo `.gitignore` covers
neither — verified here: one `pip install .` takes a clean tree to
`?? build/ ?? aicash.egg-info/`. The untidiness is the small half. The large
half is that setuptools *reuses* `build/lib`, so a module later deleted from
`impl/aicash` keeps shipping in every wheel built from that tree until someone
removes the directory by hand. Build from a throwaway copy instead:

```bash
BUILD=$(mktemp -d)
tar -C /path/to/aicash --exclude=.git --exclude=.venv --exclude=__pycache__ \
    --exclude='*.db' --exclude='*keys.json' -cf - . | tar -C "$BUILD" -xf -
/opt/aicash/venv/bin/pip wheel --no-deps -w "$BUILD/dist" "$BUILD"
/opt/aicash/venv/bin/pip install "$BUILD"/dist/aicash-*.whl
rm -rf "$BUILD"
```

Run verbatim on this build: the wheel builds, installs with `cryptography`
resolved from the index, and the source checkout is byte-identical afterwards.
The `*.db` and `*keys.json` excludes are not about the wheel — the wheel never
contains them either way — built by the recipe above on this build, its full
namelist is `aicash/__init__.py` and the 14 `aicash` modules, `run_mint.py`,
`mint_console.py` and five `aicash-0.4.0.dist-info/` entries, nothing else —
they are about not copying a live signing key and ledger through `/tmp` on
the way past.

Either way you get the `aicash` package on the path (it lives at `impl/aicash`
in the tree; `pyproject.toml` maps it) and the launcher installed as
`/opt/aicash/venv/bin/aicash-mint`. That absolute path is what the systemd unit
in §6 uses, so the unit does not depend on where the repo was cloned.

Verify the install is real before going further:

```bash
cd /tmp && /opt/aicash/venv/bin/python -c "import aicash; print(aicash.__file__)"
/opt/aicash/venv/bin/aicash-mint --help
```

**One legal note before you hand this to anyone else.** There is no `LICENSE`
file in this repo and `pyproject.toml` declares no license, so the built
distribution's METADATA carries no License field at all. Under default
copyright that means *all rights reserved* — fine for running it yourself, a
real blocker for anyone whose legal review has to clear third-party code before
it can hold value. Choosing one is the copyright holder's call and not this
document's; if that is you, make it before you publish a wheel.

---

## 3. First start, and the two decisions you cannot take back

```bash
cd /var/lib/aicash
/opt/aicash/venv/bin/aicash-mint \
    --mint-id my-mint \
    --model-class my-baseline-v1 \
    --port 8787 \
    --console-port 0 \
    --db /var/lib/aicash/mint.db \
    --keys /var/lib/aicash/mint-keys.json
```

Two values are permanent from that moment:

1. **`--mint-id`.** It is inside every token string (`v3:<mint_id>:<amount>:<secret>`)
   and inside the signed snapshot. `/v3/exchange` rejects any token whose
   `mint_id` is not this mint's. Changing it abandons every token in existence.
2. **`--model-class` (the baseline).** §4.1 makes it immutable for the life of
   the `mint_id`; it is the peg that defines a millicredit. The launcher pins it
   into the key file on first run and refuses to start if you later pass a
   different one. This is deliberate: a silent baseline change reprices every
   outstanding credit while the §3.6 supply counters — denominated in mc — stay
   put, so the invariant still holds and **nothing in the ledger can detect it.**

**What that first start does about the admin credential — nothing you have
to do, and one thing you have to know.** §1 says a mint refuses to build
unless `admin_token` names one of three states. That is a library rule, and
it does **not** mean you must invent a credential before your first start:
the command above names none, and `run_mint.py` generates one for you
(`base64url(os.urandom(24))`) and passes it as the `"<secret>"` state. Run
verbatim on this build, that start printed

```
  "admin_token": "(written to /var/lib/aicash/mint-admin-keys.json, JSON field \"admin_token\")",
```

and wrote that file mode 0600 — the credential itself is deliberately kept
off stdout, because under a process manager stdout is a log. What you have
to know is where it went: `--admin-token-file` defaults to the **relative**
path `mint-admin-keys.json`, the same relative-path trap `--keys` has (§9),
so it lands in the process's working directory — which is why the `cd
/var/lib/aicash` above and the `WorkingDirectory=` in §6 are load-bearing
and not decoration. Verified on this build: an unauthenticated `POST
/admin/issue` against that mint answers **401**, which is the §11 checklist
line, and it answers 401 without your having configured anything.

Also settled at first start: the burn policy (`--rate-ppm`, `--cap-mc`,
`--exempt-below-mc`, §7.3/L12) can change later, but §7.3 expects a published
change notice (`burn_policy_next`) before it does — the launcher has no flag for
that field, so an operator who intends to change burn is writing a small
launcher of their own around `MintConfig`.

**The mint binds loopback only.** `MintServer.start()` takes a `host`, the
launcher never passes one, and that is the right default: transport is plain
HTTP (L17). Do not go looking for a flag to bind `0.0.0.0`. Put a proxy in
front instead.

---

## 4. The reverse proxy is not optional

L17 puts TLS in **deployment, not code**. That is a decision about where the
work happens, not a decision that the work is unnecessary. Without a proxy in
front, every exchange request crosses the network in clear text — and a `/v3/exchange`
body contains **token secrets**, which are bearer value. Plain HTTP on a routable
interface is equivalent to publishing your users' money.

The proxy is carrying four jobs: TLS, rate limiting (§5), request-size and
timeout bounds in front of a stdlib HTTP server, and keeping `/admin/issue` off
the internet.

**The address you hand out is the `https://` one.** That sounds too obvious to
write down, and it is written down because it was not true: `MintClient`
(`impl/aicash/wallet.py`) refused every scheme but `http`, so a mint deployed
exactly as this section requires could not be reached by this project's own
client — the guide and the client disagreed, and the guide was right. The
client now accepts `http` and `https`, defaults the port from the scheme
(80/443), and verifies the certificate chain **and** hostname against the
system trust store with no opt-out. Two consequences for you:

- The base URL is a bare **origin** — `https://mint.example.org`, or
  `https://mint.example.org:8443` if you moved the port. Not a path: every
  route the client issues is absolute (`/v3/exchange`), so a mint published
  under a path prefix (`https://example.org/mint/`) is refused at construction
  rather than quietly requested at your proxy's root. If you want a prefix,
  give the mint its own name instead.
- A certificate your clients' trust store does not accept is, to them,
  indistinguishable from the mint being down: they raise `MintUnavailable`
  carrying the exception type and nothing else. A self-signed certificate on a
  public mint is therefore not "TLS with a warning" — it is an outage. Use a
  real one; §4.1 and §4.2 both do.

`http://127.0.0.1:<port>` is still accepted, because that is what a local
operator on the mint host, the GUI in `gui/`, and the tests all speak. It is
the loopback address, not a deployment address.

### 4.1 Caddy (shortest path, with one caveat that is not cosmetic)

```caddyfile
{
        # caddy-ratelimit is a third-party module, so its directive has no
        # place in Caddy's built-in ordering. Without this global option the
        # config does not load at all.
        order rate_limit before reverse_proxy
}

mint.example.org {
        encode zstd gzip

        # Caddy provisions and renews its own certificate, and can answer the
        # ACME challenge over TLS-ALPN on 443. That is why this path does not
        # need the port-80 block §4.2 does.
        header Strict-Transport-Security "max-age=31536000"

        # /admin/issue is operator-only issuance. It is protected by a bearer
        # token in code, but there is no reason for it to be reachable from the
        # internet at all: fund the mint over an SSH tunnel to 127.0.0.1.
        # First `handle` that matches wins, so this one shadows everything
        # under /admin/ before any proxying can be reached.
        handle /admin/* {
                respond 404
        }

        rate_limit {
                # See §5 — AND read the caveat below. This is not the same
                # shape as the rate the descriptor publishes.
                zone anon {
                        key    {remote_host}
                        events 50
                        window 1s
                }
        }

        # Everything the protocol actually exposes (L2: no auth here, ever).
        handle /v3/* {
                request_body {
                        # aicash.mintapi.MAX_BODY_BYTES is 1 MiB, sized from
                        # max_batch (256) entries. Refuse oversize bodies
                        # before they reach Python.
                        max_size 1MB
                }
                reverse_proxy 127.0.0.1:8787 {
                        # The mint is a stdlib ThreadingHTTPServer: one thread
                        # per connection and no timeouts of its own. Bound what
                        # can be bounded here. NOTE: `read_timeout` and
                        # `write_timeout` are *fastcgi* transport options, not
                        # http ones — an unrecognized subdirective is a hard
                        # config-load failure, so they are deliberately absent.
                        transport http {
                                dial_timeout            5s
                                response_header_timeout 15s
                        }
                }
        }

        handle {
                respond 404
        }
}
```

**The caveat.** caddy-ratelimit's `events`/`window` is a strict sliding window
with **no burst concept**. The descriptor this build publishes says
`{"per_caller_rps": 50, "burst": 200, "scope": "ip"}`. Deploy the config above
unchanged and you advertise a burst allowance of 200 that the proxy does not
grant: a conformant client sending the advertised burst gets 429s. That is
precisely the false-conformance shape §5 rule 1 forbids, and the §11 checklist
line "limiter matches the descriptor's published `anonymous_rate` exactly"
cannot honestly be ticked. Two ways out, both fine, neither optional:

- **Publish `burst: 0`.** It is a legal value (`MintConfig` validates
  `burst >= 0`), so build the small custom launcher §5 rule 2 describes and let
  the descriptor say what the limiter actually does; or
- **take the nginx path in §4.2,** whose `limit_req … burst=200 nodelay` does
  implement the published shape.

**Neither config in this section was syntax-checked.** No `caddy` or `nginx`
binary exists on the host this was written on and neither could be installed
there; these are written from the upstream documentation, and they are
structurally right rather than machine-verified. Run
`caddy validate --config /etc/caddy/Caddyfile` or `nginx -t` before you reload
anything, and treat a failure as this document's bug, not yours.

### 4.2 nginx (full worked config)

```nginx
# /etc/nginx/conf.d/aicash-mint.conf

# One shared limiter. scope:"ip" in the descriptor means per client address,
# so the key is the address, not a token or a cookie — Layer 0 has neither.
limit_req_zone $binary_remote_addr zone=aicash_anon:16m rate=50r/s;
limit_conn_zone $binary_remote_addr zone=aicash_conn:16m;

upstream aicash_mint {
    server 127.0.0.1:8787;
    keepalive 32;
}

# Port 80 is here for exactly two reasons: the ACME HTTP-01 challenge that
# renews the certificate below, and redirecting anyone who typed the bare
# hostname. It proxies nothing to the mint, ever.
#
# This block is load-bearing and its omission is a ~90-day fuse. certbot's
# `--nginx` and `--webroot` renewals both answer HTTP-01 on port 80; with no
# :80 server and no 80/tcp in the firewall, renewal fails, TLS expires, and you
# are living the §10.4 failure this document warns about. If you would rather
# keep 80 closed, switch the client to TLS-ALPN-01 or DNS-01 and say so right
# here in the config, because the next operator will assume HTTP-01.
server {
    listen 80;
    listen [::]:80;
    server_name mint.example.org;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;      # certbot ... --webroot -w /var/www/certbot
    }

    location / { return 308 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;                 # `listen ... http2` is deprecated since nginx 1.25.1
    server_name mint.example.org;

    ssl_certificate     /etc/letsencrypt/live/mint.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mint.example.org/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # A /v3/exchange body is bearer value. Once a client has seen this host
    # over TLS, do not let it be talked back down to the :80 server above.
    add_header Strict-Transport-Security "max-age=31536000" always;

    # A /v3/exchange body carries token secrets. The mint normalizes its OWN
    # access log to a route pattern for exactly this reason (aicash.mintapi
    # logs "POST /v3/exchange 200" and never a body or a raw path) — but nginx
    # does not inherit that discipline. A client that wrongly puts a token in a
    # URL would have it written to disk here, in plaintext, forever. Log the
    # route without the query string, or not at all.
    log_format aicash '$remote_addr $status $request_method $uri $body_bytes_sent';
    access_log /var/log/nginx/aicash.log aicash;

    # The mint reads at most 1 MiB (aicash.mintapi.MAX_BODY_BYTES). Reject
    # bigger bodies at the edge so Python never allocates for them.
    client_max_body_size 1m;
    client_body_timeout  15s;
    client_header_timeout 15s;

    # Layer 0, public and unauthenticated by design (L2/§3.7).
    location /v3/ {
        limit_req  zone=aicash_anon burst=200 nodelay;   # §5
        limit_conn aicash_conn 64;
        limit_req_status 429;

        proxy_pass http://aicash_mint;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # BaseHTTPRequestHandler has no request timeout of its own and holds a
        # thread per connection: slowloris is a real risk, and these are the
        # only defence in the deployment.
        proxy_connect_timeout 5s;
        proxy_send_timeout    15s;
        proxy_read_timeout    30s;
        proxy_buffering on;
    }

    # Operator issuance. Not reachable from the internet, full stop.
    location /admin/ {
        return 404;
    }

    location / { return 404; }
}
```

Then close the mint's own port at the host firewall so a proxy
misconfiguration cannot silently become direct exposure:

```bash
ufw default deny incoming
ufw allow 443/tcp
ufw allow 80/tcp     # ACME HTTP-01 renewal + the redirect. Drop this ONLY if
                     # your ACME client uses TLS-ALPN-01 or DNS-01 (Caddy does
                     # TLS-ALPN by default; certbot does not).
ufw allow 22/tcp
# 8787 and 8080 are never opened. The mint binds 127.0.0.1 anyway; this is the
# second lock on the same door.
ss -ltnp | grep -E '8787|8080'   # must show 127.0.0.1, never 0.0.0.0
```

Then prove renewal works *before* you need it, because the failure mode is a
silent clock:

```bash
certbot renew --dry-run                  # must reach the :80 block above
systemctl list-timers | grep -i certbot  # the renewal timer must be active
```

Certificate expiry belongs in §8's monitoring, not in your memory.

---

## 5. Rate limiting: published in code, enforced at the proxy

L17 is precise here: *"everyone is served as the anonymous tier (trivially
non-discriminatory); enforcement is a stub. Do not flag missing rate-limit
enforcement, DO flag missing publication."*

So the descriptor makes a promise the code does not keep. Fetch it and read the
promise you have inherited:

```bash
$ curl -s http://127.0.0.1:8787/v3/mints | python3 -m json.tool | grep -A6 limits
"limits": {
    "anonymous_rate": {"burst": 200, "per_caller_rps": 50, "scope": "ip"},
    "max_batch": 256,
    "registered_rate": {"burst": 200, "per_caller_rps": 50, "scope": "ip"}
}
```

Those are the defaults every mint publishes unless its operator builds a custom
`MintConfig`. **Your proxy limiter is the only thing that makes them true** —
hence `rate=50r/s burst=200` keyed on `$binary_remote_addr` (scope `ip`) in §4.2.
Three rules follow:

1. **Keep the numbers identical.** A descriptor that advertises 50 rps while the
   proxy allows 5 is a false conformance claim; §3.6 treats a contradicted
   descriptor as portable proof of nonconformance, and L11's honesty clause is
   what makes the published figures worth anything.
2. **If you want different numbers, change both.** The launcher exposes no rate
   flags, so changing the published figures means constructing `MintConfig`
   with your own `anonymous_rate`/`registered_rate` in a small launcher of your
   own, and moving the proxy in lockstep.
3. **Do not limit the anonymous tier harder than anyone else** (L13). In this
   build everyone *is* the anonymous tier, so one zone for all callers is both
   the simplest and the only conformant arrangement.

Match the *shape*, not only the numbers. `burst` is part of the published
promise: a limiter with no burst concept — caddy-ratelimit's sliding window,
§4.1 — contradicts a descriptor advertising `burst: 200` just as surely as a
wrong rps figure would, and a client that sends the burst it was promised gets
429s for it. Either the limiter implements the burst, or the descriptor stops
claiming it (`burst: 0` validates).

Note what a limiter cannot do for you: `max_batch` (256 entries per call) is
enforced in code, but a caller may still send 50 full-size batches per second
per IP, and each one takes SQLite's write lock. Rate limiting is a fairness
mechanism here, not a capacity plan.

---

## 6. systemd unit

```ini
# /etc/systemd/system/aicash-mint.service
[Unit]
Description=AICash mint (v0.4 reference implementation)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aicash
Group=aicash
WorkingDirectory=/var/lib/aicash
# The launcher treats a MISSING key file as a first run and generates a new
# identity over your existing ledger (§9) — an unchained key change, which
# §3.6/R13 makes indistinguishable from seizure. That is the one dangerous
# case the launcher does NOT refuse, so refuse it here instead.
ExecStartPre=/usr/bin/test -s /var/lib/aicash/mint-keys.json

ExecStart=/opt/aicash/venv/bin/aicash-mint \
    --mint-id my-mint \
    --model-class my-baseline-v1 \
    --port 8787 \
    --console-port 0 \
    --db /var/lib/aicash/mint.db \
    --keys /var/lib/aicash/mint-keys.json \
    --access-log /var/lib/aicash/mint-access.log

# --- shutdown -------------------------------------------------------------
# systemd's default stop signal is SIGTERM, which is what the launcher
# handles (see the note below). Give in-flight exchanges time to commit
# before systemd escalates to SIGKILL.
#
# TimeoutStopSec MUST exceed --drain-seconds (default 10). The launcher spends
# up to that long waiting for in-flight request handlers after it closes the
# listening socket; if systemd's deadline expires first it SIGKILLs the mint in
# the middle of its own drain, which strands exactly the requests the drain
# exists to protect. 30 > 10 here with room for the rest of shutdown. If you
# raise --drain-seconds, raise this too.
KillMode=mixed
TimeoutStopSec=30

# --- restart --------------------------------------------------------------
# on-failure, not always: a refusal to start (baseline mismatch, port already
# bound, unreadable key file) is a decision the launcher made on purpose, and
# restarting into it forever only hides it.
Restart=on-failure
RestartSec=5

# --- hardening ------------------------------------------------------------
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/aicash
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
UMask=0077

[Install]
WantedBy=multi-user.target
```

**About the stop signal, and the drain.** The launcher installs the same
handler for SIGINT and SIGTERM: it flips a stop event, and the main thread then
shuts the console down, calls `MintServer.stop()` (which stops the serving
loop, closes the listening socket and joins the serve thread), then calls
`drain_handlers(port, --drain-seconds)` to wait for request handlers that are
still inside a call, and prints `stopped.`. So systemd's default SIGTERM *is*
the clean path and needs no `KillSignal` override. Verified on this build
(2026-09-15): `kill -TERM` on the mint process logged `stopping on SIGTERM...`
then `stopped.` and exited 0.

`--drain-seconds` defaults to **10.0**. That is the number that decides whether
`systemctl stop` truncates an in-flight `/v3/exchange`, so it is the number the
unit's `TimeoutStopSec` has to be read against — see the comment in the unit
above. Handlers still running when the deadline expires are abandoned and the
launcher says so on stdout; their clients fall back to §3.3 idempotency keys,
same as after a hard kill.

Verify it yourself rather than trusting this paragraph — the launcher is not
protocol and does change: `systemctl stop aicash-mint`, then
`journalctl -u aicash-mint -n 20` and look for those two lines. If they are
absent and the unit shows `status=15/TERM`, your build's shutdown hangs off
`KeyboardInterrupt` only; add `KillSignal=SIGINT` to the unit to get the
orderly path back.

**An abrupt kill is survivable too, and here is exactly why.** Every ledger mutation
is one `BEGIN IMMEDIATE` transaction on a rollback-journal SQLite database with
default `synchronous=FULL`; the key file is written to a temp file, fsynced, and
`os.replace`d into position. A SIGKILL mid-write leaves either the committed
state or the pre-transaction state — never half of one. After a hard kill the
database checks out clean (`pragma integrity_check` → `ok`, verified on this
build). What you *do* lose is in-flight HTTP requests: clients see a dropped
connection on a `/v3/exchange` they cannot tell committed or not. That is what
§3.3 idempotency keys are for — a client that resubmits the same call with the
same key gets the original result back, byte for byte, rather than double-spending
its own inputs. Tell your integrators to use them; they are the recovery story.

---

## 7. Backups

Two files matter, and they matter differently.

### `mint-keys.json` — the irreplaceable one

It holds the Ed25519 private key that signs every supply snapshot, plus the
pinned `mint_id` and `baseline_model_class`. Treat it the way you would treat a
CA key:

- 0600, owned by the service user, on an encrypted volume.
- Backed up **out of band** from the database — offline, encrypted, somewhere a
  compromise of the mint host does not reach.
- Never in git (`.gitignore` already excludes `mint-keys.json` and `*-keys.json`;
  do not defeat that), never in a container image, never in a log.

**What losing it actually costs, stated precisely.** Key rotation is
unimplemented in this build (§10). §3.6 defines the rotation path —
`signing_pubkey_next`, cross-signed by the current key — and the descriptor
this code emits carries that key **always set to `null`** (`aicash/mintapi.py`
writes the literal `"signing_pubkey_next": None`; a live `GET /v3/mints` on
this build returns `"signing_pubkey_next": null`, verified). Nothing ever
populates it, so the effect is the same and the shape is not: a monitor that
tests `"signing_pubkey_next" in descriptor` gets **True** and learns nothing.
Test the value, never the key. Either way there is no graceful way to
introduce a new key. Start over with a fresh keypair under the same
`mint_id` and:

- every client that pinned your `signing_pubkey` (TOFU, per §3.6) sees an
  **unchained key change**, which R13 says *is the alarm* — indistinguishable,
  from the outside, from your mint having been seized or compromised;
- the signed monotonic snapshot chain — the only portable evidence a single
  mint can offer under L3 — breaks at that point and cannot be repaired;
- tokens themselves are keyed in the ledger by hash, not by signature, so with
  `mint.db` intact they *do* still redeem. The loss is the mint's identity and
  every trust relationship built on it, not the balances. Both are fatal to a
  running mint; be accurate about which one you are suffering.

### `mint.db` — the ledger, and never with `cp`

The ledger runs in SQLite's default rollback-journal mode (`journal_mode=delete`,
verified on this build). A plain `cp` of a live database can copy a file that is
mid-transaction while leaving its journal behind, producing a backup that is
silently torn — one that restores, opens, and lies to you. **Do not `cp`, `rsync`
or snapshot the file while the mint is running.** Use an online backup:

```bash
# Preferred: the SQLite backup API, safe against a live writer.
sqlite3 /var/lib/aicash/mint.db ".backup '/backup/mint-$(date +%F-%H%M).db'"

# Or a consistent compacted copy:
sqlite3 /var/lib/aicash/mint.db "VACUUM INTO '/backup/mint-$(date +%F-%H%M).db'"
```

The `sqlite3` CLI is often not installed on a minimal server (it was not on the
host this was written on). The Python in your venv is always there and does the
same thing through the same API:

```bash
/opt/aicash/venv/bin/python - <<'PY'
import sqlite3, time
src = sqlite3.connect("/var/lib/aicash/mint.db")
dst = sqlite3.connect(time.strftime("/backup/mint-%Y-%m-%d-%H%M.db"))
with dst:
    src.backup(dst)          # online backup API
print(dst.execute("pragma integrity_check").fetchone()[0])
PY
```

Both forms were run against a live, serving mint on this build and produced a
readable copy with `integrity_check` → `ok`.

**Restore = stop, replace, start.** Stop the unit, put the backup at
`--db`, put the matching `mint-keys.json` at `--keys`, start. There is no replay
and no reconciliation step; the file *is* the state. **Wait for the old process
to be gone before you start the new one**: the ledger takes an advisory
single-writer lock, and a start against a `--db` the previous mint has not
released dies on an unhandled `RuntimeError: another mint process already
serves this ledger` — the one hard stop in §9 that does not get a friendly
message. Confirm with `systemctl is-active` (or `ss -ltnp` on the mint's port)
rather than assuming the stop finished.

**Read the rest of this section before you ever do that in production.**

### Restoring an older ledger publishes signed proof that you rugged your users

This is the sharpest edge in the whole document and it is structural, not a
bug. Under the same `mint-keys.json`, a restore rewinds `cumulative_issued_mc`
and `cumulative_burned_mc` — they come straight out of the ledger file you just
replaced. §3.6 says those counters **MUST be monotonic non-decreasing across
snapshots** and that *"any two signed snapshots violating monotonicity
constitute portable proof of nonconformance"*; §8(a) repeats it (`supply` is
"permanent, never prunable", monotonic). Your pre-restore snapshot and your
first post-restore snapshot are exactly that pair, they carry the same
`signing_pubkey`, and both verify. You have signed, with your own key, the
evidence that §14 and L3 tell your counterparties to read as dilution.

Reproduced end to end on this build, twice — once as written below, and again
on 2026-09-16 against the current tree, which reproduced every figure that
matters (same `signing_pubkey`, `verify_obj` `True` on both snapshots, the
invariant holding on B, `cumulative_issued_mc` 9000 → 0, and the 9000 mc token
going from `{"state": "unspent", "amount_mc": 9000}` to `{"state": "unknown"}`)
and differed only in `snapshot_seq`, for the reason in the first bullet below.
With the installed launcher and the §7 procedure exactly as written above:
take the online backup, issue 9000 mc after it, fetch snapshot A
(`cumulative_issued_mc=9000`, `outstanding_mc=9000`,
`snapshot_seq=3`), `systemctl stop`, copy the backup over `--db`, start again
with the **same** `mint-keys.json`. Snapshot B comes back
`cumulative_issued_mc=0`, `outstanding_mc=0`, `snapshot_seq=1026`, same
`signing_pubkey`, and `verify_obj` returns `True` on both. Everything a monitor
would normally catch this with stays quiet:

- **`snapshot_seq` did not go backwards in either restore run here**, so a
  `>=` monotonicity assertion on the seq alone passed both times. That is an
  observation about these two restores and **not** a property of the system:
  a restore can step the seq backwards, and this bullet is not telling you it
  cannot. The sequence is handed out from reserved blocks whose high-water
  mark lives in `mintapi_state` *inside `mint.db`*, so a restore rewinds the
  counter along with everything else, and where it lands is an accident of
  how much the backup had already reserved. Run above, it jumped 3 → 1026.
  Re-run on this build on 2026-09-16 with a backup taken at the very start of
  the mint's life, it went **1 → 1** — flat, and still silently passing `>=`.
  A backup old enough makes it step backwards, and then a seq-only monitor
  *would* catch it. Both directions are reachable from the same procedure, so
  the seq is not a reliable detector of a restore either way: that is the
  cumulative counters' job, below;
- the arithmetic invariant `outstanding == issued − burned` holds on B, because
  the restored file is internally consistent;
- the pinned-pubkey check passes, because the identity did not change.

The §8 monitor recipe therefore cannot see it unless it remembers the
cumulative counters too, which is why the version in §8 now persists them.
Meanwhile every token issued between the backup and the failure is simply gone:
its entry is not in the restored ledger. In the same run, the 9000 mc token
went from `{"state": "unspent", "amount_mc": 9000}` on `/v3/status/<hash>`
before the restore to `{"state": "unknown"}` after it — a holder's value
evaporating silently, with no reconciliation step anywhere in this build to put
it back.

**So: your RPO is denominated in other people's money.** A nightly backup means
"up to 24 hours of other people's tokens may be annihilated, and the recovery
will be cryptographically indistinguishable from theft." Three things follow,
and they are operational decisions you make *before* the incident:

1. **Back up far more often than nightly.** `.backup` against a live mint is
   cheap; the cost of the window is measured in tokens, not megabytes.
2. **Decide now what you publish when it happens.** The honest disclosure is
   the pre-restore snapshot, the post-restore snapshot, the time window, and
   the list of entry hashes that existed in the first and not the second. Say
   it before a counterparty finds it, because they can check it and you cannot
   retract it.
3. **Do not paper over it by starting a fresh keypair.** That converts a
   monotonicity break into an unchained key change (§3.6/R13) — which is a
   *louder* alarm, not a quieter one, and it also abandons every client's TOFU
   pin. There is no move here that makes the evidence go away. Plan for
   disclosure, not concealment.

**Rehearse it.** A backup you have never restored is a hypothesis. Restore into
a throwaway directory on a spare port — never against the live key file — fetch
`/v3/mints`, and check `outstanding_mc == cumulative_issued_mc − cumulative_burned_mc`.
Note what that check does *not* prove: the invariant holds on a rewound ledger
too. A rehearsal tells you the file is readable. It tells you nothing about
whether restoring it in production would be conformant, and the answer to that
is "no" whenever the backup is older than your last issuance.

### What is *not* in a backup

`mint.db` stores entry **hashes**, never token secrets — stealing it does not let
the thief spend anything. The bearer secrets live in wallets, on the holders'
machines (L8: lose one and the value is gone, with no operator override — you
cannot help them, and you should say so before they ask). The admin token, by
contrast, *is* a live credential: whoever holds it can issue without limit. This
build writes it to `--admin-token-file` (default `mint-admin-keys.json` — the
name ends that way on purpose, so the repo `.gitignore`'s `*-keys.json` pattern
catches a live minting credential; mode 0600) rather than printing it, so it is
a file on the mint host with password sensitivity and no backup value of its own — rotate it by restarting with a new
`--admin-token`, and treat a copy of it leaving the host as an incident.

A plain restart rotates it too, and that surprises people. Unless you pass
`--admin-token`, the launcher generates a **fresh** credential on every start
and overwrites the file — it never reads the old one back. Verified here: two
consecutive starts in the same directory wrote two different tokens. So
anything holding a copy (a console started separately, a funding script, a
colleague's terminal) is invalidated by every restart, which is good hygiene
and a bad surprise at 3am. Pass `--admin-token` from your own secret store if
you need it stable.

Losing that file is not a way to open issuance up, and not a way to lose your
mint either. The running mint holds its credential in memory from startup, so
deleting or editing the file changes nothing until the process restarts — and
what a restart does is generate a **new** credential and write the file again
(the paragraph just above; §9 carries the same fact in the restart list). What
you lose with the file is your own copy: issuance is unreachable until the next
restart, while the ledger, the identity and every outstanding token are
untouched. What you cannot do is make the endpoint open by taking the
credential away; openness has to be asked for by name (§1, L19).

---

## 8. What to monitor

**The invariant, from outside.** The highest-value check is the one §3.6 built
for you. Fetch the descriptor, verify its signature against your pinned public
key, and assert the supply invariant and snapshot monotonicity:

```python
# monitor.py — run it from somewhere that is not the mint host.
import base64, json, os, urllib.request
from aicash.signing import verify_obj

PINNED = "…your signing_pubkey, recorded at launch…"      # b64u, as published
STATE  = "/var/lib/aicash-monitor/highwater.json"          # must survive runs
pub = base64.urlsafe_b64decode(PINNED + "=" * (-len(PINNED) % 4))  # verify_obj takes raw bytes

d = json.load(urllib.request.urlopen("https://mint.example.org/v3/mints"))
s = d["supply"]
assert d["signing_pubkey"] == PINNED, "KEY CHANGED — treat as compromise (R13)"
assert verify_obj(s, pub), "snapshot signature does not verify"
assert s["outstanding_mc"] == s["cumulative_issued_mc"] - s["cumulative_burned_mc"]

# §3.6 monotonicity needs memory, so keep some — and keep it on all THREE
# fields, not just the sequence. A restore from an older backup (§7) rewinds
# the cumulative counters while snapshot_seq still moves forward and the
# arithmetic invariant still holds, so a seq-only monitor sees nothing. That
# pair of snapshots is the portable proof of nonconformance; this is the check
# that catches it, whether the cause is your own recovery or someone else's
# dishonesty.
WATCH = ("snapshot_seq", "cumulative_issued_mc", "cumulative_burned_mc")
try:
    with open(STATE) as f:
        prev = json.load(f)
except FileNotFoundError:
    prev = {}                       # first run: nothing to compare against yet
for field in WATCH:
    was = prev.get(field)
    assert was is None or s[field] >= was, (
        f"§3.6 MONOTONICITY BREAK on {field}: {was} -> {s[field]}. Keep "
        f"{STATE} and this descriptor — together they ARE the evidence.")

os.makedirs(os.path.dirname(STATE), exist_ok=True)
tmp = STATE + ".new"
with open(tmp, "w") as f:                      # keep the last good descriptor:
    json.dump({**{k: s[k] for k in WATCH}, "descriptor": d}, f)   # it is signed
os.replace(tmp, STATE)          # atomic; never leaves a half-written high-water
```

Notes on that block, all checked rather than assumed. The decode matters: the
descriptor publishes the key as base64url text and `verify_obj` wants the 32
raw bytes. It was run verbatim (with the fetch replaced by the saved
descriptor) against the two real signed snapshots from the §7 restore
reproduction: on A the pin matched, `verify_obj` returned `True`, the invariant
held and the high-water file was written; on B — same key, `snapshot_seq`
3 → 1026, `cumulative_issued_mc` 9000 → 0 — it raised
`§3.6 MONOTONICITY BREAK on cumulative_issued_mc: 9000 -> 0`, and left the
stored high-water at 9000 rather than overwriting the thing that proves it. A
first run with no state file passes, by design; there is nothing yet to compare
against.

`STATE` is evidence, not a cache. Put it somewhere durable, back it up, and do
not let a redeploy of the monitor start it empty: a monitor with amnesia
silently re-baselines on whatever the mint says today, which is the one thing
this check exists to prevent. Run it on a schedule short enough that the stored
snapshot is never far behind reality — the gap between two stored snapshots is
the window an incident can hide in.

A failure of any of those lines is not a metrics blip — it is either a bug in
the mint or evidence of tampering, and it is the portable kind (§3.6, L3): the
signed snapshot is proof anyone can check.

**The certificate.** TLS is the only thing between a `/v3/exchange` body and
the wire (§4), it expires on a clock, and nothing in this build knows that.
Check the expiry from outside, on a schedule, and alert with weeks of room:

```bash
echo | openssl s_client -servername mint.example.org -connect mint.example.org:443 2>/dev/null \
  | openssl x509 -noout -checkend $((21*86400)) || echo "CERT EXPIRES WITHIN 21 DAYS"
```

Also alert on the renewal *mechanism*, not only the result: an inactive certbot
timer, or a `certbot renew --dry-run` that starts failing, gives you weeks of
warning where the certificate itself gives you none. See §4.2 — a config with no
port-80 ACME path renews nothing.

**Process and host.** Unit state (`systemctl is-active`), that the listener is
still on `127.0.0.1` and not a routable address, free disk on the ledger's
filesystem, and `mint.db` growth. The ledger only shrinks when pruning runs
(§8(b) retention, `Ledger.prune()`, which deletes spent entries and expired
idempotency records older than `recovery_window_ms` — 90 days by default). On
this build the launcher runs that on a background thread every
`--prune-interval-hours` (default 6; any positive value below
`MIN_PRUNE_HOURS` = 0.01 h is refused by argparse, because `prune()` takes
`BEGIN IMMEDIATE` and blocks every writer while it runs).

**`prunes_spent_records` is a one-way claim, and `--prune-interval-hours 0`
does not retract it.** The descriptor field is not derived from this run's
flag. The first start with pruning on writes `"prunes_spent_records": true`
into the **key file**, beside `mint_id` and `baseline_model_class`
(`pin_retention()` in `run_mint.py`), and the mint publishes it from then on
whatever the flag says — deliberately, because records already deleted cannot
be undeleted, and over-warning a counterparty is the safe direction.
Verified on this build, same `--keys` and `--db` across two starts:

```
run 1, default 6h              retention.prunes_spent_records: true
key file after run 1           {"private": "<44-char base64url seed>",
                                "public": "<44-char base64url>",
                                "mint_id": "p2",
                                "baseline_model_class": "b1",
                                "prunes_spent_records": true}
                               THE SIGNING KEY IS IN THIS FILE, ahead of the
                               pins, and it is mode 0600. §1 and §7 both say
                               so; the dump is written out in full here
                               because an earlier version of this block
                               showed only the three metadata fields, which
                               reads as a file that is safe to paste.
run 2, --prune-interval-hours 0
                               retention.prunes_spent_records: STILL true
                               NOTE: pruning is disabled this run, but the
                               descriptor still says prunes_spent_records:
                               true — this mint_id has pruned before ...
```

A mint that has **never** pruned and starts with `0` does publish
`prunes_spent_records: false` — verified on a fresh `--db`/`--keys` pair. So
the flag controls the behaviour, only a never-pruned mint's first start
controls the claim, and once set the claim is as permanent as the baseline.
Set the interval to 0 on a mint that has already pruned and the ledger grows
forever while the descriptor goes on promising deletion; that is the drift
this pin chooses over the other one. Watch for the `prune: deleted N spent
ledger entries` line in the access log; its absence over a day is the signal
that retention has stopped.

**The access log.** `--access-log` gives you one line per request, and the
shape is `TIMESTAMP METHOD route STATUS` — a route *pattern*, never a body and
never a raw path. Sampled from a live mint on this build:

```
2026-09-16 06:41:03,123 GET /v3/mints 200
2026-09-16 06:41:03,131 GET /v3/status/<hash> 200
2026-09-16 06:41:03,140 POST /v3/status 400
2026-09-16 06:41:03,148 POST /admin/issue 401
2026-09-16 06:41:03,156 GET <unknown> 404
```

Note the last two lines. `/v3/status/<hash>` is written with the literal
placeholder rather than the entry hash, and a path that matches no route at
all is logged as `<unknown>` — so this file cannot be used to find out *what*
someone probed, only that they probed. That is deliberate (a caller who wrongly
puts a token in a URL must not have it land on disk) and it is a limit on what
you can investigate from here. Watch:
- **401s on `/admin/issue`** — someone is probing the issuance credential. If
  `/admin/` is unreachable from outside as §4 requires, any 401 at all is a
  problem.
- **5xx rate.** The handler deliberately returns `{"status":"error"}` with no
  stack trace and logs no traceback, so a rising 500 count tells you something
  is wrong and gives you nothing to diagnose it with. Treat any sustained 500s
  as an incident and reproduce off the live host.
- **429s at the proxy** — your only signal that the published rate limit is
  actually biting.

**Latency.** The descriptor's `performance` block is self-attested and nullable
(L11) and the launcher never populates it, so your mint publishes `null` — which
is honest. If you ever fill it in, measure it for real and let it go stale to
`null` rather than reporting old numbers as fresh; reporting stale figures as
current is the one performance behavior L11 calls a violation.

---

## 9. Restart and recovery behavior

Verified against this build:

- **A restart rotates the admin credential, unless you pin it.** Identity and
  ledger survive a restart (next bullet); the *issuance credential* does not.
  Unless `--admin-token` is passed, the launcher generates a fresh one on every
  start and overwrites `--admin-token-file` — it never reads the old one back.
  Every separately started console, funding script or colleague's terminal
  holding the previous token is invalidated by the restart, and gets a 401 with
  no other symptom. Plan restarts accordingly, or pass `--admin-token` from your
  own secret store. Detail and the two-start verification are in §7.
- **A restart preserves identity and state.** Same `--keys` file → same
  `signing_pubkey`, same `mint_id`, same pinned baseline. Same `--db` →
  the same outstanding supply. Observed across a stop/start cycle:
  `outstanding_mc` and `cumulative_issued_mc` unchanged, `signing_pubkey`
  identical.
- **`snapshot_seq` continues across restarts, never restarts at zero.** It is
  persisted next to the ledger for exactly this reason: a mint must not be able
  to violate §3.6 monotonicity merely by being restarted. It *jumps forward* at
  each restart, because the sequence is handed out from reserved blocks —
  observed here going 1 → 1025 → 2049 across two restarts. A gap is expected
  and harmless; a step backward would be the §3.6 violation. Monitors must
  assert `>=`, never `== last + 1`.
- **A port already in use is a hard stop, not a fallback.** The launcher exits
  with an `ss -ltnp` hint rather than picking another port, because a second
  mint answering on a different port while clients keep talking to the old one
  is worse than no mint at all. One thing it does leave behind, verified here:
  the key file is loaded-or-created *before* the bind, so a start that dies on
  `Address already in use` with a fresh `--keys` path has already written a new
  keypair to it. That file is not yet any mint's identity and deleting it is
  safe — but never delete the one a running mint is using, and never let a
  retry point `--keys` at it by accident. (The admin-token file and the
  retention pin are the opposite: those are written only after a successful
  bind, so a failed start cannot clobber the running mint's credential.)
- **A `--db` another mint process is already serving is a hard stop, and the
  only one that arrives as a raw traceback.** The ledger takes an advisory
  single-writer lock — an `flock(LOCK_EX|LOCK_NB)` on the **ledger file
  itself**, not on a separate `.lock` file (`_claim_single_writer()` in
  `impl/aicash/mintapi.py`) — at `server.start()`, and a second mint pointed
  at the same file dies before it binds. This matters directly to §7's restore
  procedure, which is *stop, replace, start*: start while the old unit is
  still draining and this is the refusal you get. Reproduced on this build —
  two `run_mint.py` on one `--db`, second start:

  ```
  generated a new mint keypair -> .../k2.json
  Traceback (most recent call last):
    File ".../run_mint.py", line 666, in <module>
      main()
    File ".../run_mint.py", line 504, in main
      port = server.start(args.port)
    File ".../impl/aicash/mintapi.py", line 1472, in start
      self._core._claim_single_writer()
    File ".../impl/aicash/mintapi.py", line 716, in _claim_single_writer
      raise RuntimeError(
  RuntimeError: another mint process already serves this ledger
  (.../m.db). One ledger file is served by exactly one mint: §3.6 snapshot
  monotonicity is ordered per process, so a second server could sign
  snapshots that are portable proof of nonconformance against this mint_id.
  Stop the other process, or give this mint its own ledger.
  ```

  Exit status 1, nothing bound, nothing written to the ledger — but unlike
  every other hard stop in this list there is no friendly one-line refusal,
  so the operator meets a Python traceback and has to read the last line of
  it. Two things it *does* leave behind, both visible above: the keypair was
  written before the failure (same note as the port bullet), and the message
  names the ledger file it could not claim. `systemctl restart` is not affected — the unit's stop
  completes first; the exposure is a manual start, a second unit pointed at
  the same `--db`, or a restore started too early.
- **A changed baseline or a mismatched `mint_id` is a hard stop.** Expect the
  unit to fail to start after a fat-fingered `ExecStart` edit; read the message,
  do not "fix" it by deleting the key file.
- **A MISSING key file is *not* a hard stop — it is treated as first run.**
  This is the important asymmetry, and the list above would otherwise imply the
  opposite. `load_or_create_keys()` only validates pins when the file exists; if
  it does not, the launcher generates a fresh keypair, writes it, prints one
  line (`generated a new mint keypair -> …`) that a process manager swallows
  into a log, and serves a **different `signing_pubkey` over your existing
  ledger**. Verified here with `mint.db` intact: moving `mint-keys.json` aside
  and restarting with the same `--mint-id`, `--model-class` and `--db` started
  clean and served `ztweYMe-E8Hq…` where it had been serving `UlNzuzTW58Rv…`.
  No refusal, no warning beyond that one stdout line.
  Per §3.6/R13 that is an unchained key change under a live `mint_id` —
  indistinguishable from seizure or compromise, and "exactly the alarm".
  It is one `cd` away, because `--keys` defaults to the *relative* path
  `mint-keys.json` while `--db` is typically absolute: `aicash-mint --db
  /var/lib/aicash/mint.db` from the wrong working directory is enough. If you
  want it to fail instead, guard it yourself: the `ExecStartPre` line in §6's
  unit turns a path typo into a refusal to start rather than a new mint
  identity, and it is the only reason that case is not in the list above.
- **A restore from an older backup is not a hard stop either, and is a
  conformance event.** The launcher has no idea the ledger moved backwards.
  See §7: it breaks §3.6 monotonicity under the same key and only the §8
  high-water monitor will notice.
- **After a crash or `kill -9`,** SQLite rolls the journal back on the next
  open. No operator action, no repair tool, no fsck step. Verified here:
  `kill -9` on a mint that had just issued, then `pragma integrity_check` →
  `ok`, and a restart came back with the supply figures intact.
- **Upgrading the code under an existing ledger is unguarded.** See §10.

---

## 10. UNRESOLVED deployment risks

Read this section as the terms of the deal. None of these is a to-do item that
someone is quietly working on; they are the known state of the build.

**1. The cryptography has never had an independent human review.** Every
signature, hash-lock, chain-derivation and swap construction in this
implementation was designed and checked inside the same process that produced
it. The test suite — 394 cases passing when this line was last updated
(2026-09-16), and still
growing, so run `python3 -m unittest discover -s tests -t .` from `impl/` for
today's number rather than trusting a figure in prose — covers the adversarial
cases the authors *thought of*. No external cryptographer has audited the Ed25519 usage, the domain separation
in the channel chain (L7), the rung construction in escrow panels (L15), or the
swap atomicity argument (§11). If you are putting value on this, you are
trusting an unreviewed implementation of a ratified-on-paper protocol. Commission
a review before the value at risk exceeds what you would pay for one.

**2. Key rotation is unimplemented.** §3.6/R13 specify rotation — publish
`signing_pubkey_next`, cross-signed by the current key over
`{mint_id, pubkey, effective_at}` — and this build emits the field as a
permanent `null` and never fills it in (§7: `"signing_pubkey_next": null` on
every descriptor; present as a key, empty as a value). There is
no path from a compromised or suspected-compromised signing key to a new one
that your counterparties can distinguish from an attack. Plan operationally
around that: guard the key file as though there is no recovery, because there
is not.

**3. There is no schema-migration story.** The ledger schema is created with
`CREATE TABLE IF NOT EXISTS` and nothing records a schema version — no
`PRAGMA user_version`, no migrations table, no version column anywhere in
`impl/`. Against an existing `mint.db`, a future release that changes the schema
will silently *not* apply its change and will then run against the old shape.
Until a migration mechanism exists, treat any code upgrade as a procedure: stop
the mint, take a backup (§7), read the diff for schema changes, and be prepared
to restore. Do not upgrade a mint holding live value on a whim.

**4. The security of the deployment is the proxy's, not the code's.** TLS,
rate-limit enforcement and blind signatures are all scoped out by L17. That is a
defensible scoping decision for a reference build and a large standing risk for
an operator: a single misconfigured `server` block, an expired certificate
handled by falling back to `:80`, or a limiter zone that silently never matches,
and you are serving bearer secrets in clear text or serving them without limit.
Test the proxy as a security control — not just for a 200. §4.2's port-80 block
exists to make renewal work and nothing else: it serves the ACME challenge and a
redirect, and proxies nothing to the mint, precisely so that "fall back to :80"
is never an available shortcut for anyone, you included.

**5. One process, one file, no high availability.** No replication, no failover,
no read replicas, no horizontal scale; writes serialize on a single SQLite write
lock. Host loss is downtime, and downtime means no one can spend. Your recovery
time is however long it takes to restore §7 onto new hardware, by hand.

**6. Single-mint trust is the disclosed model (L3).** A mint *can* lie about
state. The mitigation on offer is the signed monotonic snapshot — evidence after
the fact, portable to anyone — not prevention. Everyone holding your tokens is
trusting you, and the honest thing is to say so in whatever terms you publish
rather than let the cryptography imply otherwise.

**7. Accepted protocol-level exposures your users inherit.** These are locked
decisions, not bugs, and an operator should be able to explain each of them:
bearer loss is unrecoverable with no operator override (L8); a status-verified
token can be double-spent until it is redeemed, which is a quantified fraud
margin, not a defect (L14); drawn-but-unsettled channel value refunds to the
payer at expiry (L16); credits are permanently nonconvertible (L9, §12) and
there is no earned issuance or attestation (L10).

**8. Issuance is one bearer credential — and its absence is now a refusal.**
Whoever holds the admin token mints without limit; that has not changed. The
other half did. `MintConfig.admin_token=None` used to mean *allow everyone*, so
any program that built a mint from a default config served `/admin/issue` to
whoever could reach the port — a credential whose absence was read as
permission. It now means nothing at all: `admin_token` has three named states
and `None` is not one of them, so the config refuses to build and says which
three to choose from (§1, L19). That is a breaking change for anything that
relied on the old default, deliberately, because the old default was the
risk.

Two things about this launcher. First, it was never the source of the hole and
still is not: every path through it passes one of the three named states, so it
cannot produce an unset one. It is, however, affected by the change — the
pre-change launcher spelled `--open-issuance` as `admin_token=None`, the very
value that is now refused, so an older `aicash-mint` script will not start
against this library until that one line becomes `ADMIN_ISSUANCE_OPEN` (§1). `--open-issuance` still does exactly what it says
— it is now spelled `ADMIN_ISSUANCE_OPEN` in the config, still deletes
`--admin-token-file` on the way up so no stale file implies a protection that
is not there, still warns on stderr, and the mint itself now logs a warning
naming the open `mint_id` on every start — through the mint's logger, so with
this launcher it lands in `--access-log` and on stdout (verified here:
`mint <id>: /admin/issue is UNAUTHENTICATED (ADMIN_ISSUANCE_OPEN)`). It
remains a laptop-demo flag: an open mint is one that anybody who reaches the
port can mint from, without limit.
Second, the credential is regenerated on every start unless you pass
`--admin-token` (§7), so a restart is also a rotation. Note the one asymmetry
that follows: the console started by `--open-issuance` is handed no credential,
and it refuses to issue rather than send an uncredentialled request — an open
mint is fundable on its own port, not through the console.

The operator console holds the token server-side, is loopback-only, requires
the capability URL it prints at startup (exchanged once for a session cookie)
on every route, and refuses to start with no credential at all — but it is
still a process holding a credential that mints without limit, so keep it on
loopback, or turn it off with `--console-port 0`.

**9. The HTTP server is stdlib.** `ThreadingHTTPServer` plus
`BaseHTTPRequestHandler` is a thread per connection, and it caps neither
connections nor threads: N sockets are N threads, and nothing in this process
says no. A single *request* is bounded — that part of this entry used to say
"no request timeouts of its own" and that is no longer true. Verified in
`impl/aicash/mintapi.py`: a 10-second idle timeout per recv (`_Handler.timeout`),
a 30-second wall-clock deadline on the whole request line, headers and body
(`MAX_REQUEST_SECONDS`, enforced through `_DeadlineRaw` precisely so a slow
drip cannot keep resetting the idle timer), a 1 MiB body cap refused on the
declared `Content-Length` *before* anything is allocated (`MAX_BODY_BYTES`), a
128-character idempotency-key cap (`MAX_IDEMPOTENCY_KEY_LEN`), and a
`max_batch` that `MintConfig` refuses to publish above what that body cap can
carry. That is the extent of it: per-request bounds, no concurrency bound, no
per-client bound. Rate limiting is still the proxy's job (§5), which is another
way of saying the §4 proxy is load-bearing.

**10. Recovery from backup is a conformance event, not a routine.** §7 has the
detail; the term of the deal is this: there is no replay log, so restoring an
older `mint.db` destroys every token issued since that backup and publishes
signed snapshots whose cumulative counters moved *backwards* — which §3.6 makes
portable proof of nonconformance, under your own key. Your backup interval is
therefore a promise to your users about how much of their money a disk failure
may annihilate, and about how large a disclosure you will owe when it does.
Nothing in this build reconciles it for you and nothing in the protocol lets
you retract it.

**11. You are the cheapest thing to attack.** `BOOTSTRAP.md` §1.1 is blunt about
this: until operator plurality exists, the network is
*operator-censorship-vulnerable*, and pressuring one human is far cheaper than
attacking the infrastructure. Mitigations named there — a corporate shell
separable from your personal finances, cloud and registrar accounts arranged so
one frozen invoice does not take the fleet down — are partial. They widen the
gap between "pressure the operator" and "the network dies"; they do not close
it.

---

## 11. Pre-flight checklist

- [ ] `mint_id` and `--model-class` chosen deliberately; both are permanent (§3)
- [ ] `mint-keys.json` 0600, backed up offline and encrypted, out of git (§7)
- [ ] Mint listening on `127.0.0.1` only; `ss -ltnp` confirms it (§4)
- [ ] TLS terminates at the proxy; port 8787 firewalled; `/admin/` returns 404
      from outside (§4)
- [ ] The address you publish to clients is the `https://` origin, and a real
      client reaches it from a machine that is **not** the mint host —
      `PYTHONPATH=impl python3 -c 'from aicash.wallet import MintClient;
      print(MintClient("https://mint.example.org").descriptor()["mint_id"])'`
      must print your `mint_id`. `curl` succeeding is not the same check:
      curl and the client need not share a trust store (they do when Python
      is linked against the same OpenSSL, and do not when it ships certifi
      or uses a platform store, as on macOS and Windows), and a certificate
      your users' store rejects reads to them as downtime, not as a
      warning (§4)
- [ ] Proxy config actually loads: `nginx -t` / `caddy validate` run, not
      assumed — neither config in §4 was syntax-checked when it was written (§4)
- [ ] Certificate **renewal** proven, not just issuance: `certbot renew
      --dry-run` passes, the ACME challenge path is reachable, and the renewal
      timer is active (§4.2)
- [ ] Certificate expiry is monitored from outside with weeks of headroom (§8)
- [ ] Proxy limiter matches the descriptor's published `anonymous_rate`
      exactly — including `burst`, which caddy-ratelimit cannot express (§4.1/§5)
- [ ] An admin credential is in force, and issuance without it is refused —
      checked on the host, not assumed: `curl -si -X POST
      http://127.0.0.1:8787/admin/issue -d '{"outputs":[]}'` with no
      `X-Admin-Token` must answer **401**, never 200. This launcher generates
      one unless you pass `--admin-token` or `--open-issuance`, so the box is
      normally already true; tick it by running the curl, and know where
      `--admin-token-file` put the credential (§1/§3/§10.8)
- [ ] `--console-port 0`, or console reachable only through an SSH tunnel (§1).
      The console's own capability-URL auth does **not** substitute for this:
      if the console is running at all, confirm its startup URL was not
      captured to a log by a service manager, since that file then holds a
      minting credential until the process is restarted (§1)
- [ ] Proxy access log cannot capture a token-bearing URL (§4.2)
- [ ] systemd unit stops cleanly — verified by watching for the launcher's own
      shutdown line in the journal; `TimeoutStopSec` > `--drain-seconds` (§6)
- [ ] Online backup scheduled with `.backup`/`VACUUM INTO`, never `cp`; a restore
      has actually been rehearsed, into a throwaway directory and never against
      the live key file (§7)
- [ ] Backup interval chosen as an RPO **denominated in users' tokens**, and the
      disclosure you will publish after a restore drafted in advance (§7/§10.10)
- [ ] `ExecStartPre` (or equivalent) refuses to start when `mint-keys.json` is
      absent — the launcher will happily mint a new identity instead (§9)
- [ ] Off-host monitor verifies the signed snapshot, the pinned pubkey, the
      supply invariant **and** a persisted high-water mark on both cumulative
      counters, with its state file backed up (§8)
- [ ] §10 read in full, and its consequences accepted in writing by whoever is
      accountable for the value at risk
