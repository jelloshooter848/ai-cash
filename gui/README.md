# aicash operator GUI

A local web page for running one aicash mint and moving money between
wallets on your own machine. Starting it is one terminal command, below.
Everything after that — start a mint, create wallets, create money, pay
from one wallet to another, watch what the burn destroys — happens on the
page: no second terminal, no curl, and no reading the spec.

## Start it

From this tree, at the repo root:

```
python3 -m venv .venv && . .venv/bin/activate
pip install cryptography
python3 gui/app.py
```

If `cryptography` is already importable in the interpreter you are about
to use, it is just the last line.

### From a fresh clone: not yet, and here is the exact reason

**Cloning from GitHub today does not get you this directory.** The
published `jelloshooter848/ai-cash` HEAD is `c23b44c`; the commit that
adds `gui/` is local and unpushed. So this —

```
git clone https://github.com/jelloshooter848/ai-cash.git   # no gui/ in it today
cd ai-cash
python3 gui/app.py
```

— ends in `python3: can't open file '.../ai-cash/gui/app.py': [Errno 2]
No such file or directory`. `git ls-tree --name-only c23b44c` is the whole
of what a clone gets today — `BOOTSTRAP.md`, `impl/`, `components/`,
`examples/`, `run_mint.py`, `wallet_cli.py`, `mint_console.py` and the spec
and design documents — with no `gui/` anywhere in it. Check it yourself
before trusting any clone recipe:

```
git ls-remote https://github.com/jelloshooter848/ai-cash.git   # what is published
git log --oneline --diff-filter=A -- gui/app.py                # when gui/ was added
git branch -r --contains $(git log -1 --format=%H -- gui/app.py)   # empty = unpushed
```

Until that third command names a remote branch, get this tree from the
machine it was built on rather than from a clone. Once `gui/` is pushed,
the fresh-clone recipe is the block at the top of this section with
`git clone https://github.com/jelloshooter848/ai-cash.git && cd ai-cash`
in front of it, and nothing else about it changes.

### Where it runs from, and what it needs

`python3 gui/app.py` works from any directory — the workdir it uses by
default is `gui/var` beside `app.py`, not something under the directory
you happened to be in.

`cryptography` is the only dependency: the mint signs its descriptor with
an Ed25519 key. Everything else is Python 3.12 and the standard library.
Nothing is downloaded at runtime, there is no build step, and the page
loads no script from anywhere but this server.

Options: `--port` (default 8799), `--workdir` (default `gui/var`),
`--host` (must be a loopback address — see below), `--no-auth` (tests
only — see below).

### The URL it prints is the password

```
  aicash operator GUI
  workdir   .../aicash/gui/var
  wallets   .../aicash/gui/var/wallets

  OPEN      http://127.0.0.1:8799/?k=<43 random characters, new every start>   <- open this in a browser
```

Open **that whole line**, `?k=` and all. The key is 32 random bytes
generated fresh on every start and kept only in memory: it is not written
to a file, a log line or any response body, so this terminal is the only
place it exists. Opening the URL once trades it for a session cookie and
every button on the page then works; a `/` without the right key, and
every `/api/*` request without the cookie, is a 401. Lost the URL? There
is no recovery and none is wanted: Ctrl-C and start again for a new key.

### If pressing Start mint says `ModuleNotFoundError`

Without `cryptography` installed, `python3 gui/app.py` still starts and
the page still opens — the GUI itself is pure stdlib. The failure lands
on the first press of **Start mint**, in red under the button:

```
the mint crashed while it was starting up.
ModuleNotFoundError: No module named 'cryptography'
```

and `gui/var/mint.log` ends with the traceback it came from:

```
  File ".../impl/aicash/signing.py", line 24, in <module>
    from cryptography.exceptions import InvalidSignature
ModuleNotFoundError: No module named 'cryptography'
```

The fix is `pip install cryptography` **into the interpreter that is
running `app.py`** (the mint is launched with that same interpreter, so a
system-wide install while the GUI runs inside a venv does nothing). You do
not have to restart the GUI: install it, press **Start mint** again.

## What to do once it is open

The page is one screen with three numbered sections, all visible at once
— mint, wallets, send & receive. The tour is four steps.

1. **Mint.** Press **Start mint**. Change nothing: the defaults are mint id
   `local-test-mint`, baseline `baseline-v1`, port 8787, and a burn policy
   that is **already switched on** — `rate_ppm 10000`, `cap_mc 1000`,
   `exempt_below_mc 10`, which is 1% capped at 1,000 mc with exchanges of
   10 mc and under exempt. The page says the same thing under **Mint
   settings**: "These start at a demo value, not at zero." That is the
   policy every figure below was measured under, so leaving it alone is
   what makes the rest of this tour match. If you ever want a mint where a
   payment moves its whole amount, set the rate and the cap to 0 — but not
   `exempt_below_mc`, which the mint refuses below 10. The button comes
   back when the mint is actually answering, not when the
   process was launched. Underneath are the mint's descriptor, its log
   tail, and the **operator funding** control that creates money.
2. **Wallets.** Create two, say `alice` and `bob`. Click one to make it the
   *active* wallet: the one that pays and receives in section 3.
3. **Fund alice.** In section 1's funding control, amount `1000`, count
   `1`, into wallet `alice`. Two things happen on that one click, and only
   the first is on the button: the mint **creates** 1,000 mc that did not
   exist, and then alice **redeems** it, which is an exchange like any
   other and is therefore burned. Under a 1% policy alice ends up with
   **990 mc**, not 1,000. The result line afterwards says exactly that —
   created, burned, credited — but the warning beside the button mentions
   only the creation, so know the second half before you press it.
4. **Pay bob.** With `alice` active, type `300`, choose `wallet: bob`, read
   the cost line, press Pay. Both balances move: alice 990 → 687, bob 297.
   Where the missing 6 mc went is the next section.

The whole demo is about a minute.

## The burn is charged twice, and the page says so

This is the one number it is easy to get wrong, so here is a walkthrough
that was run rather than reasoned about. A §7.3 burn is assessed **once
per `/v3/exchange` call**, on the **sum of that call's inputs** — not on
the amount you typed. A payment between two wallets is *two* calls:

* the paying wallet splits its coins into the tokens it hands over — burn
  one, on the sum of the coins it had to spend to cover the payment;
* the receiving wallet redeems those tokens — burn two, on their face sum.

Run the four steps above against a mint on the default policy — 1% capped
at 1,000 mc, exempt below 10 mc — and this is what the mint does:

```
issue 1,000 mc, credit alice   1,000 created, 990 credited, 10 burned
alice now holds                9 x 100 + 9 x 10 = 990 mc in 18 coins
pay 300 to bob
  coins spent (inputs)         100 + 100 + 100 + 10 = 310 mc
  burn one                     3 mc      (1% of 310 = 3.1, rounded down)
  paid out                     300 mc    (3 tokens)
  change back to alice         7 mc      (7 x 1 mc coins)
  alice                        990 -> 687   (303 mc left the wallet)
bob redeems the 3 tokens
  burn two                     3 mc      (1% of 300)
  bob credited                 297 mc
```

So the payment destroyed **6 mc** — 3 on the split, 3 on the redeem — and
of the 1,000 mc that was created, **16 mc is gone** once you count the
10 mc burned to get it into a wallet in the first place. One payment,
three different numbers — 300 asked for, 303 out of the payer, 297 into
the recipient — and none of them is the one you typed twice. That is why
the page quotes it for you instead of leaving you to multiply by 1%.

The coins matter, and this is the part that is easy to lose. Alice spent
310 mc of inputs to pay 300, because the smallest set of her coins that
covers 300 plus the burn is three 100s and a 10. The burn was computed on
that 310, not on 300 or on 303. With her coins it came to the same 3 mc —
1% of 310 floors to 3 — but that is a coincidence of this ladder, not a
rule. Change the coins and the arithmetic changes with them: a wallet
holding a single 1,000 mc coin (which is what you get if you set `rate_ppm`
to 0 before starting the mint, fund the wallet, then Stop mint, put the rate
back and Start again — the policy is only read at startup) has nothing
smaller to
spend, so paying 300 mc spends the **whole 1,000 mc coin** — burn 10 mc,
690 mc back as change, and the recipient still nets 297. That payment
destroys 13 mc instead of 6, for the same 300 mc paid.

Do not read a percentage off the amount. Read the cost line: it is quoted
from the coins the wallet will really spend.

The cost line under the amount box shows both halves before you commit,
and the Pay button names what the recipient will actually end up with. The
page computes the second half from the mint's own published `burn_policy`
(and from `burn_policy_next` when it has taken effect, per the mint's
clock, never the browser's); if it cannot read the policy it says the
recipient will get less rather than quoting a figure it cannot stand
behind.

Operator funding is the same story in one call instead of two: issuing
1,000 mc into a wallet credits it 990 mc under a 1% policy, and the page
reports what was created, what was burned and what was credited — but in
the result line, after the click. The warning by the **Issue into wallet**
button covers the creation ("cannot be undone") and not the burn, so the
cost of funding is disclosed a moment later than the cost of paying is.

## Things the page is deliberate about

- **The cost is shown before you commit.** Typing an amount fetches a
  quote. The Pay button stays disabled until that quote arrives, and it is
  disabled again *the instant* the amount or the recipient changes — not
  when a debounce timer eventually fires. A click pays the amount from the
  quote on screen, never the number in the box: if the two have drifted
  apart the page refuses, says nothing was paid, and re-quotes.
- **The mint's settings are read back from the mint.** The mint id,
  baseline and burn policy in the form are overwritten with what the
  running mint actually reports, and what this GUI last started is
  remembered in the workdir. Stop followed by Start therefore restarts the
  same mint on the same economics instead of re-sending whatever the form
  defaulted to. The policy is also printed in words under the mint status,
  not only inside the descriptor blob.
- **A rejected token says why.** Receiving a batch shows each rejected
  string next to its reason — already spent, malformed, wrong mint — and
  never loses the good tokens that were in the same paste. A paste where
  *nothing* was taken is reported as a failure, not in the success colour.
- **A token is never silently dropped.** A payment or an issue produces
  bearer token strings that exist in exactly one place: that response. If
  the recipient wallet fails to take them, the page shows the strings and
  says loudly that they are the only copy. Nothing here ever hides money it
  created.
- **When the mint is stopped it says so** and disables what cannot work.
  Wallet balances still show, marked *last known*.
- **Nothing spins forever.** Every request from the page has a deadline,
  and every connection into the server has one too.

## Security: read this before you move it anywhere

**This is a local operator tool, not a hosted service.** It has a lock on
it now — the URL it prints, exchanged for a session cookie — and that lock
changes nothing about where it should be listening. Loopback is a weaker
boundary than it sounds: it does not separate users on a shared machine,
it does not stop another local process, and it does not stop a web page
open in your own browser from firing requests at `127.0.0.1`. The cookie
is a second lock on a door that should still not face the street.

- **Every route needs the session cookie.** A `GET /` with the right `?k=`
  is the one place the cookie is handed out (`HttpOnly; SameSite=Strict;
  Path=/`); `/` with a wrong or missing key is a 401 HTML page telling you
  to use the URL from the terminal. Every `/api/*` route — the read-only
  ones too — is a 401 JSON `{"error":{"reason":"unauthorized", ...}}`
  without that cookie, and the key is **not** accepted in an API query
  string: the key opens the page, the cookie drives it.
- It binds a **loopback address only**, and separately it checks the
  `Host` header is a loopback literal — `127.0.0.1`, `::1`, `[::1]` or
  `localhost`, with an optional port. Anything else is 403. That check is
  the DNS-rebinding defence, and it is the reason binding to loopback is
  not enough on its own: a hostile page can make your browser resolve its
  own domain to `127.0.0.1`, and only the `Host` check catches it.
- It answers **its own page only**. `Origin` and `Referer`, when present,
  must be exactly this server, and `Sec-Fetch-Site` must be
  `same-origin`/`none`; a mismatch is 403 whatever the `Host` header says.
  Absent is allowed, because a same-origin fetch and curl both omit them.
  With `SameSite=Strict` on the cookie, this is the cross-site defence.
- `--no-auth` turns all of that off and exists **for automated tests
  only**. It prints a loud multi-line warning to stderr on every start
  (`THIS GUI IS SERVING WITH NO PASSWORD`) and it is not a way to recover a
  lost URL — stop the GUI and start it again instead. Running with no flags
  at all is authenticated; you have to ask for the open door.
- **Anyone who gets the cookie, or the URL, can mint money and spend every
  wallet in the workdir.** Treat that URL exactly as you would treat the
  wallet files themselves, and do not paste it anywhere.
- The mint's `/admin/issue` credential is read from
  `var/mint-admin-keys.json` on the server side, attached to the mint
  request there, and scrubbed out of anything that leaves this process. It
  is not in `page.html`, not in an API response, and not in a log line.
  Neither is the GUI's own key: it lives in memory and is printed to the
  terminal once.
- Each wallet is one sqlite file under `var/wallets/`, mode 0600, and it
  holds that wallet's secrets. **Whoever has the file has the money.** There
  is no backup and no recovery phrase.
- To reach the page from another machine, forward the port over ssh rather
  than binding a routable address:
  `ssh -L 8799:127.0.0.1:8799 user@this-host` (use your own `--port`).

## What lives where

```
gui/app.py        this server: the page, the JSON API, the key/cookie and
                  loopback rules
gui/page.html     the entire interface, one self-contained file
gui/mintctl.py    starts, supervises and stops run_mint.py as a subprocess
gui/walletops.py  a thin wrapper over aicash.wallet.Wallet
gui/test_app.py       tests for app.py and page.html (see below)
gui/test_mintctl.py   tests for the supervisor
gui/test_walletops.py tests for the wallet wrapper
gui/var/          workdir: mint.db, mint-keys.json, mint-admin-keys.json,
                  mint-token-digests.json, mint-control.json, mint.log,
                  gui-state.json, wallets/<name>.db
```

The workdir is runtime state of one machine and two of its files are
secrets, so `gui/var/` is in the repo's `.gitignore` as a whole directory.
The older `*.db` / `*-keys.json` / `*.log` rules do not reach
`mint-control.json`, `mint-token-digests.json` or `gui-state.json`, which
is why the directory is named outright rather than left to them.

`gui/var/gui-state.json` is this server's own note of what it last started
a mint with — mint id, baseline, port, burn policy, base URL — so that the
form is right after a browser reload and a wallet can still show its last
known balance while the mint is down. It holds no secrets. Deleting it is
harmless; the page falls back to whatever the supervisor still knows.

`mint-control.json` and `mint-token-digests.json` belong to `mintctl.py`;
everything else in the workdir belongs to the mint itself.

None of this is protocol. `aicash-spec-v0.4.md` describes the mint; this
directory only drives it, and changes no mint behaviour. If something here
looks like it needs the spec to change, that is a bug in here.

## The JSON API

The page uses it; you can too, from the same machine — with the session
cookie, which curl gets the same way the browser does, by opening `/` with
the key from the terminal:

```
K=<the k= value app.py printed>
C=$(curl -s -D - -o /dev/null "http://127.0.0.1:8799/?k=$K" \
    | sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p')
curl -s -H "Cookie: $C" http://127.0.0.1:8799/api/mint/status
```

Without that cookie every route below is a 401, and the key alone in the
query string will not do it. (`--no-auth` skips all of this and is for
automated tests, not for saving three lines of shell.)

```
GET  /api/mint/status                       POST /api/wallet/create  {name}
POST /api/mint/start    {mint_id, ...}      GET  /api/wallet/list
POST /api/mint/stop     {drain_seconds}     GET  /api/wallet/summary?name=
GET  /api/mint/logs?lines=N                 GET  /api/wallet/history?name=&limit=
GET  /api/mint/descriptor                   POST /api/wallet/receive {name, tokens}
POST /api/mint/issue    {amount_mc, count}  POST /api/wallet/pay     {name, amount_mc}
GET  /api/token/status?token=               POST /api/wallet/quote   {name, amount_mc}
                                            POST /api/wallet/recover {name}
```

Every failure is a 4xx or 5xx carrying `{"error": {"reason", "detail"}}`
with a `detail` written for a person and a `reason` that is always
snake_case. That holds for every method, including the ones no route uses:
`PUT`, `DELETE`, `OPTIONS` and anything else get a JSON 405, never an HTML
error page. A traceback never reaches the caller; it goes to the terminal
running `app.py`.

Amounts are **whole millicredits**. `12.7` is refused, not rounded down.

`GET /api/mint/status` adds one key beyond the supervisor's own fields:
`last_start`, the settings this GUI last started a mint with (or `null`).
The page uses it to refill the form; it is a convenience, not protocol.

`GET /api/wallet/history` returns rows whose `ts_ms` is always `0`, and
`0` there means **unknown**, not 1 January 1970: the wallet's sqlite has no
clock column, so there is no time to report and none is invented. Rows are
newest-first by insertion order. In Python, `walletops.history()` returns
that field as the exported `TS_UNKNOWN` sentinel, which is the integer `0`
but prints as `unknown`; across the JSON boundary it is a plain `0`, so a
consumer of this API has to carry the disclosure itself. The page does:
each such When cell reads the words *not recorded*, and one note above the
table says how many cells that is and that this wallet's database stores no
time for them.

`POST /api/mint/issue` returns token strings and credits nothing on its own
— the page then calls `/api/wallet/receive` to put them in the chosen
wallet. That is two steps on purpose: if the crediting step fails, the
tokens are already in your hands rather than lost inside a failed
transaction.

## Tests

```
cd aicash && python3 -m unittest gui.test_app -v          # this component
cd aicash && python3 -m unittest discover -s gui -t .     # all of gui/
```

Three kinds, because this component makes three kinds of claim:

* **The server.** A real server on a real port, driven with raw sockets:
  the origin controls (cross-site POSTs are refused and move nothing), the
  error envelope, whole-number amounts, wallet-name containment, credential
  redaction, the connection deadline, and that a GET writes nothing to the
  workdir.
* **The page.** `page.html`'s actual JavaScript, executed by node under a
  small DOM against a fake API: the cost line predicts what the payment
  then does, a stale quote cannot be paid, the settings panel stays open,
  Stop/Start keeps the burn policy, an all-rejected paste is not green, and
  the page's burn arithmetic matches `impl/aicash/burncalc.compute_burn`
  across a table of policies. These tests need `node` on PATH; without it
  that class skips and says so.
* **The money.** One end-to-end run — real mint, real wallets, real
  components, through this API — asserting that the figure the page shows
  before the click is the figure the mint produces after it.
