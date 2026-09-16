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
   `local-test-mint`, baseline model class `baseline-v1`, port 8787, and a
   burn policy that is **already switched on** — `rate_ppm 10000`,
   `cap_mc 1000`, `exempt_below_mc 10`, which is 1% capped at 1,000 mc with
   exchanges of 10 mc and under exempt. The page says the same thing under
   **Mint settings**: "These start at a demo value, not at zero." That is the
   policy every figure below was measured under, so leaving it alone is
   what makes the rest of this tour match. If you ever want a mint where a
   payment moves its whole amount, set the rate and the cap to 0 — but not
   `exempt_below_mc`, which the mint refuses below 10. You cannot go the
   other way: `rate_ppm 10000` is the **ceiling**, not a middle setting —
   see *The rate has a ceiling* below. The button comes back when the mint
   is actually answering, not when the process was launched. Underneath are
   the mint's descriptor, its log tail, and the **operator funding** control
   that creates money.
2. **Wallets.** Create two, say `alice` and `bob`. Click one to make it the
   *active* wallet: the one that pays and receives in section 3.
3. **Fund alice.** In section 1's funding control, amount `1000`, count
   `1`, into wallet `alice`. Two things happen on that one click: the mint
   **creates** 1,000 mc that did not exist, and then alice **redeems** it,
   which is an exchange like any other and is therefore burned. Under a 1%
   policy alice ends up with **990 mc**, not 1,000. Both halves are on the
   screen *before* you press — the cost line above the button names what
   will be created, what will be burned and what alice will be credited,
   and the warning beside it covers the creation and points at that line
   for the burn. The result line afterwards repeats the three figures as
   they actually landed.
4. **Pay bob.** With `alice` active, type `300`, choose `wallet: bob`, read
   the cost line, press Pay. Both balances move: alice 990 → 687, bob 297.
   Where the missing 6 mc went is the next section. That click also
   **records that bob was the one who got it**: the page sends `to` with
   the payment, this server performs the delivery, and the history row
   carries bob, the delivery outcome and its cause — so the row still says
   it three months later, which is what *The screen and the record say the same thing*
   below is about.

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
smaller to spend, so paying 300 mc spends the **whole 1,000 mc coin** —
burn 10 mc, 690 mc back as change, and the recipient still nets 297. That
payment destroys 13 mc instead of 6, for the same 300 mc paid.

Do not read a percentage off the amount. Read the cost line: it is quoted
from the coins the wallet will really spend.

### The rate has a ceiling, and the demo default is already sitting on it

The form invites you to change `rate_ppm`, and it is worth knowing which
way you can move it. **`rate_ppm` may not exceed 10,000 — that is 1%, the
limit §7.3 puts on the burn rate** (`MAX_RATE_PPM` in
`impl/aicash/burncalc.py`, checked again in `gui/mintctl.py` before a mint
is spawned). The demo default *is* 10,000. So on this GUI the burn can
only be turned **down**, never up: there is no policy it will start under
which an exchange costs more than 1% of the coins it consumes.

Exceed it and nothing starts. With no mint running, asking for 10,001:

```
$ curl -s -H "Cookie: $C" -H 'Content-Type: application/json' \
    -d '{"mint_id":"local-test-mint","baseline_model_class":"baseline-v1","port":8787,"rate_ppm":10001,"cap_mc":1000,"exempt_below_mc":10}' \
    http://127.0.0.1:8799/api/mint/start
{"error": {"reason": "mint_control", "detail": "rate_ppm must be between 0 and 10000 (that is 1%, the ceiling the spec puts on the burn rate in §7.3); got 10001.", "cause": "unknown"}}
```

http 400, and it is a refusal *before* anything happens: no process is
spawned, `mint.log` is byte-for-byte unchanged, and `GET /api/mint/status`
still says `running: false`, `pid: null`, with the sentence above in
`last_error`. On the page it lands in red under **Start mint**, the same
place a `ModuleNotFoundError` would. 50,000 fails identically. Note that
if a mint is *already* running you get "a mint is already running here
(pid …, port …). Stop it before starting another." instead — that check
comes first, so the ceiling is only visible from a stopped mint.

The other two numbers are not symmetric with it. `cap_mc` has **no**
ceiling — it is a millicredit amount, and any `cap_mc` at or above
`rate_ppm × inputs ÷ 1,000,000` simply never binds. `exempt_below_mc` has
a **floor** of 10 and no ceiling; 9 is refused with "exempt_below_mc must
be at least 10 — §7.3 requires that small payments are never burned;
got 9." Neither the form nor the note beside it states the rate ceiling;
this paragraph is the only place it is written down for an operator.

The cost line under the amount box shows both halves before you commit,
and the Pay button names what the recipient will actually end up with. The
page computes the second half from the mint's own published `burn_policy`
(and from `burn_policy_next` when it has taken effect, per the mint's
clock, never the browser's); if it cannot read the policy it says the
recipient will get less rather than quoting a figure it cannot stand
behind.

Operator funding is the same story in one call instead of two, and it is
disclosed the same way: before the click, not only after it. Issuing 1,000
mc into a wallet credits it 990 mc under a 1% policy, and the cost line
above the **Issue into wallet** button says so in advance — what will be
created, what will be burned and what the wallet will be credited —
recomputed as you type and read off the same policy the payment quote uses
(`burn_policy`, or `burn_policy_next` once the mint's own clock says it is
in force). The warning beside the button carries the half that is about
creation ("cannot be undone") and hands the burn straight to that line —
"the mint burns part of it on the way in — the line above says how much,
before you press." If the page cannot read the policy, the cost line says
the wallet will be credited somewhat *less* than what is created rather
than quoting a figure
it cannot stand behind — the same refusal to guess that the payment quote
makes. The result line afterwards repeats created, burned and credited as
they actually landed.

One thing the cost line is careful about and a reader might not expect: a
count above 1 is still **one** exchange, so the burn is charged once on the
whole batch rather than once per token, and the sentence says that where it
applies.

## Things the page is deliberate about

- **The cost is shown before you commit.** Typing an amount fetches a
  quote. The Pay button stays disabled until that quote arrives, and it is
  disabled again *the instant* the amount or the recipient changes — not
  when a debounce timer eventually fires. A click pays the amount from the
  quote on screen, never the number in the box: if the two have drifted
  apart the page refuses, says nothing was paid, and re-quotes.
- **Seven things void that cost sentence, not two.** The amount and the
  recipient are the two you cause. The other five are the mint moving
  underneath you, and they are precisely the ones nothing on screen would
  look stale for, so they get the same answer instead of waiting for the
  next poll: every cost sentence is stamped with the mint state it was
  computed under (`mintKey()` in `page.html`) and is thrown away the moment
  that state changes. The five are **the link to the mint failing**, **the
  mint stopping**, **the mint being stopped, given a new burn policy, and
  started again on the same id and port** — where the sentence is not
  merely old, its arithmetic is now wrong and nothing about it looks stale
  — **`app.py` no longer being able to say what the mint is doing**, and
  **the link coming back**, because "nothing can be paid" is itself a stale
  sentence once it can be. A quote is voided one more way: by being
  **spent**, on the same tick it is used, so a second click cannot re-pay
  an estimate already consumed. The principle under all of them is one
  sentence: a cost estimate describing a payment this page can no longer
  check must not sit on screen looking agreed to — so it is removed, not
  merely made unclickable.
- **The mint's settings are read back from the mint.** The mint id,
  baseline model class and burn policy in the form are overwritten with
  what the running mint actually reports, and what this GUI last started is
  remembered in the workdir. Stop followed by Start therefore restarts the
  same mint on the same economics instead of re-sending whatever the form
  defaulted to. The policy is also printed in words under the mint status,
  not only inside the descriptor blob.
- **A rejected token says why, and only what is known.** Receiving a batch
  shows each rejected string next to its reason — already spent, malformed,
  wrong mint — and never loses the good tokens that were in the same paste.
  A paste where *nothing* was taken is reported as a failure, not in the
  success colour. Every failure on the page carries a machine cause from one
  closed set (listed under **The JSON API** below), put there by the layer
  that knew it; nothing downstream substitutes a guess, and a cause that was
  never determined says so instead of picking a likelier story.
- **A token is never silently dropped.** A payment or an issue produces
  bearer token strings, and if the recipient wallet fails to take them the
  page shows the strings rather than hiding money it created. Where the
  *other* copy lives differs between the two, and the page no longer
  flattens the difference:

  - **Issue** really does produce strings that exist in exactly one place,
    that response. `/api/mint/issue` persists nothing and the mint stores
    ledger-key hashes, never secrets, so the page says ONLY copy and means
    it. That is why crediting them into a wallet is a separate, retryable
    step, and why the issue panel must not be dismissed before it succeeds.
  - **Payment** strings are written into the payer's own wallet file before
    the exchange is sent, which is what makes `recover()` possible. So "the
    only copy" was false there, on the two most alarming paths the page has.
    The page now *asks* `GET /api/wallet/outstanding?name=` and reports what
    came back: that all of them were read back, that only some were, or that
    it could not check at all. It never promises a recovery it has not seen.
    It also tells the server who the payment was for, so the durable
    record carries the recipient and the real delivery outcome rather than
    *bearer* and *unknown* — see *The screen and the record say the same thing* below.
- **When the mint is stopped it says so** and disables what cannot work.
  Wallet balances still show, marked *last known*.
- **A mint can be down in two ways, and the page shows both.** Stopped is
  the obvious one. The neighbour is a mint process that is alive and **not
  answering** — wedged, paused, mid-crash, or simply still starting up.
  `GET /api/mint/status` reports `running: true` with a real pid for that
  one, so for a long time the page drew it exactly like a healthy mint:
  the green indicator, the word *running*, and a climbing uptime, on a
  mint that refused every payment. The whole difference sat in
  `last_error`, which the page rendered **only when the mint was
  stopped** — so on screen there was no difference at all.
  `MintControl.status()` probes the descriptor and reports the answer as
  **`responding`**; `app.py` relays it without inferring it, and the page
  now renders a third mint state: an amber indicator, *RUNNING BUT NOT
  ANSWERING* with the reason beside it, a **State** of *not answering*,
  and Pay, Issue, Receive, Recover and token lookup disabled — while Stop
  and Refresh stay live, because those are how an operator gets out of it.
  A stale cost estimate is voided the same way it is on every other mint
  state change: `responding` is part of `mintKey()`.
  `responding` is `true`/`false`, or **`null` when the component did not
  say** — "we were not told" is a third answer, and nothing infers it from
  `last_error` or from `running`.
- **Which is down does not change what a wallet shows.** Both ways give
  every wallet `connected: false`, so that field cannot tell them apart —
  but the failure `cause` can, and it is the one that matters:
  `mint_stopped` means nothing was sent, so nothing can be half-done;
  `mint_unreachable` means something may have been sent and never
  answered, which is §5.1 territory and what `POST /api/wallet/recover`
  exists to settle. Read the cause, not the colour.
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
- A wallet is **two** files under `var/wallets/`, and they are not the same
  kind of thing.
  - `<name>.db` is the **store**: the money. It is created mode 0600 and it
    holds that wallet's secrets. **Whoever has the file has the money.**
    There is no backup and no recovery phrase.
  - `<name>.payments.db` is the **payment record**, written by a payment
    and by nothing else. It holds no secret — amounts, op_ids, recipient
    names, delivery outcomes and the sentence beside each — so copying it
    steals nothing and deleting it loses no money (every row it would have
    answered then reads *unknown*, which is what is true once it is gone).
    It is created mode **0600** like the store, and `chmod`ed to 0600 on
    every write — so a file an earlier build left world-readable is
    repaired the next time a payment touches it, with no operator action.
    "Holds no secret" was never the same claim as "safe to leave
    readable": it names who this wallet paid and how much, which is the
    wallet's whole payment graph, and on a machine where the security
    section above matters — its whole argument being that loopback "does
    not separate users on a shared machine" — that is not a file to leave
    open to every one of those users.
- **The same four gates guard `../mint_console.py`**, the smaller console
  for a mint you started yourself in a terminal. The two implement the same
  design and deliberately share no code — read that file's docstring before
  changing either, because a change here is a change to make there too, and
  it is where the class of defect both of them had is written down.
- To reach the page from another machine, forward the port over ssh rather
  than binding a routable address:
  `ssh -L 8799:127.0.0.1:8799 user@this-host` (use your own `--port`).

## What lives where

```
gui/README.md     this file
gui/__init__.py   makes gui/ a package, so `python3 -m unittest gui.test_app`
                  works from the repo root; docstring only, no code
gui/app.py        this server: the page, the JSON API, the key/cookie and
                  loopback rules
gui/page.html     the entire interface, one self-contained file
gui/mintctl.py    starts, supervises and stops run_mint.py as a subprocess
gui/walletops.py  a thin wrapper over aicash.wallet.Wallet
gui/test_app.py       tests for app.py and page.html (see below)
gui/test_mintctl.py   tests for the supervisor
gui/test_walletops.py tests for the wallet wrapper
gui/test_console_auth.py  tests for ../mint_console.py: the same four gates
                  as this server's, against a real console in front of a
                  real mint. It lives here because it is a GUI-suite test,
                  not because mint_console.py is part of this directory.
gui/var/          workdir: mint.db, mint-keys.json, mint-admin-keys.json,
                  mint-token-digests.json, mint-control.json, mint.log,
                  gui-state.json,
                  wallets/<name>.db           the wallet store: THE MONEY,
                                              mode 0600
                  wallets/<name>.payments.db  the payment record: who this
                                              wallet paid and whether it
                                              landed. No secrets, and NOT
                                              0600 — see Security above.
                                              Created by a payment; absent
                                              until a wallet has made one
```

Two files per wallet, not one, and `walletops.py`'s module docstring says
the same ("This module writes exactly TWO files"). The record is beside the
store rather than inside it because the store's schema belongs to the
protocol and a recipient is not a protocol concept — the wallet hands over
bearer strings and has no opinion about who is meant to take them.

The workdir is runtime state of one machine and several of its files are
secrets — the mint's two key files, and every `wallets/<name>.db` — so
`gui/var/` is in the repo's `.gitignore` as a whole directory.
The older `*.db` / `*-keys.json` / `*.log` rules do not reach
`mint-control.json`, `mint-token-digests.json` or `gui-state.json`, which
is why the directory is named outright rather than left to them.

`gui/var/gui-state.json` is this server's own note of what it last started
a mint with — mint id, baseline model class, port, burn policy, base URL —
so that the form is right after a browser reload and a wallet can still
show its last known balance while the mint is down. It holds no secrets.
Deleting it is harmless; the page falls back to whatever the supervisor
still knows.

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

Two rules first, because they decide where a parameter goes and this
document used to be vague about it. **A GET route reads the query string
and nothing else; a POST route reads the JSON body and nothing else.** A
parameter put in the wrong half is not read — it is simply absent, and
you get the missing-parameter error rather than a hint. And **nothing is
nested**: there is no `burn_policy` object anywhere in this API. Every
route, with the names the server actually reads:

```
GET  /api/mint/status        -
POST /api/mint/start         body {mint_id, baseline_model_class, port,
                                   rate_ppm, cap_mc, exempt_below_mc}
                             all six required, all flat, no nesting;
                             port 1-65535, rate_ppm 0-10000 (see the
                             ceiling, above), cap_mc >= 0,
                             exempt_below_mc >= 10      [all REFUSED]
POST /api/mint/stop          body {drain_seconds}   optional, default 10,
                                                    0-120   [REFUSED]
GET  /api/mint/logs          query ?lines=          optional, default 200,
                                                    1-2000  [CLAMPED]
GET  /api/mint/descriptor    -
POST /api/mint/issue         body {amount_mc, count}
                             amount_mc required, 1-(2^53 - 1); count
                             optional, default 1, 1-100   [both REFUSED]
GET  /api/token/status       query ?token=   a whole aicash:v3:<mint>:<amount>
                                             :<secret> string, or a bare
                                             ledger key
GET  /api/wallet/list        -
POST /api/wallet/create      body {name}
GET  /api/wallet/summary     query ?name=
GET  /api/wallet/history     query ?name=&limit=    limit optional,
                                                    default 50, 1-500
                                                            [CLAMPED]
GET  /api/wallet/outstanding query ?name=&limit=    limit optional,
                                                    default 20, 1-100
                                                            [CLAMPED]
POST /api/wallet/receive     body {name, tokens, payer, op_id}
                             tokens is a list of strings, or one string;
                             at most 100 [REFUSED]. payer + op_id are
                             optional and go together (half a pair is a
                             400): they name the payment these strings
                             came from, so this server settles the PAYER's
                             record from the delivery it just watched.
                             With neither, this is the plain Receive it
                             always was — strings pasted out of an email
                             have no payment this server can name
POST /api/wallet/quote       body {name, amount_mc}
POST /api/wallet/pay         body {name, amount_mc, to, deliver}
                             to optional: a recipient LABEL (non-empty,
                             <= 64 chars, no control characters). Omit it,
                             or send "", to take the strings away as
                             bearer money. page.html DOES send it, so a
                             page-made payment records its recipient.
                             deliver optional, default true: with
                             deliver=false this server records the payee
                             by name and hands nothing over — delivery
                             "unknown", delivery_attempt "not_attempted",
                             which is exactly true. A `to` naming no local
                             wallet WITHOUT deliver=false is a 404
POST /api/wallet/recover     body {name}
```

`[CLAMPED]` and `[REFUSED]` are not decoration, and this file used to write
both as a bare range: **a range in this API means one of two opposite
things, and the number alone will not tell you which.** Send a `[REFUSED]`
value out of range and you get a 400 and nothing happens — `count=101` is
`"Count must be a whole number from 1 to 100."`, `drain_seconds=121` is
`"drain_seconds must be a whole number from 0 to 120."`, a 101st token is
`"Receive at most 100 tokens at a time."` Send a `[CLAMPED]` value out of
range and you get **200 and a quietly different answer**:
`history?limit=100000` returns at most 500 rows, `outstanding?limit=99999`
at most 100, `logs?lines=99999` at most 2,000, and none of the three says a
word about the number you asked for. Zero and nonsense clamp as well —
`limit=0` and `limit=abc` both fall back to the default rather than
erroring. If you are paging, count the rows you got back; do not trust the
limit you sent.

`/api/mint/start` is the one worth pasting, because it is the one an
earlier version of this file described loosely. This is the request, byte
for byte, that starts the mint the whole tour above was measured on:

```
curl -s -H "Cookie: $C" -H 'Content-Type: application/json' \
  -d '{"mint_id":"local-test-mint","baseline_model_class":"baseline-v1","port":8787,"rate_ppm":10000,"cap_mc":1000,"exempt_below_mc":10}' \
  http://127.0.0.1:8799/api/mint/start
```

and this is what comes back — the supervisor's status with `last_start`
appended:

```
{"running": true, "pid": 744700, "port": 8787, "mint_id": "local-test-mint", "base_url": "http://127.0.0.1:8787", "started_at_ms": 1789553504315, "last_error": null, "last_start": {"mint_id": "local-test-mint", "baseline_model_class": "baseline-v1", "port": 8787, "rate_ppm": 10000, "cap_mc": 1000, "exempt_below_mc": 10}}
```

Spell the baseline field `baseline`, or wrap the three burn numbers in a
`burn_policy` object, and the real fields are missing — the server does not
guess:

```
{"error": {"reason": "bad_request", "detail": "Baseline model class cannot be empty. baseline-v1 is the usual value.", "cause": "unknown"}}
```

A route answers one method and says which: `GET /api/wallet/pay` is a 405
`"/api/wallet/pay answers POST, not GET."`, and a path that is not a route
at all is a 404 `"No API route /api/nope."`

`/api/wallet/outstanding` reads back the bearer strings of payments this
wallet has handed out, with the mint's verdict on each string. It persists
nothing new — the wallet already wrote every one of them before sending the
exchange — and it returns live bearer secrets, so it sits behind the same
session cookie as everything else. Three things about the answer that the
route's name does not suggest:

* **It lists recent payments, not only unredeemed ones.** A payment that
  was fully delivered and whose every string the mint now calls `spent` is
  still in `payments`, with `live_mc: 0`. The total is the separate
  top-level `unredeemed_mc`, the sum of what is still live — and it is an
  integer **only when every string in the answer carries a definite
  state**. Otherwise it is `null`, because an unchecked or unrecognised
  string is neither money nor dead and either number would be a lie. The
  response decomposes the whole handed-over value into four figures that
  add up and fold nothing into anything: `unspent_mc`, `spent_mc`,
  `unstated_mc` (the mint answered but has no ledger entry — a different
  mint's database) and `unchecked_mc` (the mint was not asked). So
  `checked: true` with 5000 mc unstated answers `unredeemed_mc: null,
  unstated_mc: 5000`, not `0`. `page.html` keeps the same decomposition,
  so the page and the API answer this question identically. The
  per-payment `live_mc` follows the same rule one level down: an integer
  only when every string in that payment has an answer, `null` otherwise.
* **Each payment carries the record fields** — `recipient`,
  `recipient_kind`, `delivery`, `delivery_cause`, `delivery_attempt` —
  read from the same
  payment record `GET /api/wallet/history` reads, so one payment cannot say
  *delivered* in one view and *unknown* in the other.
* **It carries a `scope` sentence, and so does `POST /api/wallet/recover`**,
  because the two answer different questions and can disagree at the same
  instant with neither being wrong. This route asks *what have I handed
  over that nobody has redeemed* — 220 mc across four strings, say. Recover
  asks *which operations did I start and never get an answer for*, and
  "nothing to settle" is a correct answer to that while the first is still
  220 mc. The sentences are on the wire so that a caller holding one number
  can tell which question produced it.

Every failure is a 4xx or 5xx carrying
`{"error": {"reason", "detail", "cause"}}`, with a `detail` written for a
person and a `reason` that is always snake_case. That holds for every
method, including the ones no route uses: `PUT`, `DELETE`, `OPTIONS` and
anything else get a JSON 405, never an HTML error page. A traceback never
reaches the caller; it goes to the terminal running `app.py`.

One thing the HTTP status codes do **not** do for you, verified against a
mint frozen mid-request: the same cause arrives under different codes
depending on which route it came through. A **stopped** mint is 409
everywhere. A mint that is **running and not answering** is 400 from `POST
/api/wallet/quote` and `POST /api/wallet/pay`, and 502 from `GET
/api/mint/descriptor` and `POST /api/mint/issue` — all four with `cause:
mint_unreachable`. A 400 conventionally means *your request was bad*, and
in that case it does not: the request was fine and the mint was not there.
**Read `cause`, not the status line.** The status codes are not a second
parallel vocabulary, and where they seem to say something the `cause`
does not, the `cause` is the one a layer actually determined.

`cause` is the machine answer to *why did this fail*, from one closed set —
`mint_unreachable`, `mint_stopped`, `mint_rejected`, `already_spent`,
`malformed_token`, `wrong_mint`, `insufficient_funds`, `unknown` — and it
is carried through from whichever layer actually determined it, never
re-guessed higher up. Two rules go with it: *the mint rejected it* is said
only for `mint_rejected` (and its refinement `already_spent`), because a
request the mint never received was not refused by it; and `unknown` reads
as undetermined on screen, never dressed up as the likeliest story.

Amounts are **whole millicredits**. `12.7` is refused, not rounded down
(`"Amount must be a whole number of millicredits greater than zero."`), and
the ceiling on a single `amount_mc` is 2^53 - 1 = 9,007,199,254,740,991 —
the largest integer a browser can carry without losing a millicredit.

`GET /api/mint/status` adds one key beyond the supervisor's own fields:
`last_start`, the settings this GUI last started a mint with (or `null`).
The page uses it to refill the form; it is a convenience, not protocol.
It also relays the supervisor's **`responding`** — `true` when the mint's
descriptor answered on that call, `false` when the process is alive and
did not, `null` when the component did not say. `running` answers "is the
process alive"; `responding` answers "does it work", and they are not the
same question.

`GET /api/wallet/history` rows carry the same `cause` field for any
operation that did not commit — read back from what was recorded at the
moment it failed, never re-derived later from the stored state, which
cannot tell a refusal from a request the mint never received. A row keeps
the cause it was written with, permanently; it is what an operator debugs
from months later.

A `pay` row is the durable record of where the money went, and every part
of it is written at the moment of the payment rather than reconstructed
later from the stored state. `POST /api/wallet/pay` answers with, and each
`pay` row from `GET /api/wallet/history` carries back:

```
op_id           this payment's id, the same string in both places, and the
                key /api/wallet/outstanding returns its strings under
amount_mc       what was paid out
recipient       the wallet named in `to`, or "" when there was none
recipient_kind  "wallet" or "bearer"
delivery        "delivered", "undelivered" or "unknown"
delivery_cause  for an undelivered one, the cause, from the closed set
```

The pay response adds `burn_mc`, `change_mc`, `balance_mc` and
`delivery_detail` — the sentence version of the three record fields, and
the same words the history row's `detail` ends with. On a history row the
burn and the change are in that `detail` sentence instead, because the row
is what an operator reads months later and a sentence survives better than
bare numbers. `GET /api/wallet/outstanding` lists its payments under these
same `op_id`s, so an undelivered or unknown row is enough to find the
bearer strings again — that is what makes those two values useful rather
than merely honest.

`unknown` is a value there, not a placeholder, and it renders as unknown.
A payment is recorded as a combination of THREE machine fields —
`recipient_kind`, `delivery` and `delivery_attempt` — and it takes all
three to tell the rows apart. `delivery_attempt` is `"not_attempted"` or
`"attempted"`, written *before* the delivery is tried, and it is the only
thing separating a delivery nobody ever made from one that was made and
lost:

```
recipient_kind  delivery      attempt        what it means, and what put it there
bearer          unknown       not_attempted  No `to` was sent. The strings went
                                             back to the caller and this wallet
                                             cannot follow them: "paid out as
                                             bearer strings with no recipient
                                             named; where they went after that is
                                             not knowable from this wallet."
wallet          unknown       not_attempted  `to` was named and this server was
                                             told `deliver: false` — it recorded
                                             the payee and deliberately handed
                                             nothing over. Nothing failed here.
wallet          delivered     attempted      `to` was named and that wallet took
                                             the whole payment: "delivered to the
                                             recipient 'bob', credited 50 mc
                                             there (op ...)".
wallet          undelivered   attempted      `to` was named and something
                                             ANSWERED, refusing — or refusing
                                             part of it. delivery_cause says
                                             which: mint_stopped, mint_rejected,
                                             already_spent, malformed_token,
                                             wrong_mint or insufficient_funds.
                                             Whether the refused value is still
                                             money DEPENDS ON THE CAUSE — see
                                             below.
wallet          unknown       attempted      `to` was named, the delivery was
                                             made and NOTHING answered, or the
                                             GUI was killed mid-delivery.
                                             delivery_cause is mint_unreachable
                                             when nobody answered, "unknown" when
                                             something was observed that
                                             established nothing, and "" when the
                                             process died before anything was
                                             observed at all. Whether the
                                             recipient was credited is
                                             undetermined: "the recipient 'bob'
                                             was sent this payment and nothing
                                             answered: ... — whether it was
                                             credited there is undetermined".
```

**An `undelivered` row does not by itself mean the money came back.** The
cause decides, and `walletops._refused_value_clause()` writes the answer
into the record rather than leaving the reader to assume one:

* `already_spent` — the strings had **already been redeemed**. That value
  is not this wallet's money, cannot be paid again, and re-sending those
  strings accomplishes nothing. This is the one row where an undelivered
  payment is money that is *gone*.
* `mint_stopped`, `mint_rejected`, `wrong_mint`, `malformed_token`,
  `insufficient_funds` — a §3.8 rejection is atomic and consumes nothing,
  so the refused value was still this wallet's money **when the row was
  written**. The row is permanent and a third party can redeem a
  handed-over string a second later, so it states what was true then and
  points at `GET /api/wallet/outstanding` for what is live now.
* anything else — not established, and recorded as not established.

The pay panel and the history detail in `page.html` print the same
three-way split from `refusedValueClause()`, deliberately using the same
cause sets in the same order: the moment those two lists drift, the record
and the screen start describing one payment differently again.

So `delivery: unknown` on its own does **not** mean bearer money. Read it
with `recipient_kind`: bearer/unknown is "we never had a recipient to
follow", wallet/unknown is "we had one, we sent it, and we never found
out". They send an operator to different places — the first to whoever was
handed the strings, the second to the mint's ledger and `POST
/api/wallet/recover`. The split between `undelivered` and `unknown` is
made in the direction of claiming less, and once: a cause meaning
*something answered* supports `undelivered`; `mint_unreachable` and
`unknown` support nothing stronger than `unknown`, because calling those
undelivered would be a guess about somebody else's money.

A wallet cannot pay itself (400, nothing moves) and a `to` naming a wallet
that does not exist is a 404 with nothing paid. A delivery that fails does
**not** fail the request: the money left, the strings are in the response,
and `delivery` says what became of them — answering 4xx there would tell
the operator nothing moved, which is false.

### The screen and the record say the same thing, and here is why that took work

This section used to document the opposite, and the history is the point.
The page paid and delivered in **two** calls — `POST /api/wallet/pay` with
`{name, amount_mc}` and nothing else, then a separate `POST
/api/wallet/receive` into the recipient. The server was therefore told
there was no recipient and recorded exactly that, while the delivery the
page performed afterwards happened somewhere no record could see. One
screen then said two things about one payment:

```
the result panel   "bob received 297 and now holds 297"
                   — true, read from bob's own wallet the instant it landed
the history row    Delivery unknown; recipient blank; "paid out as bearer
                   strings with no recipient named; where they went after
                   that is not knowable from this wallet"
```

Both were accurate about what they saw, and the panel's half died on the
next reload — so what survived was the weaker answer, and three months
later that was all there was.

**It is closed at the producer.** `payNow()` sends `to` with the payment;
`app.py` performs the delivery with both wallets locked in name order;
`walletops` writes the record **first** and delivers **second**, so the
durable row carries the recipient and the real outcome, and a process
killed between the two records `unknown` — which is then what is true —
rather than a guess. The result panel is rendered *from that record*, in
the record's own vocabulary, through the same `deliveryOf()` /
`recipientOf()` helpers the history table uses: one payment cannot read
`delivered` in one view and `unknown` in the other, because both views
read the same fields from the same row.

The page does not assert what it did not watch. On `delivered` it says
plainly that it did not perform the delivery, prints the wallet's own
recorded sentence (which carries the credited figure) and notes that the
recipient's balance in the list is read back from the mint. `"The mint
rejected it"` remains reachable only from cause `mint_rejected`.

Two things worth knowing about the edges:

* A server build that **ignores** `to` is detected on the *response*
  (`recipient_kind` and `recipient`, never assumed from the request). That
  path falls back to the old two-call delivery and prints a banner saying
  the permanent record will read bearer with delivery unknown and that the
  screen's answer dies on reload. It also now sends `payer` and `op_id`
  with the fallback `receive`, so a server that *can* record settles the
  payer's row from the delivery it just watched.
* A `walletops` build that cannot record refuses with `gui_incomplete`
  **before any money moves**. There is no quiet fall back to an unrecorded
  payment.

What every row carries, and what makes it worth reading at all: the op_id,
the amount that left, the burn and the change — e.g. *"paid out 300 mc,
burn 3 mc, 7 mc change returned to the wallet"* — plus the recipient, the
recipient kind, the delivery, its cause and whether it was attempted. And
`GET /api/wallet/outstanding` still hands back that payment's bearer
strings under the same op_id, so undelivered value is findable.

The limit of that, stated rather than left to be discovered: history records
*operations*, and a token rejected **locally** never becomes one. A receive
whose tokens are all malformed or all from another mint is filtered before
any `/v3/exchange` is built, so nothing is sent, nothing is started, and no
row is written — the rejections come back in the response's `rejected` list
with their `malformed_token` / `wrong_mint` cause and appear nowhere else.
History is the log of what this wallet *attempted against the mint*, not of
every paste that was refused.

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
  workdir. Read that last one precisely: it is about what **`app.py`**
  writes. A `GET /api/mint/descriptor` does grow `var/mint.log` by a line,
  because the mint process is a separate program keeping its own access
  log; no read route in this server creates or edits a wallet store, a
  payment record, or `gui-state.json`.
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
