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

### The Mint-settings note used to give a different formula; it no longer does

Until this round `page.html` printed, under **Mint settings**: *"The burn is
**min(cap, amount × rate ÷ 1,000,000)**"*. That is a percentage of the amount
you typed, which is exactly what the section above says not to read — and it
is not what the mint does. Spec §7.3 computes the burn on `sum(inputs)` of the
`/v3/exchange` call (`burn_mc = 0 if sum(inputs) <= exempt_below_mc`,
proportional on `sum(inputs)` above it), and `impl/aicash/burncalc.py`
implements that.

Measured against a live mint in this tree under `rate_ppm 10000 / cap_mc 1000
/ exempt_below_mc 10`: `POST /api/wallet/quote` for **7,000 mc** out of a
wallet whose covering coins came to 7,100 mc answered `burn_mc: 71`,
`change_mc: 29`, `inputs_mc: 7100`. The old note's formula predicts
`min(1000, 7000 × 10000 ÷ 1,000,000) = 70`. It was wrong by 1 mc there, by
9 mc on a 100 mc payment out of a 1,000 mc coin (`burn_mc: 10`), and by 7 mc
on this section's own second example.

**The note was the side that was wrong, and the note is what changed.** The
behaviour matches §7.3 and was never in question; the cost line under the
amount box was right all along, because it comes from `POST
/api/wallet/quote`, which reports the burn the mint will really charge on the
coins the wallet will really spend. The note now reads *min(cap, **sum** ×
rate ÷ 1,000,000), where sum is the face value of the coins the exchange
spends — not the amount asked for*, and carries the measured 7,000/7,100/71
example so the difference is visible rather than asserted. `page.html`'s
`burnFor(sum, p)` helper, which is what the cost line's recipient half is
computed from, always took the sum and is unchanged.

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
got 9."

Where the product states the ceiling, and where it does not: the **Mint
settings** note under the form tells you how to *get* a 1% burn ("set rate
10000 and cap 1000") and never says 10,000 is the maximum, and the input box
has no `max` on it. The one place the page prints the figure is the refusal
above — in red under **Start mint**, naming both the bound and §7.3 — which
you only see after asking for something it will not do. So the ceiling *is*
written down for an operator by the product itself; it is written down
**after** the attempt, and this paragraph is where it is written down
before.

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
- **Eight things void that cost sentence, not two.** The amount and the
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
  sentence once it can be. That is seven. The eighth is not staleness at all: a
  quote is also voided by being **spent**, on the same tick it is used
  (`invalidateQuote()` in `page.html`, called from both the pay and the
  issue path), so a second click cannot re-pay an estimate already
  consumed. The principle under all of them is one
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
  `responding` has three values and the pair `running`/`responding` is
  total: **`true`** the mint answered this call; **`false`** the process is
  alive and this GUI got no answer out of it — either the probe failed, or
  the record does not say which port to send one to; **`null`** there is no
  mint process here, so nothing was asked. `running: false` always pairs
  with `responding: null`, and `running: true` always pairs with a real
  boolean — a live process with no recorded port used to come back
  `responding: null`, which the page drew as the fully healthy state
  because its own test was `responding === false`. The difference between
  a probe that failed and a probe that could not be addressed is real and
  is carried in `last_error`, which is exactly the field printed beside
  the amber indicator. Nothing infers `responding` from `last_error` or
  from `running`.
- **Which is down does not change what a wallet shows.** Both ways give
  every wallet `connected: false`, so that field cannot tell them apart —
  but the failure `cause` can, and it is the one that matters:
  `mint_stopped` means nothing was sent, so nothing can be half-done;
  `mint_unreachable` means something may have been sent and never
  answered, which is §5.1 territory and what `POST /api/wallet/recover`
  exists to settle. Read the cause, not the colour.
- **Nothing spins forever.** Every request from the page has a deadline,
  and every connection into the server has one too.

## Does the money on the screen add up

Yes, and there is a panel that does the arithmetic for you. It is the
largest money surface in the product and the only one that reconciles the
mint's own books against everything the page can point to, so it gets its
own section.

Under the mint status the page prints a **supply reconciliation**:
`reconcileSupply()` and `supplyLines()` in `page.html`, both pure functions
with no DOM and no fetch in them, so the rule can be read without running
the page. It does one subtraction:

```
  the mint's signed supply snapshot   outstanding_mc
- what every wallet here can spend    sum of balance_mc
- what they handed out and nobody redeemed   sum of unspent_mc, read back
= the residual
```

Worked, on a session driven end to end through this GUI's own HTTP API for
this round — both functions run under `node` against the live API
responses, printing the same lines the panel prints. The session issued
50,000 mc in five 10,000 mc tokens, credited four of them to `alice`, paid
`bob` with delivery, paid bearer, paid a payee this workdir does not hold
with `deliver:false`, pasted its own bearer strings back into `carol`,
pasted a mixed batch of live / already-redeemed / malformed strings,
pressed Recover, and stopped and restarted the mint under a different burn
policy:

```
signed snapshot     50,000 ever issued   779 ever burned   49,221 outstanding
wallets             alice 24,373   bob 8,069   carol 4,729        37,171
handed over, unredeemed                                            2,050
accounted                                                         39,221
residual                                                          10,000
```

and the panel's own third line: *"10,000 mc of live money is in no wallet
on this page and in no string this page can see."* That figure was exactly
right and exactly explicable: it is the fifth issued token, 10,000 mc, that
was never credited to a wallet. Its string existed only in the issue result
panel; the mint keeps hashes and never secrets, so nothing anywhere can
read it back, and it appears on no other surface on the page. An
independent ledger kept alongside the session — every unit created, spent,
burned and received, tracked by hand — came to the same 49,221 mc as the
mint's signed snapshot at every one of the twelve checkpoints in the run,
and 37,171 + 2,050 + 10,000 is that number. That is what this panel is for.

A second reading from the same session, after two wallets had been pushed
past the read-back window on purpose, shows the floor-and-ceiling
machinery doing its job:

```
signed snapshot  50,000 issued   881 burned   49,119 outstanding
wallets                                                    33,419
handed over and confirmed unredeemed                        3,500
accounted (a FLOOR)                                        36,919
residual (a CEILING)                                       12,200
gap named in the panel: 15,380 mc of handed-out value unasked about
```

Note that the named gap, 15,380 mc, is **larger** than the residual it
qualifies, and that this is not a contradiction: handed-out value that a
wallet on this same page has since redeemed is inside the balances *and*
inside that gap, because the paying wallet's own file never learned what
became of its strings. The panel says so in as many words, because a
reader who adds the two gets a total the mint's own snapshot contradicts.

Five things it is careful about, and each one is a claim it would otherwise
be making falsely:

- **The mint's own invariant is checked, not assumed.** `issued − burned ==
  outstanding` is tested against the same signed snapshot the subtraction
  stands on, and a snapshot whose own three numbers disagree is printed as
  a warning rather than smoothed over.
- **No subtraction across two clocks.** The supply and the balances must
  come from one read pass, their timestamps within `PAIR_GAP_MS` (3,000 ms)
  of each other, and the mint's total must read the same immediately before
  and immediately after the balances. Fail any of those and the panel
  prints **no residual at all** and says why, rather than publishing the
  gap between two reads as an account of money.
- **The accounted side is a floor; the residual is therefore a ceiling.** A
  wallet whose balance could not be read, a read-back the mint could not be
  asked about, a read-back the server said did not cover the whole wallet —
  each sets the floor flag, and the sentences change with it: "at least
  36,919 mc in all" and "**at most** 12,200 mc of live money is in no
  wallet". Read the qualifier; it is the difference between a number and a
  bound.
- **A zero is only printed when it is a fact about the mint.** If the mint
  could not be asked about the strings a wallet handed out, the panel does
  not add 0 for them and call it "nobody has redeemed them" — it names the
  value that went out unverified in its list of what is *not* in the
  figure.
- **Wallets bound to a different mint are left out of the arithmetic
  altogether** and counted separately, because they hold none of this
  mint's money.

**"Unaccounted" means two different things in this product, and they are
not comparable.** `gui/walletops.py`'s `unaccounted_mc` is value one wallet
handed over that the component could put in none of its four buckets; it
was 0 in every call made for this document and it exists as a tripwire. The
panel's residual is the mint's outstanding total minus everything the whole
page can point to; it is routinely non-zero and a large value there is
normal on a workdir where anyone has pressed Issue without crediting. A
reader who sees `unaccounted_mc: 0` and concludes the reconciliation
balances has read the wrong number.

One dependency worth knowing: the unredeemed half of the subtraction comes
from `GET /api/wallet/outstanding` at `limit=100`. Until this round that
route published a confident `unredeemed_mc` that could be silently short of
the truth, and the page worked around it by ignoring the field and counting
rows. Both halves are fixed: the route now relays `truncated`,
`payment_count` and `unlisted_outstanding_mc` and drops its headline to
`null` when outstanding value did not fit, and the page reads those flags
off the wire instead of inferring them. The page still sums the per-token
states itself for the figure it prints, which is the right thing for a
surface that must show the parts as well as the total — see *The JSON API*
below.

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
- `--no-auth` turns off **the key and the cookie, and only those**, and
  exists **for automated tests only**. It prints a loud multi-line warning
  to stderr on every start (`THIS GUI IS SERVING WITH NO PASSWORD`) and it
  is not a way to recover a lost URL — stop the GUI and start it again
  instead. Running with no flags at all is authenticated; you have to ask
  for the open door. What it does *not* relax is the other two bullets
  above: measured against a `--no-auth` server, `Host: evil.example`,
  `Origin: https://evil.example`, `Referer: https://evil.example/x` and
  `Sec-Fetch-Site: cross-site` are each still **403**, while the same
  request with none of those headers is 200 and the bare `/` serves the
  page. So the flag opens the door to any local process; it does not open
  it to a web page in your browser.
- **Anyone who gets the cookie, or the URL, can mint money and spend every
  wallet in the workdir.** Treat that URL exactly as you would treat the
  wallet files themselves, and do not paste it anywhere.
- The mint's `/admin/issue` credential is read from
  `var/mint-admin-keys.json` on the server side, attached to the mint
  request there, and scrubbed out of anything that leaves this process. It
  is not in `page.html`, not in an API response, and not in a log line.
  Neither is the GUI's own key: it lives in memory and is printed to the
  terminal once.
- A wallet is **one file** under `var/wallets/` until it makes a payment, and
  **two** after that. They are not the same kind of thing, and the second one
  is created by the first payment rather than by `Create wallet` — verified on
  disk after the tour above: `alice.db` and `alice.payments.db` for the wallet
  that paid, `bob.db` alone for the one that only received.
  - `<name>.db` is the **store**: the money. It ends up mode 0600 — sqlite
    creates it under the umask and `impl/aicash/wallet.py` `chmod`s it —
    and it holds that wallet's secrets. **Whoever has the file has the
    money.** There is no backup and no recovery phrase.
  - `<name>.payments.db` is the **payment record**, written by a payment
    and by nothing else. It holds no secret — amounts, op_ids, recipient
    names, delivery outcomes and the sentence beside each — so copying it
    steals nothing and deleting it loses no money (every row it would have
    answered then reads *unknown*, which is what is true once it is gone).
    It ends up **0600**, the same as the store, by the same route the
    store takes: sqlite creates the file under the ambient umask (0644 on
    a default 022) and the code `chmod`s it to 0600 — here in
    `WalletJournal._write`, *before* the first statement runs and again on
    every write after, so a file an earlier build left world-readable is
    repaired the next time a payment touches it, with no operator action.
    Verified on disk after the four-step tour above: `alice.db 0600`,
    `alice.payments.db 0600`.
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
                                              landed. No secrets, and 0600
                                              ANYWAY — see Security above
                                              for why those are two
                                              different claims. Created by
                                              a payment; absent until a
                                              wallet has made one
```

At most two files per wallet, and `walletops.py`'s module docstring says the
same ("This module writes exactly TWO files") — that is a ceiling on what it
will ever write, not a count of what is on disk. A wallet that has never paid
has only its store; `bob.db` sat alone through the whole tour above. The record is beside the
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

`mint-control.json` and `mint-token-digests.json` belong to `mintctl.py`
and `gui-state.json` belongs to `app.py` (it is written by `_remember()`
there, and by nothing else); everything else in the workdir belongs to the
mint itself.

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

and this is what comes back — the supervisor's status with three keys
appended, `last_start` and the two that say where each of its fields came
from. Copied out of the response, whole:

```
{"running": true, "pid": 1262195, "port": 8787, "mint_id": "local-test-mint", "base_url": "http://127.0.0.1:8787", "started_at_ms": 1789571105274, "last_error": null, "responding": true, "last_start": {"mint_id": "local-test-mint", "baseline_model_class": "baseline-v1", "port": 8787, "rate_ppm": 10000, "cap_mc": 1000, "exempt_below_mc": 10}, "last_start_sources": {"mint_id": "the mint supervisor's record for this workdir", "baseline_model_class": "the mint supervisor's record for this workdir", "port": "the mint supervisor's record for this workdir", "rate_ppm": "the mint supervisor's record for this workdir", "cap_mc": "the mint supervisor's record for this workdir", "exempt_below_mc": "the mint supervisor's record for this workdir"}, "last_start_ignored_note": null}
```

`GET /api/mint/status` returns the same eleven keys; the two routes differ
only in that `start` spawns the mint first. If you are writing a client,
count the keys rather than trusting this paragraph — this block has been
wrong before, and it is wrong the moment somebody adds a twelfth.

Spell the baseline field `baseline`, or wrap the three burn numbers in a
`burn_policy` object, and the real fields are missing — the server does not
guess, and it names the first one it missed rather than the mistake you
made, which is why the two bodies read as if they are about different
problems:

```
{"baseline": "b", ...}         {"error": {"reason": "bad_request", "detail": "Baseline model class cannot be empty. baseline-v1 is the usual value.", "cause": "unknown"}}
{"burn_policy": {...}, ...}    {"error": {"reason": "bad_request", "detail": "rate_ppm must be a whole number of at least 0.", "cause": "unknown"}}
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

* **It lists payments, not only unredeemed ones, and not simply the
  newest ones.** A payment that
  was fully delivered and whose every string the mint now calls `spent` is
  still in `payments`, with `live_mc: 0`. The headline total is the
  separate top-level `unredeemed_mc`, the sum of what is still live — and
  it is an integer **only when every string in the answer carries a
  definite state**. Otherwise it is `null`, because an unchecked or
  unrecognised string is neither money nor dead and either number would be
  a lie. Under it the value is decomposed by *what the mint actually said
  about each string*, folding nothing into anything: `unspent_mc`,
  `spent_mc`, `unstated_mc` (the mint answered and has no ledger entry — a
  different mint's database) and `unchecked_mc` (the mint was not asked).
  So `checked: true` with 5000 mc unstated answers `unredeemed_mc: null,
  unstated_mc: 5000`, not `0`. The per-payment `live_mc` follows the same
  rule one level down: an integer only when every string in that payment
  has an answer, `null` otherwise. **That rule is sound about the strings
  in the answer and is not sound about the wallet** on its own — it says
  nothing about payments the window left out. Read the next two paragraphs
  before you use `unredeemed_mc` as a total.

  **What those figures add up to, exactly, because "adds up" was doing too
  much work here.** `unspent_mc`, `spent_mc`, `unstated_mc`, `unchecked_mc`
  and `unaccounted_mc` sum to `listed_mc` — the value handed over by **the
  payments in this response** — not to what this wallet has handed over in
  its life. That whole-life figure is `handed_over_mc`, and
  `handed_over_mc == listed_mc + unlisted_mc`. `limit` is a number of
  payment *operations*, it defaults to **20** and clamps at 100, and there
  is no offset.

  **The window is not "the newest N".** `gui/walletops.py` spends it on
  payments that still hold a string the wallet's own file calls
  `handed_over` — newest first within that half — and only then on
  payments it has already retired in full. A hundred dead payments cannot
  push a live one off the end. Anything the window does drop is reported
  by value, not left to be guessed at: `unlisted_outstanding_mc` is the
  part of `unlisted_mc` the wallet still shows as handed over.

  **And `unredeemed_mc` is `null` whenever that figure is non-zero**, not
  a confident integer that is short by it. Measured through this HTTP API
  against a wallet that had made 106 payments, 105 of them live 30 mc
  bearer payments nobody redeemed:

  ```
  GET /api/wallet/outstanding?name=bob&limit=20
      unredeemed_mc: null   truncated: true   payment_count: 106
      listed_mc: 600    unlisted_mc: 2600   unlisted_outstanding_mc: 2600
      handed_over_mc: 3200

  GET /api/wallet/outstanding?name=bob&limit=100
      unredeemed_mc: null   truncated: true   payment_count: 106
      listed_mc: 3000   unlisted_mc: 200    unlisted_outstanding_mc: 200
      handed_over_mc: 3200          <- same at both: whole life

  gui/walletops.py unredeemed_payments(limit=500)   (no window)
      unredeemed_mc: 3200   truncated: false   unlisted_outstanding_mc: 0
  ```

  The true figure at that instant was **3,200**, and no call above states
  a total it knows is short. Until this round the first two rows read
  `unredeemed_mc: 600` and `unredeemed_mc: 3000` — confident integers with
  no truncation marker — because `route_wallet_outstanding` re-derived the
  headline from the per-token states of the payments it forwarded and
  dropped everything the component said about its own window. That was the
  defect; the route now relays `truncated`, `payment_count`,
  `handed_over_mc`, `listed_mc`, `unlisted_mc`, `unlisted_outstanding_mc`,
  `unaccounted_mc`, `recovered_mc` and `recovered_ops`, and drops its
  headline to `null` when outstanding value did not fit. The rule
  `gui/walletops.py` states in its own docstring — *"a caller that totals
  the rows must publish `truncated` and `unlisted_outstanding_mc` beside
  them, or drop its own headline to `None` when they are set"* — now
  binds this route too, and the `scope` sentence in every response
  repeats it for the next caller down.

  **`recovered_mc` is not in any of those sums and must not be added to
  them.** It is pay operations that handed nothing over — `pay()` raised,
  `recover()` put the coins back — so the value is already inside the
  wallet's `balance_mc`. Adding it to the handed-over figures counts the
  same coins on two screens, which is the arithmetic an operator must not
  be made to do. It was 0 on every wallet measured for this document.

  **What the route still does not relay, if you call the component
  directly.** Three figures on every payment: `retired_mc`,
  `outstanding_mc` and its own `unaccounted_mc`. Two on every token: `key`
  (the ledger key) and `store_state` — this wallet's own word for the
  string (`handed_over` or `spent_out`), a different witness from the
  mint's `state` and kept apart from it on purpose. `retired_mc` is the
  **store's** word about its own copy and is deliberately outside the
  mint's four-way decomposition: a string this wallet has retired can
  still read `unknown` at a replaced mint, which is two questions with two
  answers rather than a contradiction.

  `unaccounted_mc` is a **named residual** for value the component knows
  was handed over and could put in none of the four boxes; it was 0 in
  every call made for this document, and it exists so that a future scan
  which drops a string shows up as a gap rather than as a smaller total
  nobody can see. It is **not** the residual the reconciliation panel
  prints — see *Does the money on the screen add up* above, which is a
  different quantity with the same English name.

  **What the page does with all this.** `summariseUnredeemed` in
  `gui/page.html` now takes `truncated`, `payment_count` and
  `unlisted_outstanding_mc` off the wire instead of inferring truncation
  from a full page of rows (the row-count rule is kept only as a fallback
  for a server build that sends no flag). The sentences that used to say
  the read "covered only the 100 most recent payments" said something
  false about a live-money-first window and pointed the reader at old
  payments instead of at the figure that names the gap; they now say how
  many of how many payments were read and print
  `unlisted_outstanding_mc` when there is one.

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

One thing the HTTP status codes do **not** do for you, measured against a
mint frozen mid-request (`SIGSTOP` on the mint's pid, every route driven
from curl's side of this API): the same cause arrives under different
codes depending on which route it came through.

A **stopped** mint is 409 with `cause: mint_stopped` on every route that
needs the mint — quote, pay, recover, issue, descriptor and token lookup —
while `GET /api/wallet/summary` and `GET /api/wallet/outstanding` still
answer **200**, because a wallet file can be read without a mint; they say
`connected: false` instead of failing.

A mint that is **running and not answering** is `cause: mint_unreachable`
on all six of those routes, under two different status codes:

```
400   POST /api/wallet/quote     POST /api/wallet/pay     POST /api/wallet/recover
502   GET  /api/mint/descriptor  POST /api/mint/issue     GET  /api/token/status
```

A 400 conventionally means *your request was bad*, and on those three it
does not: the request was fine and the mint was not there.
**Read `cause`, not the status line.** The status codes are not a second
parallel vocabulary, and where they seem to say something the `cause`
does not, the `cause` is the one a layer actually determined.

**That instruction is for a caller of this API. From the page, part of it
is unreachable, and the reason is a deadline, not a bug in the cause.**
`page.html` aborts its own fetch at `TIMEOUTS.default` = 20 s and prints
its own sentence — that nothing answered before the page gave up — so a
`cause` this server computes at second 37 is a correct answer nobody sees.

**Every route that can meet a wedged mint under the page's default 20 s
abort is in this table** — an earlier version listed seven and left four
out entirely (`/api/wallet/list`, `/api/wallet/outstanding`,
`/api/wallet/receive`, `/api/wallet/create`), among them the wallet list
behind every balance on screen and the read-back behind the handed-over
figure. (`/api/mint/start` and
`/api/mint/stop` are the two exceptions, and deliberately: they are
supervised process transitions with their own timeouts, and the page gives
exactly those two longer deadlines — `TIMEOUTS.start` 90 s and
`TIMEOUTS.stop` 70 s — so the 20 s abort is not their budget. `GET
/api/mint/logs` reads `var/mint.log` off disk and never touches the mint.)
Wall-clock against a `SIGSTOP`ped mint, two runs, both columns shown so the
spread is visible rather than averaged away:

```
                                 run 1    run 2   status  what the caller gets
under the 20 s abort, so the page shows this server's cause
  GET  /api/mint/status           2.02 s   2.04 s   200   running:true, responding:false
  POST /api/mint/issue            8.84 s  10.02 s   502   cause mint_unreachable
  GET  /api/mint/descriptor      10.07 s  10.85 s   502   cause mint_unreachable
  GET  /api/token/status         10.02 s  10.02 s   502   cause mint_unreachable
  GET  /api/wallet/list          12.81 s  14.01 s   200   every row connected:false
  GET  /api/wallet/summary       14.01 s  12.79 s   504   wallet_not_read
  GET  /api/wallet/outstanding   14.01 s  12.79 s   504   wallet_not_read
over it, so the page shows ITS OWN give-up message instead
  POST /api/wallet/quote         35.76 s  38.53 s   400   cause mint_unreachable
  POST /api/wallet/pay           36.86 s  36.86 s   400   cause mint_unreachable
  POST /api/wallet/recover       36.92 s  37.66 s   400   cause mint_unreachable
  POST /api/wallet/receive       36.92 s  36.83 s   400   cause mint_unreachable
right on the line
  POST /api/wallet/create                 20.30 s   200   the wallet is created
```

Four different mechanisms produce those bands, and none of them is a single
socket timeout:

* **2 s** is `MintControl.probe_timeout_s` alone — one descriptor probe,
  no wallet and no mint HTTP call. This is what keeps the amber *RUNNING
  BUT NOT ANSWERING* indicator responsive while everything else hangs.
* **~10 s** is `app.py`'s own `MINT_HTTP_TIMEOUT_S` (8 s) plus that probe.
  These three go out through `_mint_http` and nowhere near the wallet.
* **~13-14 s** is `app.py`'s read deadline, `READ_DEADLINE_S` = 12 s,
  enforced by `Api._read_within()`, plus the probe. These three do **not**
  go through `_mint_http`: they go through `gui/walletops.py` into
  `aicash.wallet.MintClient`, whose own socket deadline is **30 s** and is
  not `app.py`'s to set or to shorten. Without the read deadline they ran
  32 s (one wallet), 62 s (two mint calls) and 64 s (two wallets read one
  after another) — the three slowest routes in the product, all of them
  past the page's abort, and `/api/wallet/list` is the one every balance on
  screen comes from. `_read_within()` answers with what it has instead, and
  `/api/wallet/list` marks the rows it could not read rather than dropping
  them.
* **~36-39 s** is that 30 s `MintClient` deadline, unbounded on purpose.
  These four **move money**, and `_read_within()` answers by *abandoning*
  its worker — safe for a read, and not safe for an operation still in
  flight inside the thread you walked away from. They wait for
  `walletops.py` to finish and report what it actually determined, even
  when that lands after the page has stopped listening; the wallet's
  history row is still written, and `POST /api/wallet/recover` (slow for
  the same reason) is what settles an operation left in flight.
* **`POST /api/wallet/create` is unbounded for a different reason**: it
  makes a file. Abandoning it would let this server answer "not created"
  while the worker it walked away from was still creating the wallet. It
  measured **20.30 s** against the wedged mint — sitting on the page's
  20 s abort, so which sentence the operator gets is a coin flip. It
  succeeds either way; the wallet appears on the next refresh.

So: from curl, every row above is reachable and the instruction to read
`cause` reads plainly. From the page, a wedged mint gets you this server's
`cause` on **everything except the four money routes**, and on those you
get `page.html`'s own "nothing answered" sentence instead — and on
`Create wallet`, either, depending on which side of 20 s it lands. The
operator is not misled either way; they are simply told less by the slow
end.

**This is the fastest-moving table in this document** — it is a
measurement of three timeout constants that live in three different files,
and one of them (`READ_DEADLINE_S`) did not exist a build ago. Re-measure
rather than trust it: `kill -STOP` the mint's pid, then `time curl` each
path above.

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

`GET /api/mint/status` adds **three** keys beyond the supervisor's own
fields, not one.

`last_start` — the six values the Start form asks for (`mint_id`,
`baseline_model_class`, `port`, `rate_ppm`, `cap_mc`, `exempt_below_mc`),
or `null` on a workdir where nothing has ever started a mint. It is merged
from **two** records, not one: the supervisor's `mint-control.json`, which
it writes on every start and when it adopts a mint it did not spawn, and
`last_start` in `gui-state.json`, which only a start made through *this*
server writes. The supervisor's wins where it knows something, this
server's note fills the gaps, and `mint_id` and `port` are overwritten with
whatever `status()` is reporting on the same call — so the form and the
status line beside it cannot name two different mints. Verified: delete
`gui-state.json` under a running mint and `last_start` still comes back
complete.

`last_start_sources` — the same six field names, each mapped to an English
sentence naming which record that value came out of ("the mint supervisor's
record for this workdir", "this GUI's own note of the last mint it started
here", or the status line's own record). When the pin in the paragraph
above actually overrides something, the sentence for that field says so
instead of hiding it. It is `null` when `last_start` is.

`last_start_ignored_note` — `null` almost always, and an object when this
GUI's own note was about a **different mint** from the one this workdir
holds, in which case the note is dropped whole rather than used to fill
gaps. Reproduced by putting a note for `note-mint` into `gui-state.json`
under a running `local-test-mint`:

```
"last_start_ignored_note": {"mint_id": "note-mint", "port": 9999,
  "why": "this GUI last started mint 'note-mint' from here, but this workdir
   holds 'local-test-mint'. Another mint's burn policy is not this mint's, so
   nothing from that note was used to fill this form."}
```

All three are a convenience for refilling the form and reporting where its
values came from; none of them is protocol.

It also relays the supervisor's **`responding`** — `true` when the mint's
descriptor answered on that call, `false` when the process is alive and
this GUI got no answer out of it (the probe failed, **or** there was no
address to send one to), `null` when no mint process is running here and
so nothing was asked. `running` answers "is the process alive";
`responding` answers "does it work", and they are not the same question.
A live process with no usable address is also what turns the next request
into a **502 `mint_unreachable`** naming the pid rather than a 409
`mint_stopped`: `mint_stopped` is a claim about a process, and there is a
live witness against it.

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
