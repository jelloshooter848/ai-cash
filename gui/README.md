# aicash operator GUI

A local web page for running one aicash mint and moving money between
wallets on your own machine. It exists so that seeing aicash work does not
require a terminal, a second terminal, or reading the spec.

## Start it

```
cd aicash/gui
python3 app.py
```

It prints a URL. Open it in a browser:

```
  aicash operator GUI
  workdir   .../aicash/gui/var
  wallets   .../aicash/gui/var/wallets

  OPEN      http://127.0.0.1:8799/   <- open this in a browser
```

Python 3.12 and the standard library, plus the `cryptography` package the
mint itself uses for its Ed25519 signing key. Nothing is downloaded, there
is no build step, and the page loads no script from anywhere but this
server.

Options: `--port` (default 8799), `--workdir` (default `gui/var`),
`--host` (must be a loopback address — see below).

## What to do once it is open

The page is one screen with three numbered sections, all visible at once.

1. **Mint.** Press **Start mint**. The defaults — mint id `local-test-mint`,
   baseline `baseline-v1`, port 8787, no burn — are fine. The button comes
   back when the mint is actually answering, not when the process was
   launched. Underneath are the mint's descriptor, its log tail, and the
   **operator funding** control that creates money.
2. **Wallets.** Create two, say `alice` and `bob`. Click one to make it the
   *active* wallet: the one that pays and receives in section 3.
3. **Send & receive.** With `alice` active, put money in her (section 1's
   funding control, "into wallet: alice"), then pay `bob`: type an amount,
   choose `wallet: bob`, read the cost line, press Pay. Both balances move.

The whole demo is about a minute.

## The burn is charged twice, and the page says so

This is the one number it is easy to get wrong, so it is worth stating
plainly. A §7.3 burn is assessed **once per `/v3/exchange` call**, and a
payment between two wallets is *two* calls:

* the paying wallet splits its coins into the tokens it hands over — burn
  one, on the sum of the inputs it spent;
* the receiving wallet redeems those tokens — burn two, on their sum.

So with a 1% policy capped at 1,000 mc, paying 300 mc takes **303 mc** out
of the payer and leaves the recipient with **297 mc**: 6 mc destroyed, not
3. The cost line under the amount box shows both halves before you commit,
and the Pay button names what the recipient will actually end up with. The
page computes the second half from the mint's own published `burn_policy`
(and from `burn_policy_next` when it has taken effect, per the mint's
clock, never the browser's); if it cannot read the policy it says the
recipient will get less rather than quoting a figure it cannot stand
behind.

Operator funding is the same story: issuing 1,000 mc into a wallet credits
it 990 mc under a 1% policy, and the page reports what was created, what
was burned and what was credited.

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

**This is a local operator tool, not a hosted service.** It has no login, no
accounts, and no authorisation of any kind.

- It binds a **loopback address only**. `--host` with anything routable is
  refused with an explanation, and a request whose `Host` header is not
  `127.0.0.1`, `localhost` or `::1` is rejected, so a web page somewhere
  else cannot point a hostname at your machine and drive it from your
  browser.
- It answers **its own page only**. A request a browser marks as coming
  from another site — `Sec-Fetch-Site` other than `same-origin`/`none`, or
  an `Origin` that is not this exact server — is refused with 403, whatever
  its `Host` header says. Without that, any page in any other tab could
  POST straight to `127.0.0.1` with a simple content type, needing neither
  DNS rebinding nor CORS permission, and mint, drain or stop. A request
  with neither header (curl, a script, the examples below) is not a browser
  request and is allowed.
- **Anyone who can reach this port can mint money and can spend every
  wallet in the workdir.** There is nothing to log in to. Treat the port
  exactly as you would treat the wallet files themselves.
- The mint's `/admin/issue` credential is read from
  `var/mint-admin-keys.json` on the server side, attached to the mint
  request there, and scrubbed out of anything that leaves this process. It
  is not in `page.html`, not in an API response, and not in a log line.
- Each wallet is one sqlite file under `var/wallets/`, mode 0600, and it
  holds that wallet's secrets. **Whoever has the file has the money.** There
  is no backup and no recovery phrase.
- To reach the page from another machine, forward the port over ssh rather
  than binding a routable address:
  `ssh -L 8799:127.0.0.1:8799 user@this-host` (use your own `--port`).

## What lives where

```
gui/app.py        this server: the page, the JSON API, the loopback rules
gui/page.html     the entire interface, one self-contained file
gui/mintctl.py    starts, supervises and stops run_mint.py as a subprocess
gui/walletops.py  a thin wrapper over aicash.wallet.Wallet
gui/test_app.py   tests for app.py and page.html (see below)
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

The page uses it; you can too, from the same machine.

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

`POST /api/mint/issue` returns token strings and credits nothing on its own
— the page then calls `/api/wallet/receive` to put them in the chosen
wallet. That is two steps on purpose: if the crediting step fails, the
tokens are already in your hands rather than lost inside a failed
transaction.

## Tests

```
cd aicash && python3 -m unittest gui.test_app -v
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
