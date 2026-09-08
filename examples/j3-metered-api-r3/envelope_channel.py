"""J3 confirmation (round 3): the §9.5 envelope -> §9.1 channel path.

Produced during a cold usability test to confirm the previously-broken
integrator path — build_envelope -> parse_envelope -> ChannelPayee.on_draw —
now works end to end using only the package-root public API.

Run:  PYTHONPATH=impl python3 examples/j3-metered-api-r3/envelope_channel.py
"""
import tempfile, os
from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
    ChannelPayer, ChannelPayee, build_envelope, parse_envelope,
)

priv, pub = generate_keypair()
cfg = MintConfig(mint_id="metered-mint", baseline_model_class="m1",
                 burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
                 signing_private=priv, signing_public=pub, admin_token="op")
server, ledger = make_mint(cfg, db_path=os.path.join(tempfile.mkdtemp(), "m.db"), clock=system_clock)
port = server.start(); base = f"http://127.0.0.1:{port}"
try:
    client = MintClient(base)
    d = tempfile.mkdtemp()
    s = new_secret()
    client.admin_issue([{"amount_mc": 5000, "secret_hash": ledger_key(s)}], admin_token="op")
    payer_w = Wallet(os.path.join(d, "payer.db"), client, "metered-mint")
    payer_w.receive(format_token("metered-mint", 5000, s))

    payee = ChannelPayee(client, "metered-mint",
                         wallet=Wallet(os.path.join(d, "seller.db"), client, "metered-mint"))
    payer = ChannelPayer(payer_w)
    N, unit = 20, 10
    now = client.descriptor()["mint_time"]
    secrets = [new_secret() for _ in range(N)]
    info = payer.open([ledger_key(x) for x in secrets], unit, N, expiry_ms=now + 3_600_000)
    payee.accept(info.to_json(), secrets)

    verified = 0
    for k in range(1, 6):
        draw = payer.draw(k)                        # x_k as b64u wire string
        req = build_envelope({"method": "next"}, "metered-mint", tokens=[], channel_draw=draw)
        env = parse_envelope(req)                   # decodes x_k to raw bytes
        verified = payee.on_draw(env.channel_draw)  # normalizes bytes-or-string
    settled = payee.settle()
    assert verified == 5, verified
    print(f"envelope->on_draw verified {verified} draws, settled net {settled} mc — OK")
finally:
    server.stop()
