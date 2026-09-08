"""JOURNEY 5 (round 2) — milestone escrow with a k-of-n arbiter panel.

Written COLD from the AICash repo docs alone (README + aicash-spec-v0.4 §9.3/§9.6
+ the component "Public API" blocks C09/C07/C06/C03/C01/C12) by an integrator who
had never seen this codebase. No implementation function bodies were relied on.

Demonstrates, against a REAL in-process HTTP mint (make_mint from the README
quickstart, driven by a FakeClock so deadlines can be advanced):

  1. a 2-milestone job with a 3-arbiter panel, quorum k=2;
  2. funding by signed rung attestations, then the MANDATORY §9.3 pre-work
     verify_funding — performed on a FundingInfo that crossed a PROCESS BOUNDARY
     as a JSON wire message (FundingInfo.to_dict -> canonical_json bytes ->
     json.loads -> FundingInfo.from_dict), proving the JSON codec exists;
  3. milestone 1: full release by a 2-of-3 quorum of signed votes
     (also shows reveal REFUSED with only 1 of k=2 votes);
  4. milestone 2: disputed, split 60/40 by quorum — payee gets exactly the
     5x1000+4x100 rung subset per arbiter, the 40% remainder refunds at expiry;
  5. signed §10.2 dispute-outcome records for both milestones, panel-verified;
  6. PAYEE PROTECTION: a payer who funds a rung with a SELF-INVENTED preimage
     hash is caught by verify_funding BEFORE work starts (offending rung named),
     and — with the check skipped — the arbiter's genuine release opens nothing.

Run:  PYTHONPATH=/home/lando/projects/aicash/impl python3 run_escrow.py
"""

import hashlib
import json
import sys
import tempfile
import uuid

# ---- Package-root exports (README: "from aicash import ...") ---------------
from aicash import (
    Arbiter, EscrowPayer, EscrowPayee, FundingInfo, MintConfig, MintClient,
    MintRejected, BurnPolicy, FakeClock, compute_deadlines, generate_keypair,
    make_mint, new_secret, ledger_key, format_token,
)
# ---- Symbols the component "Public API" blocks name but __all__ omits ------
#   (each block states its module path, so the submodule import is doc-grounded)
from aicash.escrow import (            # C09 Public API block
    rung_composition, make_dispute_record, FundingInvalid, QuorumNotMet,
)
from aicash.tokencodec import canonical_json      # C01 Public API block
from aicash.burncalc import compute_burn          # C03 Public API block
from aicash.receipts import verify_dispute        # C12 Public API block

PASSED = 0


def check(label, cond, detail=""):
    global PASSED
    tag = "ok  " if cond else "FAIL"
    print(f"  [{tag}] {label}" + (f"  -> {detail}" if detail else ""))
    if not cond:
        sys.exit(f"\nCHECK FAILED: {label}")
    PASSED += 1


def sha_b64u(b):
    from aicash.tokencodec import b64u_encode
    return b64u_encode(hashlib.sha256(b).digest())


# ---------------------------------------------------------------------------
# 0. Boot a real mint (README quickstart shape) on a FakeClock.
# ---------------------------------------------------------------------------
T0 = 1_756_000_000_000
clock = FakeClock(T0)
GRACE = 5_000
policy = BurnPolicy(rate_ppm=1000, cap_mc=100, exempt_below_mc=10)   # 0.1%, cap 100
priv, pub = generate_keypair()
MINT = "j5r2-escrow-mint"
config = MintConfig(
    mint_id=MINT,
    baseline_model_class="cold-usability-r2",
    burn_policy=policy,
    signing_private=priv,
    signing_public=pub,
    grace_ms=GRACE,
    admin_token="operator-secret",
)
db = tempfile.mktemp(suffix=".sqlite", prefix="aicash-j5r2-")
server, ledger = make_mint(config, db_path=db, clock=clock)
port = server.start()
client = MintClient(f"http://127.0.0.1:{port}")
print(f"mint '{MINT}' live on 127.0.0.1:{port}, mint_time={clock()}")

# Operator funds the payer (70,000 mc) and a would-be attacker "mallory" (4,000 mc).
payer_secret = new_secret()
mallory_secret = new_secret()
client.admin_issue(
    [
        {"amount_mc": 70_000, "secret_hash": ledger_key(payer_secret)},
        {"amount_mc": 4_000, "secret_hash": ledger_key(mallory_secret)},
    ],
    admin_token="operator-secret",
)
payer_token = format_token(MINT, 70_000, payer_secret)
mallory_token = format_token(MINT, 4_000, mallory_secret)
ISSUED = 74_000

# ---------------------------------------------------------------------------
# 1. Build the job: 2 milestones, panel of 3 arbiters (k=2), 1,000 mc fee each.
#    Each arbiter independently funds the full milestone rung value (9,000 mc);
#    the k-of-n redundancy is what bounds a single arbiter's defection to 1/n.
# ---------------------------------------------------------------------------
JOB = "job-" + uuid.uuid4().hex[:8]
N, K = 3, 2
RUNGS = rung_composition(9_000, (1000, 100, 10))     # §9.6 ladder: 8x1000+9x100+10x10
FEE = 1_000
check("rung_composition(9000) sums to 9000", sum(RUNGS) == 9_000, str(RUNGS))

arbiters = [Arbiter(f"arb-{i}") for i in range(N)]
panel_pubs = {a.arbiter_id: a.public for a in arbiters}
for a in arbiters:
    a.set_panel(K, panel_pubs)

MARGIN = 60_000
milestones = [
    {"m": 1, "evidence_deadline": T0 + 100_000, "decision_deadline": T0 + 200_000},
    {"m": 2, "evidence_deadline": T0 + 400_000, "decision_deadline": T0 + 500_000},
]
expiries = {
    1: compute_deadlines(T0 + 100_000, T0 + 200_000, GRACE, MARGIN) + 30_000,
    2: compute_deadlines(T0 + 400_000, T0 + 500_000, GRACE, MARGIN) + 30_000,
}

attestations = []
for m in (1, 2):
    for a in arbiters:
        attestations.extend(a.attest_rungs(JOB, m, RUNGS, fee_mc=FEE))
print(f"job {JOB}: {len(attestations)} signed attestations "
      f"({N} arbiters x 2 milestones x ({len(RUNGS)} rungs + 1 fee))")

# Payee holds the rung output secrets; the panel's fee account holds the fee ones.
payee = EscrowPayee(client, MINT, panel_pubs)
fee_acct = EscrowPayee(client, MINT, panel_pubs)
payee_hashes = payee.generate_output_hashes(attestations)                # kinds=("rung",)
payee_hashes.update(fee_acct.generate_output_hashes(attestations, kinds=("fee",)))

payer = EscrowPayer(client, MINT, [payer_token],
                    settlement_margin_ms=MARGIN, arbiter_pubs=panel_pubs)
info = payer.fund(JOB, milestones, attestations, payee_hashes, expiries)
escrowed = sum(o["amount_mc"] for o in info.outputs)
print(f"funded: {escrowed} mc across {len(info.outputs)} outputs, "
      f"burn {info.burn_mc} mc, change {info.change_mc} mc")
check("escrow total == 60,000 mc (2 x (3x9,000 + 3x1,000))", escrowed == 60_000)

# ---------------------------------------------------------------------------
# 2. Hand FundingInfo across a process boundary as a JSON WIRE MESSAGE.
# ---------------------------------------------------------------------------
wire_bytes = canonical_json(info.to_dict())          # C01 pinned canonical JSON
received = json.loads(wire_bytes.decode("utf-8"))    # ... as if off a socket
info_rx = FundingInfo.from_dict(received)            # strict parse on the far side
check("FundingInfo survives to_dict -> canonical_json -> from_dict round trip",
      info_rx.job_id == JOB and info_rx.mint_id == MINT
      and len(info_rx.outputs) == len(info.outputs),
      f"{len(wire_bytes)} bytes on the wire")

# MANDATORY §9.3 pre-work verification, done on the WIRE-RECONSTRUCTED FundingInfo.
payee.verify_funding(info_rx, attestations)
fee_acct.verify_funding(info_rx, attestations)
check("both secret-holders verify the wire FundingInfo against signed "
      "attestations on the ledger", True)

# ---------------------------------------------------------------------------
# 3. Milestone 1 — full release by a 2-of-3 quorum (one dissenter).
# ---------------------------------------------------------------------------
clock.set(T0 + 90_000)
ev1 = {"job_id": JOB, "milestone": 1, "deliverable_sha256": "aa" * 32}
v_rel = [arbiters[0].vote(JOB, 1, ev1, "release"),
         arbiters[1].vote(JOB, 1, ev1, "release")]
v_dis = arbiters[2].vote(JOB, 1, ev1, "refund")
votes1 = v_rel + [v_dis]

try:
    arbiters[0].reveal(JOB, 1, "release", votes=[v_rel[0]])   # 1 of k=2
    check("reveal refused without quorum", False)
except QuorumNotMet as e:
    check("reveal with 1 of k=2 votes refused (QuorumNotMet)", True, str(e))

clock.set(T0 + 190_000)                                       # before decision deadline
reveals1 = [a.reveal(JOB, 1, "release", votes=v_rel) for a in arbiters]
check("all 3 arbiters reveal m1 (quorum reached)",
      all(r["quorum"] for r in reveals1))

got1 = payee.redeem(1, reveals1)
fee1 = fee_acct.redeem(1, reveals1)
b27, b3 = compute_burn(27_000, policy), compute_burn(3_000, policy)
check("m1 payee credited 27,000 mc minus one burn", got1 == 27_000 - b27, f"net {got1}")
check("m1 fee account credited 3,000 mc minus one burn", fee1 == 3_000 - b3, f"net {fee1}")

mt, _ = client.status([])
rec1 = make_dispute_record(JOB, 1, 27_000, 27_000, list(panel_pubs), ev1, mt, votes1)
for a in arbiters:
    rec1 = a.sign_dispute(rec1)
check("m1 dispute record: decision 'released', panel-signed, verifies",
      rec1["decision"] == "released" and verify_dispute(rec1, panel_pubs))

# ---------------------------------------------------------------------------
# 4. Milestone 2 — disputed, split 60/40 by quorum.
# ---------------------------------------------------------------------------
clock.set(T0 + 390_000)
ev2 = {"job_id": JOB, "milestone": 2, "deliverable_sha256": "bb" * 32,
       "dispute": "partial delivery"}
SPLIT = (3, 5)                                                # 60%
v_split = [arbiters[0].vote(JOB, 2, ev2, SPLIT),
           arbiters[1].vote(JOB, 2, ev2, SPLIT)]
v_out = arbiters[2].vote(JOB, 2, ev2, "release")             # outvoted
votes2 = v_split + [v_out]

clock.set(T0 + 490_000)
reveals2 = [a.reveal(JOB, 2, SPLIT, votes=v_split) for a in arbiters]
for r in reveals2:
    amts = sorted((e["amount_mc"] for e in r["preimages"] if e["rung"] != "fee"),
                  reverse=True)
    check(f"{r['arbiter_id']} m2 reveal == 5x1000+4x100 (5,400 mc)",
          amts == [1000] * 5 + [100] * 4)

got2 = payee.redeem(2, reveals2)
fee2 = fee_acct.redeem(2, reveals2)
b16 = compute_burn(16_200, policy)
check("m2 payee credited 16,200 mc (60%) minus one burn", got2 == 16_200 - b16, f"net {got2}")
check("m2 fees credited on a SPLIT decision too (decision-neutral)",
      fee2 == 3_000 - b3, f"net {fee2}")

mt, _ = client.status([])
rec2 = make_dispute_record(JOB, 2, 27_000, 16_200, list(panel_pubs), ev2, mt, votes2)
for a in arbiters:
    rec2 = a.sign_dispute(rec2)
check("m2 dispute record: decision 'split', panel-signed, verifies",
      rec2["decision"] == "split" and verify_dispute(rec2, panel_pubs))
print(f"  signed dispute record (m2): claimed={rec2['claimed_mc']} "
      f"released={rec2['released_mc']} decision={rec2['decision']} "
      f"arbiters={rec2['arbiter_ids']}")

# The 40% remainder refunds to the PAYER — at expiry, and not before.
try:
    payer.refund_expired(2)
    check("refund before T_2 refused", False)
except MintRejected:
    check("refund before T_2 refused by the mint (lock not expired)", True)

clock.set(expiries[2] + 1)
refund2 = payer.refund_expired(2)
b10_8 = compute_burn(10_800, policy)
check("payer refunded the 10,800 mc (40%) remainder minus burn at T_2",
      refund2 == 10_800 - b10_8, f"net {refund2}")

# ---------------------------------------------------------------------------
# 5. Conservation: every millicredit accounted for.
# ---------------------------------------------------------------------------
burns = info.burn_mc + b27 + b3 + b16 + b3 + b10_8
total = payer.balance() + payee.balance() + fee_acct.balance() + 4_000  # mallory untouched
check("balances + burns reconcile with issuance",
      total + burns == ISSUED,
      f"payer {payer.balance()} + payee {payee.balance()} + fees "
      f"{fee_acct.balance()} + mallory 4000 + burns {burns} == {ISSUED}")

# ---------------------------------------------------------------------------
# 6. PAYEE PROTECTION: the self-invented-preimage attack, caught pre-work.
# ---------------------------------------------------------------------------
print("\n--- attack: payer funds rung 2 with a self-invented preimage hash ---")
JOB2 = "job-atk-" + uuid.uuid4().hex[:8]
solo = Arbiter("arb-solo")                                   # degenerate k=1 panel
atk_atts = solo.attest_rungs(JOB2, 1, [1000, 1000, 1000])    # rungs 0,1,2
payee2 = EscrowPayee(client, MINT, {"arb-solo": solo.public})
hashes2 = payee2.generate_output_hashes(atk_atts)

T_ATK = clock() + 500_000
mallory_x = new_secret()          # mallory's OWN invented preimage (rung 2 poison)
mallory_refund = new_secret()
outputs, records = [], []
for a in atk_atts:
    key = (a["milestone"], a["arbiter_id"], a["rung"])
    poison = a["rung"] == 2
    lock_hash = sha_b64u(mallory_x) if poison else a["preimage_hash"]
    outputs.append({
        "amount_mc": a["amount_mc"], "secret_hash": hashes2[key],
        "lock": {"preimage_hash": lock_hash, "expiry": T_ATK,
                 "refund_hash": sha_b64u(mallory_refund)},
    })
    records.append({            # what mallory CLAIMS in the FundingInfo: the attested hash
        "milestone": 1, "arbiter_id": "arb-solo", "rung": a["rung"],
        "amount_mc": a["amount_mc"], "secret_hash": hashes2[key],
        "preimage_hash": a["preimage_hash"], "expiry": T_ATK,
    })
burn_atk = compute_burn(4_000, policy)
outputs.append({"amount_mc": 4_000 - 3_000 - burn_atk,
                "secret_hash": ledger_key(new_secret()), "lock": None})
client.exchange(str(uuid.uuid4()), [mallory_token], outputs)   # §3.3 real spend
info2 = FundingInfo(job_id=JOB2, mint_id=MINT, outputs=tuple(records),
                    expiries={1: T_ATK}, burn_mc=burn_atk)

try:
    payee2.verify_funding(info2, atk_atts)
    check("verify_funding catches the self-invented preimage", False)
except FundingInvalid as e:
    check("verify_funding raises FundingInvalid NAMING rung 2, before any work",
          e.rung == 2 and e.milestone == 1 and e.arbiter_id == "arb-solo", str(e))

# Load-bearing proof: a NEGLIGENT payee skips the check, does the work, and the
# arbiter's GENUINE release opens nothing — the on-ledger lock is mallory's hash.
atk_vote = solo.vote(JOB2, 1, {"work": "done"}, "release")
atk_reveal = solo.reveal(JOB2, 1, "release", votes=[atk_vote])
try:
    payee2.redeem(1, [atk_reveal], allow_unverified=True)
    check("negligent redeem should fail at the mint", False)
except MintRejected as e:
    check("without §9.3 verify, the arbiter's real release opens nothing "
          "(mint rejects) — the check is load-bearing", True, str(e)[:70])

server.stop()
print(f"\nALL {PASSED} CHECKS PASSED — real money moved on a real mint.")
