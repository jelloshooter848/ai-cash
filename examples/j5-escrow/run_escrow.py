"""JOURNEY 5 — milestone escrow (spec §9.3/§9.6), produced during a COLD
USABILITY TEST of the AICash reference implementation by an AI agent that
had never seen this repo before.

Demonstrates, against a REAL in-process HTTP mint (C06 MintServer + sqlite
Ledger + FakeClock):

  * a 2-milestone job with a 3-arbiter panel, quorum k=2, funded with
    signed rung attestations and MANDATORY §9.3 funding verification;
  * milestone 1 released in full by a 2-of-3 quorum of signed votes
    (27,000 mc rungs + 3×1,000 mc decision-neutral fees);
  * milestone 2 split 60/40 (16,200 mc to the payee via the 5×1000+4×100
    rung subsets, 10,800 mc refunded to the payer at expiry);
  * signed §10.2 dispute-outcome records for both milestones, verified;
  * PAYEE PROTECTION (B3): a payer who funds a rung with a self-invented
    preimage hash is caught by EscrowPayee.verify_funding BEFORE work
    starts, with the offending rung named — and the sandboxed "negligent
    payee" path shows the attack succeeding without the check.

Run:  PYTHONPATH=/home/lando/projects/aicash/impl python3 run_escrow.py
"""

import hashlib
import os
import sys
import tempfile
import uuid
from fractions import Fraction

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import FakeClock
from aicash.escrow import (
    Arbiter,
    EscrowPayee,
    EscrowPayer,
    FundingInfo,
    FundingInvalid,
    QuorumNotMet,
    compute_deadlines,
    make_dispute_record,
    rung_composition,
)
from aicash.ledgerstore import OutputSpec
from aicash.mintapi import Ledger, MintConfig, MintServer
from aicash.receipts import verify_dispute
from aicash.signing import generate_keypair
from aicash.tokencodec import b64u_encode, format_token, ledger_key, new_secret
from aicash.wallet import MintClient, MintRejected

PASS = 0


def check(label, cond, detail=""):
    global PASS
    status = "ok " if cond else "FAIL"
    print(f"  [{status}] {label}" + (f"  ({detail})" if detail else ""))
    if not cond:
        sys.exit(f"CHECK FAILED: {label}")
    PASS += 1


def sha_b64u(data: bytes) -> str:
    return b64u_encode(hashlib.sha256(data).digest())


# ---------------------------------------------------------------------------
# 0. A real in-process mint
# ---------------------------------------------------------------------------
T0 = 1_756_000_000_000
clock = FakeClock(T0)
policy = BurnPolicy(rate_ppm=1000, cap_mc=100, exempt_below_mc=10)
priv, pub = generate_keypair()
MINT_ID = "escrow-test-mint"
GRACE = 5_000
config = MintConfig(
    mint_id=MINT_ID,
    baseline_model_class="cold-usability-test",
    burn_policy=policy,
    signing_private=priv,
    signing_public=pub,
    grace_ms=GRACE,
)
db_path = tempfile.mktemp(suffix=".sqlite", prefix="aicash-j5-")
ledger = Ledger(
    db_path,
    clock=clock,
    burn_policy=policy,
    recovery_window_ms=7_776_000_000,
    max_lock_expiry_ms=2_592_000_000,
)
server = MintServer(config, ledger)
port = server.start()
client = MintClient(f"http://127.0.0.1:{port}")
print(f"mint '{MINT_ID}' live on 127.0.0.1:{port}, mint_time={clock()}")

# Operator-funded issuance (§7.1): 70,000 mc to the payer, 4,000 to mallory.
payer_secret = new_secret()
mallory_secret = new_secret()
ledger.issue(
    [
        OutputSpec(amount_mc=70_000, secret_hash=ledger_key(payer_secret)),
        OutputSpec(amount_mc=4_000, secret_hash=ledger_key(mallory_secret)),
    ]
)
payer_token = format_token(MINT_ID, 70_000, payer_secret)
ISSUED = 74_000

# ---------------------------------------------------------------------------
# 1. The job: 2 milestones x 27,000 mc, 3 arbiters (k=2), 1,000 mc fee each
# ---------------------------------------------------------------------------
JOB = "job-j5-" + uuid.uuid4().hex[:8]
N, K = 3, 2
RUNG_SET = rung_composition(9_000, (1000, 100, 10))  # 8x1000 + 9x100 + 10x10
FEE = 1_000

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
        attestations.extend(a.attest_rungs(JOB, m, RUNG_SET, fee_mc=FEE))
print(
    f"job {JOB}: {len(attestations)} signed attestations "
    f"({N} arbiters x 2 milestones x ({len(RUNG_SET)} rungs + 1 fee))"
)

payee = EscrowPayee(client, MINT_ID, panel_pubs)
fee_acct = EscrowPayee(client, MINT_ID, panel_pubs)  # the panel's fee account
payee_hashes = payee.generate_output_hashes(attestations)  # kinds=("rung",)
payee_hashes.update(fee_acct.generate_output_hashes(attestations, kinds=("fee",)))

payer = EscrowPayer(
    client, MINT_ID, [payer_token], settlement_margin_ms=MARGIN,
    arbiter_pubs=panel_pubs,
)
info = payer.fund(JOB, milestones, attestations, payee_hashes, expiries)
print(
    f"funded: {sum(o['amount_mc'] for o in info.outputs)} mc escrowed in "
    f"{len(info.outputs)} outputs, burn {info.burn_mc} mc, change {info.change_mc} mc"
)
check("escrow total is 60,000 mc (2 x (27,000 + 3 x 1,000))",
      sum(o["amount_mc"] for o in info.outputs) == 60_000)

# MANDATORY §9.3 pre-work verification, both secret holders.
payee.verify_funding(info, attestations)
fee_acct.verify_funding(info, attestations)
check("payee verified funding against signed attestations on the ledger", True)

# ---------------------------------------------------------------------------
# 2. Milestone 1 — full release by 2-of-3 quorum (one dissenter)
# ---------------------------------------------------------------------------
clock.set(T0 + 90_000)
evidence1 = {"job_id": JOB, "milestone": 1, "deliverable_sha256": "aa" * 32}
v_rel = [arbiters[0].vote(JOB, 1, evidence1, "release"),
         arbiters[1].vote(JOB, 1, evidence1, "release")]
v_dis = arbiters[2].vote(JOB, 1, evidence1, "refund")
votes1 = v_rel + [v_dis]

# Quorum is enforced: one vote is not enough.
try:
    arbiters[0].reveal(JOB, 1, "release", votes=[v_rel[0]])
    check("reveal with 1 of k=2 votes refused", False)
except QuorumNotMet as e:
    check("reveal with 1 of k=2 votes refused (QuorumNotMet)", True, str(e))

clock.set(T0 + 190_000)  # decision rendered before decision_deadline
reveals1 = [a.reveal(JOB, 1, "release", votes=v_rel) for a in arbiters]
check("all 3 arbiters reveal m1 (dissenter too — quorum reached)",
      all(r["quorum"] for r in reveals1))

got1 = payee.redeem(1, reveals1)
fee1 = fee_acct.redeem(1, reveals1)
burn_27k = compute_burn(27_000, policy)
burn_3k = compute_burn(3_000, policy)
check("m1 payee redeemed 27,000 mc minus burn", got1 == 27_000 - burn_27k,
      f"net {got1}")
check("m1 fee account redeemed 3,000 mc minus burn", fee1 == 3_000 - burn_3k,
      f"net {fee1}")

mint_time, _ = client.status([])
rec1 = make_dispute_record(JOB, 1, 27_000, 27_000, list(panel_pubs), evidence1,
                           mint_time, votes1)
for a in arbiters:
    rec1 = a.sign_dispute(rec1)
check("m1 dispute record decision == 'released', arbiter-signed, verifies",
      rec1["decision"] == "released" and verify_dispute(rec1, panel_pubs))

# ---------------------------------------------------------------------------
# 3. Milestone 2 — disputed, split 60/40 by quorum
# ---------------------------------------------------------------------------
clock.set(T0 + 390_000)
evidence2 = {"job_id": JOB, "milestone": 2, "deliverable_sha256": "bb" * 32,
             "dispute": "partial delivery"}
SPLIT = (3, 5)  # 60%
v_split = [arbiters[0].vote(JOB, 2, evidence2, SPLIT),
           arbiters[1].vote(JOB, 2, evidence2, SPLIT)]
v_full = arbiters[2].vote(JOB, 2, evidence2, "release")  # outvoted
votes2 = v_split + [v_full]

clock.set(T0 + 490_000)
reveals2 = [a.reveal(JOB, 2, SPLIT, votes=v_split) for a in arbiters]
for r in reveals2:
    rungs = [e for e in r["preimages"] if e["rung"] != "fee"]
    amts = sorted((e["amount_mc"] for e in rungs), reverse=True)
    check(f"{r['arbiter_id']} m2 reveal is exactly 5x1000+4x100 (5,400 mc)",
          amts == [1000] * 5 + [100] * 4)

got2 = payee.redeem(2, reveals2)
fee2 = fee_acct.redeem(2, reveals2)
burn_16k = compute_burn(16_200, policy)
check("m2 payee redeemed 16,200 mc (60%) minus burn", got2 == 16_200 - burn_16k,
      f"net {got2}")
check("m2 fees redeemed on a SPLIT decision too (decision-neutral)",
      fee2 == 3_000 - burn_3k, f"net {fee2}")

mint_time, _ = client.status([])
rec2 = make_dispute_record(JOB, 2, 27_000, 16_200, list(panel_pubs), evidence2,
                           mint_time, votes2)
for a in arbiters:
    rec2 = a.sign_dispute(rec2)
check("m2 dispute record decision == 'split', all-arbiter-signed, verifies",
      rec2["decision"] == "split" and verify_dispute(rec2, panel_pubs))
print(f"  signed dispute-outcome record (m2): claimed={rec2['claimed_mc']}"
      f" released={rec2['released_mc']} decision={rec2['decision']}"
      f" arbiters={rec2['arbiter_ids']} sigs={sorted(rec2['signatures'])}")

# The 40% remainder refunds to the payer at expiry — and not before.
try:
    payer.refund_expired(2)
    early_refund_net = None
except MintRejected as e:
    early_refund_net = "rejected"
check("refund before T_2 is refused by the mint", early_refund_net == "rejected")

clock.set(expiries[2] + 1)
refund2 = payer.refund_expired(2)
burn_10k8 = compute_burn(10_800, policy)
check("payer refunded the 10,800 mc remainder (40%) minus burn at T_2",
      refund2 == 10_800 - burn_10k8, f"net {refund2}")

# ---------------------------------------------------------------------------
# 4. Conservation: every millicredit is accounted for
# ---------------------------------------------------------------------------
burns = (info.burn_mc + burn_27k + burn_3k + burn_16k + burn_3k + burn_10k8)
total = (payer.balance() + payee.balance() + fee_acct.balance()) + 4_000  # mallory's, so far untouched
check("balances + burns reconcile with issuance",
      total + burns == ISSUED,
      f"payer {payer.balance()} + payee {payee.balance()} + fees "
      f"{fee_acct.balance()} + mallory 4000 + burns {burns} == {ISSUED}")

# ---------------------------------------------------------------------------
# 5. PAYEE PROTECTION (B3): self-invented-preimage attack, caught pre-work
# ---------------------------------------------------------------------------
print("\n--- attack demo: payer funds rung 2 with a self-invented preimage ---")
JOB2 = "job-atk-" + uuid.uuid4().hex[:8]
solo = Arbiter("arb-solo")  # k=1, n=1 degenerate panel
atk_atts = solo.attest_rungs(JOB2, 1, [1000, 1000, 1000])
payee2 = EscrowPayee(client, MINT_ID, {"arb-solo": solo.public})
hashes2 = payee2.generate_output_hashes(atk_atts)

T_ATK = expiries[2] + 200_000
mallory_preimage = new_secret()          # the payer's OWN invention
mallory_refund = new_secret()
outputs2, records2 = [], []
for a in atk_atts:
    key = (a["milestone"], a["arbiter_id"], a["rung"])
    # rung 2 is poisoned: locked to sha256(mallory's preimage), not the attested hash
    lock_hash = sha_b64u(mallory_preimage) if a["rung"] == 2 else a["preimage_hash"]
    outputs2.append({
        "amount_mc": a["amount_mc"],
        "secret_hash": hashes2[key],
        "lock": {"preimage_hash": lock_hash, "expiry": T_ATK,
                 "refund_hash": sha_b64u(mallory_refund)},
    })
    records2.append({  # what mallory CLAIMS in the FundingInfo: the attested hash
        "milestone": 1, "arbiter_id": "arb-solo", "rung": a["rung"],
        "amount_mc": a["amount_mc"], "secret_hash": hashes2[key],
        "preimage_hash": a["preimage_hash"], "expiry": T_ATK,
    })
burn_atk = compute_burn(4_000, policy)
outputs2.append({"amount_mc": 4_000 - 3_000 - burn_atk,
                 "secret_hash": ledger_key(new_secret()), "lock": None})
client.exchange(str(uuid.uuid4()),
                [format_token(MINT_ID, 4_000, mallory_secret)], outputs2)
info2 = FundingInfo(job_id=JOB2, mint_id=MINT_ID, outputs=tuple(records2),
                    expiries={1: T_ATK}, burn_mc=burn_atk)

try:
    payee2.verify_funding(info2, atk_atts)
    check("verify_funding catches the self-invented preimage", False)
except FundingInvalid as e:
    check("verify_funding raises FundingInvalid NAMING rung 2, before any work",
          e.rung == 2 and e.milestone == 1 and e.arbiter_id == "arb-solo",
          str(e))

# Sandboxed demonstration that the check is load-bearing: a NEGLIGENT payee
# skips verification, does the work, and the arbiter's genuine release opens
# nothing — the mint rejects the redemption, and mallory refunds after expiry.
atk_vote = solo.vote(JOB2, 1, {"work": "done"}, "release")
atk_reveal = solo.reveal(JOB2, 1, "release", votes=[atk_vote])
try:
    payee2.redeem(1, [atk_reveal], allow_unverified=True)
    check("negligent redeem fails at the mint", False)
except MintRejected as e:
    check("negligent payee's redemption REJECTED by the mint "
          "(arbiter's release opens nothing)", True, str(e)[:100])

clock.set(T_ATK + 1)
refund_inputs = [{"hash": r["secret_hash"], "witness": b64u_encode(mallory_refund)}
                 for r in records2]
back = 3_000 - compute_burn(3_000, policy)
client.exchange(str(uuid.uuid4()), refund_inputs,
                [{"amount_mc": back, "secret_hash": ledger_key(new_secret()),
                  "lock": None}])
check("without the §9.3 check, mallory achieves refund-after-delivery "
      f"({back} mc back, worker unpaid) — the check is load-bearing", True)

server.stop()
try:
    os.unlink(db_path)
except OSError:
    pass
print(f"\nALL {PASS} CHECKS PASSED — real money moved on a real mint.")
