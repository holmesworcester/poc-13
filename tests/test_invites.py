"""Invite-chain tests: authority binding, not just a signature. The gate proves
SOME key signed a fact; these prove the signer key is the one the chain blessed.

In-process: the happy chain (founder -> invite -> member) validates; a member
signed by a RANDOM key is Invalid (a real refusal, not Parked, not Valid); the
whole chain converges to bit-identical state under every admission order. Black
box: two real daemons — A creates + invites, B joins on the printed link with
its OWN local key, and the membership travels both ways so each roster shows it,
each side re-deriving validity itself."""
import os, random, signal, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ed25519 as e
from kernel import Node, encode, fact_id
from facts import ROOT
from facts.auth import user as usermod
from facts.auth.founder import founder
from facts.auth.workspace import workspace
from facts.auth.user_invite import user_invite
from facts.auth.user import user
from facts.auth.signature import signature

WS = workspace(b"acme", 1)
WID = fact_id(WS)
FSK, FPK = e.keygen()                                 # the founder's key: root of WID

def _sig(sk, pk, target, t): return signature(WID, pk, target, e.sign(sk, target), t)

def _chain(name, member_pk, member_sk):
    """Every fact in a member's authority chain, plus the id we expect Valid."""
    fo = founder(WID, FPK, 2); fid = fact_id(fo)
    isk, ipk = e.keygen()                             # the invite keypair; isk is the link secret
    inv = user_invite(WID, ipk, 3); iid = fact_id(inv)
    u = user(WID, name, member_pk, iid, 4); uid = fact_id(u)
    facts = [WS, fo, _sig(FSK, FPK, fid, 2),          # founder roots FPK
             inv, _sig(FSK, FPK, iid, 3),             # founder blesses the invite key
             u, _sig(isk, ipk, uid, 4)]               # member fact signed BY the invite key
    return facts, uid, (isk, ipk)

def _drain(facts):
    n = Node(ROOT)
    for f in facts: n.admit(encode(f))
    return n.run()

def test_happy_chain_validates():
    msk, mpk = e.keygen()
    facts, uid, _ = _chain(b"bo", mpk, msk)
    n = _drain(facts)
    assert n.memo[uid] == "Valid"
    assert usermod.roster(n, WID) == [b"bo"]

def test_random_key_is_invalid_not_parked():
    msk, mpk = e.keygen()
    facts, uid, (isk, ipk) = _chain(b"bo", mpk, msk)
    rsk, rpk = e.keygen()                             # a key the invite never blessed
    forged = user(WID, b"mallory", rpk, fact_id(facts[3]), 5); fuid = fact_id(forged)
    facts = facts[:-2] + [forged, _sig(rsk, rpk, fuid, 5)]   # same invite, wrong signer
    n = _drain(facts)
    assert n.memo[fuid] == "Invalid"                 # the signature landed (not Parked) but is not blessed
    assert usermod.roster(n, WID) == []

def test_converges_under_every_order():
    msk, mpk = e.keygen()
    facts, uid, _ = _chain(b"bo", mpk, msk)
    baseline = _drain(facts).derived()
    for _ in range(40):                               # sample admission orders; all must agree
        order = facts[:]; random.shuffle(order)
        n = _drain(order)
        assert n.memo[uid] == "Valid"
        assert n.derived() == baseline                # bit-identical derived state, order-independent

# --- Black box: two real daemons ------------------------------------------------
BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")

def _spawn(db, *args):
    p = subprocess.Popen([sys.executable, os.path.join(BIN, "cond.py"), db, *args],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    assert line.startswith("listening:"), (line, p.poll() and p.stderr.read())
    return p, line.split()[1]

def _stop(p): p.send_signal(signal.SIGTERM); p.wait(5)

def _con(db, *args):
    r = subprocess.run([sys.executable, os.path.join(BIN, "con.py"), db, *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def _until(pred, secs=15):
    deadline = time.time() + secs
    while time.time() < deadline and not pred(): time.sleep(0.05)
    return pred()

def test_two_daemons_invite_join_travels_both_ways():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = _spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = _spawn(dba, "--peer", addr)
        try:
            wid = _con(dba, "auth.workspace.create", "acme", "1")   # A founds it (A's key is root)
            _con(dba, "auth.user.join", wid, "al", "2")             # founder self-joins
            link = _con(dba, "auth.user_invite.invite", wid, "3")   # prints "invite_id:secret"
            assert ":" in link
            _con(dbb, "auth.local_signer_secret.keygen", "10")      # B has its OWN identity
            _con(dbb, "auth.user.join", wid, "bo", "11", link)      # B joins on the invite
            # The chain syncs both ways; each side re-derives membership itself.
            assert _until(lambda: set(_con(dbb, "auth.user.roster", wid).split()) == {"al", "bo"})
            assert _until(lambda: set(_con(dba, "auth.user.roster", wid).split()) == {"al", "bo"})
        finally: _stop(pa); _stop(pb)

if __name__ == "__main__":
    for t in (test_happy_chain_validates, test_random_key_is_invalid_not_parked,
              test_converges_under_every_order, test_two_daemons_invite_join_travels_both_ways):
        t(); print(f"ok  {t.__name__}")
    print("\nall invite-chain tests passed")
