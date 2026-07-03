"""Multiplayer e2e tests: real cond daemons over TCP, driven black-box through
con.py. Ports poc-11's network scenarios to poc-13 and adds the multiplayer
cases poc-11 lacked. Every assertion is on CLI-observable state only (never
transport internals) and converges within a deadline, so the suite is robust
to sync arriving out of order or late. Peering is directional: the daemon that
--peers dials and sends; the one that --listens receives.

Scenarios:
  1 cross_node_validation  — a dependent chain (workspace<-message<-reaction)
                             authored on A re-derives valid on B; B trusts no
                             one, so the reaction surfaces only once ITS message
                             and the workspace are present too (poc-11 Test C).
  2 out_of_order_converge  — messages authored before their workspace park
                             everywhere, then all validate when the root lands
                             last (poc-11 Test D).
  3 no_resurrection        — author+delete, converge, restart BOTH daemons on
                             the same dbs/ports: the tombstone survives replay
                             and a fresh author/converge proves sync is live.
  4 partition_and_heal     — kill B, mutate A (incl. a deletion), respawn B;
                             B converges to the exact post-deletion state.
  5 bidirectional_converge — A and B dial each other; disjoint concurrent
                             authorship merges to one (ts,owner)-ordered feed on
                             both, then cross deletions re-converge.
  6 burst_stays_responsive — 100 rapid authors on A reach B within the deadline
                             while A keeps answering a feed query mid-burst.
  7 three_node_relay       — A->B->C chain: B relays A's fact to C because the
                             durable+shareable facts it holds are offered on to
                             its own peers.
"""
import os, socket, tempfile
from test_daemon import spawn, stop, con, until   # reuse the black-box idioms

def port():                              # grab an OS-assigned port, then free it
    s = socket.socket(); s.bind(("127.0.0.1", 0)); n = s.getsockname()[1]; s.close()
    return "127.0.0.1:%d" % n

def test_cross_node_validation():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba, "--peer", addr)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            mid = con(dba, "content.message.send", wid, "general", "al", "hi", "2")
            con(dba, "content.reaction.react", wid, mid, ":+1:", "3")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "hi")
            # closure: the reaction can only validate on B once B holds its
            # message AND the workspace the message requires — B re-derives all.
            assert until(lambda: con(dbb, "content.reaction.on", wid, mid) == ":+1:")
        finally: stop(pa); stop(pb)

def test_out_of_order_convergence():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        wid = con(os.path.join(d, "calc.facts"), "auth.workspace.create", "acme", "1")  # id is deterministic
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba, "--peer", addr)
        try:
            for i in range(3): con(dba, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
            assert not until(lambda: con(dbb, "content.message.feed", wid, "general"), 1)  # parked: no workspace anywhere
            assert con(dba, "auth.workspace.create", "acme", "1") == wid                    # root lands last
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "m0\nm1\nm2")
        finally: stop(pa); stop(pb)

def test_no_resurrection_across_restart():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        A, B = port(), port()
        pb, _ = spawn(dbb, "--listen", B, "--peer", A)
        pa, _ = spawn(dba, "--listen", A, "--peer", B)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            doomed = con(dba, "content.message.send", wid, "general", "al", "doomed", "2")
            con(dba, "content.message.send", wid, "general", "al", "keep", "3")
            con(dba, "content.message_deletion.delete", wid, doomed, "4")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "keep")  # sync + suppression reached B
        finally: stop(pa); stop(pb)
        pb, _ = spawn(dbb, "--listen", B, "--peer", A)       # restart both: same dbs, same peering
        pa, _ = spawn(dba, "--listen", A, "--peer", B)
        try:
            assert con(dba, "content.message.feed", wid, "general") == "keep"   # tombstone survived A's replay
            assert con(dbb, "content.message.feed", wid, "general") == "keep"   # ... and B's
            con(dba, "content.message.send", wid, "general", "al", "live", "5")  # sync is live again
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "keep\nlive")  # doomed did not resurrect
        finally: stop(pa); stop(pb)

def test_partition_and_heal():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        B = port()
        pb, _ = spawn(dbb, "--listen", B)
        pa, _ = spawn(dba, "--peer", B)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            m1 = con(dba, "content.message.send", wid, "general", "al", "one", "2")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "one")
            stop(pb)                                          # partition
            con(dba, "content.message.send", wid, "general", "al", "two", "3")
            con(dba, "content.message.send", wid, "general", "al", "three", "4")
            con(dba, "content.message_deletion.delete", wid, m1, "5")
            pb, _ = spawn(dbb, "--listen", B)                 # heal: same port, A's pump reconnects
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "two\nthree")
        finally: stop(pa); stop(pb)

def test_bidirectional_convergence():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        A, B = port(), port()
        pa, _ = spawn(dba, "--listen", A, "--peer", B)
        pb, _ = spawn(dbb, "--listen", B, "--peer", A)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            assert until(lambda: con(dbb, "auth.workspace.index").endswith("acme"))  # A->B leg is live
            ma = con(dba, "content.message.send", wid, "general", "al", "a1", "3")   # disjoint authorship,
            mb = con(dbb, "content.message.send", wid, "general", "bo", "b1", "2")   # both sides at once
            con(dba, "content.message.send", wid, "general", "al", "a2", "5")
            con(dbb, "content.message.send", wid, "general", "bo", "b2", "4")
            want = "b1\na1\nb2\na2"                            # merged, ordered by (ts, owner)
            assert until(lambda: con(dba, "content.message.feed", wid, "general") == want)
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == want)
            con(dba, "content.message_deletion.delete", wid, ma, "6")   # each side deletes one of its own
            con(dbb, "content.message_deletion.delete", wid, mb, "7")
            assert until(lambda: con(dba, "content.message.feed", wid, "general") == "b2\na2")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "b2\na2")
        finally: stop(pa); stop(pb)

def test_burst_stays_responsive():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba, "--peer", addr)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            for i in range(100):
                con(dba, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
                if i == 50: assert con(dba, "content.message.feed", wid, "general")  # A answers queries mid-burst
            assert until(lambda: len(con(dbb, "content.message.feed", wid, "general").splitlines()) == 100)
        finally: stop(pa); stop(pb)

def test_three_node_relay():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb, dbc = (os.path.join(d, x) for x in ("a.facts", "b.facts", "c.facts"))
        pc, addrc = spawn(dbc, "--listen", "127.0.0.1:0")
        pb, addrb = spawn(dbb, "--listen", "127.0.0.1:0", "--peer", addrc)   # B both receives and relays
        pa, _ = spawn(dba, "--peer", addrb)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            con(dba, "content.message.send", wid, "general", "al", "hop", "2")
            # B relays because pump offers every durable+shareable fact it holds
            # to its own peers, including the ones it just received from A. If a
            # future transport dropped transitive relay, this assertion is where
            # that gap would surface.
            assert until(lambda: con(dbc, "content.message.feed", wid, "general") == "hop")
        finally: stop(pa); stop(pb); stop(pc)

if __name__ == "__main__":
    for t in (test_cross_node_validation, test_out_of_order_convergence,
              test_no_resurrection_across_restart, test_partition_and_heal,
              test_bidirectional_convergence, test_burst_stays_responsive,
              test_three_node_relay):
        t(); print(f"ok  {t.__name__}")
