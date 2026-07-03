"""Two real daemons dialing each other, black box through con.py. One story
walks every two-player semantic in an order where each phase builds on already-
converged state; a second test proves bad peers can't wedge delivery. Collapses
the old test_multiplayer.py (cross-node validation, out-of-order convergence,
no resurrection, partition and heal, bidirectional convergence, burst) plus
test_daemon.py's travel/tombstone/wedge tests and test_invites.py's black box.

Phases of the story:
  parked without root   — messages authored before their workspace park on
                          BOTH nodes, then all validate when the root lands
                          last (dependency-aware sync, out-of-order safe).
  invite chain          — A founds and invites; B joins with its own key on
                          the printed link; membership travels both ways and
                          each side re-derives validity itself.
  reaction closure      — a reaction authored on A surfaces on B only atop
                          B's own copy of the message and workspace.
  concurrent authorship — disjoint sends from both sides merge to one
                          (ts, owner)-ordered feed on both.
  cross deletions       — each side deletes one of its own; both re-converge.
  partition and heal    — B dies; A keeps authoring (incl. a deletion); B
                          respawns on the same port and converges exactly.
  restart both          — replay alone restores state (nothing resurrects),
                          then a fresh send proves sync is live again."""
import os, socket, tempfile
from harness import con, converge, fleet, never, port

def test_pair_story():
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        A, B = port(), port()
        f.spawn(dba, "--listen", A, "--peer", B)
        f.spawn(dbb, "--listen", B, "--peer", A)
        # parked without root: the workspace id is deterministic (name + ts)
        wid = con(os.path.join(d, "scratch.facts"), "auth.workspace.create", "acme", "1")
        mids = [con(dba, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
                for i in range(3)]
        never(dbb, lambda got: got != "", "content.message.feed", wid, "general",
              secs=1, phase="parked without root")
        assert con(dba, "auth.workspace.create", "acme", "1") == wid
        converge(dbb, "m0\nm1\nm2", "content.message.feed", wid, "general", phase="root landed last")
        # invite chain travels both ways
        con(dba, "auth.user.join", wid, "al", "5")
        link = con(dba, "auth.user_invite.invite", wid, "6")
        con(dbb, "auth.local_signer_secret.keygen", "7")
        con(dbb, "auth.user.join", wid, "bo", "8", link)
        converge(dba, "al\nbo", "auth.user.roster", wid, phase="B's membership reaches A")
        converge(dbb, "al\nbo", "auth.user.roster", wid, phase="A's membership reaches B")
        # reaction closure re-derives on B
        con(dba, "content.reaction.react", wid, mids[0], ":+1:", "9")
        converge(dbb, ":+1:", "content.reaction.on", wid, mids[0], phase="reaction closure")
        # concurrent disjoint authorship merges to one (ts, owner) feed
        b1 = con(dbb, "content.message.send", wid, "general", "bo", "b1", "10")
        a1 = con(dba, "content.message.send", wid, "general", "al", "a1", "11")
        con(dbb, "content.message.send", wid, "general", "bo", "b2", "12")
        con(dba, "content.message.send", wid, "general", "al", "a2", "13")
        merged = "m0\nm1\nm2\nb1\na1\nb2\na2"
        converge(dba, merged, "content.message.feed", wid, "general", phase="merged feed on A")
        converge(dbb, merged, "content.message.feed", wid, "general", phase="merged feed on B")
        # cross deletions travel
        con(dba, "content.message_deletion.delete", wid, a1, "14")
        con(dbb, "content.message_deletion.delete", wid, b1, "15")
        pruned = "m0\nm1\nm2\nb2\na2"
        converge(dba, pruned, "content.message.feed", wid, "general", phase="cross deletions on A")
        converge(dbb, pruned, "content.message.feed", wid, "general", phase="cross deletions on B")
        # partition: mutate A (including a deletion) while B is down, then heal
        f.stop(dbb)
        con(dba, "content.message.send", wid, "general", "al", "p1", "16")
        con(dba, "content.message_deletion.delete", wid, mids[2], "17")
        f.spawn(dbb, "--listen", B, "--peer", A)
        healed = "m0\nm1\nb2\na2\np1"
        converge(dbb, healed, "content.message.feed", wid, "general", phase="healed partition")
        # restart both: replay restores state, nothing resurrects, sync is live
        f.stop(dba); f.stop(dbb)
        f.spawn(dba, "--listen", A, "--peer", B)
        f.spawn(dbb, "--listen", B, "--peer", A)
        converge(dba, healed, "content.message.feed", wid, "general", secs=0, phase="A replay after restart")
        converge(dbb, healed, "content.message.feed", wid, "general", secs=0, phase="B replay after restart")
        con(dba, "content.message.send", wid, "general", "al", "live", "18")
        converge(dbb, healed + "\nlive", "content.message.feed", wid, "general",
                 phase="sync live after restart")

def test_pair_never_wedges():
    # An absent peer (connection refused) and a connected-but-never-reading
    # peer must not stop a 100-message burst from reaching the one real peer,
    # nor stop the author from answering queries mid-burst.
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        slow = socket.socket(); slow.bind(("127.0.0.1", 0)); slow.listen(1)
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        addr = f.spawn(dbb, "--listen", "127.0.0.1:0")
        f.spawn(dba, "--peer", "127.0.0.1:1",
                "--peer", "127.0.0.1:%d" % slow.getsockname()[1], "--peer", addr)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            for i in range(100):
                con(dba, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
                if i == 50:
                    converge(dba, 51, "content.message.feed", wid, "general",
                             secs=0, phase="A answers mid-burst")
            converge(dba, 100, "content.message.feed", wid, "general", secs=0, phase="A holds the burst")
            converge(dbb, 100, "content.message.feed", wid, "general", secs=30,
                     phase="burst reaches B past two bad peers")
        finally: slow.close()

if __name__ == "__main__":
    for t in (test_pair_story, test_pair_never_wedges):
        t(); print(f"ok  {t.__name__}")
