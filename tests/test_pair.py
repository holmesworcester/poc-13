"""Two real daemons over a SEALED connection, black box through con.py. B
bootstrap-connects on A's invite link; the durable request means a restarted B
re-dials and re-handshakes deterministically, so the connection survives
restarts. One story walks every two-player semantic atop the encrypted
transport; a second proves a burst can't wedge delivery.

Phases:
  bootstrap + accept    — B dials A on the link, accepts the workspace, and
                          A's pre-authored messages sync to B over sealed frames.
  invite chain          — B joins as a member on the same link; membership
                          travels both ways and each side re-derives validity.
  reaction closure      — a reaction on A surfaces on B atop B's own copy.
  concurrent authorship — disjoint sends from both merge to one (ts, owner) feed.
  cross deletions       — each side deletes one of its own; both re-converge.
  partition and heal    — B dies; A keeps authoring; B respawns and its durable
                          request re-handshakes and converges.
  restart both          — replay restores state, the connection re-establishes,
                          and a fresh send proves sync is live again."""
import os, tempfile
from harness import con, converge, fleet, port

def _bootstrap(dba, dbb, wid, addr_a, addr_b):
    link = con(dba, "auth.user_invite.invite", wid)
    iid, secret = link.split(":")
    ep = con(dba, "auth.endpoint.endpoint")
    con(dbb, "connection.request.connect", wid, iid, secret, ep, addr_a, addr_b)
    return link

def test_pair_story():
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        A, B = port(), port()
        f.spawn(dba, "--listen", A)
        f.spawn(dbb, "--listen", B)
        wid = con(dba, "auth.workspace.create", "acme", "1")
        mids = [con(dba, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
                for i in range(3)]
        # bootstrap: B dials A on the link, accepts the workspace, and syncs
        link = _bootstrap(dba, dbb, wid, A, B)
        converge(dbb, "m0\nm1\nm2", "content.message.feed", wid, "general", phase="bootstrap sync to B")
        assert wid in con(dbb, "auth.workspace.index")
        # invite chain: B joins as a member on the same link; membership travels
        con(dbb, "auth.user.join", wid, "bo", link, "8")
        converge(dba, "founder\nbo", "auth.user.roster", wid, phase="B's membership reaches A")
        converge(dbb, "founder\nbo", "auth.user.roster", wid, phase="A's membership on B")
        # reaction closure re-derives on B
        con(dba, "content.reaction.react", wid, mids[0], ":+1:", "9")
        converge(dbb, ":+1: founder", "content.reaction.on", wid, mids[0], phase="reaction closure")
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
        # partition: mutate A while B is down, then heal — B's durable request re-handshakes
        f.stop(dbb)
        con(dba, "content.message.send", wid, "general", "al", "p1", "16")
        con(dba, "content.message_deletion.delete", wid, mids[2], "17")
        f.spawn(dbb, "--listen", B)
        healed = "m0\nm1\nb2\na2\np1"
        converge(dbb, healed, "content.message.feed", wid, "general", secs=20, phase="healed partition")
        # restart both: replay restores state, the connection re-establishes
        f.stop(dba); f.stop(dbb)
        f.spawn(dba, "--listen", A)
        f.spawn(dbb, "--listen", B)
        converge(dba, healed, "content.message.feed", wid, "general", secs=0, phase="A replay after restart")
        converge(dbb, healed, "content.message.feed", wid, "general", secs=0, phase="B replay after restart")
        con(dba, "content.message.send", wid, "general", "al", "live", "18")
        converge(dbb, healed + "\nlive", "content.message.feed", wid, "general", secs=20,
                 phase="sync live after restart")

def test_pair_burst_does_not_wedge():
    # A 100-message burst reaches B over the sealed connection, and the author
    # keeps answering queries mid-burst.
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        A, B = port(), port()
        f.spawn(dba, "--listen", A)
        f.spawn(dbb, "--listen", B)
        wid = con(dba, "auth.workspace.create", "acme", "1")
        _bootstrap(dba, dbb, wid, A, B)
        converge(dbb, lambda got: wid in got, "auth.workspace.index", secs=10, phase="connection up")
        for i in range(100):
            con(dba, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
            if i == 50:
                converge(dba, 51, "content.message.feed", wid, "general",
                         secs=0, phase="A answers mid-burst")
        converge(dba, 100, "content.message.feed", wid, "general", secs=0, phase="A holds the burst")
        converge(dbb, 100, "content.message.feed", wid, "general", secs=30,
                 phase="burst reaches B")

if __name__ == "__main__":
    for t in (test_pair_story, test_pair_burst_does_not_wedge):
        t(); print(f"ok  {t.__name__}")
