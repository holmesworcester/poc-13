"""Three real daemons in a hub over sealed connections, black box through
tiny.py: bob and carol each bootstrap-connect to alice, so every bob<->carol leg
relays through her (a node ships every durable sync-leaf owner it holds to each
of its own peers, not just its own authorship). Ports poc-10's three-daemon
late-joiner story and poc-7's offline-delta rejoin, scaled to a ~1k delta
authored over the unix socket (sock() is bench.py's uverb idiom).

Story: alice founds and invites bob -> steady pair traffic -> carol joins LATE
on a second invite and everyone converges, relayed legs included -> carol goes
offline and her file freezes -> alice and bob author the delta plus a tail
marker -> carol rejoins (her durable request re-handshakes) and catches the
whole delta -> live sends from all three still deliver everywhere."""
import os, tempfile
from harness import tiny, converge, fleet, port, sock

DELTA = 500                              # per author; the "one k" offline delta

def _join(dba, wid, addr_a, ep_a, db, addr, name, t):
    link = tiny(dba, "auth.user_invite.invite", wid)   # alice mints + retains the invite
    iid, secret = link.split(":")
    tiny(db, "connection.request.connect", wid, iid, secret, ep_a, addr_a, addr)   # bootstrap dial
    tiny(db, "auth.user.join", wid, name, link, t)  # join as a member on the same link

def test_trio_story():
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        dba, dbb, dbc = (os.path.join(d, x) for x in ("a.facts", "b.facts", "c.facts"))
        A, B, C = port(), port(), port()             # fixed ports: a rejoin reuses its address
        addr_a = f.spawn(dba, "--listen", A)
        addr_b = f.spawn(dbb, "--listen", B)
        wid = tiny(dba, "auth.workspace.create", "acme", "1")
        ep_a = tiny(dba, "auth.endpoint.endpoint")
        # bob bootstrap-connects to alice on the first invite, then joins
        _join(dba, wid, addr_a, ep_a, dbb, addr_b, "bo", "5")
        converge(dba, "founder\nbo", "auth.user.roster", wid, secs=15, phase="bob's join reaches alice")
        tiny(dba, "content.message.send", "wid="+wid, "general", "steady-al", "t=6")
        tiny(dbb, "content.message.send", "wid="+wid, "general", "steady-bo", "t=7")
        converge(dba, 2, "content.message.feed", "wid="+wid, "general", secs=15, phase="steady traffic on alice")
        converge(dbb, 2, "content.message.feed", "wid="+wid, "general", secs=15, phase="steady traffic on bob")
        # carol joins late; her chain and bob's cross-relay through alice
        addr_c = f.spawn(dbc, "--listen", C)
        _join(dba, wid, addr_a, ep_a, dbc, addr_c, "ca", "10")
        trio = ((dba, "alice"), (dbb, "bob"), (dbc, "carol"))
        for db, who in trio:
            converge(db, "founder\nbo\nca", "auth.user.roster", wid, secs=25, phase="full roster on " + who)
        tiny(dba, "content.message.send", "wid="+wid, "general", "probe-al", "t=11")
        tiny(dbb, "content.message.send", "wid="+wid, "general", "probe-bo", "t=12")
        tiny(dbc, "content.message.send", "wid="+wid, "general", "probe-ca", "t=13")
        for db, who in trio:
            converge(db, 5, "content.message.feed", "wid="+wid, "general", secs=25,
                     phase="probes relayed to " + who)
        # carol offline: pin her at the pre-offline count while still up (tiny.py no
        # longer cold-reads a stopped daemon's file), then freeze her by stopping
        converge(dbc, 5, "content.message.feed", "wid="+wid, "general", secs=0, phase="carol pinned pre-offline")
        f.stop(dbc)
        # the delta she misses: ~1k messages plus a tail marker from each author
        for i in range(DELTA):
            sock(dba, "content.message.send", "wid="+wid, "general", "d%d" % i, "t="+str(1000 + i))
        for i in range(DELTA):
            sock(dbb, "content.message.send", "wid="+wid, "general", "e%d" % i, "t="+str(2000 + i))
        sock(dba, "content.message.send", "wid="+wid, "general", "tail-al", "t=3001")
        sock(dbb, "content.message.send", "wid="+wid, "general", "tail-bo", "t=3002")
        total = 5 + 2 * DELTA + 2
        converge(dba, total, "content.message.feed", "wid="+wid, "general", secs=90,
                 phase="delta converges on alice")
        converge(dbb, total, "content.message.feed", "wid="+wid, "general", secs=90,
                 phase="delta converges on bob")
        # rejoin: carol's durable request re-handshakes and she catches the whole delta
        f.spawn(dbc, "--listen", C)
        got = converge(dbc, total, "content.message.feed", "wid="+wid, "general", secs=150,
                       phase="carol rejoin catch-up")
        assert "tail-al" in got and "tail-bo" in got, "carol caught the count but not both tails"
        # post-rejoin liveness in every direction
        tiny(dba, "content.message.send", "wid="+wid, "general", "post-al", "t=4001")
        tiny(dbb, "content.message.send", "wid="+wid, "general", "post-bo", "t=4002")
        for db, who in trio:
            converge(db, total + 2, "content.message.feed", "wid="+wid, "general", secs=40,
                     phase="post-rejoin sends reach " + who)
        tiny(dbc, "content.message.send", "wid="+wid, "general", "post-ca", "t=4003")
        converge(dba, total + 3, "content.message.feed", "wid="+wid, "general", secs=40,
                 phase="carol's send reaches alice")
        converge(dbb, total + 3, "content.message.feed", "wid="+wid, "general", secs=40,
                 phase="carol's send reaches bob")

if __name__ == "__main__":
    test_trio_story(); print("ok  test_trio_story")
