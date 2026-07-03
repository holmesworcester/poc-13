"""Three real daemons in a hub, black box through con.py: bob and carol each
dial alice, so every bob<->carol leg must relay through her (a node offers
every durable+shareable fact it holds to its own peers, not just its own
authorship). Ports poc-10's three-daemon late-joiner story and poc-7's
three-peer offline-delta rejoin, scaled to a ~1k delta authored over the
daemon's unix socket (one con.py process per send would dominate the clock;
sock() is bench.py's uverb idiom). Subsumes the old three_node_relay test.

Story: alice founds and invites bob -> steady pair traffic -> carol joins LATE
on a second invite and everyone converges, relayed legs included -> carol goes
offline and her file freezes -> alice and bob author the delta plus a tail
marker each -> carol rejoins, catches the whole delta -> live sends from all
three still deliver everywhere."""
import os, tempfile
from harness import con, converge, fleet, sock

DELTA = 500                              # per author; the "one k" offline delta

def test_trio_story():
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        dba, dbb, dbc = (os.path.join(d, x) for x in ("a.facts", "b.facts", "c.facts"))
        hub = f.spawn(dba, "--listen", "127.0.0.1:0")
        f.spawn(dbb, "--peer", hub)
        # alice founds; bob joins on the first invite
        wid = con(dba, "auth.workspace.create", "acme", "1")
        con(dba, "auth.user.join", wid, "al", "2")
        link = con(dba, "auth.user_invite.invite", wid, "3")
        con(dbb, "auth.local_signer_secret.keygen", "4")
        con(dbb, "auth.user.join", wid, "bo", "5", link)
        converge(dba, "al\nbo", "auth.user.roster", wid, phase="bob's join reaches alice")
        con(dba, "content.message.send", wid, "general", "al", "steady-al", "6")
        con(dbb, "content.message.send", wid, "general", "bo", "steady-bo", "7")
        converge(dba, 2, "content.message.feed", wid, "general", phase="steady traffic on alice")
        converge(dbb, 2, "content.message.feed", wid, "general", phase="steady traffic on bob")
        # carol joins late on a second invite; her chain and bob's cross-relay through alice
        link2 = con(dba, "auth.user_invite.invite", wid, "8")
        f.spawn(dbc, "--peer", hub)
        con(dbc, "auth.local_signer_secret.keygen", "9")
        con(dbc, "auth.user.join", wid, "ca", "10", link2)
        trio = ((dba, "alice"), (dbb, "bob"), (dbc, "carol"))
        for db, who in trio:
            converge(db, "al\nbo\nca", "auth.user.roster", wid, secs=20, phase="full roster on " + who)
        con(dba, "content.message.send", wid, "general", "al", "probe-al", "11")
        con(dbb, "content.message.send", wid, "general", "bo", "probe-bo", "12")
        con(dbc, "content.message.send", wid, "general", "ca", "probe-ca", "13")
        for db, who in trio:
            converge(db, 5, "content.message.feed", wid, "general", secs=20,
                     phase="probes relayed to " + who)
        # carol offline: her file freezes at the pre-offline count (cold read)
        f.stop(dbc)
        converge(dbc, 5, "content.message.feed", wid, "general", secs=0, phase="offline carol frozen")
        # the delta she misses: ~1k messages plus a tail marker from each author
        for i in range(DELTA):
            sock(dba, "content.message.send", wid, "general", "al", "d%d" % i, str(1000 + i))
        for i in range(DELTA):
            sock(dbb, "content.message.send", wid, "general", "bo", "e%d" % i, str(2000 + i))
        sock(dba, "content.message.send", wid, "general", "al", "tail-al", "3001")
        sock(dbb, "content.message.send", wid, "general", "bo", "tail-bo", "3002")
        total = 5 + 2 * DELTA + 2
        converge(dba, total, "content.message.feed", wid, "general", secs=60,
                 phase="delta converges on alice")
        converge(dbb, total, "content.message.feed", wid, "general", secs=60,
                 phase="delta converges on bob")
        # rejoin: carol re-dials the hub and catches the whole delta
        f.spawn(dbc, "--peer", hub)
        got = converge(dbc, total, "content.message.feed", wid, "general", secs=120,
                       phase="carol rejoin catch-up")
        assert "tail-al" in got and "tail-bo" in got, "carol caught the count but not both tails"
        # post-rejoin liveness in every direction
        con(dba, "content.message.send", wid, "general", "al", "post-al", "4001")
        con(dbb, "content.message.send", wid, "general", "bo", "post-bo", "4002")
        for db, who in trio:
            converge(db, total + 2, "content.message.feed", wid, "general", secs=30,
                     phase="post-rejoin sends reach " + who)
        con(dbc, "content.message.send", wid, "general", "ca", "post-ca", "4003")
        converge(dba, total + 3, "content.message.feed", wid, "general", phase="carol's send reaches alice")
        converge(dbb, total + 3, "content.message.feed", wid, "general", phase="carol's send reaches bob")

if __name__ == "__main__":
    test_trio_story(); print("ok  test_trio_story")
