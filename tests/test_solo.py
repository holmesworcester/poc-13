"""One daemon, black box: every solo CLI semantic in one story. con.py only
proxies now, so a real cond.py owns the db for the whole run and every verb goes
down the socket; the restart phase proves the daemon flushes durable facts and a
fresh daemon replays them from the file. Collapses the old test_blackbox.py
(content/outbox/workspace roundtrips) and test_daemon.py's proxy-and-restart
test."""
import os, subprocess, sys, tempfile
from harness import BIN, con, converge, fleet

def test_solo_story():
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        db = os.path.join(d, "w.facts")
        f.spawn(db)
        # workspace bootstrap authors a real replicated #general channel
        wid = con(db, "auth.workspace.create", "acme", "1")
        general = con(db, "content.channel.id", wid, "general")
        assert len(general) == 64
        random = con(db, "content.channel.create", wid, "random", "2")
        listing = con(db, "content.channel.list", wid).splitlines()
        assert listing == [f"{general} general", f"{random} random"]
        # idempotent authorship and channel-isolated feeds through the proxy
        m_hi = con(db, "content.message.send", wid, "general", "al", "hi", "2")
        assert con(db, "content.message.send", wid, "general", "al", "hi", "2") == m_hi, \
            "resending the same fact must return the same id"
        con(db, "content.message.send", wid, "general", "bo", "there", "3")
        con(db, "content.message.send", wid, "random", "al", "elsewhere", "4")
        converge(db, "hi\nthere", "content.message.feed", wid, "general", secs=0, phase="feed")
        converge(db, "elsewhere", "content.message.feed", wid, random, secs=0,
                 phase="separate channel feed by id")
        # membership + authority: create ran the whole bootstrap DAG with an
        # ephemeral root key (then dropped), enrolling the founder as member+admin
        assert len(con(db, "auth.local_signer_secret.whoami")) == 64, "whoami must print the 32-byte pk hex"
        converge(db, "founder", "auth.user.roster", wid, secs=0, phase="founder enrolled by create")
        converge(db, 1, "auth.admin.admins", wid, secs=0, phase="founder is the bootstrap admin")
        # signed content: a workspace this node is no member of refuses the send
        # client-side (it used to admit and park — authorship now needs membership)
        ghost = "00" * 32
        r = subprocess.run([sys.executable, os.path.join(BIN, "con.py"), db,
                            "content.message.send", ghost, ghost, "al", "ghost", "6"],
                           capture_output=True, text=True)
        assert r.returncode != 0 and "local signer is not a workspace member" in r.stderr
        # reactions live and die with their message
        con(db, "content.reaction.react", wid, m_hi, ":+1:", "7")
        converge(db, ":+1: founder", "content.reaction.on", wid, m_hi, secs=0, phase="reaction lands")
        con(db, "content.message_deletion.delete", wid, m_hi, "8")
        converge(db, "there", "content.message.feed", wid, "general", secs=0, phase="deletion suppresses")
        converge(db, "", "content.reaction.on", wid, m_hi, secs=0, phase="reaction dies with its message")
        # retention roundtrip (outbox sends are volatile: exercised in the daemon pair/trio tests)
        con(db, "content.retention_policy.set", wid, "1440", "9")
        converge(db, "1440", "content.retention_policy.window", wid, secs=0, phase="retention window")
        # a fresh send lands and is idempotent through the proxy too
        m_warm = con(db, "content.message.send", wid, "general", "al", "warm", "12")
        assert con(db, "content.message.send", wid, "general", "al", "warm", "12") == m_warm, \
            "resend must be idempotent through the proxy too"
        converge(db, "there\nwarm", "content.message.feed", wid, "general", secs=0, phase="live feed before restart")
        # clean shutdown removes the socket; a fresh daemon replays the flushed file
        f.stop(db)
        assert not os.path.exists(db + ".sock"), "clean shutdown must remove the socket"
        f.spawn(db)
        converge(db, "there\nwarm", "content.message.feed", wid, "general", secs=0, phase="restart replay")

if __name__ == "__main__":
    test_solo_story(); print("ok  test_solo_story")
