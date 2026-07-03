"""One node, black box: every CLI semantic in one story. The cold phases run
one con.py process per verb, so each step also exercises crash-and-demand
hydration from the file; the daemon phase proves the proxy path answers with
the same state and that a restart replays it. Collapses the old
test_blackbox.py (content/outbox/workspace roundtrips) and test_daemon.py's
proxy-and-restart test."""
import os, tempfile
from harness import con, converge, fleet

def test_solo_story():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "w.facts")
        # cold CLI: idempotent authorship, feed across processes
        wid = con(db, "auth.workspace.create", "acme", "1")
        m_hi = con(db, "content.message.send", wid, "general", "al", "hi", "2")
        assert con(db, "content.message.send", wid, "general", "al", "hi", "2") == m_hi, \
            "resending the same fact must return the same id"
        con(db, "content.message.send", wid, "general", "bo", "there", "3")
        converge(db, "hi\nthere", "content.message.feed", wid, "general", secs=0, phase="cold feed")
        # membership + authority: create ran the whole bootstrap DAG with an
        # ephemeral root key (then dropped), enrolling the founder as member+admin
        assert len(con(db, "auth.local_signer_secret.whoami")) == 64, "whoami must print the 32-byte pk hex"
        converge(db, "founder", "auth.user.roster", wid, secs=0, phase="founder enrolled by create")
        converge(db, 1, "auth.admin.admins", wid, secs=0, phase="founder is the bootstrap admin")
        # a scope with no workspace parks its messages
        con(db, "content.message.send", "00" * 32, "general", "al", "ghost", "6")
        converge(db, "", "content.message.feed", "00" * 32, "general", secs=0, phase="ghost workspace parks")
        # reactions live and die with their message
        con(db, "content.reaction.react", wid, m_hi, ":+1:", "7")
        converge(db, ":+1:", "content.reaction.on", wid, m_hi, secs=0, phase="reaction lands")
        con(db, "content.message_deletion.delete", wid, m_hi, "8")
        converge(db, "there", "content.message.feed", wid, "general", secs=0, phase="deletion suppresses")
        converge(db, "", "content.reaction.on", wid, m_hi, secs=0, phase="reaction dies with its message")
        # retention + outbox roundtrips
        con(db, "content.retention_policy.set", wid, "1440", "9")
        converge(db, "1440", "content.retention_policy.window", wid, secs=0, phase="retention window")
        iid = con(db, "outbox.intent.queue", "peer1", "hello", "10")
        assert con(db, "outbox.intent.pending").startswith(iid), "queued intent must be pending"
        con(db, "outbox.performed.report", iid, "11")
        converge(db, "", "outbox.intent.pending", secs=0, phase="performed clears pending")
        # daemon proxy parity, clean shutdown, restart replay
        with fleet() as f:
            f.spawn(db)
            converge(db, "there", "content.message.feed", wid, "general", secs=0, phase="proxy feed parity")
            m_warm = con(db, "content.message.send", wid, "general", "al", "warm", "12")
            assert con(db, "content.message.send", wid, "general", "al", "warm", "12") == m_warm, \
                "resend must be idempotent through the proxy too"
            f.stop(db)
            assert not os.path.exists(db + ".sock"), "clean shutdown must remove the socket"
            f.spawn(db)
            converge(db, "there\nwarm", "content.message.feed", wid, "general", secs=0, phase="restart replay")

if __name__ == "__main__":
    test_solo_story(); print("ok  test_solo_story")
