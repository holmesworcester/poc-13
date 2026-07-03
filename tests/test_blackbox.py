"""Black-box tests: drive bin/con.py one process per command. Every
invocation hydrates from the db on demand, so these also exercise the
crash-and-demand story."""
import os, subprocess, sys, tempfile

CON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "con.py")

def con(db, *args):
    r = subprocess.run([sys.executable, CON, db, *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def test_content_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "w.facts")
        wid = con(db, "auth.workspace.create", "acme", "1")
        fid = con(db, "content.message.send", wid, "general", "al", "hi", "2")
        assert con(db, "content.message.send", wid, "general", "al", "hi", "2") == fid  # idempotent
        con(db, "content.message.send", wid, "general", "bo", "there", "3")
        assert con(db, "content.message.feed", wid, "general") == "hi\nthere"
        con(db, "content.message_deletion.delete", wid, fid, "4")
        assert con(db, "content.message.feed", wid, "general") == "there"   # suppressed across processes

def test_outbox_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "w.facts")
        iid = con(db, "outbox.intent.queue", "peer1", "hello", "1")
        assert con(db, "outbox.intent.pending").startswith(iid)
        con(db, "outbox.performed.report", iid, "2")
        assert con(db, "outbox.intent.pending") == ""

def test_workspace_story():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "w.facts")
        wid = con(db, "auth.workspace.create", "acme", "1")
        con(db, "content.message.send", "00" * 32, "general", "al", "ghost", "2")
        assert con(db, "content.message.feed", "00" * 32, "general") == ""  # no workspace: parked
        uid = con(db, "auth.user.join", wid, "al", "pk-al", "3")
        assert con(db, "auth.user.roster", wid) == "al"
        con(db, "auth.admin.grant", wid, uid, "4")
        assert con(db, "auth.admin.admins", wid) == uid
        mid = con(db, "content.message.send", wid, "general", "al", "hi", "5")
        con(db, "content.reaction.react", wid, mid, ":+1:", "6")
        assert con(db, "content.reaction.on", wid, mid) == ":+1:"
        con(db, "content.message_deletion.delete", wid, mid, "7")
        assert con(db, "content.message.feed", wid, "general") == ""        # feed drops it
        assert con(db, "content.reaction.on", wid, mid) == ""               # reaction died with it
        con(db, "content.retention_policy.set", wid, "1440", "8")
        assert con(db, "content.retention_policy.window", wid) == "1440"

if __name__ == "__main__":
    for t in (test_content_roundtrip, test_outbox_roundtrip, test_workspace_story):
        t(); print(f"ok  {t.__name__}")
