"""Black-box tests: drive bin/con.py one process per command. Every
invocation replays the dumb file, so these also exercise the crash story."""
import os, subprocess, sys, tempfile

CON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "con.py")

def con(db, *args):
    r = subprocess.run([sys.executable, CON, db, *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def test_chat_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "w.facts")
        fid = con(db, "chat.note.send", "general", "hi", "1")
        assert con(db, "chat.note.send", "general", "hi", "1") == fid   # idempotent
        con(db, "chat.note.send", "general", "there", "2")
        assert con(db, "chat.note.feed", "general") == "hi\nthere"
        con(db, "chat.tombstone.delete", "general", fid, "3")
        assert con(db, "chat.note.feed", "general") == "there"          # suppressed across processes

def test_outbox_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "w.facts")
        iid = con(db, "outbox.intent.queue", "peer1", "hello", "1")
        assert con(db, "outbox.intent.pending").startswith(iid)
        con(db, "outbox.performed.report", iid, "2")
        assert con(db, "outbox.intent.pending") == ""

if __name__ == "__main__":
    for t in (test_chat_roundtrip, test_outbox_roundtrip):
        t(); print(f"ok  {t.__name__}")
