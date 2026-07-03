"""Black-box daemon tests: spawn bin/cond.py as a real subprocess, wait for
its `listening:` line, drive it through con.py's proxy path and real TCP
peering, kill it on teardown."""
import os, signal, socket, subprocess, sys, tempfile, time

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")

def spawn(db, *args):                    # -> (proc, announced addr)
    p = subprocess.Popen([sys.executable, os.path.join(BIN, "cond.py"), db, *args],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    assert line.startswith("listening:"), (line, p.poll() and p.stderr.read())
    return p, line.split()[1]

def stop(p):
    p.send_signal(signal.SIGTERM); p.wait(5)

def con(db, *args):
    r = subprocess.run([sys.executable, os.path.join(BIN, "con.py"), db, *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def until(pred, secs=10):                # poll with a deadline
    deadline = time.time() + secs
    while time.time() < deadline and not pred(): time.sleep(0.05)
    return pred()

def test_proxy_roundtrip_and_restart():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "a.facts")
        p, _ = spawn(db)
        try:
            wid = con(db, "auth.workspace.create", "acme", "1")
            fid = con(db, "content.message.send", wid, "general", "al", "hi", "2")
            assert con(db, "content.message.send", wid, "general", "al", "hi", "2") == fid  # idempotent via proxy
            assert con(db, "content.message.feed", wid, "general") == "hi"
        finally: stop(p)
        assert not os.path.exists(db + ".sock")          # clean shutdown removed the socket
        p, _ = spawn(db)                                 # restart: replay from its own file
        try: assert con(db, "content.message.feed", wid, "general") == "hi"
        finally: stop(p)

def test_two_daemons_fact_travels():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba, "--peer", addr)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            con(dba, "content.message.send", wid, "general", "al", "over the wire", "2")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "over the wire")
        finally: stop(pa); stop(pb)

def test_tombstone_travels():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba, "--peer", addr)
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            doomed = con(dba, "content.message.send", wid, "general", "al", "doomed", "2")
            con(dba, "content.message.send", wid, "general", "al", "keep", "3")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "doomed\nkeep")
            con(dba, "content.message_deletion.delete", wid, doomed, "4")
            assert until(lambda: con(dbb, "content.message.feed", wid, "general") == "keep")
        finally: stop(pa); stop(pb)

def test_slow_and_absent_peers_never_wedge():
    with tempfile.TemporaryDirectory() as d:
        slow = socket.socket(); slow.bind(("127.0.0.1", 0)); slow.listen(1)  # connects, never reads
        db = os.path.join(d, "a.facts")
        p, _ = spawn(db, "--peer", "127.0.0.1:1",        # absent: connection refused
                     "--peer", "127.0.0.1:%d" % slow.getsockname()[1])
        try:
            wid = con(db, "auth.workspace.create", "acme", "1")
            for i in range(20): con(db, "content.message.send", wid, "general", "al", "m%d" % i, str(i + 2))
            assert len(con(db, "content.message.feed", wid, "general").splitlines()) == 20
        finally: stop(p); slow.close()

if __name__ == "__main__":
    for t in (test_proxy_roundtrip_and_restart, test_two_daemons_fact_travels,
              test_tombstone_travels, test_slow_and_absent_peers_never_wedge):
        t(); print(f"ok  {t.__name__}")
