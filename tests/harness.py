"""tests/harness.py — shared black-box idioms with self-describing failures.

spawn/stop/con drive real cond.py/con.py subprocesses; sock() sends one framed
verb straight down a daemon's unix socket (con.py semantics without a process
per call — for bulk authoring, same precedent as bench.py's uverb). The story
tests are only acceptable because failures self-describe: converge() names the
phase, the node, what was expected and what was last observed; fleet() tracks
every spawned daemon and appends each one's stderr tail to any failure."""
import os, random, signal, socket, subprocess, sys, tempfile, time
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, ROOT)
from kernel import Node, Store, frame, _rd

def reboot(node, seed=0):
    """The crash story: flush the node's durable set to a store (shuffled —
    db row order must not matter), then a fresh node over that store boots
    by ONE total hydrate fact. There is no load and no replay to call."""
    from facts.store import hydrate
    s = Store()
    bs = list(node.durable.values()); random.Random(seed).shuffle(bs)
    for b in bs: s.add(b)
    m = Node(node.root, s)
    hydrate.demand(m)
    return m

def spawn(db, *args):                    # -> (proc, announced addr)
    p = subprocess.Popen([sys.executable, os.path.join(BIN, "cond.py"), db, *args],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    assert line.startswith("listening:"), (line, p.poll() and p.stderr.read())
    return p, line.split()[1]

def stop(p):
    try: p.send_signal(signal.SIGTERM); p.wait(5)
    except ProcessLookupError: pass
    except subprocess.TimeoutExpired: p.kill(); p.wait(5)

def con(db, *args):                      # one con.py process: proxy if a daemon holds the db, else cold
    r = subprocess.run([sys.executable, os.path.join(BIN, "con.py"), db, *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def sock(db, *args):                     # one framed verb over the daemon's unix socket
    s = socket.socket(socket.AF_UNIX); s.connect(db + ".sock")
    s.sendall(frame(args[0].encode(), *(a.encode() for a in args[1:])))
    s.shutdown(socket.SHUT_WR)
    b = b""
    while (c := s.recv(65536)): b += c
    s.close(); r, _ = _rd(b, 0)
    if not r.startswith(b"+"): raise RuntimeError(r[1:].decode())
    return r[1:].decode()

def until(pred, secs=10):                # poll with a deadline
    deadline = time.time() + secs
    while time.time() < deadline and not pred(): time.sleep(0.05)
    return pred()

def port():                              # grab an OS-assigned port, then free it
    s = socket.socket(); s.bind(("127.0.0.1", 0)); n = s.getsockname()[1]; s.close()
    return "127.0.0.1:%d" % n

# --- self-describing assertions -----------------------------------------------
def converge(db, want, *verb, secs=10, phase=""):
    """Poll `con(db, *verb)` until the output satisfies want; return the output.
    want: exact string | int (exact line count, "" = 0 lines) | predicate.
    secs=0 asserts a single immediate read. On timeout the error names the
    phase, the node, the verb, the expectation, and the last observed output."""
    deadline = time.time() + secs
    while True:
        got = con(db, *verb)
        if _ok(got, want): return got
        if time.time() >= deadline: break
        time.sleep(0.05)
    raise AssertionError("%s: %s never showed %s via `%s`; last saw %s after %gs"
                         % (phase or "converge", os.path.basename(db), _want(want),
                            " ".join(verb), _got(got), secs))

def never(db, bad, *verb, secs=1, phase=""):
    """Assert `con(db, *verb)` does NOT satisfy bad at any point within secs."""
    deadline = time.time() + secs
    while time.time() < deadline:
        got = con(db, *verb)
        if _ok(got, bad):
            raise AssertionError("%s: %s wrongly showed %s via `%s`: %s"
                                 % (phase or "never", os.path.basename(db),
                                    _want(bad), " ".join(verb), _got(got)))
        time.sleep(0.05)

def _ok(got, want):
    if callable(want): return want(got)
    if isinstance(want, int): return len(got.splitlines()) == want
    return got == want

def _want(want):
    if callable(want): return getattr(want, "__doc__", None) or "<predicate>"
    if isinstance(want, int): return "%d lines" % want
    return repr(want)

def _got(got):
    lines = got.splitlines()
    if len(lines) <= 8: return repr(got)
    return "%r ... (%d lines) ... %r" % ("\n".join(lines[:3]), len(lines), "\n".join(lines[-3:]))

# --- daemon fleet: teardown + stderr on failure --------------------------------
class Fleet:
    """Spawned daemons keyed by db. On any exception inside `with fleet() as f:`
    every daemon (running or already stopped) gets its stderr tail appended to
    the failure — the difference between "assert False" and a diagnosis."""
    def __init__(self): self.running, self.dead = {}, []
    def spawn(self, db, *args):
        p, addr = spawn(db, *args); self.running[db] = p; return addr
    def stop(self, db):
        p = self.running.pop(db); stop(p); self.dead.append((db, p)); return p
    def stop_all(self):
        for db in list(self.running): self.stop(db)
    def stderr_tails(self, n=20):
        out = []
        for db, p in self.dead:
            tail = (p.stderr.read() or "").splitlines()[-n:]
            if tail: out.append("\n--- stderr %s ---\n%s" % (os.path.basename(db), "\n".join(tail)))
        return "".join(out)

@contextmanager
def fleet():
    f = Fleet()
    try:
        yield f
    except Exception as e:
        f.stop_all()
        raise AssertionError("%s%s" % (e, f.stderr_tails())) from e
    finally:
        f.stop_all()
