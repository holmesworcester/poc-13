"""Connection transport, in process: the gate-honesty the sealed wire relies on.
A tampered frame opens to nothing and is dropped whole; a corrupt fact inside an
opened frame misses while its siblings still admit (a per-fact miss never poisons
the batch). The end-to-end handshake, sync, restart, and ciphertext properties
live in test_transport.py and test_pair.py."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import Node, encode, fact_id, unframe
from facts import ROOT
from facts.connection import frame as frames
from facts.auth.workspace import workspace
from facts.content.message import message, feed

def test_tampered_frame_opens_to_nothing():
    secret, cid = os.urandom(32), os.urandom(32)
    [(blob, _)] = frames.pack_counts([b"one", b"two"])
    wire = frames.seal(blob, cid, secret, os.urandom(24))
    assert frames.open_frame(wire, secret) == blob            # honest frame opens
    bad = bytearray(wire); bad[-1] ^= 0xff                    # flip a ciphertext byte
    assert frames.open_frame(bytes(bad), secret) is None      # tamper: whole-frame miss
    assert frames.open_frame(wire, os.urandom(32)) is None    # wrong session key: miss

def test_corrupt_inner_fact_misses_siblings_land():
    ws = workspace(b"acme", os.urandom(32), 1); wid = fact_id(ws)   # any workspace bytes: we test admission
    channel_id = b"\x07" * 32
    msgs = [message(wid, channel_id, b"al", b"m%d" % i, i + 2) for i in range(4)]
    items = [encode(m) for m in msgs]
    items[2] += b"\x00"                                        # a trailing byte: msgs[2] no longer decodes
    [(blob, _)] = frames.pack_counts(items)
    secret, cid = os.urandom(32), os.urandom(32)
    wire = frames.seal(blob, cid, secret, os.urandom(24))
    n = Node(ROOT)
    for inner in unframe(frames.open_frame(wire, secret)):   # exactly what the daemon does per frame
        try: n.admit(inner)
        except Exception: pass
    landed = {fid for fid, f in n.facts.items() if f.type_tag == b"content.message"}
    assert landed == {fact_id(msgs[0]), fact_id(msgs[1]), fact_id(msgs[3])}   # sibling of the corrupt one land
    assert fact_id(msgs[2]) not in n.facts                    # the corrupt inner missed

if __name__ == "__main__":
    for t in (test_tampered_frame_opens_to_nothing, test_corrupt_inner_fact_misses_siblings_land):
        t(); print(f"ok  {t.__name__}")
