"""Connection family tests. Black-box daemon runs prove the request/close/hello
vocabulary end to end (a runtime-authored request dials a peer; a close stops the
session and survives restart; hellos bind each peer to its identity key). Two
in-process tests pin the gate honesty the wire relies on: a tampered hello is an
inert miss, and a corrupt fact inside a bundle misses while its siblings land."""
import os, socket, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin"))
from kernel import Node, decode, encode, fact_id
from facts import ROOT
from facts.connection import frame as bundles, hello
from facts.auth.workspace import workspace
from facts.content.message import message, feed
from ed25519 import keygen
from harness import spawn, stop, con, until              # reuse the black-box idioms


def port():                              # an OS-assigned port, then freed for the daemon to claim
    s = socket.socket(); s.bind(("127.0.0.1", 0)); n = s.getsockname()[1]; s.close()
    return "127.0.0.1:%d" % n


# --- Black box: peers come from request facts -----------------------------------
def test_request_fact_dials():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba)                               # NO --peer: A dials nobody at startup
        try:
            wid = con(dba, "auth.workspace.create", "acme", "1")
            con(dba, "content.message.send", wid, "g", "al", "over the wire", "2")
            assert con(dbb, "content.message.feed", wid, "g") == ""     # unpeered: nothing travels
            con(dba, "connection.request.connect", addr)               # author a dial request at runtime
            assert until(lambda: con(dbb, "content.message.feed", wid, "g") == "over the wire")
        finally: stop(pa); stop(pb)


def test_close_stops_session_and_survives_restart():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        try:
            pa, _ = spawn(dba)
            try:
                wid = con(dba, "auth.workspace.create", "acme", "1")
                rid = con(dba, "connection.request.connect", addr)
                con(dba, "content.message.send", wid, "g", "al", "one", "2")
                assert until(lambda: con(dbb, "content.message.feed", wid, "g") == "one")
                con(dba, "connection.close.close", rid)                # retire the request
                con(dba, "content.message.send", wid, "g", "al", "two", "3")
                assert not until(lambda: "two" in con(dbb, "content.message.feed", wid, "g"), 2)
            finally: stop(pa)
            pa, _ = spawn(dba)                                         # restart: close is durable
            try:
                assert con(dba, "connection.request.dials") == ""      # the closed request is not a dial target
                con(dba, "content.message.send", wid, "g", "al", "three", "4")
                assert not until(lambda: "three" in con(dbb, "content.message.feed", wid, "g"), 2)
            finally: stop(pa)
        finally: stop(pb)


def test_hello_binds_peers_to_identity_keys():
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pb, addr = spawn(dbb, "--listen", "127.0.0.1:0")
        pa, _ = spawn(dba, "--peer", addr)
        try:
            apk, bpk = con(dba, "auth.local_signer_secret.whoami"), con(dbb, "auth.local_signer_secret.whoami")
            assert apk and bpk and apk != bpk                          # two distinct node identities
            assert until(lambda: bpk in con(dba, "connection.connection.peers"))  # A recorded B's proven key
            assert until(lambda: apk in con(dbb, "connection.connection.peers"))  # B recorded A's
            assert con(dba, "connection.connection.peers").endswith("anon")       # neither is a workspace member
        finally: stop(pa); stop(pb)


# --- In process: the gate honesty the wire depends on ---------------------------
def test_tampered_hello_is_inert():
    sk, pk = keygen()
    hb = hello.greeting(sk, pk, b"127.0.0.1:5000", 1000)
    n = Node(ROOT)
    assert n.admit(hb) is not None                        # an honest hello passes the CHECK gate
    bad = bytearray(hb); bad[-1] ^= 0xff                  # flip a signature byte
    assert n.admit(bytes(bad)) is None                    # tampered: an inert miss, never a bad fact


def test_corrupt_inner_fact_in_bundle_misses_siblings_land():
    ws = workspace(b"acme", 1); wid = fact_id(ws)
    msgs = [message(wid, b"g", b"al", b"m%d" % i, i + 2) for i in range(4)]
    items = [encode(ws)] + [encode(m) for m in msgs]
    items[3] += b"\x00"                                    # a trailing byte: msgs[2] no longer decodes
    [wb] = bundles.pack(items)                             # one bundle carries good facts and the rotten one
    n = Node(ROOT)
    for ib in bundles.items(decode(wb)):                  # unpack and admit each inner, exactly as the daemon does
        n.admit(ib)
    n.run()
    assert feed(n, wid, b"g") == [b"m0", b"m1", b"m3"]     # the corrupt inner missed; its siblings validated


if __name__ == "__main__":
    for t in (test_request_fact_dials, test_close_stops_session_and_survives_restart,
              test_hello_binds_peers_to_identity_keys, test_tampered_hello_is_inert,
              test_corrupt_inner_fact_in_bundle_misses_siblings_land):
        t(); print(f"ok  {t.__name__}")
