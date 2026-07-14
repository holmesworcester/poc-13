"""Transport black box: two real daemons complete the sealed handshake over TCP
and sync a workspace through encrypted frames. The bootstrap joiner dials the
inviter with its link; membership travels; and a tap on the wire proves the
transit is ciphertext — a known plaintext never appears after the handshake."""
import os, socket, sys, tempfile, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import fleet, sock, until

def _invite(dba, wid):
    link = sock(dba, "auth.user_invite.invite", wid)
    iid, secret = link.split(":")
    return iid, secret, sock(dba, "auth.endpoint.endpoint")

def test_bootstrap_connect_and_sync():
    with fleet() as f:
        with tempfile.TemporaryDirectory() as d:
            dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
            addr_a = f.spawn(dba, "--listen", "127.0.0.1:0")
            addr_b = f.spawn(dbb, "--listen", "127.0.0.1:0")
            wid = sock(dba, "auth.workspace.create", "acme", "1")
            assert sock(dba, "auth.user.roster", wid) == "founder"     # create enrolled the founder
            iid, secret, ep = _invite(dba, wid)
            sock(dba, "content.message.send", wid, "general", "al", "hi-from-host", "5")
            # the joiner bootstraps on the link; its own listen addr is the reply route
            sock(dbb, "connection.request.connect", wid, iid, secret, ep, addr_a, addr_b)
            assert until(lambda: sock(dbb, "content.message.feed", wid, "general") == "hi-from-host", secs=10), \
                "workspace + message must sync to the joiner over the sealed connection"
            # and it validated on the joiner only because connect authored acceptance
            assert wid in sock(dbb, "auth.workspace.index")
            # reverse direction: the joiner must become a signed member before authoring
            sock(dbb, "auth.user.join", wid, "bo", iid + ":" + secret, "6")
            sock(dbb, "content.message.send", wid, "general", "bo", "hi-from-joiner", "7")
            assert until(lambda: sock(dba, "content.message.feed", wid, "general")
                         == "hi-from-host\nhi-from-joiner", secs=10)

def test_wire_is_ciphertext():
    cap = bytearray()
    def relay(listen_port, target_port):
        srv = socket.create_server(("127.0.0.1", listen_port))
        while True:
            try: c, _ = srv.accept()
            except OSError: return
            u = socket.create_connection(("127.0.0.1", target_port))
            def pipe(a, b):
                try:
                    while (data := a.recv(65536)): cap.extend(data); b.sendall(data)
                except OSError: pass
            for aa, bb in ((c, u), (u, c)):
                threading.Thread(target=pipe, args=(aa, bb), daemon=True).start()
    with fleet() as f:
        with tempfile.TemporaryDirectory() as d:
            dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
            addr_a = f.spawn(dba, "--listen", "127.0.0.1:0")
            addr_b = f.spawn(dbb, "--listen", "127.0.0.1:0")
            port_a = int(addr_a.rsplit(":", 1)[1])
            s = socket.socket(); s.bind(("127.0.0.1", 0)); tap = s.getsockname()[1]; s.close()
            threading.Thread(target=relay, args=(tap, port_a), daemon=True).start()
            time.sleep(0.3)
            wid = sock(dba, "auth.workspace.create", "acme", "1")
            iid, secret, ep = _invite(dba, wid)
            leak = b"TOPSECRETPLAINTEXTQZX"
            sock(dba, "content.message.send", wid, "general", "al", leak.decode(), "5")
            # joiner dials the TAP (which forwards to A), so cap sees every joiner<->A byte
            sock(dbb, "connection.request.connect", wid, iid, secret, ep, "127.0.0.1:%d" % tap, addr_b)
            assert until(lambda: sock(dbb, "content.message.feed", wid, "general") == leak.decode(), secs=10)
            assert len(cap) > 0, "the tap must have seen wire bytes"
            assert leak not in bytes(cap), "plaintext leaked onto the wire — transit is not encrypted"

if __name__ == "__main__":
    for t in (test_bootstrap_connect_and_sync, test_wire_is_ciphertext):
        t(); print(f"ok  {t.__name__}")
    print("\nall transport tests passed")
