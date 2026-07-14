"""A real two-daemon attachment story: a multi-chunk binary file crosses the
sealed transport, survives receiver restart, saves byte-for-byte, then a synced
message deletion physically removes the message and complete attachment tree on
both databases while leaving an already exported user file alone."""
import os, tempfile
from harness import con, converge, fleet, port, sock
from kernel import Store


def _bootstrap(dba, dbb, wid, addr_a, addr_b):
    link = con(dba, "auth.user_invite.invite", wid)
    invite_id, secret = link.split(":")
    endpoint = con(dba, "auth.endpoint.endpoint")
    con(dbb, "connection.request.connect", wid, invite_id, secret, endpoint, addr_a, addr_b)


def _field(output, name):
    prefix = name + ": "
    return next(line[len(prefix):] for line in output.splitlines() if line.startswith(prefix))


def test_file_attachment_sync_restart_save_and_real_delete():
    with tempfile.TemporaryDirectory() as directory, fleet() as f:
        alice = os.path.join(directory, "alice.facts")
        bob = os.path.join(directory, "bob.facts")
        addr_a, addr_b = port(), port()
        f.spawn(alice, "--listen", addr_a)
        f.spawn(bob, "--listen", addr_b)
        wid = con(alice, "auth.workspace.create", "files", "1")
        _bootstrap(alice, bob, wid, addr_a, addr_b)
        converge(bob, lambda output: wid in output, "auth.workspace.index",
                 phase="bob accepts the workspace")

        source = os.path.join(directory, "payload.bin")
        payload = bytes(i % 251 for i in range(300_123))
        with open(source, "wb") as output: output.write(payload)
        sent = con(alice, "content.file.send", wid, "general", "al", "see attached",
                   source, "application/octet-stream", "2")
        message_id = _field(sent, "message_id")
        assert _field(sent, "filename") == "payload.bin"
        assert _field(sent, "total_chunks") == "2"

        converge(bob, lambda output: "1. complete payload.bin" in output,
                 "content.file.list", wid, secs=30, phase="attachment completes on bob")
        converge(bob, lambda output: "see attached" in output and "file: payload.bin" in output,
                 "content.message.view", wid, "general", secs=0,
                 phase="message view includes attachment")
        target = os.path.join(directory, "bob-copy.bin")
        saved = con(bob, "content.file.save", wid, "#1", target)
        assert _field(saved, "bytes_written") == str(len(payload))
        assert open(target, "rb").read() == payload

        f.stop(bob); f.spawn(bob, "--listen", addr_b)
        converge(bob, lambda output: "1. complete payload.bin" in output,
                 "content.file.list", wid, secs=0, phase="attachment survives bob restart")
        after_restart = os.path.join(directory, "bob-copy-after-restart.bin")
        con(bob, "content.file.save", wid, "1", after_restart)
        assert open(after_restart, "rb").read() == payload

        con(alice, "content.message_deletion.delete", wid, message_id, "3")
        converge(alice, "FILES (0 total):", "content.file.list", wid, secs=0,
                 phase="source attachment is physically deleted")
        converge(bob, "FILES (0 total):", "content.file.list", wid, secs=30,
                 phase="synced deletion removes bob attachment")
        converge(bob, "", "content.message.feed", wid, "general", secs=0,
                 phase="deleted parent leaves the feed")
        try:
            sock(bob, "content.file.save", wid, "1", os.path.join(directory, "deleted.bin"))
            assert False, "deleted attachment remained saveable"
        except RuntimeError as error:
            assert "did not match a visible attachment" in str(error)
        assert open(target, "rb").read() == payload       # exports are outside the fact store

        f.stop(alice); f.stop(bob)
        content_tags = (b"content.message", b"content.file", b"content.file_outboard",
                        b"content.file_chunk")
        for db in (alice, bob):
            store = Store(db)
            remaining = {row[0] for row in store.db.execute("SELECT tag FROM facts")}
            assert not remaining.intersection(content_tags)
            assert b"content.message_deletion" in remaining
            store.db.close()


if __name__ == "__main__":
    test_file_attachment_sync_restart_save_and_real_delete()
    print("ok  test_file_attachment_sync_restart_save_and_real_delete")
