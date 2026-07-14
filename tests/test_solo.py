"""One daemon, black box: every solo CLI semantic in one story. tiny.py only
proxies now, so a real tinyd.py owns the db for the whole run and every verb goes
down the socket; the restart phase proves the daemon flushes durable facts and a
fresh daemon replays them from the file. Also pins the demo CLI grammar: a
selected active workspace lets verbs omit `wid=`, and ambient context (`wid=`,
`t=`) is keyed so a numeric or hex-looking body is never mis-read."""
import os, subprocess, sys, tempfile
from harness import BIN, tiny, converge, fleet

def _tiny(*args):                        # tiny.py with no db: the daemon-free local affordances
    return subprocess.run([sys.executable, os.path.join(BIN, "tiny.py"), *args],
                          capture_output=True, text=True)

def test_solo_story():
    with tempfile.TemporaryDirectory() as d, fleet() as f:
        db = os.path.join(d, "w.facts")
        f.spawn(db)
        # workspace bootstrap authors a real replicated #general channel
        wid = tiny(db, "auth.workspace.create", "acme", "1")
        # select it once: from here every verb may omit wid= (the active workspace)
        tiny(db, "auth.active_workspace.use", wid, "1")
        assert tiny(db, "auth.active_workspace.current") == wid
        general = tiny(db, "content.channel.id", "general")
        assert len(general) == 64
        random = tiny(db, "content.channel.create", "random", "t=2")
        listing = tiny(db, "content.channel.list").splitlines()
        assert listing == [f"{general} general", f"{random} random"]
        # idempotent authorship and channel-isolated feeds — all wid-less
        m_hi = tiny(db, "content.message.send", "general", "hi", "t=2")
        assert tiny(db, "content.message.send", "general", "hi", "t=2") == m_hi, \
            "resending the same fact must return the same id"
        tiny(db, "content.message.send", "general", "there", "t=3")
        tiny(db, "content.message.send", "random", "elsewhere", "t=4")
        converge(db, "hi\nthere", "content.message.feed", "general", secs=0, phase="feed")
        converge(db, "elsewhere", "content.message.feed", random, secs=0,
                 phase="separate channel feed by id")
        # the deterministic grammar: a numeric body is a body (not a t=), and a
        # multi-word body joins — neither is inferred from a positional's shape
        tiny(db, "content.channel.create", "trap", "t=5")
        tiny(db, "content.message.send", "trap", "42", "t=6")
        tiny(db, "content.message.send", "trap", "meet", "at", "ten", "t=7")
        converge(db, "42\nmeet at ten", "content.message.feed", "trap", secs=0, phase="numeric+multiword body")
        # discovery + completion need no daemon at all
        assert "content.message.send" in _tiny("--commands").stdout
        assert "auth.active_workspace.use" in _tiny("--commands").stdout
        assert "complete -F _tiny_complete" in _tiny("--completion", "bash").stdout
        # membership + authority: create ran the whole bootstrap DAG with an
        # ephemeral root key (then dropped), enrolling the founder as member+admin
        assert len(tiny(db, "auth.local_signer_secret.whoami")) == 64, "whoami must print the 32-byte pk hex"
        converge(db, "founder", "auth.user.roster", wid, secs=0, phase="founder enrolled by create")
        converge(db, 1, "auth.admin.admins", wid, secs=0, phase="founder is the bootstrap admin")
        # signed content: a workspace this node is no member of refuses the send
        # (explicit wid= + a channel id bypasses name lookup to reach the member gate)
        ghost = "00" * 32
        r = _tiny(db, "content.message.send", "wid=" + ghost, ghost, "ghost", "t=6")
        assert r.returncode != 0 and "local signer is not a workspace member" in r.stderr
        # reactions live and die with their message
        tiny(db, "content.reaction.react", m_hi, ":+1:", "t=7")
        converge(db, ":+1: founder", "content.reaction.on", m_hi, secs=0, phase="reaction lands")
        tiny(db, "content.message_deletion.delete", m_hi, "t=8")
        converge(db, "there", "content.message.feed", "general", secs=0, phase="deletion suppresses")
        converge(db, "", "content.reaction.on", m_hi, secs=0, phase="reaction dies with its message")
        # retention roundtrip (outbox sends are volatile: exercised in the daemon pair/trio tests)
        tiny(db, "content.retention_policy.set", "1440", "t=9")
        converge(db, "1440", "content.retention_policy.window", secs=0, phase="retention window")
        # a fresh send lands and is idempotent through the proxy too
        m_warm = tiny(db, "content.message.send", "general", "warm", "t=12")
        assert tiny(db, "content.message.send", "general", "warm", "t=12") == m_warm, \
            "resend must be idempotent through the proxy too"
        converge(db, "there\nwarm", "content.message.feed", "general", secs=0, phase="live feed before restart")
        # clean shutdown removes the socket; a fresh daemon replays the flushed file
        f.stop(db)
        assert not os.path.exists(db + ".sock"), "clean shutdown must remove the socket"
        f.spawn(db)
        converge(db, "there\nwarm", "content.message.feed", "general", secs=0, phase="restart replay")

if __name__ == "__main__":
    test_solo_story(); print("ok  test_solo_story")
