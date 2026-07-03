"""Source-contract test: every fact file has the six-part shape, in order,
with responsibilities where they belong (docs/DESIGN.md, The Fact Contract)."""
import pathlib

FACTS = pathlib.Path(__file__).resolve().parent.parent / "facts"
SECTIONS = ["# SHAPE", "# EXTRACT", "# PROJECT", "# COMMANDS", "# QUERIES", "# CLI"]

def test_fact_contract():
    files = [p for p in FACTS.rglob("*.py") if p.name != "__init__.py"]
    assert files
    for p in files:
        src, rel = p.read_text(), p.relative_to(FACTS).with_suffix("")
        assert src.startswith(f'"""facts/{"/".join(rel.parts)}.py — '), p
        assert f'TAG = b"{".".join(rel.parts)}"' in src, p        # tag = path = namespace
        idx = [src.find(s) for s in SECTIONS]
        assert min(idx) >= 0 and idx == sorted(idx), p            # all six, in order
        bounds = idx + [len(src)]
        part = {s: src[bounds[i]:bounds[i + 1]] for i, s in enumerate(SECTIONS)}
        for s in SECTIONS:
            if s != "# COMMANDS":                                 # only commands write
                assert "admit(" not in part[s], (p, s)
            if s in ("# SHAPE", "# EXTRACT", "# PROJECT"):        # pure of the node
                assert "node" not in part[s], (p, s)
            if s != "# PROJECT":                                  # only project sees ctx
                assert "ctx" not in part[s], (p, s)
        assert "CLI = {" in part["# CLI"], p                      # explicit verb table

if __name__ == "__main__":
    test_fact_contract(); print("ok  test_fact_contract")
