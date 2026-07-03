"""Source-contract test: every fact file has the six-part shape, in order,
with responsibilities where they belong (docs/DESIGN.md, The Fact Contract)."""
import ast, pathlib

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

def test_needs_carry_no_values():
    """Need values belong to the engine — today that is the hydration window
    on Watch needs (kernel Store.pull keys on a 21-byte value). A family
    that put a value on a need would get silently windowed pulls, so no
    family constructs one; store/hydrate is the single exemption, since
    authoring the window is its whole job."""
    for p in FACTS.rglob("*.py"):
        if p.name == "__init__.py" or p.relative_to(FACTS).parts == ("store", "hydrate.py"):
            continue
        for node in ast.walk(ast.parse(p.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Atom" and node.args
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == "NEED"):
                assert len(node.args) <= 4, (p, node.lineno)      # no positional value
                assert all(k.arg != "value" for k in node.keywords), (p, node.lineno)

if __name__ == "__main__":
    for t in (test_fact_contract, test_needs_carry_no_values):
        t(); print(f"ok  {t.__name__}")
