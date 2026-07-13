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
        c = src.find("# CHECK")                                   # optional seventh part
        if c >= 0: assert idx[1] < c < idx[2], p                  # self-check: EXTRACT..PROJECT
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
    """Needs carry no values — a need is a key, and MATCHING reads nothing
    else (the hydration window died with the store spider: a demand is one
    value-free Watch need). One carve-out, exactly as wide as the mechanism:
    a RESERVED need (NUL-prefixed role) is answered by an index, never
    matched against offers, so its value is the query argument — the summary
    need's window floor. The role must resolve to a reserved constant."""
    for p in FACTS.rglob("*.py"):
        if p.name == "__init__.py":
            continue
        tree = ast.parse(p.read_text())
        consts = {t.id: v.value                                   # module-level Name -> bytes
                  for node in ast.walk(tree) if isinstance(node, ast.Assign)
                  for t, v in zip((node.targets[0].elts if isinstance(node.targets[0], ast.Tuple)
                                   else [node.targets[0]]),
                                  (node.value.elts if isinstance(node.value, ast.Tuple)
                                   else [node.value]))
                  if isinstance(t, ast.Name) and isinstance(v, ast.Constant)
                  and isinstance(v.value, bytes)}
        def reserved(r):
            v = r.value if isinstance(r, ast.Constant) else consts.get(getattr(r, "id", None))
            return isinstance(v, bytes) and v[:1] == b"\x00"
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Atom" and node.args
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == "NEED"
                    and not (len(node.args) > 1 and reserved(node.args[1]))):
                assert len(node.args) <= 4, (p, node.lineno)      # no positional value
                assert all(k.arg != "value" for k in node.keywords), (p, node.lineno)

if __name__ == "__main__":
    for t in (test_fact_contract, test_needs_carry_no_values):
        t(); print(f"ok  {t.__name__}")
