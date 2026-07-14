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

def test_extract_contract_has_one_result():
    """EXTRACT is one durability result; tuple-shaped policy classifications
    must not return through a family implementation."""
    for p in FACTS.rglob("*.py"):
        if p.name == "__init__.py":
            continue
        tree = ast.parse(p.read_text())
        extracts = [node for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "extract"]
        for extract in extracts:
            returns = [node for node in ast.walk(extract) if isinstance(node, ast.Return)]
            assert returns and all(not isinstance(node.value, ast.Tuple) for node in returns), p

def test_fact_atoms_use_the_closed_relationship_alphabet():
    """Every authored atom names one of the four relationships directly.
    This prevents the retired kind/effect product and accidental integer tags
    from creeping back into fact shapes."""
    relationships = {"PROVIDE", "GATHER", "REQUIRE", "SUPPRESS_IF"}
    for p in FACTS.rglob("*.py"):
        if p.name == "__init__.py":
            continue
        for node in ast.walk(ast.parse(p.read_text())):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Atom"):
                continue
            assert node.args and isinstance(node.args[0], ast.Name), (p, node.lineno)
            assert node.args[0].id in relationships, (p, node.lineno)

def test_provenance_shapes_have_an_intrinsic_check():
    """Source policy is handler-local, but it must be canonical: any family
    using a provenance atom has a one-argument CHECK that can reject a sender
    who removes or substitutes that atom. No tag classification lives here."""
    policy_names = {"remote_suppress", "bare_suppress",
                    "connection_suppress", "connection_gather"}
    for p in FACTS.rglob("*.py"):
        if p.name == "__init__.py": continue
        tree = ast.parse(p.read_text())
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} & policy_names
        if not used: continue
        checks = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == "check"]
        assert len(checks) == 1, (p, used)
        assert len(checks[0].args.args) == 1 and not checks[0].args.vararg, p

def test_consumer_relationships_carry_no_values():
    """Ordinary Gather, Require, and SuppressIf atoms are match addresses,
    not payloads. The one carve-out is a reserved Gather: it is answered by a
    family index rather than matching Provides, so its value is a query
    argument (sync summary's window floor)."""
    consumers = {"GATHER", "REQUIRE", "SUPPRESS_IF"}
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
                    and isinstance(node.args[0], ast.Name) and node.args[0].id in consumers
                    and not (len(node.args) > 1 and reserved(node.args[1]))):
                assert len(node.args) <= 4, (p, node.lineno)      # no positional value
                assert all(k.arg != "value" for k in node.keywords), (p, node.lineno)

if __name__ == "__main__":
    for t in (test_fact_contract, test_extract_contract_has_one_result,
              test_fact_atoms_use_the_closed_relationship_alphabet,
              test_provenance_shapes_have_an_intrinsic_check,
              test_consumer_relationships_carry_no_values):
        t(); print(f"ok  {t.__name__}")
