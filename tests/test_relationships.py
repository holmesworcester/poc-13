"""The four atom relationships share one shape and one exhaustive match path.

Provide is the indexed source. Gather, Require, and SuppressIf all fault every
matching stored provider resident; only their settlement rule differs.
"""
import os, sqlite3, sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Atom, DOMAIN, EXACT, GATHER, PROVIDE, RELATIONSHIPS, REQUIRE,
                    SELF, SUPPRESS_IF, Node, Out, Router, Store, dec_atom,
                    enc_atom, encode, fact, fact_id, frame, mat, unframe)


def _project(f, _ctx):
    return Out(provides=tuple(a for a in f.atoms if a.relationship == PROVIDE))


ROOT = Router({b"toy": SimpleNamespace(extract=lambda _f: True, project=_project)})
SCOPE, KEY = b"relationships", b"key"


def test_relationships_have_one_atom_shape_and_one_wire_tag():
    assert RELATIONSHIPS == (PROVIDE, GATHER, REQUIRE, SUPPRESS_IF)
    assert tuple(Atom.__dataclass_fields__) == ("relationship", "name", "scope", "target", "value")
    assert tuple(Out.__dataclass_fields__) == ("verdict", "provides")
    node = Node(ROOT)
    assert not any(hasattr(node, retired) for retired in
                   ("watched", "valid_offers", "offers_for", "needs_for"))
    for relationship in RELATIONSHIPS:
        atom = Atom(relationship, b"named", SCOPE, (KEY, KEY), b"same-shape")
        encoded = enc_atom(atom)
        header = unframe(encoded)[0]
        assert header == bytes((relationship, EXACT))
        assert dec_atom(encoded) == atom
    assert DOMAIN == b"tinyp2p.fact.v2"


def test_retired_kind_effect_header_is_not_a_relationship():
    old_header = frame(bytes((0, 1, EXACT)), b"named", SCOPE, KEY)
    with pytest.raises((TypeError, ValueError)):
        dec_atom(old_header)


def test_reserved_names_are_gather_only():
    reserved = b"\x00index"
    assert dec_atom(enc_atom(Atom(GATHER, reserved, SCOPE, (KEY, KEY))))
    for relationship in (PROVIDE, REQUIRE, SUPPRESS_IF):
        with pytest.raises(ValueError):
            dec_atom(enc_atom(Atom(relationship, reserved, SCOPE, (KEY, KEY))))


def test_every_consumer_relationship_faults_all_matching_stored_providers():
    providers = [
        fact(b"toy.provider", Atom(PROVIDE, b"subject", SCOPE, (KEY, KEY), b"exact-1")),
        fact(b"toy.provider", Atom(PROVIDE, b"subject", SCOPE, (KEY, KEY), b"exact-2")),
        fact(b"toy.provider", Atom(PROVIDE, b"subject", SCOPE, (b"a", b"z"), b"range")),
    ]
    unrelated = fact(b"toy.provider",
                     Atom(PROVIDE, b"subject", SCOPE, (b"other", b"other"), b"unrelated"))
    provider_ids = {fact_id(provider) for provider in providers}

    for relationship in (GATHER, REQUIRE, SUPPRESS_IF):
        store = Store()
        for provider in providers + [unrelated]:
            store.add(encode(provider))
        node = Node(ROOT, store)
        consumer = fact(b"toy.consumer",
                        Atom(relationship, b"subject", SCOPE, (KEY, KEY)),
                        Atom(PROVIDE, b"result", SCOPE, SELF))
        consumer_id = node.admit(encode(consumer))
        node.run()

        assert provider_ids <= set(node.facts), relationship
        assert fact_id(unrelated) not in node.facts, relationship
        query = mat(next(a for a in consumer.atoms if a.relationship == relationship), consumer_id)
        assert {row.owner for row in node.matches(query)} == provider_ids
        if relationship == SUPPRESS_IF:
            assert consumer_id not in node.facts
        else:
            assert node.memo[consumer_id] == "Valid"


def test_consumer_settlement_differs_only_on_match_cardinality():
    outcomes = {}
    for relationship in (GATHER, REQUIRE, SUPPRESS_IF):
        node = Node(ROOT)
        consumer = fact(b"toy.consumer",
                        Atom(relationship, b"absent", SCOPE, (KEY, KEY)),
                        Atom(PROVIDE, b"result", SCOPE, SELF))
        consumer_id = node.admit(encode(consumer)); node.run()
        outcomes[relationship] = node.memo[consumer_id]
    assert outcomes == {GATHER: "Valid", REQUIRE: "Parked", SUPPRESS_IF: "Valid"}


def test_input_derived_non_provide_projection_is_invalid_not_a_crash():
    bad = SimpleNamespace(extract=lambda _f: False,
                          project=lambda f, _ctx:
                              Out(provides=tuple(a for a in f.atoms if a.name == b"bad")))
    node = Node(Router({b"bad": bad}))
    owner = node.admit(encode(fact(b"bad.projector",
                                   Atom(GATHER, b"bad", SCOPE, (KEY, KEY)))))
    node.run()
    assert node.memo[owner] == "Invalid"
    assert node.provided(b"bad", SCOPE) == []


def test_v1_store_schema_fails_closed(tmp_path):
    path = tmp_path / "v1.facts"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE facts(fid BLOB PRIMARY KEY, tag BLOB) WITHOUT ROWID")
    db.execute("CREATE TABLE atoms(fid BLOB, kind INT, effect INT, role BLOB, scope BLOB,"
               " value BLOB, ex INT, lo BLOB, hi BLOB)")
    db.commit(); db.close()

    with pytest.raises(RuntimeError, match="requires a new database"):
        Store(path)
