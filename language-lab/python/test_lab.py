import unittest

from lab_kernel import (
    Atom,
    Bucket,
    Effect,
    Kind,
    Node,
    Out,
    Row,
    SELF,
    Verdict,
    by,
    decode,
    decode_atom,
    encode,
    encode_atom,
    exact,
    fact_id,
    frame,
    make_fact,
    span,
)
from lab_runtime import OutLink, WireDecoder, cycle, outbox, pump, wire_message


def offer(role, scope, target, value=None):
    return Atom(Kind.OFFER, role, scope, target, value)


def need(role, scope, target, effect):
    return Atom(Kind.NEED, role, scope, target, effect=effect)


class DemoRoot:
    def extract(self, fact):
        return fact.tag != b"courier"

    def project(self, fact, context):
        if fact.tag == b"invalid":
            return Out(Verdict.INVALID)
        if fact.tag == b"courier" and by(context, b"shipped"):
            return Out(Verdict.REAP)
        if fact.tag == b"clock" and not by(context, b"now"):
            return Out()
        if fact.tag in (b"pass", b"courier", b"clock"):
            return Out(offers=tuple(atom for atom in fact.atoms if atom.kind is Kind.OFFER))
        return None


class LanguageLabTest(unittest.TestCase):
    def test_canonical_round_trip_and_golden_id(self):
        atoms = (
            offer(b"result", b"s", SELF, b"ok"),
            need(b"dep", b"s", exact(b"key"), Effect.REQUIRE),
        )
        fact = make_fact(
            b"pass",
            atoms[1],
            atoms[0],
            atoms[1],
        )
        self.assertEqual(len(fact.atoms), 2)
        blob = encode(fact)
        self.assertEqual(decode(blob), fact)
        self.assertEqual(
            fact_id(fact).hex(),
            "33a234f18d975af511b7648e6199ac1db55521a60b811e1478e57fe16943b8c7",
        )
        self.assertIsNone(Node(DemoRoot()).admit(blob[:-1]))
        reversed_fact = frame(fact.tag) + b"".join(
            frame(encode_atom(atom)) for atom in reversed(fact.atoms)
        )
        self.assertIsNone(Node(DemoRoot()).admit(reversed_fact))
        noncanonical_range = frame(
            bytes((Kind.OFFER, Effect.NONE, 2)), b"r", b"s", b"x", b"x"
        )
        with self.assertRaises(ValueError):
            decode_atom(noncanonical_range)

    def test_bucket_matches_point_and_range_both_directions(self):
        point = Row(b"p", 0, offer(b"r", b"s", exact(b"m")))
        ranged = Row(b"r", 0, offer(b"r", b"s", span(b"a", b"z")))
        bucket = Bucket()
        bucket.add(point)
        bucket.add(ranged)
        self.assertEqual(set(bucket.matching(exact(b"m"))), {point, ranged})
        self.assertEqual(bucket.matching(span(b"l", b"n")), [point])
        self.assertEqual(bucket.matching(span(b"a", b"z")), [point])

    def test_require_parks_then_offer_wakes_and_promotes(self):
        node = Node(DemoRoot())
        dependent = make_fact(
            b"pass",
            need(b"dep", b"s", exact(b"key"), Effect.REQUIRE),
            offer(b"result", b"s", SELF, b"yes"),
        )
        dep_id = node.admit(encode(dependent))
        node.run()
        self.assertEqual(node.memo[dep_id], Verdict.PARKED)
        self.assertEqual(node.watched(b"result", b"s"), [])
        provider = make_fact(b"pass", offer(b"dep", b"s", exact(b"key"), b"ready"))
        node.admit(encode(provider))
        node.run()
        self.assertEqual(node.memo[dep_id], Verdict.VALID)
        self.assertEqual([row.owner for row in node.watched(b"result", b"s")], [dep_id])

    def test_suppress_withdraws_and_evicts_whole_owner(self):
        node = Node(DemoRoot())
        victim = make_fact(
            b"pass",
            need(b"dead", b"s", SELF, Effect.SUPPRESS),
            offer(b"live", b"s", SELF),
        )
        victim_id = node.admit(encode(victim))
        node.run()
        killer = make_fact(b"pass", offer(b"dead", b"s", exact(victim_id)))
        node.admit(encode(killer))
        node.run()
        self.assertNotIn(victim_id, node.facts)
        self.assertNotIn(victim_id, node.durable)
        self.assertEqual(node.watched(b"live", b"s"), [])

        precedence_victim = make_fact(
            b"pass",
            need(b"dead-priority", b"s", SELF, Effect.SUPPRESS),
            need(b"missing", b"s", exact(b"nothing"), Effect.REQUIRE),
            offer(b"never", b"s", SELF),
        )
        precedence_id = fact_id(precedence_victim)
        precedence_killer = make_fact(
            b"pass", offer(b"dead-priority", b"s", exact(precedence_id))
        )
        node.admit(encode(precedence_killer))
        node.run()
        node.admit(encode(precedence_victim))
        node.run()
        self.assertNotIn(precedence_id, node.facts)
        self.assertEqual(node.watched(b"never", b"s"), [])

    def test_clock_watch_and_bound(self):
        node = Node(DemoRoot())
        clocked = make_fact(
            b"clock",
            need(b"now", b"clock", span((100).to_bytes(8, "big"), b"\xff" * 8), Effect.WATCH),
            offer(b"ready", b"s", SELF),
        )
        node.admit(encode(clocked))
        node.turn(99, bound=1)
        self.assertEqual(node.watched(b"ready", b"s"), [])
        node.turn(100, bound=1)
        self.assertEqual(len(node.watched(b"ready", b"s")), 1)
        node.turn(101, bound=1)
        now_rows = node.watched(b"now", b"clock")
        self.assertEqual(len(now_rows), 1)
        self.assertEqual(now_rows[0].atom.target.lo, (101).to_bytes(8, "big"))
        node.admit(encode(make_fact(b"pass", offer(b"a", b"s", SELF))))
        node.admit(encode(make_fact(b"pass", offer(b"b", b"s", SELF))))
        node.turn(bound=1)
        self.assertEqual(len(node.frontier), 1)

    def test_inline_pump_then_shipped_reaps(self):
        node = Node(DemoRoot())
        courier = make_fact(
            b"courier",
            offer(b"send", b"outbox", exact(b"peer"), b"hello"),
            need(b"shipped", b"wire", SELF, Effect.WATCH),
        )
        courier_id = fact_id(courier)
        cycle(node, [encode(courier)], 1)
        got = []
        fired = pump(
            node,
            lambda cid: (b"127.0.0.1:9", b"secret") if cid == b"peer" else None,
            lambda cid, address, secret, inners: got.extend(inners) or len(inners),
            set(),
        )
        self.assertEqual(got, [b"hello"])
        self.assertEqual(fired, {courier_id})
        node.admit(encode(make_fact(b"pass", offer(b"backlog-a", b"s", SELF))))
        node.admit(encode(make_fact(b"pass", offer(b"backlog-b", b"s", SELF))))
        cycle(node, [], 2, tuple(fired), bound=1)
        self.assertIn(courier_id, node.facts)
        redelivered = []
        self.assertEqual(
            pump(
                node,
                lambda cid: (b"127.0.0.1:9", b"secret") if cid == b"peer" else None,
                lambda _cid, _address, _secret, inners: redelivered.extend(inners) or len(inners),
                fired,
            ),
            set(),
        )
        self.assertEqual(redelivered, [])
        cycle(node, [], 3, tuple(fired), bound=1)
        cycle(node, [], 4, tuple(fired), bound=1)
        self.assertNotIn(courier_id, node.facts)
        self.assertEqual(outbox(node), [])

    def test_reference_dedup_and_short_delivery_retry(self):
        node = Node(DemoRoot())
        first = make_fact(b"pass", offer(b"data", b"s", SELF, b"one"))
        second = make_fact(b"pass", offer(b"data", b"s", SELF, b"two"))
        first_id, second_id = fact_id(first), fact_id(second)
        node.admit(encode(first))
        node.admit(encode(second))
        node.run()
        def shipper(round_id):
            return make_fact(
                b"courier",
                offer(b"ship", b"outbox", exact(b"peer"), frame(first_id, second_id)),
                offer(b"round", b"test", SELF, round_id),
                need(b"shipped", b"wire", SELF, Effect.WATCH),
            )

        first_shipper = shipper(b"one")
        first_shipper_id = fact_id(first_shipper)
        cycle(node, [encode(first_shipper)], 1)
        sent = {}
        got = []
        fired = pump(node, lambda _: (b"a", None), lambda *args: got.extend(args[-1][:1]) or 1, set(), sent)
        self.assertEqual(got, [encode(first)])
        self.assertEqual(sent[b"peer"], {first_id})
        self.assertEqual(fired, {first_shipper_id})
        cycle(node, [], 2, tuple(fired))
        self.assertNotIn(first_shipper_id, node.facts)

        second_shipper = shipper(b"two")
        cycle(node, [encode(second_shipper)], 3)
        got.clear()
        pump(node, lambda _: (b"a", None), lambda *args: got.extend(args[-1]) or len(args[-1]), set(), sent)
        self.assertEqual(got, [encode(second)])

    def test_fragmented_wire_and_bounded_output(self):
        decoder = WireDecoder()
        wire = wire_message(0, b"hello") + wire_message(1, b"world")
        self.assertEqual(decoder.feed(wire[:3]), [])
        self.assertEqual(decoder.feed(wire[3:8]), [])
        self.assertEqual(decoder.feed(wire[8:]), [(0, b"hello"), (1, b"world")])
        link = OutLink(len(wire))
        self.assertTrue(link.enqueue(0, b"hello"))
        self.assertTrue(link.enqueue(1, b"world"))
        self.assertFalse(link.enqueue(1, b"overflow"))
        self.assertEqual(link.take(-1), b"")
        self.assertEqual(link.pending, len(wire))
        self.assertEqual(link.take(3) + link.take(10_000), wire)
        self.assertEqual(link.pending, 0)


if __name__ == "__main__":
    unittest.main()
