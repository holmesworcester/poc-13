import assert from "node:assert/strict";
import test from "node:test";

import {
  Effect,
  Kind,
  TargetTag,
  SELF,
  decodeAtom,
  decodeFact,
  encodeAtom,
  encodeFact,
  exact,
  factId,
  frame,
  isOffer,
  key,
  makeFact,
  need,
  offer,
  span,
  type Atom,
  type Bytes,
  type Fact,
} from "./model.ts";
import {
  Bucket,
  Node,
  Verdict,
  by,
  outcome,
  valid,
  type Context,
  type Root,
  type Row,
} from "./kernel.ts";
import {
  BOUND,
  ByteSet,
  OutLink,
  WireDecoder,
  cycle,
  outbox,
  pump,
  wireMessage,
  type Sent,
} from "./runtime.ts";

const b = (value: string): Bytes => Buffer.from(value);
const same = (left: Uint8Array, right: Uint8Array): boolean => Buffer.compare(left, right) === 0;

class DemoRoot implements Root {
  extract(fact: Fact): boolean {
    return !same(fact.tag, b("courier"));
  }

  project(fact: Fact, context: Context) {
    if (same(fact.tag, b("invalid"))) return outcome(Verdict.Invalid);
    if (same(fact.tag, b("courier")) && by(context, b("shipped")).length !== 0) {
      return outcome(Verdict.Reap);
    }
    if (same(fact.tag, b("clock")) && by(context, b("now")).length === 0) return valid();
    if (["pass", "courier", "clock", "duplicate"].some((tag) => same(fact.tag, b(tag)))) {
      const offers = fact.atoms.filter(isOffer);
      if (same(fact.tag, b("duplicate")) && offers[0] !== undefined) offers.push(offers[0]);
      return valid(...offers);
    }
    return undefined;
  }
}

function mustAdmit(node: Node, fact: Fact): Bytes {
  const owner = node.admit(encodeFact(fact));
  assert.ok(owner, "fact was not admitted");
  return owner;
}

function framedIds(...ids: readonly Uint8Array[]): Bytes {
  return frame(...ids);
}

test("canonical bytes, shared golden ID, normalization, and malformed rejection", () => {
  const result = offer(b("result"), b("s"), SELF, b("ok"));
  const dependency = need(b("dep"), b("s"), exact(b("key")), Effect.Require);
  const fact = makeFact(b("pass"), result, dependency, result);
  const reordered = makeFact(b("pass"), dependency, result);
  assert.deepEqual(factId(fact), factId(reordered));
  assert.equal(factId(fact).toString("hex"), "33a234f18d975af511b7648e6199ac1db55521a60b811e1478e57fe16943b8c7");

  const normalized = makeFact(b("pass"), offer(b("r"), b("s"), span(b("x"), b("x"))));
  assert.equal(normalized.atoms[0]!.target.tag, TargetTag.Exact);
  const encoded = encodeFact(fact);
  assert.deepEqual(encodeFact(decodeFact(encoded)), encoded);

  const node = new Node(new DemoRoot());
  assert.equal(node.admit(encoded.subarray(0, -1)), undefined);
  const reversed = frame(fact.tag, ...[...fact.atoms].reverse().map(encodeAtom));
  assert.throws(() => decodeFact(reversed), /unsorted/);

  const degenerate = frame(
    Buffer.from([Kind.Need, Effect.Watch, TargetTag.Range]),
    b("r"), b("s"), b("x"), b("x"),
  );
  assert.throws(() => decodeAtom(degenerate), /degenerate/);
  const extra = frame(
    Buffer.from([Kind.Need, Effect.Watch, TargetTag.Exact]),
    b("r"), b("s"), b("x"), b("value"), b("extra"),
  );
  assert.throws(() => decodeAtom(extra), /arity/);
  const reserved = frame(
    Buffer.from([Kind.Offer, Effect.None, TargetTag.Exact]),
    Buffer.from([0, 114]), b("s"), b("x"),
  );
  assert.throws(() => decodeAtom(reserved), /reserved/);
  const effectedOffer = frame(
    Buffer.from([Kind.Offer, Effect.Require, TargetTag.Exact]),
    b("r"), b("s"), b("x"),
  );
  assert.throws(() => decodeAtom(effectedOffer), /effect/);
  assert.notDeepEqual(
    encodeAtom(offer(b("r"), b("s"), exact(b("x")))),
    encodeAtom(offer(b("r"), b("s"), exact(b("x")), Buffer.alloc(0))),
  );

  const owner = node.admit(encoded);
  assert.ok(owner);
  assert.equal(node.pending, 1);
  assert.deepEqual(node.admit(encoded), owner);
  assert.equal(node.pending, 1, "idempotent admission must not enqueue twice");
  const unknown = mustAdmit(node, makeFact(b("no-family")));
  node.run();
  assert.equal(node.verdict(unknown), Verdict.Parked);
});

test("exact and range targets match in both supported directions", () => {
  const point: Row = {
    owner: Buffer.alloc(32), timestamp: 0n,
    atom: offer(b("r"), b("s"), exact(b("m"))),
  };
  const rangeOwner = Buffer.alloc(32);
  rangeOwner[0] = 1;
  const ranged: Row = {
    owner: rangeOwner, timestamp: 0n,
    atom: offer(b("r"), b("s"), span(b("a"), b("z"))),
  };
  const bucket = new Bucket();
  bucket.add(point);
  bucket.add(ranged);
  assert.equal(bucket.matching(exact(b("m"))).length, 2);
  for (const target of [span(b("l"), b("n")), span(b("a"), b("z"))]) {
    const rows = bucket.matching(target);
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0]!.owner, point.owner);
  }
});

test("Require parks, then duplicate projected offers wake and promote it", () => {
  const node = new Node(new DemoRoot());
  const dependent = makeFact(
    b("pass"),
    need(b("dep"), b("s"), exact(b("key")), Effect.Require),
    offer(b("result"), b("s"), SELF, b("yes")),
  );
  const dependentId = mustAdmit(node, dependent);
  node.run();
  assert.equal(node.verdict(dependentId), Verdict.Parked);
  assert.equal(node.watched(b("result"), b("s")).length, 0);

  mustAdmit(node, makeFact(
    b("duplicate"),
    offer(b("dep"), b("s"), exact(b("key")), b("ready")),
  ));
  node.run();
  assert.equal(node.watched(b("dep"), b("s")).length, 2, "index preserves projected duplicates");
  assert.equal(node.verdict(dependentId), Verdict.Valid, "set delta must still wake once");
  const published = node.watched(b("result"), b("s"));
  assert.equal(published.length, 1);
  assert.deepEqual(published[0]!.owner, dependentId);
});

test("projector-produced degenerate ranges normalize to indexed points", () => {
  const root: Root = {
    extract: () => false,
    project: (fact) => {
      if (same(fact.tag, b("raw-range"))) {
        return valid(offer(b("dep"), b("s"), {
          tag: TargetTag.Range, lo: b("m"), hi: b("m"),
        }));
      }
      if (same(fact.tag, b("pass"))) return valid(...fact.atoms.filter(isOffer));
      return undefined;
    },
  };
  const node = new Node(root);
  const dependent = mustAdmit(node, makeFact(
    b("pass"),
    need(b("dep"), b("s"), span(b("l"), b("n")), Effect.Require),
    offer(b("result"), b("s"), SELF),
  ));
  node.run();
  assert.equal(node.verdict(dependent), Verdict.Parked);
  mustAdmit(node, makeFact(b("raw-range")));
  node.run();
  assert.equal(node.verdict(dependent), Verdict.Valid);
  assert.equal(node.watched(b("dep"), b("s"))[0]!.atom.target.tag, TargetTag.Exact);
});

test("Suppress precedes Require, withdraws offers, and evicts the owner", () => {
  const node = new Node(new DemoRoot());
  const victim = makeFact(
    b("pass"),
    need(b("dead"), b("s"), SELF, Effect.Suppress),
    offer(b("live"), b("s"), SELF),
  );
  const victimId = mustAdmit(node, victim);
  node.run();
  assert.equal(node.watched(b("live"), b("s")).length, 1);
  mustAdmit(node, makeFact(b("pass"), offer(b("dead"), b("s"), exact(victimId))));
  node.run();
  assert.equal(node.hasFact(victimId), false);
  assert.equal(node.hasDurable(victimId), false);
  assert.equal(node.watched(b("live"), b("s")).length, 0);

  const precedence = makeFact(
    b("pass"),
    need(b("missing"), b("s"), exact(b("never")), Effect.Require),
    need(b("dead"), b("s"), SELF, Effect.Suppress),
  );
  const precedenceId = factId(precedence);
  mustAdmit(node, makeFact(b("pass"), offer(b("dead"), b("s"), exact(precedenceId))));
  node.run();
  mustAdmit(node, precedence);
  node.run();
  assert.equal(node.hasFact(precedenceId), false);
});

test("clock Watch reprojects, transient slots replace, and turns are bounded", () => {
  const node = new Node(new DemoRoot());
  const deadline = Buffer.alloc(8);
  deadline.writeBigUInt64BE(100n);
  mustAdmit(node, makeFact(
    b("clock"),
    need(b("now"), b("clock"), span(deadline, Buffer.alloc(8, 0xff)), Effect.Watch),
    offer(b("ready"), b("s"), SELF),
  ));
  node.turn(99n, [], 1);
  assert.equal(node.watched(b("ready"), b("s")).length, 0);
  const at99 = Buffer.alloc(8);
  at99.writeBigUInt64BE(99n);
  assert.equal(node.validOffers(need(b("now"), b("clock"), exact(at99), Effect.Watch)).length, 1);
  node.turn(100n, [], 1);
  assert.equal(node.watched(b("ready"), b("s")).length, 1);
  assert.equal(node.validOffers(need(b("now"), b("clock"), exact(at99), Effect.Watch)).length, 0);

  mustAdmit(node, makeFact(b("pass"), offer(b("a"), b("s"), SELF)));
  mustAdmit(node, makeFact(b("pass"), offer(b("b"), b("s"), SELF)));
  node.turn(undefined, [], 1);
  assert.equal(node.pending, 1);
});

test("inline courier fires, retained shipped feedback spans a bounded backlog, then reaps", () => {
  const node = new Node(new DemoRoot());
  const courier = makeFact(
    b("courier"),
    offer(b("send"), b("outbox"), exact(b("peer")), b("hello")),
    need(b("shipped"), b("wire"), SELF, Effect.Watch),
  );
  const courierId = factId(courier);
  cycle(node, [encodeFact(courier)], 1n);
  const delivered: Bytes[] = [];
  const route = () => ({ address: b("127.0.0.1:9"), secret: b("secret") });
  const fire = pump(node, route, (_cid, _route, inners) => {
    delivered.push(...inners.map((inner) => Buffer.from(inner)));
    return inners.length;
  });
  assert.deepEqual(delivered, [b("hello")]);
  assert.equal(fire.has(courierId), true);
  const exposed = [...fire][0]!;
  exposed.fill(0);
  assert.equal(fire.has(courierId), true, "iteration must not expose mutable set storage");

  mustAdmit(node, makeFact(b("pass"), offer(b("backlog-a"), b("s"), SELF)));
  mustAdmit(node, makeFact(b("pass"), offer(b("backlog-b"), b("s"), SELF)));
  cycle(node, [], 2n, fire, 1);
  assert.equal(node.hasFact(courierId), true);
  assert.equal(pump(node, route, () => { throw new Error("redelivery"); }, fire).size, 0);
  cycle(node, [], 3n, fire, 1);
  cycle(node, [], 4n, fire, 1);
  assert.equal(node.hasFact(courierId), false);
  assert.equal(outbox(node).length, 0);
});

test("by-reference delivery records its prefix and a re-authored courier retries the tail", () => {
  const node = new Node(new DemoRoot());
  const first = makeFact(b("pass"), offer(b("data"), b("s"), SELF, b("one")));
  const second = makeFact(b("pass"), offer(b("data"), b("s"), SELF, b("two")));
  const firstId = mustAdmit(node, first);
  const secondId = mustAdmit(node, second);
  node.run();
  const shipper = (round: string): Fact => makeFact(
    b("courier"),
    offer(b("ship"), b("outbox"), exact(b("peer")), framedIds(firstId, secondId)),
    offer(b("round"), b("test"), SELF, b(round)),
    need(b("shipped"), b("wire"), SELF, Effect.Watch),
  );

  const firstShipper = shipper("one");
  const firstShipperId = factId(firstShipper);
  cycle(node, [encodeFact(firstShipper)], 1n);
  const sent: Sent = new Map();
  const delivered: Bytes[] = [];
  const fired = pump(
    node,
    () => ({ address: b("a"), secret: undefined }),
    (_cid, _route, inners) => {
      delivered.push(Buffer.from(inners[0]!));
      return 1;
    },
    [],
    sent,
  );
  assert.deepEqual(delivered, [encodeFact(first)]);
  assert.equal(sent.get(key(b("peer")))?.has(firstId), true);
  assert.equal(sent.get(key(b("peer")))?.size, 1);
  assert.equal(fired.has(firstShipperId), true);
  cycle(node, [], 2n, fired);
  assert.equal(node.hasFact(firstShipperId), false);

  const retried: Bytes[] = [];
  cycle(node, [encodeFact(shipper("two"))], 3n);
  pump(
    node,
    () => ({ address: b("a"), secret: undefined }),
    (_cid, _route, inners) => {
      retried.push(...inners.map((inner) => Buffer.from(inner)));
      return inners.length;
    },
    [],
    sent,
  );
  assert.deepEqual(retried, [encodeFact(second)]);
  assert.equal(sent.get(key(b("peer")))?.size, 2);
});

test("wire input is incremental and outbound chunks drain within capacity", () => {
  const first = wireMessage(0, b("hello"));
  const second = wireMessage(1, b("world"));
  const wire = Buffer.concat([first, second]);
  const decoder = new WireDecoder();
  assert.deepEqual(decoder.feed(wire.subarray(0, 3)), []);
  assert.deepEqual(decoder.feed(wire.subarray(3, 8)), []);
  assert.deepEqual(decoder.feed(wire.subarray(8)), [
    { kind: 0, body: b("hello") },
    { kind: 1, body: b("world") },
  ]);
  assert.equal(decoder.buffered, 0);

  const link = new OutLink(wire.length);
  assert.equal(link.enqueue(0, b("hello")), true);
  assert.equal(link.enqueue(1, b("world")), true);
  assert.equal(link.enqueue(1, b("overflow")), false);
  assert.deepEqual(Buffer.concat([link.take(3), link.take(Number.MAX_SAFE_INTEGER)]), wire);
  assert.equal(link.pending, 0);
});

test("wire queues release consumed large prefixes while retaining incomplete tails", () => {
  const large = wireMessage(7, Buffer.alloc((1 << 20) + 16));
  const incomplete = Buffer.from([0, 0, 0, 10]);
  const decoder = new WireDecoder();
  const messages = decoder.feed(Buffer.concat([large, incomplete]));
  assert.equal(messages.length, 1);
  assert.equal(decoder.buffered, incomplete.length);
  assert.equal(decoder.retained, incomplete.length);

  const sentinel = wireMessage(8, b("tail"));
  const link = new OutLink(large.length + sentinel.length);
  assert.equal(link.enqueue(7, Buffer.alloc((1 << 20) + 16)), true);
  assert.equal(link.enqueue(8, b("tail")), true);
  assert.equal(link.take(large.length).length, large.length);
  assert.equal(link.pending, sentinel.length);
  assert.equal(link.retained, sentinel.length);
});
