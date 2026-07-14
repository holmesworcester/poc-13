import {
  Effect,
  Kind,
  TargetTag,
  cloneFact,
  covers,
  encodeAtom,
  exact,
  frame,
  key,
  materialize,
  offer,
  type Atom,
  type Bytes,
  type Fact,
  type NeedAtom,
  type OfferAtom,
  type Target,
} from "./model.ts";
import { decodeFact, factId } from "./model.ts";

export const Verdict = {
  Valid: "valid",
  Invalid: "invalid",
  Parked: "parked",
  Suppressed: "suppressed",
  Reap: "reap",
  Unknown: "unknown",
} as const;
export type Verdict = (typeof Verdict)[keyof typeof Verdict];

export interface Row {
  readonly owner: Bytes;
  readonly timestamp: bigint;
  readonly atom: Atom;
}

export interface Answer {
  readonly need: NeedAtom;
  readonly rows: readonly Row[];
}

export type Context = readonly Answer[];

export interface Out {
  readonly verdict: Verdict;
  readonly offers: readonly OfferAtom[];
}

export interface Root {
  extract(fact: Fact): boolean;
  project(fact: Fact, context: Context): Out | undefined;
}

export function valid(...offers: readonly OfferAtom[]): Out {
  return { verdict: Verdict.Valid, offers };
}

export function outcome(verdict: Exclude<Verdict, typeof Verdict.Valid>): Out {
  return { verdict, offers: [] };
}

export function by(context: Context, role: Uint8Array): Row[] {
  const wanted = key(role);
  return context.flatMap((answer) => key(answer.need.role) === wanted ? answer.rows : []);
}

function rowKey(row: Row): string {
  return `${key(row.owner)}:${row.timestamp}:${key(encodeAtom(row.atom))}`;
}

function addressKey(role: Uint8Array, scope: Uint8Array): string {
  return key(frame(role, scope));
}

function indexKey(kind: Kind, role: Uint8Array, scope: Uint8Array): string {
  return key(frame(Buffer.from([kind]), role, scope));
}

function targetPoint(target: Target): Bytes | undefined {
  return target.tag === TargetTag.Exact ? target.value : undefined;
}

export class Bucket {
  readonly #exact = new Map<string, { point: Bytes; rows: Row[] }>();
  readonly #ranges: Row[] = [];

  add(row: Row): void {
    const point = targetPoint(row.atom.target);
    if (point !== undefined) {
      const id = key(point);
      const entry = this.#exact.get(id);
      if (entry === undefined) this.#exact.set(id, { point: Buffer.from(point), rows: [row] });
      else entry.rows.push(row);
      return;
    }
    if (row.atom.target.tag === TargetTag.Self) throw new Error("resident SELF target");
    this.#ranges.push(row);
  }

  remove(row: Row): void {
    const point = targetPoint(row.atom.target);
    if (point !== undefined) {
      const id = key(point);
      const entry = this.#exact.get(id);
      if (entry === undefined) return;
      const index = entry.rows.findIndex((candidate) => rowKey(candidate) === rowKey(row));
      if (index >= 0) entry.rows.splice(index, 1);
      if (entry.rows.length === 0) this.#exact.delete(id);
      return;
    }
    const index = this.#ranges.findIndex((candidate) => rowKey(candidate) === rowKey(row));
    if (index >= 0) this.#ranges.splice(index, 1);
  }

  matching(target: Target): Row[] {
    if (target.tag === TargetTag.Self) return [];
    if (target.tag === TargetTag.Exact) {
      const matches = [...(this.#exact.get(key(target.value))?.rows ?? [])];
      for (const row of this.#ranges) if (covers(row.atom.target, target)) matches.push(row);
      return matches;
    }
    const matches: Row[] = [];
    for (const { point, rows } of this.#exact.values()) {
      if (Buffer.compare(target.lo, point) <= 0 && Buffer.compare(point, target.hi) <= 0) {
        matches.push(...rows);
      }
    }
    return matches;
  }

  all(): Row[] {
    return [...this.#exact.values()].flatMap(({ rows }) => rows).concat(this.#ranges);
  }

  get size(): number {
    let result = this.#ranges.length;
    for (const { rows } of this.#exact.values()) result += rows.length;
    return result;
  }
}

const NOW = Buffer.from("now");
const CLOCK = Buffer.from("clock");
const SHIPPED = Buffer.from("shipped");
const WIRE = Buffer.from("wire");

function hostOwner(name: string): Bytes {
  const owner = Buffer.alloc(32);
  owner[0] = 0xff;
  owner.write(name, 1);
  return owner;
}

const NOW_OWNER = hostOwner("now");
const SHIPPED_OWNER = hostOwner("ship");

interface ResidentFact {
  readonly owner: Bytes;
  readonly fact: Fact;
}

export class Node {
  readonly #root: Root;
  readonly #durable = new Map<string, Bytes>();
  readonly #facts = new Map<string, ResidentFact>();
  readonly #rows = new Map<string, Bucket>();
  readonly #memo = new Map<string, Verdict>();
  readonly #clean = new Map<string, Bucket>();
  readonly #owned = new Map<string, Row[]>();
  #frontier: Bytes[] = [];
  #head = 0;
  readonly #queued = new Set<string>();

  constructor(root: Root) {
    this.#root = root;
  }

  admit(data: Uint8Array): Bytes | undefined {
    let fact: Fact;
    try {
      fact = decodeFact(data);
    } catch {
      return undefined;
    }
    const owner = factId(fact);
    const id = key(owner);
    if (this.#facts.has(id)) return Buffer.from(owner);
    this.#facts.set(id, { owner, fact });
    this.#memo.set(id, Verdict.Unknown);
    if (this.#root.extract(cloneFact(fact))) this.#durable.set(id, Buffer.from(data));
    for (const atom of fact.atoms) {
      const bucket = this.#bucket(this.#rows, indexKey(atom.kind, atom.role, atom.scope));
      bucket.add({ owner, timestamp: 0n, atom: materialize(atom, owner) });
    }
    this.#enqueue(owner);
    return Buffer.from(owner);
  }

  offersFor(needAtom: NeedAtom): Row[] {
    return this.#matching(this.#rows.get(indexKey(Kind.Offer, needAtom.role, needAtom.scope)), needAtom.target);
  }

  needsFor(offerAtom: OfferAtom): Row[] {
    return this.#matching(this.#rows.get(indexKey(Kind.Need, offerAtom.role, offerAtom.scope)), offerAtom.target);
  }

  validOffers(needAtom: NeedAtom): Row[] {
    return this.#matching(this.#clean.get(addressKey(needAtom.role, needAtom.scope)), needAtom.target);
  }

  watched(role: Uint8Array, scope: Uint8Array): Row[] {
    return this.#clean.get(addressKey(role, scope))?.all() ?? [];
  }

  turn(nowMs: bigint | undefined, shipped: Iterable<Uint8Array>, bound: number): void {
    if (nowMs !== undefined) {
      if (nowMs < 0n || nowMs > 0xffff_ffff_ffff_ffffn) throw new RangeError("bad clock value");
      const encoded = Buffer.allocUnsafe(8);
      encoded.writeBigUInt64BE(nowMs);
      this.#present(NOW, CLOCK, [{
        owner: NOW_OWNER,
        timestamp: nowMs,
        atom: offer(NOW, CLOCK, exact(encoded)),
      }]);
    }
    const shippedRows: Row[] = [];
    for (const owner of shipped) {
      shippedRows.push({
        owner: SHIPPED_OWNER,
        timestamp: 0n,
        atom: offer(SHIPPED, WIRE, exact(owner)),
      });
    }
    this.#present(SHIPPED, WIRE, shippedRows);
    const steps = Math.min(this.pending, Math.max(0, Math.floor(bound)));
    for (let step = 0; step < steps; step += 1) this.#step(this.#pop());
  }

  run(limit = 100_000): void {
    for (let turn = 0; turn < limit && this.pending !== 0; turn += 1) {
      this.turn(undefined, [], 64);
    }
    if (this.pending !== 0) throw new Error("no quiescence");
  }

  get pending(): number {
    return this.#frontier.length - this.#head;
  }

  hasFact(owner: Uint8Array): boolean {
    return this.#facts.has(key(owner));
  }

  hasDurable(owner: Uint8Array): boolean {
    return this.#durable.has(key(owner));
  }

  verdict(owner: Uint8Array): Verdict | undefined {
    return this.#memo.get(key(owner));
  }

  durable(owner: Uint8Array): Bytes | undefined {
    const data = this.#durable.get(key(owner));
    return data === undefined ? undefined : Buffer.from(data);
  }

  #step(owner: Bytes): void {
    const resident = this.#facts.get(key(owner));
    if (resident === undefined) return;
    const needs = resident.fact.atoms
      .filter((atom): atom is NeedAtom => atom.kind === Kind.Need)
      .map((atom) => materialize(atom, owner));
    let output = outcome(Verdict.Parked);
    if (needs.some((atom) => atom.effect === Effect.Suppress && this.validOffers(atom).length !== 0)) {
      output = outcome(Verdict.Suppressed);
    } else if (needs.some((atom) => atom.effect === Effect.Require && this.validOffers(atom).length === 0)) {
      output = outcome(Verdict.Parked);
    } else {
      const context: Answer[] = needs
        .filter((atom) => atom.effect === Effect.Require || atom.effect === Effect.Watch)
        .map((atom) => ({ need: atom, rows: this.validOffers(atom) }));
      output = this.#root.project(cloneFact(resident.fact), context) ?? outcome(Verdict.Parked);
    }
    this.#settle(owner, resident.fact, output);
  }

  #settle(owner: Bytes, fact: Fact, output: Out): void {
    const id = key(owner);
    this.#memo.set(id, output.verdict);
    const old = this.#owned.get(id) ?? [];
    this.#owned.delete(id);
    for (const row of old) this.#clean.get(addressKey(row.atom.role, row.atom.scope))?.remove(row);
    const fresh: Row[] = [];
    if (output.verdict === Verdict.Valid) {
      for (const atom of output.offers) {
        const row: Row = { owner, timestamp: 0n, atom: materialize(atom, owner) };
        this.#bucket(this.#clean, addressKey(atom.role, atom.scope)).add(row);
        fresh.push(row);
      }
    }
    if (fresh.length !== 0) this.#owned.set(id, fresh);

    // Duplicates remain visible in indexes, but wake-up deltas compare semantic row sets.
    const before = new Map(old.map((row) => [rowKey(row), row]));
    const after = new Map(fresh.map((row) => [rowKey(row), row]));
    for (const [rowId, row] of before) if (!after.has(rowId)) this.#wake(row.atom as OfferAtom, id);
    for (const [rowId, row] of after) if (!before.has(rowId)) this.#wake(row.atom as OfferAtom, id);
    if (output.verdict === Verdict.Reap || output.verdict === Verdict.Suppressed) this.#evict(owner, fact);
  }

  #evict(owner: Bytes, fact: Fact): void {
    const id = key(owner);
    this.#facts.delete(id);
    this.#memo.delete(id);
    this.#owned.delete(id);
    this.#durable.delete(id);
    for (const atom of fact.atoms) {
      this.#rows.get(indexKey(atom.kind, atom.role, atom.scope))?.remove({
        owner,
        timestamp: 0n,
        atom: materialize(atom, owner),
      });
    }
  }

  #present(role: Bytes, scope: Bytes, rows: Row[]): void {
    const bucket = new Bucket();
    for (const row of rows) bucket.add(row);
    this.#clean.set(addressKey(role, scope), bucket);
    for (const row of rows) this.#wake(row.atom as OfferAtom);
  }

  #wake(atom: OfferAtom, skip?: string): void {
    for (const row of this.needsFor(atom)) if (key(row.owner) !== skip) this.#enqueue(row.owner);
  }

  #enqueue(owner: Bytes): void {
    const id = key(owner);
    if (this.#queued.has(id)) return;
    this.#frontier.push(Buffer.from(owner));
    this.#queued.add(id);
  }

  #pop(): Bytes {
    const owner = this.#frontier[this.#head]!;
    this.#head += 1;
    this.#queued.delete(key(owner));
    if (this.#head === this.#frontier.length) {
      this.#frontier = [];
      this.#head = 0;
    } else if (this.#head > 1024 && this.#head * 2 >= this.#frontier.length) {
      this.#frontier = this.#frontier.slice(this.#head);
      this.#head = 0;
    }
    return owner;
  }

  #bucket(index: Map<string, Bucket>, id: string): Bucket {
    let bucket = index.get(id);
    if (bucket === undefined) {
      bucket = new Bucket();
      index.set(id, bucket);
    }
    return bucket;
  }

  #matching(bucket: Bucket | undefined, target: Target): Row[] {
    return bucket?.matching(target) ?? [];
  }
}
