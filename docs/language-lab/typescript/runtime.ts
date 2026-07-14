import { TargetTag, isOffer, key, unframe, type Bytes, type OfferAtom } from "./model.ts";
import { Node, type Row } from "./kernel.ts";

export const BOUND = 64;

export function cycle(
  node: Node,
  inbox: readonly Uint8Array[],
  nowMs: bigint,
  shipped: Iterable<Uint8Array> = [],
  bound = BOUND,
): void {
  for (const data of inbox) node.admit(data);
  node.turn(nowMs, shipped, bound);
}

export function outbox(node: Node): Row[] {
  return node.watched(Buffer.from("send"), Buffer.from("outbox"))
    .concat(node.watched(Buffer.from("ship"), Buffer.from("outbox")));
}

export interface Route {
  readonly address: Bytes;
  readonly secret: Bytes | undefined;
}

export type RouteResolver = (cid: Bytes) => Route | undefined;
export type Deliver = (cid: Bytes, route: Route, inners: readonly Bytes[]) => number;
export type Sent = Map<string, ByteSet>;

export class ByteSet implements Iterable<Bytes> {
  readonly #values = new Map<string, Bytes>();

  constructor(values: Iterable<Uint8Array> = []) {
    for (const value of values) this.add(value);
  }

  add(value: Uint8Array): this {
    this.#values.set(key(value), Buffer.from(value));
    return this;
  }

  has(value: Uint8Array): boolean {
    return this.#values.has(key(value));
  }

  get size(): number {
    return this.#values.size;
  }

  *[Symbol.iterator](): IterableIterator<Bytes> {
    for (const value of this.#values.values()) yield Buffer.from(value);
  }
}

interface Group {
  readonly owner: Bytes;
  readonly atoms: OfferAtom[];
}

export function pump(
  node: Node,
  resolveRoute: RouteResolver,
  deliver: Deliver,
  shipped: Iterable<Uint8Array> = [],
  sent?: Sent,
): ByteSet {
  const retained = shipped instanceof ByteSet ? shipped : new ByteSet(shipped);
  const grouped = new Map<string, Group>();
  for (const row of outbox(node)) {
    if (retained.has(row.owner) || !isOffer(row.atom)) continue;
    const id = key(row.owner);
    let group = grouped.get(id);
    if (group === undefined) {
      group = { owner: Buffer.from(row.owner), atoms: [] };
      grouped.set(id, group);
    }
    group.atoms.push(row.atom);
  }
  const groups = [...grouped.values()].sort((left, right) => Buffer.compare(left.owner, right.owner));
  const fired = new ByteSet();
  for (const group of groups) {
    const first = group.atoms[0];
    if (first === undefined || first.target.tag === TargetTag.Self) continue;
    const cid = first.target.tag === TargetTag.Exact ? first.target.value : first.target.lo;
    const route = resolveRoute(Buffer.from(cid));
    if (route === undefined) continue;
    let seen = sent?.get(key(cid));
    if (seen === undefined) {
      seen = new ByteSet();
      sent?.set(key(cid), seen);
    }
    const atoms = [...group.atoms].sort((left, right) => {
      const roleOrder = Buffer.compare(left.role, right.role);
      if (roleOrder !== 0) return roleOrder;
      return Buffer.compare(left.value ?? Buffer.alloc(0), right.value ?? Buffer.alloc(0));
    });
    const inners: Bytes[] = [];
    const tracked: (Bytes | undefined)[] = [];
    for (const atom of atoms) {
      if (atom.value === undefined) continue;
      if (atom.role.equals(Buffer.from("send"))) {
        inners.push(Buffer.from(atom.value));
        tracked.push(undefined);
      } else if (atom.role.equals(Buffer.from("ship"))) {
        for (const encoded of unframe(atom.value)) {
          if (encoded.length !== 32 || seen.has(encoded)) continue;
          const durable = node.durable(encoded);
          if (durable === undefined) continue;
          inners.push(durable);
          tracked.push(encoded);
        }
      }
    }
    if (inners.length !== 0) {
      const reported = deliver(Buffer.from(cid), route, inners.map((inner) => Buffer.from(inner)));
      const delivered = Number.isFinite(reported)
        ? Math.min(inners.length, Math.max(0, Math.trunc(reported)))
        : 0;
      if (sent !== undefined) {
        for (const id of tracked.slice(0, delivered)) if (id !== undefined) seen.add(id);
      }
    }
    fired.add(group.owner);
  }
  return fired;
}

export function wireMessage(kind: number, body: Uint8Array): Bytes {
  if (!Number.isInteger(kind) || kind < 0 || kind > 0xff) throw new RangeError("bad wire kind");
  if (body.byteLength + 1 > 0xffff_ffff) throw new RangeError("wire message too large");
  const result = Buffer.allocUnsafe(body.byteLength + 5);
  result.writeUInt32BE(body.byteLength + 1, 0);
  result[4] = kind;
  Buffer.from(body.buffer, body.byteOffset, body.byteLength).copy(result, 5);
  return result;
}

class ChunkQueue {
  #chunks: Bytes[] = [];
  #head = 0;
  #offset = 0;
  #pending = 0;

  get length(): number {
    return this.#pending;
  }

  get retained(): number {
    let size = 0;
    for (let index = this.#head; index < this.#chunks.length; index += 1) {
      size += this.#chunks[index]!.length;
    }
    return size;
  }

  push(data: Uint8Array): void {
    if (data.byteLength === 0) return;
    this.#chunks.push(Buffer.from(data));
    this.#pending += data.byteLength;
  }

  peekUInt32BE(): number | undefined {
    if (this.#pending < 4) return undefined;
    const first = this.#chunks[this.#head]!;
    if (first.length - this.#offset >= 4) return first.readUInt32BE(this.#offset);
    const header = Buffer.allocUnsafe(4);
    let written = 0;
    for (let index = this.#head; written < 4; index += 1) {
      const chunk = this.#chunks[index]!;
      const start = index === this.#head ? this.#offset : 0;
      const count = Math.min(chunk.length - start, 4 - written);
      chunk.copy(header, written, start, start + count);
      written += count;
    }
    return header.readUInt32BE(0);
  }

  take(limit: number): Bytes {
    const size = Math.min(this.#pending, Math.max(0, Math.floor(limit)));
    if (size === 0) return Buffer.alloc(0);
    const result = Buffer.allocUnsafe(size);
    let written = 0;
    while (written < size) {
      const chunk = this.#chunks[this.#head]!;
      const count = Math.min(chunk.length - this.#offset, size - written);
      chunk.copy(result, written, this.#offset, this.#offset + count);
      written += count;
      this.#offset += count;
      this.#pending -= count;
      if (this.#offset === chunk.length) {
        this.#chunks[this.#head] = Buffer.alloc(0);
        this.#head += 1;
        this.#offset = 0;
      }
    }
    if (this.#pending === 0) {
      this.#chunks = [];
      this.#head = 0;
    } else if (this.#offset > 1 << 20) {
      this.#chunks[this.#head] = Buffer.from(this.#chunks[this.#head]!.subarray(this.#offset));
      this.#offset = 0;
    } else if (this.#head > 1024 && this.#head * 2 >= this.#chunks.length) {
      this.#chunks = this.#chunks.slice(this.#head);
      this.#head = 0;
    }
    return result;
  }
}

export interface Wire {
  readonly kind: number;
  readonly body: Bytes;
}

export class WireDecoder {
  readonly #input = new ChunkQueue();

  feed(data: Uint8Array): Wire[] {
    this.#input.push(data);
    const messages: Wire[] = [];
    while (this.#input.length >= 4) {
      const size = this.#input.peekUInt32BE()!;
      if (size > this.#input.length - 4) break;
      this.#input.take(4);
      const payload = this.#input.take(size);
      if (payload.length !== 0) messages.push({ kind: payload[0]!, body: payload.subarray(1) });
    }
    return messages;
  }

  get buffered(): number {
    return this.#input.length;
  }

  get retained(): number {
    return this.#input.retained;
  }
}

export class OutLink {
  readonly #capacity: number;
  readonly #output = new ChunkQueue();

  constructor(capacity: number) {
    if (!Number.isSafeInteger(capacity) || capacity < 0) throw new RangeError("bad link capacity");
    this.#capacity = capacity;
  }

  enqueue(kind: number, body: Uint8Array): boolean {
    const message = wireMessage(kind, body);
    if (message.length > this.#capacity - this.pending) return false;
    this.#output.push(message);
    return true;
  }

  take(size: number): Bytes {
    return this.#output.take(size);
  }

  get pending(): number {
    return this.#output.length;
  }

  get retained(): number {
    return this.#output.retained;
  }
}
