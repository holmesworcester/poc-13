import { createHash } from "node:crypto";

export type Bytes = Buffer;

export const Kind = { Need: 0, Offer: 1 } as const;
export type Kind = (typeof Kind)[keyof typeof Kind];

export const Effect = { None: 0, Require: 1, Watch: 2, Suppress: 3 } as const;
export type Effect = (typeof Effect)[keyof typeof Effect];

export const TargetTag = { Exact: 0, Self: 1, Range: 2 } as const;

export interface ExactTarget {
  readonly tag: typeof TargetTag.Exact;
  readonly value: Bytes;
}

export interface SelfTarget {
  readonly tag: typeof TargetTag.Self;
}

export interface RangeTarget {
  readonly tag: typeof TargetTag.Range;
  readonly lo: Bytes;
  readonly hi: Bytes;
}

export type Target = ExactTarget | SelfTarget | RangeTarget;

interface AtomBase {
  readonly role: Bytes;
  readonly scope: Bytes;
  readonly target: Target;
  readonly value: Bytes | undefined;
}

export interface NeedAtom extends AtomBase {
  readonly kind: typeof Kind.Need;
  readonly effect: Effect;
}

export interface OfferAtom extends AtomBase {
  readonly kind: typeof Kind.Offer;
  readonly effect: typeof Effect.None;
}

export type Atom = NeedAtom | OfferAtom;

export interface Fact {
  readonly tag: Bytes;
  readonly atoms: readonly Atom[];
}

export const SELF: SelfTarget = { tag: TargetTag.Self };
const DOMAIN = Buffer.from("tinyp2p.language-lab.v1");

export function exact(value: Uint8Array): ExactTarget {
  return { tag: TargetTag.Exact, value: Buffer.from(value) };
}

export function span(lo: Uint8Array, hi: Uint8Array): Target {
  return Buffer.compare(lo, hi) === 0
    ? exact(lo)
    : { tag: TargetTag.Range, lo: Buffer.from(lo), hi: Buffer.from(hi) };
}

export function offer(
  role: Uint8Array,
  scope: Uint8Array,
  target: Target,
  value?: Uint8Array,
): OfferAtom {
  return {
    kind: Kind.Offer,
    effect: Effect.None,
    role: Buffer.from(role),
    scope: Buffer.from(scope),
    target: cloneTarget(target),
    value: value === undefined ? undefined : Buffer.from(value),
  };
}

export function need(
  role: Uint8Array,
  scope: Uint8Array,
  target: Target,
  effect: Effect,
  value?: Uint8Array,
): NeedAtom {
  return {
    kind: Kind.Need,
    effect,
    role: Buffer.from(role),
    scope: Buffer.from(scope),
    target: cloneTarget(target),
    value: value === undefined ? undefined : Buffer.from(value),
  };
}

export function isOffer(atom: Atom): atom is OfferAtom {
  return atom.kind === Kind.Offer;
}

export function key(value: Uint8Array): string {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex");
}

export function equal(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.compare(left, right) === 0;
}

export function frame(...parts: readonly Uint8Array[]): Bytes {
  let size = 0;
  for (const part of parts) {
    if (part.byteLength > 0xffff_ffff) throw new RangeError("frame part too large");
    size += 4 + part.byteLength;
    if (!Number.isSafeInteger(size) || size > 0x7fff_ffff) {
      throw new RangeError("frame too large");
    }
  }
  const result = Buffer.allocUnsafe(size);
  let offset = 0;
  for (const part of parts) {
    result.writeUInt32LE(part.byteLength, offset);
    offset += 4;
    Buffer.from(part.buffer, part.byteOffset, part.byteLength).copy(result, offset);
    offset += part.byteLength;
  }
  return result;
}

export function unframe(data: Uint8Array): Bytes[] {
  const input = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  const parts: Bytes[] = [];
  let offset = 0;
  while (offset < input.length) {
    if (input.length - offset < 4) throw new Error("truncated frame length");
    const size = input.readUInt32LE(offset);
    offset += 4;
    if (size > input.length - offset) throw new Error("truncated frame part");
    parts.push(Buffer.from(input.subarray(offset, offset + size)));
    offset += size;
  }
  return parts;
}

function canonicalTarget(target: Target): Target {
  return target.tag === TargetTag.Range && equal(target.lo, target.hi)
    ? exact(target.lo)
    : target;
}

function validateAtom(atom: Atom): void {
  if (atom.kind !== Kind.Need && atom.kind !== Kind.Offer) throw new Error("bad atom kind");
  if (!Object.values(Effect).includes(atom.effect)) throw new Error("bad atom effect");
  if (atom.kind === Kind.Offer && atom.effect !== Effect.None) throw new Error("effect on offer");
  if (atom.role[0] === 0 && (atom.kind !== Kind.Need || atom.effect !== Effect.Watch)) {
    throw new Error("reserved role");
  }
}

export function encodeAtom(atom: Atom): Bytes {
  validateAtom(atom);
  const target = canonicalTarget(atom.target);
  const header = Buffer.from([atom.kind, atom.effect, target.tag]);
  const parts: Bytes[] = [header, atom.role, atom.scope];
  if (target.tag === TargetTag.Exact) parts.push(target.value);
  if (target.tag === TargetTag.Range) parts.push(target.lo, target.hi);
  if (atom.value !== undefined) parts.push(atom.value);
  return frame(...parts);
}

export function decodeAtom(data: Uint8Array): Atom {
  const parts = unframe(data);
  const header = parts[0];
  if (parts.length < 3 || header === undefined || header.length !== 3) {
    throw new Error("bad atom header");
  }
  const role = parts[1];
  const scope = parts[2];
  if (role === undefined || scope === undefined) throw new Error("bad atom header");
  const kind = header[0];
  const effect = header[1];
  const targetTag = header[2];
  if ((kind !== Kind.Need && kind !== Kind.Offer) || !Object.values(Effect).includes(effect as Effect)) {
    throw new Error("bad atom tag");
  }
  if (kind === Kind.Offer && effect !== Effect.None) throw new Error("effect on offer");
  if (targetTag !== TargetTag.Exact && targetTag !== TargetTag.Self && targetTag !== TargetTag.Range) {
    throw new Error("bad target tag");
  }
  const targetParts = targetTag === TargetTag.Exact ? 1 : targetTag === TargetTag.Range ? 2 : 0;
  if (parts.length !== 3 + targetParts && parts.length !== 4 + targetParts) {
    throw new Error("bad atom arity");
  }
  let target: Target;
  if (targetTag === TargetTag.Exact) {
    target = exact(parts[3]!);
  } else if (targetTag === TargetTag.Range) {
    const lo = parts[3]!;
    const hi = parts[4]!;
    if (equal(lo, hi)) throw new Error("degenerate range");
    target = span(lo, hi);
  } else {
    target = SELF;
  }
  const valuePart = parts[3 + targetParts];
  const atom = kind === Kind.Offer
    ? offer(role, scope, target, valuePart)
    : need(role, scope, target, effect as Effect, valuePart);
  if (!equal(encodeAtom(atom), data)) throw new Error("non-canonical atom");
  return atom;
}

export function makeFact(tag: Uint8Array, ...atoms: readonly Atom[]): Fact {
  const unique = new Map<string, Bytes>();
  for (const atom of atoms) {
    const encoded = encodeAtom(atom);
    unique.set(key(encoded), encoded);
  }
  const encoded = [...unique.values()].sort(Buffer.compare);
  return { tag: Buffer.from(tag), atoms: encoded.map(decodeAtom) };
}

function atomBlob(fact: Fact): Bytes {
  return Buffer.concat(fact.atoms.map((atom) => frame(encodeAtom(atom))));
}

export function encodeFact(fact: Fact): Bytes {
  return Buffer.concat([frame(fact.tag), atomBlob(fact)]);
}

export function decodeFact(data: Uint8Array): Fact {
  const parts = unframe(data);
  const tag = parts[0];
  if (tag === undefined) throw new Error("empty fact");
  for (let index = 2; index < parts.length; index += 1) {
    if (Buffer.compare(parts[index - 1]!, parts[index]!) >= 0) {
      throw new Error("unsorted or duplicate atoms");
    }
  }
  const fact: Fact = { tag, atoms: parts.slice(1).map(decodeAtom) };
  if (!equal(encodeFact(fact), data)) throw new Error("non-canonical fact");
  return fact;
}

export function factId(fact: Fact): Bytes {
  return createHash("sha256").update(frame(DOMAIN, fact.tag, atomBlob(fact))).digest();
}

export function covers(offered: Target, wanted: Target): boolean {
  if (offered.tag === TargetTag.Self || wanted.tag === TargetTag.Self) return false;
  if (wanted.tag === TargetTag.Exact) {
    if (offered.tag === TargetTag.Exact) return equal(offered.value, wanted.value);
    return Buffer.compare(offered.lo, wanted.value) <= 0 && Buffer.compare(wanted.value, offered.hi) <= 0;
  }
  if (offered.tag !== TargetTag.Exact) return false;
  return Buffer.compare(wanted.lo, offered.value) <= 0 && Buffer.compare(offered.value, wanted.hi) <= 0;
}

export function materialize<A extends Atom>(atom: A, owner: Uint8Array): A {
  if (atom.target.tag !== TargetTag.Self) return cloneAtom(atom) as A;
  return { ...cloneAtom(atom), target: exact(owner) } as A;
}

export function cloneTarget(target: Target): Target {
  if (target.tag === TargetTag.Self) return SELF;
  if (target.tag === TargetTag.Exact) return exact(target.value);
  return span(target.lo, target.hi);
}

export function cloneAtom(atom: Atom): Atom {
  const value = atom.value === undefined ? undefined : Buffer.from(atom.value);
  return atom.kind === Kind.Offer
    ? offer(atom.role, atom.scope, atom.target, value)
    : need(atom.role, atom.scope, atom.target, atom.effect, value);
}

export function cloneFact(fact: Fact): Fact {
  return { tag: Buffer.from(fact.tag), atoms: fact.atoms.map(cloneAtom) };
}
