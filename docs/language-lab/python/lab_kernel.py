from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum, IntEnum
from hashlib import sha256
from typing import Protocol


class Kind(IntEnum):
    NEED = 0
    OFFER = 1


class Effect(IntEnum):
    NONE = 0
    REQUIRE = 1
    WATCH = 2
    SUPPRESS = 3


class TargetTag(IntEnum):
    EXACT = 0
    SELF = 1
    RANGE = 2


@dataclass(frozen=True)
class Target:
    tag: TargetTag
    lo: bytes = b""
    hi: bytes = b""


def exact(value: bytes) -> Target:
    return Target(TargetTag.EXACT, value, value)


SELF = Target(TargetTag.SELF)


def span(lo: bytes, hi: bytes) -> Target:
    return Target(TargetTag.RANGE, lo, hi)


@dataclass(frozen=True)
class Atom:
    kind: Kind
    role: bytes
    scope: bytes
    target: Target
    value: bytes | None = None
    effect: Effect = Effect.NONE


@dataclass(frozen=True)
class Fact:
    tag: bytes
    atoms: tuple[Atom, ...]


def frame(*parts: bytes) -> bytes:
    if any(len(part) >= 2**32 for part in parts):
        raise ValueError("frame too large")
    return b"".join(len(part).to_bytes(4, "little") + part for part in parts)


def unframe(data: bytes) -> list[bytes]:
    parts: list[bytes] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated length")
        size = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4
        end = offset + size
        if end > len(data):
            raise ValueError("truncated part")
        parts.append(data[offset:end])
        offset = end
    return parts


def encode_atom(atom: Atom) -> bytes:
    if atom.target.tag is TargetTag.SELF:
        targets = ()
        target_tag = TargetTag.SELF
    elif atom.target.lo == atom.target.hi:
        targets = (atom.target.lo,)
        target_tag = TargetTag.EXACT
    else:
        targets = (atom.target.lo, atom.target.hi)
        target_tag = TargetTag.RANGE
    value = () if atom.value is None else (atom.value,)
    return frame(
        bytes((atom.kind, atom.effect, target_tag)),
        atom.role,
        atom.scope,
        *targets,
        *value,
    )


def decode_atom(data: bytes) -> Atom:
    parts = unframe(data)
    if len(parts) < 3 or len(parts[0]) != 3:
        raise ValueError("bad atom header")
    try:
        kind, effect, target_tag = (
            Kind(parts[0][0]),
            Effect(parts[0][1]),
            TargetTag(parts[0][2]),
        )
    except ValueError as error:
        raise ValueError("bad atom tag") from error
    if kind is Kind.OFFER and effect is not Effect.NONE:
        raise ValueError("effect on offer")
    if parts[1].startswith(b"\0") and (kind, effect) != (Kind.NEED, Effect.WATCH):
        raise ValueError("reserved role")
    target_parts = (1, 0, 2)[target_tag]
    if len(parts) not in (3 + target_parts, 4 + target_parts):
        raise ValueError("bad atom arity")
    if target_tag is TargetTag.EXACT:
        target = exact(parts[3])
    elif target_tag is TargetTag.SELF:
        target = SELF
    else:
        target = span(parts[3], parts[4])
    value = parts[3 + target_parts] if len(parts) == 4 + target_parts else None
    atom = Atom(kind, parts[1], parts[2], target, value, effect)
    if encode_atom(atom) != data:
        raise ValueError("non-canonical atom")
    return atom


def make_fact(tag: bytes, *atoms: Atom) -> Fact:
    encoded = sorted({encode_atom(atom) for atom in atoms})
    return Fact(tag, tuple(decode_atom(item) for item in encoded))


def _atom_blob(fact: Fact) -> bytes:
    return b"".join(frame(encode_atom(atom)) for atom in fact.atoms)


def encode(fact: Fact) -> bytes:
    return frame(fact.tag) + _atom_blob(fact)


def decode(data: bytes) -> Fact:
    parts = unframe(data)
    if not parts:
        raise ValueError("empty fact")
    atom_parts = parts[1:]
    if any(left >= right for left, right in zip(atom_parts, atom_parts[1:])):
        raise ValueError("unsorted or duplicate atoms")
    fact = Fact(parts[0], tuple(decode_atom(item) for item in atom_parts))
    if encode(fact) != data:
        raise ValueError("non-canonical fact")
    return fact


DOMAIN = b"tinyp2p.language-lab.v1"


def fact_id(fact: Fact) -> bytes:
    return sha256(frame(DOMAIN, fact.tag, _atom_blob(fact))).digest()


def covers(offer: Target, need: Target) -> bool:
    if TargetTag.SELF in (offer.tag, need.tag):
        return False
    if need.lo == need.hi:
        return offer.lo <= need.lo <= offer.hi
    if offer.lo == offer.hi:
        return need.lo <= offer.lo <= need.hi
    return False


def materialize(atom: Atom, owner: bytes) -> Atom:
    return replace(atom, target=exact(owner)) if atom.target.tag is TargetTag.SELF else atom


@dataclass(frozen=True)
class Row:
    owner: bytes
    timestamp: int
    atom: Atom


class Verdict(str, Enum):
    UNKNOWN = "Unknown"
    VALID = "Valid"
    INVALID = "Invalid"
    PARKED = "Parked"
    SUPPRESSED = "Suppressed"
    REAP = "Reap"


@dataclass(frozen=True)
class Out:
    verdict: Verdict = Verdict.VALID
    offers: tuple[Atom, ...] = ()


Context = list[tuple[Atom, list[Row]]]


def by(context: Context, role: bytes) -> list[Row]:
    return [row for need, rows in context if need.role == role for row in rows]


class Root(Protocol):
    def extract(self, fact: Fact) -> bool: ...

    def project(self, fact: Fact, context: Context) -> Out | None: ...


@dataclass
class Bucket:
    exact: dict[bytes, list[Row]] = field(default_factory=dict)
    ranges: list[Row] = field(default_factory=list)

    def add(self, row: Row) -> None:
        target = row.atom.target
        if target.lo == target.hi:
            self.exact.setdefault(target.lo, []).append(row)
        else:
            self.ranges.append(row)

    def remove(self, row: Row) -> None:
        target = row.atom.target
        if target.lo == target.hi:
            rows = self.exact.get(target.lo, [])
            if row in rows:
                rows.remove(row)
            if not rows:
                self.exact.pop(target.lo, None)
        elif row in self.ranges:
            self.ranges.remove(row)

    def matching(self, target: Target) -> list[Row]:
        if target.lo == target.hi:
            return list(self.exact.get(target.lo, ())) + [
                row for row in self.ranges if row.atom.target.lo <= target.lo <= row.atom.target.hi
            ]
        return [
            row
            for point, rows in self.exact.items()
            if target.lo <= point <= target.hi
            for row in rows
        ]

    def all(self) -> list[Row]:
        return [row for rows in self.exact.values() for row in rows] + list(self.ranges)


NOW_ROLE, NOW_SCOPE = b"now", b"clock"
SHIPPED_ROLE, SHIPPED_SCOPE = b"shipped", b"wire"
NOW_OWNER, SHIPPED_OWNER = b"\0now", b"\0shipped"


class Node:
    def __init__(self, root: Root):
        self.root = root
        self.durable: dict[bytes, bytes] = {}
        self.facts: dict[bytes, Fact] = {}
        self.rows: dict[tuple[Kind, bytes, bytes], Bucket] = {}
        self.memo: dict[bytes, Verdict] = {}
        self.clean: dict[tuple[bytes, bytes], Bucket] = {}
        self.owned: dict[bytes, list[Row]] = {}
        self.frontier: deque[bytes] = deque()
        self.queued: set[bytes] = set()

    def admit(self, data: bytes) -> bytes | None:
        try:
            fact = decode(data)
        except ValueError:
            return None
        owner = fact_id(fact)
        if owner in self.facts:
            return owner
        self.facts[owner] = fact
        self.memo[owner] = Verdict.UNKNOWN
        if self.root.extract(fact):
            self.durable[owner] = data
        for atom in fact.atoms:
            key = (atom.kind, atom.role, atom.scope)
            self.rows.setdefault(key, Bucket()).add(Row(owner, 0, materialize(atom, owner)))
        self._enqueue(owner)
        return owner

    def offers_for(self, need: Atom) -> list[Row]:
        bucket = self.rows.get((Kind.OFFER, need.role, need.scope))
        return bucket.matching(need.target) if bucket else []

    def needs_for(self, offer: Atom) -> list[Row]:
        bucket = self.rows.get((Kind.NEED, offer.role, offer.scope))
        return bucket.matching(offer.target) if bucket else []

    def valid_offers(self, need: Atom) -> list[Row]:
        bucket = self.clean.get((need.role, need.scope))
        return bucket.matching(need.target) if bucket else []

    def watched(self, role: bytes, scope: bytes) -> list[Row]:
        bucket = self.clean.get((role, scope))
        return bucket.all() if bucket else []

    def turn(self, now_ms: int | None = None, shipped: tuple[bytes, ...] = (), bound: int = 64) -> None:
        if now_ms is not None:
            now = now_ms.to_bytes(8, "big")
            self._present(NOW_ROLE, NOW_SCOPE, [Row(NOW_OWNER, now_ms, Atom(Kind.OFFER, NOW_ROLE, NOW_SCOPE, exact(now)))])
        self._present(
            SHIPPED_ROLE,
            SHIPPED_SCOPE,
            [Row(SHIPPED_OWNER, 0, Atom(Kind.OFFER, SHIPPED_ROLE, SHIPPED_SCOPE, exact(owner))) for owner in shipped],
        )
        for _ in range(min(bound, len(self.frontier))):
            owner = self.frontier.popleft()
            self.queued.discard(owner)
            self._step(owner)

    def run(self) -> Node:
        for _ in range(100_000):
            if not self.frontier:
                return self
            self.turn()
        raise RuntimeError("no quiescence")

    def _step(self, owner: bytes) -> None:
        fact = self.facts.get(owner)
        if fact is None:
            return
        needs = [materialize(atom, owner) for atom in fact.atoms if atom.kind is Kind.NEED]
        if any(self.valid_offers(need) for need in needs if need.effect is Effect.SUPPRESS):
            output = Out(Verdict.SUPPRESSED)
        elif any(not self.valid_offers(need) for need in needs if need.effect is Effect.REQUIRE):
            output = Out(Verdict.PARKED)
        else:
            context = [
                (need, self.valid_offers(need))
                for need in needs
                if need.effect in (Effect.REQUIRE, Effect.WATCH)
            ]
            output = self.root.project(fact, context) or Out(Verdict.PARKED)
        self._settle(owner, fact, output)

    def _settle(self, owner: bytes, fact: Fact, output: Out) -> None:
        self.memo[owner] = output.verdict
        old = self.owned.pop(owner, [])
        for row in old:
            self.clean[(row.atom.role, row.atom.scope)].remove(row)
        new = (
            [Row(owner, 0, materialize(atom, owner)) for atom in output.offers]
            if output.verdict is Verdict.VALID
            else []
        )
        for row in new:
            self.clean.setdefault((row.atom.role, row.atom.scope), Bucket()).add(row)
        if new:
            self.owned[owner] = new
        for row in set(old) ^ set(new):
            self._wake(row.atom, owner)
        if output.verdict in (Verdict.REAP, Verdict.SUPPRESSED):
            self._evict(owner, fact)

    def _evict(self, owner: bytes, fact: Fact) -> None:
        self.facts.pop(owner, None)
        self.memo.pop(owner, None)
        self.owned.pop(owner, None)
        self.durable.pop(owner, None)
        for atom in fact.atoms:
            bucket = self.rows.get((atom.kind, atom.role, atom.scope))
            if bucket:
                bucket.remove(Row(owner, 0, materialize(atom, owner)))

    def _present(self, role: bytes, scope: bytes, rows: list[Row]) -> None:
        bucket = Bucket()
        for row in rows:
            bucket.add(row)
        self.clean[(role, scope)] = bucket
        for row in rows:
            self._wake(row.atom)

    def _wake(self, offer: Atom, skip: bytes | None = None) -> None:
        for row in self.needs_for(offer):
            if row.owner != skip:
                self._enqueue(row.owner)

    def _enqueue(self, owner: bytes) -> None:
        if owner not in self.queued:
            self.frontier.append(owner)
            self.queued.add(owner)
