from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from lab_kernel import Node, Row, frame, unframe


BOUND = 64


def cycle(
    node: Node,
    inbox: list[bytes],
    now_ms: int,
    shipped: tuple[bytes, ...] = (),
    bound: int = BOUND,
) -> Node:
    for data in inbox:
        node.admit(data)
    node.turn(now_ms, shipped, bound)
    return node


def outbox(node: Node) -> list[Row]:
    return node.watched(b"send", b"outbox") + node.watched(b"ship", b"outbox")


Route = Callable[[bytes], tuple[bytes, bytes | None] | None]
Deliver = Callable[[bytes, bytes, bytes | None, list[bytes]], int]


def pump(
    node: Node,
    route: Route,
    deliver: Deliver,
    shipped: set[bytes],
    sent: dict[bytes, set[bytes]] | None = None,
) -> set[bytes]:
    grouped: dict[bytes, list] = {}
    for row in outbox(node):
        if row.owner not in shipped:
            grouped.setdefault(row.owner, []).append(row.atom)
    fired: set[bytes] = set()
    for owner, atoms in sorted(grouped.items()):
        cid = atoms[0].target.lo
        resolved = route(cid)
        if resolved is None:
            continue
        address, secret = resolved
        seen = sent.setdefault(cid, set()) if sent is not None else set()
        inners: list[bytes] = []
        keys: list[bytes | None] = []
        for atom in sorted(atoms, key=lambda item: (item.role, item.value or b"")):
            if atom.role == b"send":
                if atom.value is not None:
                    inners.append(atom.value)
                    keys.append(None)
            elif atom.value is not None:
                for fact_key in unframe(atom.value):
                    if fact_key in node.durable and fact_key not in seen:
                        inners.append(node.durable[fact_key])
                        keys.append(fact_key)
        if inners:
            delivered = max(0, min(len(inners), deliver(cid, address, secret, inners)))
            if sent is not None:
                seen.update(key for key in keys[:delivered] if key is not None)
        fired.add(owner)
    return fired


def wire_message(kind: int, body: bytes) -> bytes:
    payload = bytes((kind,)) + body
    return len(payload).to_bytes(4, "big") + payload


@dataclass
class WireDecoder:
    buffer: bytearray = field(default_factory=bytearray)

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self.buffer.extend(data)
        messages: list[tuple[int, bytes]] = []
        while len(self.buffer) >= 4:
            size = int.from_bytes(self.buffer[:4], "big")
            if len(self.buffer) < 4 + size:
                break
            payload = bytes(self.buffer[4 : 4 + size])
            del self.buffer[: 4 + size]
            if payload:
                messages.append((payload[0], payload[1:]))
        return messages


@dataclass
class OutLink:
    capacity: int
    buffer: bytearray = field(default_factory=bytearray)
    offset: int = 0

    @property
    def pending(self) -> int:
        return len(self.buffer) - self.offset

    def enqueue(self, kind: int, body: bytes) -> bool:
        message = wire_message(kind, body)
        if self.pending + len(message) > self.capacity:
            return False
        self.buffer.extend(message)
        return True

    def take(self, size: int) -> bytes:
        end = min(len(self.buffer), self.offset + size)
        data = bytes(self.buffer[self.offset:end])
        self.offset = end
        if self.offset == len(self.buffer):
            self.buffer.clear()
            self.offset = 0
        elif self.offset > 1 << 20:
            del self.buffer[: self.offset]
            self.offset = 0
        return data
