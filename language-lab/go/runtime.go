package lab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

const Bound = 64

func Cycle(node *Node, inbox [][]byte, nowMS uint64, shipped []ID, bound int) {
	for _, data := range inbox {
		node.Admit(data)
	}
	node.Turn(&nowMS, shipped, bound)
}

func Outbox(node *Node) []Row {
	return append(node.Watched(B("send"), B("outbox")), node.Watched(B("ship"), B("outbox"))...)
}

type Route struct {
	Address Blob
	Secret  *Blob
}

type RouteFunc func(cid Blob) (Route, bool)
type DeliverFunc func(cid Blob, route Route, inners [][]byte) int
type IDSet map[ID]struct{}
type Sent map[Blob]IDSet

type deliveryKey struct {
	id      ID
	tracked bool
}

func Pump(node *Node, route RouteFunc, deliver DeliverFunc, shipped IDSet, sent Sent) (IDSet, error) {
	grouped := make(map[ID][]Atom)
	for _, row := range Outbox(node) {
		if _, done := shipped[row.Owner]; !done {
			grouped[row.Owner] = append(grouped[row.Owner], row.Atom)
		}
	}
	owners := make([]ID, 0, len(grouped))
	for owner := range grouped {
		owners = append(owners, owner)
	}
	sort.Slice(owners, func(i, j int) bool { return bytes.Compare(owners[i][:], owners[j][:]) < 0 })
	fired := make(IDSet)
	for _, owner := range owners {
		atoms := grouped[owner]
		cid := atoms[0].Target.Lo
		resolved, ok := route(cid)
		if !ok {
			continue
		}
		var seen IDSet
		if sent != nil {
			seen = sent[cid]
			if seen == nil {
				seen = make(IDSet)
				sent[cid] = seen
			}
		} else {
			seen = make(IDSet)
		}
		sort.SliceStable(atoms, func(i, j int) bool {
			if atoms[i].Role != atoms[j].Role {
				return atoms[i].Role < atoms[j].Role
			}
			return atoms[i].Value < atoms[j].Value
		})
		var inners [][]byte
		var keys []deliveryKey
		for _, atom := range atoms {
			switch {
			case atom.Role == B("send") && atom.HasValue:
				inners = append(inners, blobBytes(atom.Value))
				keys = append(keys, deliveryKey{})
			case atom.Role == B("ship") && atom.HasValue:
				ids, err := Unframe(blobBytes(atom.Value))
				if err != nil {
					return nil, err
				}
				for _, encoded := range ids {
					id, valid := IDFromBlob(encoded)
					if !valid {
						continue
					}
					if _, duplicate := seen[id]; duplicate {
						continue
					}
					data, durable := node.Durable(id)
					if !durable {
						continue
					}
					inners = append(inners, data)
					keys = append(keys, deliveryKey{id: id, tracked: true})
				}
			}
		}
		if len(inners) != 0 {
			delivered := deliver(cid, resolved, inners)
			if delivered < 0 {
				delivered = 0
			}
			if delivered > len(inners) {
				delivered = len(inners)
			}
			if sent != nil {
				for _, key := range keys[:delivered] {
					if key.tracked {
						seen[key.id] = struct{}{}
					}
				}
			}
		}
		fired[owner] = struct{}{}
	}
	return fired, nil
}

func WireMessage(kind byte, body []byte) ([]byte, error) {
	if uint64(len(body))+1 > math.MaxUint32 {
		return nil, errors.New("wire message too large")
	}
	out := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(out, uint32(1+len(body)))
	out[4] = kind
	copy(out[5:], body)
	return out, nil
}

type Wire struct {
	Kind byte
	Body []byte
}

type WireDecoder struct {
	buffer []byte
	offset int
}

func (decoder *WireDecoder) Feed(data []byte) []Wire {
	decoder.compact(false)
	decoder.buffer = append(decoder.buffer, data...)
	var messages []Wire
	for len(decoder.buffer)-decoder.offset >= 4 {
		size := uint64(binary.BigEndian.Uint32(decoder.buffer[decoder.offset:]))
		available := uint64(len(decoder.buffer) - decoder.offset - 4)
		if size > available {
			break
		}
		start := decoder.offset + 4
		end := start + int(size)
		if size != 0 {
			payload := decoder.buffer[start:end]
			messages = append(messages, Wire{Kind: payload[0], Body: bytes.Clone(payload[1:])})
		}
		decoder.offset = end
	}
	decoder.compact(true)
	return messages
}

func (decoder *WireDecoder) Buffered() int { return len(decoder.buffer) - decoder.offset }

func (decoder *WireDecoder) compact(forceEmpty bool) {
	if decoder.offset == len(decoder.buffer) && forceEmpty {
		decoder.buffer = nil
		decoder.offset = 0
	} else if decoder.offset > 1<<20 {
		decoder.buffer = append([]byte(nil), decoder.buffer[decoder.offset:]...)
		decoder.offset = 0
	}
}

type OutLink struct {
	capacity int
	buffer   []byte
	offset   int
}

func NewOutLink(capacity int) (*OutLink, error) {
	if capacity < 0 {
		return nil, errors.New("negative link capacity")
	}
	return &OutLink{capacity: capacity}, nil
}

func (link *OutLink) Pending() int { return len(link.buffer) - link.offset }

func (link *OutLink) Enqueue(kind byte, body []byte) (bool, error) {
	message, err := WireMessage(kind, body)
	if err != nil {
		return false, err
	}
	if len(message) > link.capacity-link.Pending() {
		return false, nil
	}
	link.buffer = append(link.buffer, message...)
	return true, nil
}

func (link *OutLink) Take(size int) []byte {
	if size <= 0 || link.Pending() == 0 {
		return nil
	}
	end := len(link.buffer)
	if size < link.Pending() {
		end = link.offset + size
	}
	data := bytes.Clone(link.buffer[link.offset:end])
	link.offset = end
	if link.offset == len(link.buffer) {
		link.buffer = nil
		link.offset = 0
	} else if link.offset > 1<<20 {
		link.buffer = append([]byte(nil), link.buffer[link.offset:]...)
		link.offset = 0
	}
	return data
}
