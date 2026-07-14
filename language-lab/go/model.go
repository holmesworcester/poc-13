package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

// Blob is an opaque byte string. Go strings may contain arbitrary bytes and
// are comparable, which lets canonical atoms and targets serve as map keys.
type Blob string

func B(value string) Blob { return Blob(value) }

func blobBytes(value Blob) []byte { return []byte(value) }

type Kind uint8

const (
	Need Kind = iota
	Offer
)

type Effect uint8

const (
	None Effect = iota
	Require
	Watch
	Suppress
)

type TargetTag uint8

const (
	TargetExact TargetTag = iota
	TargetSelf
	TargetRange
)

type Target struct {
	Tag    TargetTag
	Lo, Hi Blob
}

func Exact(value Blob) Target { return Target{Tag: TargetExact, Lo: value, Hi: value} }
func Span(lo, hi Blob) Target {
	if lo == hi {
		return Exact(lo)
	}
	return Target{Tag: TargetRange, Lo: lo, Hi: hi}
}

var Self = Target{Tag: TargetSelf}

// Atom is comparable. HasValue distinguishes an absent value from an empty
// byte string, which have different canonical encodings.
type Atom struct {
	Kind     Kind
	Role     Blob
	Scope    Blob
	Target   Target
	Value    Blob
	HasValue bool
	Effect   Effect
}

func OfferAtom(role, scope Blob, target Target, value ...Blob) Atom {
	atom := Atom{Kind: Offer, Role: role, Scope: scope, Target: target}
	if len(value) != 0 {
		atom.Value, atom.HasValue = value[0], true
	}
	return atom
}

func NeedAtom(role, scope Blob, target Target, effect Effect, value ...Blob) Atom {
	atom := Atom{Kind: Need, Role: role, Scope: scope, Target: target, Effect: effect}
	if len(value) != 0 {
		atom.Value, atom.HasValue = value[0], true
	}
	return atom
}

type Fact struct {
	Tag   Blob
	Atoms []Atom
}

type ID [sha256.Size]byte

func (id ID) Blob() Blob { return Blob(string(id[:])) }
func (id ID) Bytes() []byte {
	return bytes.Clone(id[:])
}

func IDFromBlob(value Blob) (ID, bool) {
	var id ID
	if len(value) != len(id) {
		return id, false
	}
	copy(id[:], value)
	return id, true
}

func Frame(parts ...Blob) ([]byte, error) {
	total := uint64(0)
	for _, part := range parts {
		if uint64(len(part)) > math.MaxUint32 {
			return nil, errors.New("frame part too large")
		}
		total += 4 + uint64(len(part))
		if total > uint64(maxInt()) {
			return nil, errors.New("frame too large")
		}
	}
	out := make([]byte, int(total))
	offset := 0
	for _, part := range parts {
		binary.LittleEndian.PutUint32(out[offset:], uint32(len(part)))
		offset += 4
		copy(out[offset:], part)
		offset += len(part)
	}
	return out, nil
}

func Unframe(data []byte) ([]Blob, error) {
	parts := make([]Blob, 0)
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return nil, errors.New("truncated frame length")
		}
		size := uint64(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if size > uint64(len(data)-offset) {
			return nil, errors.New("truncated frame part")
		}
		end := offset + int(size)
		parts = append(parts, Blob(string(data[offset:end])))
		offset = end
	}
	return parts, nil
}

func EncodeAtom(atom Atom) ([]byte, error) {
	if atom.Kind > Offer || atom.Effect > Suppress || atom.Target.Tag > TargetRange {
		return nil, errors.New("bad atom tag")
	}
	if atom.Kind == Offer && atom.Effect != None {
		return nil, errors.New("effect on offer")
	}
	if len(atom.Role) != 0 && atom.Role[0] == 0 && (atom.Kind != Need || atom.Effect != Watch) {
		return nil, errors.New("reserved role")
	}
	targetTag := atom.Target.Tag
	if targetTag == TargetRange && atom.Target.Lo == atom.Target.Hi {
		targetTag = TargetExact
	}
	parts := []Blob{Blob(string([]byte{byte(atom.Kind), byte(atom.Effect), byte(targetTag)})), atom.Role, atom.Scope}
	switch targetTag {
	case TargetExact:
		parts = append(parts, atom.Target.Lo)
	case TargetSelf:
		// SELF has no target parts.
	case TargetRange:
		parts = append(parts, atom.Target.Lo, atom.Target.Hi)
	default:
		return nil, errors.New("bad target tag")
	}
	if atom.HasValue {
		parts = append(parts, atom.Value)
	}
	return Frame(parts...)
}

func DecodeAtom(data []byte) (Atom, error) {
	parts, err := Unframe(data)
	if err != nil {
		return Atom{}, err
	}
	if len(parts) < 3 || len(parts[0]) != 3 {
		return Atom{}, errors.New("bad atom header")
	}
	header := parts[0]
	atom := Atom{Kind: Kind(header[0]), Effect: Effect(header[1]), Role: parts[1], Scope: parts[2]}
	atom.Target.Tag = TargetTag(header[2])
	if atom.Kind > Offer || atom.Effect > Suppress || atom.Target.Tag > TargetRange {
		return Atom{}, errors.New("bad atom tag")
	}
	if atom.Kind == Offer && atom.Effect != None {
		return Atom{}, errors.New("effect on offer")
	}
	if len(atom.Role) != 0 && atom.Role[0] == 0 && (atom.Kind != Need || atom.Effect != Watch) {
		return Atom{}, errors.New("reserved role")
	}
	targetParts := [...]int{1, 0, 2}[atom.Target.Tag]
	if len(parts) != 3+targetParts && len(parts) != 4+targetParts {
		return Atom{}, errors.New("bad atom arity")
	}
	switch atom.Target.Tag {
	case TargetExact:
		atom.Target = Exact(parts[3])
	case TargetSelf:
		atom.Target = Self
	case TargetRange:
		if parts[3] == parts[4] {
			return Atom{}, errors.New("degenerate range")
		}
		atom.Target = Span(parts[3], parts[4])
	}
	if len(parts) == 4+targetParts {
		atom.Value, atom.HasValue = parts[3+targetParts], true
	}
	encoded, err := EncodeAtom(atom)
	if err != nil {
		return Atom{}, err
	}
	if !bytes.Equal(encoded, data) {
		return Atom{}, errors.New("non-canonical atom")
	}
	return atom, nil
}

func MakeFact(tag Blob, atoms ...Atom) (Fact, error) {
	unique := make(map[string][]byte, len(atoms))
	for _, atom := range atoms {
		encoded, err := EncodeAtom(atom)
		if err != nil {
			return Fact{}, err
		}
		unique[string(encoded)] = encoded
	}
	encoded := make([]string, 0, len(unique))
	for item := range unique {
		encoded = append(encoded, item)
	}
	sort.Strings(encoded)
	canonical := make([]Atom, 0, len(encoded))
	for _, item := range encoded {
		atom, err := DecodeAtom([]byte(item))
		if err != nil {
			return Fact{}, err
		}
		canonical = append(canonical, atom)
	}
	return Fact{Tag: tag, Atoms: canonical}, nil
}

func atomBlob(fact Fact) ([]byte, error) {
	var out []byte
	for _, atom := range fact.Atoms {
		encoded, err := EncodeAtom(atom)
		if err != nil {
			return nil, err
		}
		framed, err := Frame(Blob(string(encoded)))
		if err != nil {
			return nil, err
		}
		out = append(out, framed...)
	}
	return out, nil
}

func Encode(fact Fact) ([]byte, error) {
	head, err := Frame(fact.Tag)
	if err != nil {
		return nil, err
	}
	atoms, err := atomBlob(fact)
	if err != nil {
		return nil, err
	}
	return append(head, atoms...), nil
}

func Decode(data []byte) (Fact, error) {
	parts, err := Unframe(data)
	if err != nil {
		return Fact{}, err
	}
	if len(parts) == 0 {
		return Fact{}, errors.New("empty fact")
	}
	for i := 2; i < len(parts); i++ {
		if parts[i-1] >= parts[i] {
			return Fact{}, errors.New("unsorted or duplicate atoms")
		}
	}
	atoms := make([]Atom, 0, len(parts)-1)
	for _, encoded := range parts[1:] {
		atom, err := DecodeAtom(blobBytes(encoded))
		if err != nil {
			return Fact{}, err
		}
		atoms = append(atoms, atom)
	}
	fact := Fact{Tag: parts[0], Atoms: atoms}
	canonical, err := Encode(fact)
	if err != nil {
		return Fact{}, err
	}
	if !bytes.Equal(canonical, data) {
		return Fact{}, errors.New("non-canonical fact")
	}
	return fact, nil
}

var domain = B("tinyp2p.language-lab.v1")

func FactID(fact Fact) (ID, error) {
	atoms, err := atomBlob(fact)
	if err != nil {
		return ID{}, err
	}
	canonical, err := Frame(domain, fact.Tag, Blob(string(atoms)))
	if err != nil {
		return ID{}, err
	}
	return sha256.Sum256(canonical), nil
}

func Covers(offer, need Target) bool {
	if offer.Tag == TargetSelf || need.Tag == TargetSelf {
		return false
	}
	if need.Lo == need.Hi {
		return offer.Lo <= need.Lo && need.Lo <= offer.Hi
	}
	if offer.Lo == offer.Hi {
		return need.Lo <= offer.Lo && offer.Lo <= need.Hi
	}
	return false
}

func Materialize(atom Atom, owner ID) Atom {
	if atom.Target.Tag == TargetSelf {
		atom.Target = Exact(owner.Blob())
	}
	return atom
}

func maxInt() int { return int(^uint(0) >> 1) }
