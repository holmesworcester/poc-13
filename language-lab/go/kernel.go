package lab

import (
	"encoding/binary"
	"errors"
)

type Row struct {
	Owner     ID
	Timestamp uint64
	Atom      Atom
}

type Verdict uint8

const (
	// Valid is the zero value so a projector's Out{} means "valid, no offers",
	// matching the callback contract. Unknown is only seeded by admission.
	Valid Verdict = iota
	Invalid
	Parked
	Suppressed
	Reap
	Unknown
)

type Out struct {
	Verdict Verdict
	Offers  []Atom
}

func ValidOut(offers ...Atom) Out { return Out{Verdict: Valid, Offers: offers} }

type Answer struct {
	Need Atom
	Rows []Row
}

type Context []Answer

func By(context Context, role Blob) []Row {
	var rows []Row
	for _, answer := range context {
		if answer.Need.Role == role {
			rows = append(rows, answer.Rows...)
		}
	}
	return rows
}

// Root returns ok=false from Project when no family owns a fact tag.
type Root interface {
	Extract(Fact) bool
	Project(Fact, Context) (output Out, ok bool)
}

type Bucket struct {
	exact  map[Blob][]Row
	ranges []Row
}

func NewBucket() *Bucket { return &Bucket{exact: make(map[Blob][]Row)} }

func (bucket *Bucket) Add(row Row) {
	target := row.Atom.Target
	if target.Lo == target.Hi {
		bucket.exact[target.Lo] = append(bucket.exact[target.Lo], row)
		return
	}
	bucket.ranges = append(bucket.ranges, row)
}

func (bucket *Bucket) Remove(row Row) {
	target := row.Atom.Target
	if target.Lo == target.Hi {
		rows := bucket.exact[target.Lo]
		for i := range rows {
			if rows[i] == row {
				rows = append(rows[:i], rows[i+1:]...)
				break
			}
		}
		if len(rows) == 0 {
			delete(bucket.exact, target.Lo)
		} else {
			bucket.exact[target.Lo] = rows
		}
		return
	}
	for i := range bucket.ranges {
		if bucket.ranges[i] == row {
			bucket.ranges = append(bucket.ranges[:i], bucket.ranges[i+1:]...)
			return
		}
	}
}

func (bucket *Bucket) Matching(target Target) []Row {
	if target.Lo == target.Hi {
		rows := append([]Row(nil), bucket.exact[target.Lo]...)
		for _, row := range bucket.ranges {
			if row.Atom.Target.Lo <= target.Lo && target.Lo <= row.Atom.Target.Hi {
				rows = append(rows, row)
			}
		}
		return rows
	}
	var rows []Row
	for point, matches := range bucket.exact {
		if target.Lo <= point && point <= target.Hi {
			rows = append(rows, matches...)
		}
	}
	return rows
}

func (bucket *Bucket) All() []Row {
	rows := make([]Row, 0, bucket.Len())
	for _, matches := range bucket.exact {
		rows = append(rows, matches...)
	}
	return append(rows, bucket.ranges...)
}

func (bucket *Bucket) Len() int {
	count := len(bucket.ranges)
	for _, rows := range bucket.exact {
		count += len(rows)
	}
	return count
}

type rowKey struct {
	Kind        Kind
	Role, Scope Blob
}

type address struct{ Role, Scope Blob }

var (
	nowRole      = B("now")
	nowScope     = B("clock")
	shippedRole  = B("shipped")
	shippedScope = B("wire")
	nowOwner     = ID{0xff, 'n', 'o', 'w'}
	shippedOwner = ID{0xff, 's', 'h', 'i', 'p'}
)

type Node struct {
	root Root

	durable map[ID]Blob
	facts   map[ID]Fact
	rows    map[rowKey]*Bucket
	memo    map[ID]Verdict
	clean   map[address]*Bucket
	owned   map[ID][]Row

	frontier []ID
	head     int
	queued   map[ID]struct{}
}

func NewNode(root Root) *Node {
	return &Node{
		root:    root,
		durable: make(map[ID]Blob),
		facts:   make(map[ID]Fact),
		rows:    make(map[rowKey]*Bucket),
		memo:    make(map[ID]Verdict),
		clean:   make(map[address]*Bucket),
		owned:   make(map[ID][]Row),
		queued:  make(map[ID]struct{}),
	}
}

func (node *Node) Admit(data []byte) (ID, bool) {
	fact, err := Decode(data)
	if err != nil {
		return ID{}, false
	}
	owner, err := FactID(fact)
	if err != nil {
		return ID{}, false
	}
	if _, exists := node.facts[owner]; exists {
		return owner, true
	}
	node.facts[owner] = fact
	node.memo[owner] = Unknown
	if node.root.Extract(cloneFact(fact)) {
		node.durable[owner] = Blob(string(data))
	}
	for _, atom := range fact.Atoms {
		key := rowKey{Kind: atom.Kind, Role: atom.Role, Scope: atom.Scope}
		bucket := node.rows[key]
		if bucket == nil {
			bucket = NewBucket()
			node.rows[key] = bucket
		}
		bucket.Add(Row{Owner: owner, Atom: Materialize(atom, owner)})
	}
	node.enqueue(owner)
	return owner, true
}

func (node *Node) OffersFor(need Atom) []Row {
	return matching(node.rows[rowKey{Kind: Offer, Role: need.Role, Scope: need.Scope}], need.Target)
}

func (node *Node) NeedsFor(offer Atom) []Row {
	return matching(node.rows[rowKey{Kind: Need, Role: offer.Role, Scope: offer.Scope}], offer.Target)
}

func (node *Node) ValidOffers(need Atom) []Row {
	return matching(node.clean[address{Role: need.Role, Scope: need.Scope}], need.Target)
}

func (node *Node) Watched(role, scope Blob) []Row {
	bucket := node.clean[address{Role: role, Scope: scope}]
	if bucket == nil {
		return nil
	}
	return bucket.All()
}

func (node *Node) Turn(nowMS *uint64, shipped []ID, bound int) {
	if nowMS != nil {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], *nowMS)
		now := Blob(string(encoded[:]))
		node.present(nowRole, nowScope, []Row{{
			Owner: nowOwner, Timestamp: *nowMS,
			Atom: OfferAtom(nowRole, nowScope, Exact(now)),
		}})
	}
	shippedRows := make([]Row, 0, len(shipped))
	for _, owner := range shipped {
		shippedRows = append(shippedRows, Row{
			Owner: shippedOwner,
			Atom:  OfferAtom(shippedRole, shippedScope, Exact(owner.Blob())),
		})
	}
	node.present(shippedRole, shippedScope, shippedRows)
	steps := node.Pending()
	if bound < steps {
		steps = bound
	}
	if steps < 0 {
		steps = 0
	}
	for range steps {
		owner := node.pop()
		node.step(owner)
	}
}

func (node *Node) Run() error {
	for range 100_000 {
		if node.Pending() == 0 {
			return nil
		}
		node.Turn(nil, nil, 64)
	}
	return errors.New("no quiescence")
}

func (node *Node) Pending() int { return len(node.frontier) - node.head }

func (node *Node) HasFact(owner ID) bool {
	_, ok := node.facts[owner]
	return ok
}

func (node *Node) HasDurable(owner ID) bool {
	_, ok := node.durable[owner]
	return ok
}

func (node *Node) Verdict(owner ID) (Verdict, bool) {
	verdict, ok := node.memo[owner]
	return verdict, ok
}

func (node *Node) Durable(owner ID) ([]byte, bool) {
	data, ok := node.durable[owner]
	return blobBytes(data), ok
}

func (node *Node) step(owner ID) {
	fact, exists := node.facts[owner]
	if !exists {
		return
	}
	needs := make([]Atom, 0)
	for _, atom := range fact.Atoms {
		if atom.Kind == Need {
			needs = append(needs, Materialize(atom, owner))
		}
	}
	output := Out{Verdict: Parked}
	if anyNeed(needs, Suppress, func(need Atom) bool { return len(node.ValidOffers(need)) != 0 }) {
		output = Out{Verdict: Suppressed}
	} else if anyNeed(needs, Require, func(need Atom) bool { return len(node.ValidOffers(need)) == 0 }) {
		output = Out{Verdict: Parked}
	} else {
		context := make(Context, 0, len(needs))
		for _, need := range needs {
			if need.Effect == Require || need.Effect == Watch {
				context = append(context, Answer{Need: need, Rows: node.ValidOffers(need)})
			}
		}
		if projected, ok := node.root.Project(cloneFact(fact), context); ok {
			output = projected
		}
	}
	node.settle(owner, fact, output)
}

func anyNeed(needs []Atom, effect Effect, predicate func(Atom) bool) bool {
	for _, need := range needs {
		if need.Effect == effect && predicate(need) {
			return true
		}
	}
	return false
}

func (node *Node) settle(owner ID, fact Fact, output Out) {
	node.memo[owner] = output.Verdict
	old := node.owned[owner]
	delete(node.owned, owner)
	for _, row := range old {
		node.clean[address{Role: row.Atom.Role, Scope: row.Atom.Scope}].Remove(row)
	}
	var fresh []Row
	if output.Verdict == Valid {
		fresh = make([]Row, 0, len(output.Offers))
		for _, atom := range output.Offers {
			row := Row{Owner: owner, Atom: Materialize(atom, owner)}
			key := address{Role: row.Atom.Role, Scope: row.Atom.Scope}
			bucket := node.clean[key]
			if bucket == nil {
				bucket = NewBucket()
				node.clean[key] = bucket
			}
			bucket.Add(row)
			fresh = append(fresh, row)
		}
	}
	if len(fresh) != 0 {
		node.owned[owner] = fresh
	}
	for row := range changedRows(old, fresh) {
		node.wake(row.Atom, &owner)
	}
	if output.Verdict == Reap || output.Verdict == Suppressed {
		node.evict(owner, fact)
	}
}

func changedRows(old, fresh []Row) map[Row]struct{} {
	changed := make(map[Row]struct{}, len(old)+len(fresh))
	for _, row := range old {
		changed[row] = struct{}{}
	}
	for _, row := range fresh {
		if _, exists := changed[row]; exists {
			delete(changed, row)
		} else {
			changed[row] = struct{}{}
		}
	}
	return changed
}

func (node *Node) evict(owner ID, fact Fact) {
	delete(node.facts, owner)
	delete(node.memo, owner)
	delete(node.owned, owner)
	delete(node.durable, owner)
	for _, atom := range fact.Atoms {
		key := rowKey{Kind: atom.Kind, Role: atom.Role, Scope: atom.Scope}
		if bucket := node.rows[key]; bucket != nil {
			bucket.Remove(Row{Owner: owner, Atom: Materialize(atom, owner)})
		}
	}
}

func (node *Node) present(role, scope Blob, rows []Row) {
	bucket := NewBucket()
	for _, row := range rows {
		bucket.Add(row)
	}
	node.clean[address{Role: role, Scope: scope}] = bucket
	for _, row := range rows {
		node.wake(row.Atom, nil)
	}
}

func (node *Node) wake(offer Atom, skip *ID) {
	for _, row := range node.NeedsFor(offer) {
		if skip == nil || row.Owner != *skip {
			node.enqueue(row.Owner)
		}
	}
}

func (node *Node) enqueue(owner ID) {
	if _, exists := node.queued[owner]; exists {
		return
	}
	node.frontier = append(node.frontier, owner)
	node.queued[owner] = struct{}{}
}

func (node *Node) pop() ID {
	owner := node.frontier[node.head]
	node.frontier[node.head] = ID{}
	node.head++
	delete(node.queued, owner)
	if node.head == len(node.frontier) {
		node.frontier = nil
		node.head = 0
	} else if node.head > 1024 && node.head*2 >= len(node.frontier) {
		node.frontier = append([]ID(nil), node.frontier[node.head:]...)
		node.head = 0
	}
	return owner
}

func matching(bucket *Bucket, target Target) []Row {
	if bucket == nil {
		return nil
	}
	return bucket.Matching(target)
}

func cloneFact(fact Fact) Fact {
	return Fact{Tag: fact.Tag, Atoms: append([]Atom(nil), fact.Atoms...)}
}
