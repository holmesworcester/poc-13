package lab

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type demoRoot struct{}

func (demoRoot) Extract(fact Fact) bool { return fact.Tag != B("courier") }

func (demoRoot) Project(fact Fact, context Context) (Out, bool) {
	switch {
	case fact.Tag == B("invalid"):
		return Out{Verdict: Invalid}, true
	case fact.Tag == B("courier") && len(By(context, B("shipped"))) != 0:
		return Out{Verdict: Reap}, true
	case fact.Tag == B("clock") && len(By(context, B("now"))) == 0:
		return ValidOut(), true
	case fact.Tag == B("pass") || fact.Tag == B("courier") || fact.Tag == B("clock") || fact.Tag == B("duplicate"):
		offers := make([]Atom, 0)
		for _, atom := range fact.Atoms {
			if atom.Kind == Offer {
				offers = append(offers, atom)
			}
		}
		if fact.Tag == B("duplicate") && len(offers) != 0 {
			offers = append(offers, offers[0])
		}
		return ValidOut(offers...), true
	default:
		return Out{}, false
	}
}

func mustFact(t *testing.T, tag Blob, atoms ...Atom) Fact {
	t.Helper()
	fact, err := MakeFact(tag, atoms...)
	if err != nil {
		t.Fatal(err)
	}
	return fact
}

func mustEncode(t *testing.T, fact Fact) []byte {
	t.Helper()
	data, err := Encode(fact)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustID(t *testing.T, fact Fact) ID {
	t.Helper()
	id, err := FactID(fact)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustWire(t *testing.T, kind byte, body string) []byte {
	t.Helper()
	wire, err := WireMessage(kind, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustFramedIDs(t *testing.T, ids ...ID) Blob {
	t.Helper()
	parts := make([]Blob, len(ids))
	for i, id := range ids {
		parts[i] = id.Blob()
	}
	framed, err := Frame(parts...)
	if err != nil {
		t.Fatal(err)
	}
	return Blob(string(framed))
}

func mustFrame(t *testing.T, parts ...Blob) []byte {
	t.Helper()
	framed, err := Frame(parts...)
	if err != nil {
		t.Fatal(err)
	}
	return framed
}

func requireRun(t *testing.T, node *Node) {
	t.Helper()
	if err := node.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalRoundTripGoldenIDAndMalformedRejection(t *testing.T) {
	result := OfferAtom(B("result"), B("s"), Self, B("ok"))
	dependency := NeedAtom(B("dep"), B("s"), Exact(B("key")), Require)
	fact := mustFact(t, B("pass"), result, dependency, result)
	reordered := mustFact(t, B("pass"), dependency, result)
	if got, want := mustID(t, fact), mustID(t, reordered); got != want {
		t.Fatalf("canonical construction changed id: %x != %x", got, want)
	}
	normalized := mustFact(t, B("pass"), OfferAtom(B("r"), B("s"), Span(B("x"), B("x"))))
	if normalized.Atoms[0].Target != Exact(B("x")) {
		t.Fatal("construction did not normalize a degenerate range to Exact")
	}
	blob := mustEncode(t, fact)
	decoded, err := Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustEncode(t, decoded), blob) {
		t.Fatal("strict round trip changed bytes")
	}
	id := mustID(t, fact)
	if got := hex.EncodeToString(id[:]); got != "33a234f18d975af511b7648e6199ac1db55521a60b811e1478e57fe16943b8c7" {
		t.Fatalf("golden id = %s", got)
	}

	node := NewNode(demoRoot{})
	if _, ok := node.Admit(blob[:len(blob)-1]); ok {
		t.Fatal("truncated fact admitted")
	}
	reversed := mustFrame(t, fact.Tag)
	for i := len(fact.Atoms) - 1; i >= 0; i-- {
		encoded, encodeErr := EncodeAtom(fact.Atoms[i])
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		reversed = append(reversed, mustFrame(t, Blob(string(encoded)))...)
	}
	if _, ok := node.Admit(reversed); ok {
		t.Fatal("unsorted fact admitted")
	}

	degenerate := mustFrame(t,
		Blob(string([]byte{byte(Need), byte(Watch), byte(TargetRange)})),
		B("r"), B("s"), B("x"), B("x"),
	)
	if _, err := DecodeAtom(degenerate); err == nil {
		t.Fatal("degenerate range admitted")
	}
	extra := mustFrame(t,
		Blob(string([]byte{byte(Need), byte(Watch), byte(TargetExact)})),
		B("r"), B("s"), B("x"), B("value"), B("extra"),
	)
	if _, err := DecodeAtom(extra); err == nil {
		t.Fatal("atom with extra parts admitted")
	}
	reserved := mustFrame(t,
		Blob(string([]byte{byte(Offer), byte(None), byte(TargetExact)})),
		B("\x00reserved"), B("s"), B("x"),
	)
	if _, err := DecodeAtom(reserved); err == nil {
		t.Fatal("reserved-role offer admitted")
	}
	effectedOffer := mustFrame(t,
		Blob(string([]byte{byte(Offer), byte(Require), byte(TargetExact)})),
		B("r"), B("s"), B("x"),
	)
	if _, err := DecodeAtom(effectedOffer); err == nil {
		t.Fatal("effect-bearing offer admitted")
	}
	absent, err := EncodeAtom(OfferAtom(B("r"), B("s"), Exact(B("x"))))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := EncodeAtom(OfferAtom(B("r"), B("s"), Exact(B("x")), B("")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(absent, empty) {
		t.Fatal("absent and empty values encoded identically")
	}
	owner, ok := node.Admit(blob)
	if !ok || owner != id || node.Pending() != 1 {
		t.Fatalf("canonical admission = %x, %v, pending=%d", owner, ok, node.Pending())
	}
	if repeated, repeatedOK := node.Admit(blob); !repeatedOK || repeated != owner || node.Pending() != 1 {
		t.Fatal("admission was not idempotent")
	}
	unknown := mustFact(t, B("no-family"))
	unknownID, unknownOK := node.Admit(mustEncode(t, unknown))
	if !unknownOK {
		t.Fatal("unknown family was not admitted")
	}
	requireRun(t, node)
	if verdict, exists := node.Verdict(unknownID); !exists || verdict != Parked {
		t.Fatalf("unknown family verdict = %v, %v", verdict, exists)
	}
}

func TestBucketMatchesExactAndRangeBothDirections(t *testing.T) {
	point := Row{Atom: OfferAtom(B("r"), B("s"), Exact(B("m")))}
	ranged := Row{Owner: ID{1}, Atom: OfferAtom(B("r"), B("s"), Span(B("a"), B("z")))}
	bucket := NewBucket()
	bucket.Add(point)
	bucket.Add(ranged)
	got := bucket.Matching(Exact(B("m")))
	if len(got) != 2 || !containsRow(got, point) || !containsRow(got, ranged) {
		t.Fatalf("point match = %#v", got)
	}
	for _, target := range []Target{Span(B("l"), B("n")), Span(B("a"), B("z"))} {
		got = bucket.Matching(target)
		if len(got) != 1 || got[0] != point {
			t.Fatalf("range match %v = %#v", target, got)
		}
	}
	if Covers(Span(B("a"), B("z")), Span(B("b"), B("y"))) || Covers(Self, Exact(B("x"))) {
		t.Fatal("range-range or SELF matched")
	}
}

func TestRequireParksThenOfferWakesAndPromotes(t *testing.T) {
	node := NewNode(demoRoot{})
	dependent := mustFact(t, B("pass"),
		NeedAtom(B("dep"), B("s"), Exact(B("key")), Require),
		OfferAtom(B("result"), B("s"), Self, B("yes")),
	)
	dependentID, ok := node.Admit(mustEncode(t, dependent))
	if !ok {
		t.Fatal("dependent not admitted")
	}
	requireRun(t, node)
	if verdict, exists := node.Verdict(dependentID); !exists || verdict != Parked {
		t.Fatalf("initial verdict = %v, %v", verdict, exists)
	}
	if rows := node.Watched(B("result"), B("s")); len(rows) != 0 {
		t.Fatalf("parked offers published: %#v", rows)
	}
	provider := mustFact(t, B("duplicate"), OfferAtom(B("dep"), B("s"), Exact(B("key")), B("ready")))
	node.Admit(mustEncode(t, provider))
	requireRun(t, node)
	if verdict, _ := node.Verdict(dependentID); verdict != Valid {
		t.Fatalf("promoted verdict = %v", verdict)
	}
	rows := node.Watched(B("result"), B("s"))
	if len(rows) != 1 || rows[0].Owner != dependentID {
		t.Fatalf("published rows = %#v", rows)
	}
}

func TestSuppressPrecedesRequireWithdrawsAndEvicts(t *testing.T) {
	node := NewNode(demoRoot{})
	victim := mustFact(t, B("pass"),
		NeedAtom(B("dead"), B("s"), Self, Suppress),
		OfferAtom(B("live"), B("s"), Self),
	)
	victimID, _ := node.Admit(mustEncode(t, victim))
	requireRun(t, node)
	if len(node.Watched(B("live"), B("s"))) != 1 {
		t.Fatal("victim did not initially publish")
	}
	killer := mustFact(t, B("pass"), OfferAtom(B("dead"), B("s"), Exact(victimID.Blob())))
	node.Admit(mustEncode(t, killer))
	requireRun(t, node)
	if node.HasFact(victimID) || node.HasDurable(victimID) || len(node.Watched(B("live"), B("s"))) != 0 {
		t.Fatal("suppression did not withdraw and evict whole owner")
	}

	precedence := mustFact(t, B("pass"),
		NeedAtom(B("missing"), B("s"), Exact(B("never")), Require),
		NeedAtom(B("dead"), B("s"), Self, Suppress),
	)
	precedenceID := mustID(t, precedence)
	precedenceKiller := mustFact(t, B("pass"), OfferAtom(B("dead"), B("s"), Exact(precedenceID.Blob())))
	node.Admit(mustEncode(t, precedenceKiller))
	requireRun(t, node)
	node.Admit(mustEncode(t, precedence))
	requireRun(t, node)
	if node.HasFact(precedenceID) {
		t.Fatal("missing Require won over matching Suppress")
	}
}

func TestClockWatchReprojectsAndTurnIsBounded(t *testing.T) {
	node := NewNode(demoRoot{})
	var deadline [8]byte
	deadline[7] = 100
	clocked := mustFact(t, B("clock"),
		NeedAtom(B("now"), B("clock"), Span(Blob(string(deadline[:])), Blob(string(bytes.Repeat([]byte{0xff}, 8)))), Watch),
		OfferAtom(B("ready"), B("s"), Self),
	)
	node.Admit(mustEncode(t, clocked))
	early := uint64(99)
	node.Turn(&early, nil, 1)
	if len(node.Watched(B("ready"), B("s"))) != 0 {
		t.Fatal("clock fired early")
	}
	due := uint64(100)
	node.Turn(&due, nil, 1)
	if len(node.Watched(B("ready"), B("s"))) != 1 {
		t.Fatal("clock did not reproject at deadline")
	}
	later := uint64(101)
	node.Turn(&later, nil, 1)
	nowRows := node.Watched(B("now"), B("clock"))
	wantNow := Exact(Blob(string([]byte{0, 0, 0, 0, 0, 0, 0, 101})))
	if len(nowRows) != 1 || nowRows[0].Atom.Target != wantNow {
		t.Fatalf("clock slot did not replace: %#v", nowRows)
	}
	a := mustFact(t, B("pass"), OfferAtom(B("a"), B("s"), Self))
	b := mustFact(t, B("pass"), OfferAtom(B("b"), B("s"), Self))
	node.Admit(mustEncode(t, a))
	node.Admit(mustEncode(t, b))
	node.Turn(nil, nil, 1)
	if node.Pending() != 1 {
		t.Fatalf("bounded turn left %d pending, want 1", node.Pending())
	}
}

func TestInlineCourierPumpThenShippedReaps(t *testing.T) {
	node := NewNode(demoRoot{})
	courier := mustFact(t, B("courier"),
		OfferAtom(B("send"), B("outbox"), Exact(B("peer")), B("hello")),
		NeedAtom(B("shipped"), B("wire"), Self, Watch),
	)
	courierID := mustID(t, courier)
	Cycle(node, [][]byte{mustEncode(t, courier)}, 1, nil, Bound)
	var got [][]byte
	fired, err := Pump(node,
		func(cid Blob) (Route, bool) {
			secret := B("secret")
			return Route{Address: B("127.0.0.1:9"), Secret: &secret}, cid == B("peer")
		},
		func(_ Blob, _ Route, inners [][]byte) int {
			got = append(got, inners...)
			return len(inners)
		}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0]) != "hello" {
		t.Fatalf("delivered = %q", got)
	}
	if _, ok := fired[courierID]; !ok {
		t.Fatal("courier did not fire")
	}
	node.Admit(mustEncode(t, mustFact(t, B("pass"), OfferAtom(B("backlog-a"), B("s"), Self))))
	node.Admit(mustEncode(t, mustFact(t, B("pass"), OfferAtom(B("backlog-b"), B("s"), Self))))
	Cycle(node, nil, 2, []ID{courierID}, 1)
	if !node.HasFact(courierID) {
		t.Fatal("bounded backlog unexpectedly consumed the courier")
	}
	redelivered := 0
	refired, err := Pump(node,
		func(cid Blob) (Route, bool) { return Route{Address: B("a")}, cid == B("peer") },
		func(_ Blob, _ Route, inners [][]byte) int { redelivered += len(inners); return len(inners) },
		fired, nil)
	if err != nil || len(refired) != 0 || redelivered != 0 {
		t.Fatalf("retained shipped owner re-pumped: fired=%v delivered=%d err=%v", refired, redelivered, err)
	}
	Cycle(node, nil, 3, []ID{courierID}, 1)
	Cycle(node, nil, 4, []ID{courierID}, 1)
	if node.HasFact(courierID) || len(Outbox(node)) != 0 {
		t.Fatal("shipped courier did not reap")
	}
}

func TestReferenceDedupAndUndeliveredTailRetry(t *testing.T) {
	node := NewNode(demoRoot{})
	first := mustFact(t, B("pass"), OfferAtom(B("data"), B("s"), Self, B("one")))
	second := mustFact(t, B("pass"), OfferAtom(B("data"), B("s"), Self, B("two")))
	firstID, secondID := mustID(t, first), mustID(t, second)
	node.Admit(mustEncode(t, first))
	node.Admit(mustEncode(t, second))
	requireRun(t, node)
	shipper := func(round Blob) Fact {
		return mustFact(t, B("courier"),
			OfferAtom(B("ship"), B("outbox"), Exact(B("peer")), mustFramedIDs(t, firstID, secondID)),
			OfferAtom(B("round"), B("test"), Self, round),
			NeedAtom(B("shipped"), B("wire"), Self, Watch),
		)
	}
	firstShipper := shipper(B("one"))
	firstShipperID := mustID(t, firstShipper)
	Cycle(node, [][]byte{mustEncode(t, firstShipper)}, 1, nil, Bound)
	sent := make(Sent)
	var got [][]byte
	fired, err := Pump(node,
		func(Blob) (Route, bool) { return Route{Address: B("a")}, true },
		func(_ Blob, _ Route, inners [][]byte) int {
			got = append(got, inners[0])
			return 1
		}, nil, sent)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], mustEncode(t, first)) {
		t.Fatalf("first delivery = %x", got)
	}
	if _, ok := sent[B("peer")][firstID]; !ok || len(sent[B("peer")]) != 1 {
		t.Fatalf("sent after prefix = %#v", sent[B("peer")])
	}
	if _, ok := fired[firstShipperID]; !ok {
		t.Fatal("first shipper did not fire")
	}
	Cycle(node, nil, 2, []ID{firstShipperID}, Bound)
	if node.HasFact(firstShipperID) {
		t.Fatal("first shipper did not reap")
	}
	secondShipper := shipper(B("two"))
	Cycle(node, [][]byte{mustEncode(t, secondShipper)}, 3, nil, Bound)
	got = nil
	_, err = Pump(node,
		func(Blob) (Route, bool) { return Route{Address: B("a")}, true },
		func(_ Blob, _ Route, inners [][]byte) int {
			got = append(got, inners...)
			return len(inners)
		}, nil, sent)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], mustEncode(t, second)) {
		t.Fatalf("retry delivery = %x", got)
	}
	if len(sent[B("peer")]) != 2 {
		t.Fatalf("sent after retry = %#v", sent[B("peer")])
	}
}

func TestFragmentedWireAndBoundedPartialOutput(t *testing.T) {
	first := mustWire(t, 0, "hello")
	second := mustWire(t, 1, "world")
	wire := append(append([]byte(nil), first...), second...)
	decoder := &WireDecoder{}
	if got := decoder.Feed(wire[:3]); len(got) != 0 {
		t.Fatalf("decoded incomplete header: %#v", got)
	}
	if got := decoder.Feed(wire[3:8]); len(got) != 0 {
		t.Fatalf("decoded incomplete body: %#v", got)
	}
	got := decoder.Feed(wire[8:])
	if len(got) != 2 || got[0].Kind != 0 || string(got[0].Body) != "hello" || got[1].Kind != 1 || string(got[1].Body) != "world" {
		t.Fatalf("decoded messages = %#v", got)
	}
	if decoder.Buffered() != 0 {
		t.Fatalf("decoder retained %d bytes", decoder.Buffered())
	}

	link, err := NewOutLink(len(wire))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		kind byte
		body string
	}{{0, "hello"}, {1, "world"}} {
		ok, enqueueErr := link.Enqueue(item.kind, []byte(item.body))
		if enqueueErr != nil || !ok {
			t.Fatalf("enqueue = %v, %v", ok, enqueueErr)
		}
	}
	if ok, enqueueErr := link.Enqueue(1, []byte("overflow")); enqueueErr != nil || ok {
		t.Fatalf("overflow enqueue = %v, %v", ok, enqueueErr)
	}
	drained := append(link.Take(3), link.Take(int(^uint(0)>>1))...)
	if !bytes.Equal(drained, wire) || link.Pending() != 0 {
		t.Fatalf("partial drain = %x, pending=%d", drained, link.Pending())
	}
}

func containsRow(rows []Row, wanted Row) bool {
	for _, row := range rows {
		if row == wanted {
			return true
		}
	}
	return false
}
