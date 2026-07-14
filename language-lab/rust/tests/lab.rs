use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;
use tinyp2p_language_lab::*;

#[derive(Clone, Default)]
struct DemoRoot {
    projections: Rc<Cell<usize>>,
}

impl Root for DemoRoot {
    fn extract(&self, fact: &Fact) -> bool {
        fact.tag != b"courier"
    }

    fn project(&self, fact: &Fact, context: &Context) -> Option<Out> {
        self.projections.set(self.projections.get() + 1);
        if fact.tag == b"invalid" {
            return Some(Out::verdict(Verdict::Invalid));
        }
        if fact.tag == b"courier" && by(context, b"shipped").next().is_some() {
            return Some(Out::verdict(Verdict::Reap));
        }
        if fact.tag == b"clock" && by(context, b"now").next().is_none() {
            return Some(Out::default());
        }
        if matches!(fact.tag.as_slice(), b"pass" | b"courier" | b"clock") {
            return Some(Out::valid(
                fact.atoms
                    .iter()
                    .filter(|atom| atom.kind == Kind::Offer)
                    .cloned(),
            ));
        }
        None
    }
}

fn offer(role: &[u8], scope: &[u8], target: Target, value: Option<&[u8]>) -> Atom {
    Atom::offer(role, scope, target, value)
}

fn need(role: &[u8], scope: &[u8], target: Target, effect: Effect) -> Atom {
    Atom::need(role, scope, target, effect)
}

fn pass(atoms: Vec<Atom>) -> Fact {
    make_fact(b"pass", atoms).unwrap()
}

#[test]
fn canonical_round_trip_golden_id_and_malformed_rejection() {
    let fact = pass(vec![
        offer(b"result", b"s", SELF, Some(b"ok")),
        need(b"dep", b"s", exact(b"key"), Effect::Require),
    ]);
    let blob = encode(&fact).unwrap();
    assert_eq!(decode(&blob).unwrap(), fact);
    assert_eq!(
        hex(&fact_id(&fact).unwrap()),
        "33a234f18d975af511b7648e6199ac1db55521a60b811e1478e57fe16943b8c7"
    );

    let duplicated = make_fact(
        b"pass",
        vec![
            fact.atoms[0].clone(),
            fact.atoms[1].clone(),
            fact.atoms[0].clone(),
        ],
    )
    .unwrap();
    assert_eq!(fact_id(&duplicated).unwrap(), fact_id(&fact).unwrap());

    assert!(decode(&blob[..blob.len() - 1]).is_err());
    let reversed = {
        let atoms = fact
            .atoms
            .iter()
            .rev()
            .flat_map(|atom| frame(&[&encode_atom(atom).unwrap()]).unwrap());
        let mut bytes = frame(&[&fact.tag]).unwrap();
        bytes.extend(atoms);
        bytes
    };
    assert!(decode(&reversed).is_err());
    let repeated_atom = encode_atom(&fact.atoms[0]).unwrap();
    let mut duplicate_wire = frame(&[&fact.tag]).unwrap();
    duplicate_wire.extend(frame(&[&repeated_atom]).unwrap());
    duplicate_wire.extend(frame(&[&repeated_atom]).unwrap());
    assert_eq!(decode(&duplicate_wire), Err(CodecError::UnsortedAtoms));

    let effect_on_offer = frame(&[b"\x01\x01\x00", b"r", b"s", b"x"]).unwrap();
    assert_eq!(
        decode_atom(&effect_on_offer),
        Err(CodecError::EffectOnOffer)
    );
    let reserved_offer = frame(&[b"\x01\x00\x00", b"\0private", b"s", b"x"]).unwrap();
    assert_eq!(decode_atom(&reserved_offer), Err(CodecError::ReservedRole));
    let extra = frame(&[b"\x01\x00\x00", b"r", b"s", b"x", b"v", b"extra"]).unwrap();
    assert_eq!(decode_atom(&extra), Err(CodecError::BadAtomArity));
    let degenerate_range = frame(&[b"\x01\x00\x02", b"r", b"s", b"x", b"x"]).unwrap();
    assert_eq!(
        decode_atom(&degenerate_range),
        Err(CodecError::NonCanonicalAtom)
    );
}

#[test]
fn exact_and_range_matching_work_in_both_directions() {
    let point = Row::fact([1; 32], offer(b"r", b"s", exact(b"m"), None));
    let ranged = Row::fact([2; 32], offer(b"r", b"s", span(b"a", b"z"), None));
    let mut bucket = Bucket::default();
    bucket.add(point.clone());
    bucket.add(ranged.clone());
    assert_eq!(
        bucket
            .matching(&exact(b"m"))
            .into_iter()
            .collect::<HashSet<_>>(),
        HashSet::from([point.clone(), ranged])
    );
    assert_eq!(bucket.matching(&span(b"l", b"n")), vec![point.clone()]);
    assert_eq!(bucket.matching(&span(b"a", b"z")), vec![point.clone()]);
    assert!(!covers(&span(b"a", b"z"), &span(b"a", b"z")));
    bucket.remove(&point);
    assert!(bucket.matching(&span(b"a", b"z")).is_empty());
}

#[test]
fn require_parks_then_offer_wakes_and_promotes() {
    let mut node = Node::new(DemoRoot::default());
    let dependent = pass(vec![
        need(b"dep", b"s", exact(b"key"), Effect::Require),
        offer(b"result", b"s", SELF, Some(b"yes")),
    ]);
    let dependent_id = node.admit(&encode(&dependent).unwrap()).unwrap();
    node.run().unwrap();
    assert_eq!(node.memo[&dependent_id], Verdict::Parked);
    assert!(node.watched(b"result", b"s").is_empty());

    let provider = pass(vec![offer(b"dep", b"s", exact(b"key"), Some(b"ready"))]);
    node.admit(&encode(&provider).unwrap()).unwrap();
    node.run().unwrap();
    assert_eq!(node.memo[&dependent_id], Verdict::Valid);
    assert_eq!(
        node.watched(b"result", b"s")
            .into_iter()
            .map(|row| row.owner)
            .collect::<Vec<_>>(),
        vec![Owner::Fact(dependent_id)]
    );
}

#[test]
fn suppress_precedes_projection_withdraws_and_evicts_owner() {
    let root = DemoRoot::default();
    let calls = Rc::clone(&root.projections);
    let mut node = Node::new(root);
    let victim = pass(vec![
        need(b"dead", b"s", SELF, Effect::Suppress),
        offer(b"live", b"s", SELF, None),
    ]);
    let victim_id = node.admit(&encode(&victim).unwrap()).unwrap();
    node.run().unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(node.watched(b"live", b"s").len(), 1);

    let killer = pass(vec![offer(b"dead", b"s", exact(victim_id), None)]);
    node.admit(&encode(&killer).unwrap()).unwrap();
    node.run().unwrap();
    assert_eq!(
        calls.get(),
        2,
        "the suppressed victim never reaches project"
    );
    assert!(!node.facts.contains_key(&victim_id));
    assert!(!node.memo.contains_key(&victim_id));
    assert!(!node.durable.contains_key(&victim_id));
    assert!(node.watched(b"live", b"s").is_empty());

    let second_killer = pass(vec![offer(
        b"dead",
        b"s",
        exact(victim_id),
        Some(b"new edge"),
    )]);
    node.admit(&encode(&second_killer).unwrap()).unwrap();
    node.run().unwrap();
    assert!(
        node.frontier.is_empty(),
        "evicted asserted needs cannot wake again"
    );

    let precedence_victim = pass(vec![
        need(b"dead-priority", b"s", SELF, Effect::Suppress),
        need(b"missing", b"s", exact(b"nothing"), Effect::Require),
        offer(b"never", b"s", SELF, None),
    ]);
    let precedence_id = fact_id(&precedence_victim).unwrap();
    let precedence_killer = pass(vec![offer(
        b"dead-priority",
        b"s",
        exact(precedence_id),
        None,
    )]);
    node.admit(&encode(&precedence_killer).unwrap()).unwrap();
    node.run().unwrap();
    let calls_before_precedence = calls.get();
    node.admit(&encode(&precedence_victim).unwrap()).unwrap();
    node.run().unwrap();
    assert!(!node.facts.contains_key(&precedence_id));
    assert_eq!(
        calls.get(),
        calls_before_precedence,
        "Suppress wins over the missing Require without calling project"
    );
}

#[test]
fn clock_watch_reprojects_and_turns_are_bounded() {
    let mut node = Node::new(DemoRoot::default());
    let clocked = make_fact(
        b"clock",
        vec![
            need(
                b"now",
                b"clock",
                span(100_u64.to_be_bytes(), [0xff; 8]),
                Effect::Watch,
            ),
            offer(b"ready", b"s", SELF, None),
        ],
    )
    .unwrap();
    node.admit(&encode(&clocked).unwrap()).unwrap();
    node.turn(Some(99), &[], 1);
    assert!(node.watched(b"ready", b"s").is_empty());
    node.turn(Some(100), &[], 1);
    assert_eq!(node.watched(b"ready", b"s").len(), 1);
    node.turn(Some(101), &[], 1);
    assert_eq!(
        node.watched(b"ready", b"s").len(),
        1,
        "re-projection replaces this owner's prior offer"
    );

    node.admit(&encode(&pass(vec![offer(b"a", b"s", SELF, None)])).unwrap());
    node.admit(&encode(&pass(vec![offer(b"b", b"s", SELF, None)])).unwrap());
    node.turn(None, &[], 1);
    assert_eq!(node.frontier.len(), 1);
}

#[test]
fn inline_pump_then_shipped_signal_reaps() {
    let mut node = Node::new(DemoRoot::default());
    let courier = make_fact(
        b"courier",
        vec![
            offer(b"send", b"outbox", exact(b"peer"), Some(b"hello")),
            need(b"shipped", b"wire", SELF, Effect::Watch),
        ],
    )
    .unwrap();
    let courier_id = fact_id(&courier).unwrap();
    cycle(&mut node, &[encode(&courier).unwrap()], 1, &[], BOUND);

    let mut received = Vec::new();
    let fired = pump(
        &node,
        |cid| (cid == b"peer").then(|| (b"127.0.0.1:9".to_vec(), Some(b"secret".to_vec()))),
        |_, _, _, inners| {
            received.extend_from_slice(inners);
            inners.len()
        },
        &HashSet::new(),
        None,
    )
    .unwrap();
    assert_eq!(received, vec![b"hello".to_vec()]);
    assert_eq!(fired, HashSet::from([courier_id]));

    cycle(
        &mut node,
        &[],
        2,
        &fired.iter().copied().collect::<Vec<_>>(),
        BOUND,
    );
    assert!(!node.facts.contains_key(&courier_id));
    assert!(outbox(&node).is_empty());
}

#[test]
fn by_reference_dedup_records_prefix_and_retries_tail() {
    let mut node = Node::new(DemoRoot::default());
    let first = pass(vec![offer(b"data", b"s", SELF, Some(b"one"))]);
    let second = pass(vec![offer(b"data", b"s", SELF, Some(b"two"))]);
    let first_id = fact_id(&first).unwrap();
    let second_id = fact_id(&second).unwrap();
    node.admit(&encode(&first).unwrap()).unwrap();
    node.admit(&encode(&second).unwrap()).unwrap();
    node.run().unwrap();

    let ids = frame(&[&first_id, &second_id]).unwrap();
    let shipper = make_fact(
        b"courier",
        vec![
            offer(b"ship", b"outbox", exact(b"peer"), Some(&ids)),
            need(b"shipped", b"wire", SELF, Effect::Watch),
        ],
    )
    .unwrap();
    cycle(&mut node, &[encode(&shipper).unwrap()], 1, &[], BOUND);

    let mut sent = Sent::new();
    let mut received = Vec::new();
    let fired = pump(
        &node,
        |_| Some((b"a".to_vec(), None)),
        |_, _, _, inners| {
            received.push(inners[0].clone());
            1
        },
        &HashSet::new(),
        Some(&mut sent),
    )
    .unwrap();
    assert_eq!(received, vec![encode(&first).unwrap()]);
    assert_eq!(sent[b"peer".as_slice()], HashSet::from([first_id]));
    assert!(!fired.is_empty());

    received.clear();
    pump(
        &node,
        |_| Some((b"a".to_vec(), None)),
        |_, _, _, inners| {
            received.extend_from_slice(inners);
            inners.len()
        },
        &HashSet::new(),
        Some(&mut sent),
    )
    .unwrap();
    assert_eq!(received, vec![encode(&second).unwrap()]);
    assert_eq!(
        sent[b"peer".as_slice()],
        HashSet::from([first_id, second_id])
    );
}

#[test]
fn fragmented_wire_input_and_bounded_partial_output() {
    let mut decoder = WireDecoder::default();
    let first = wire_message(0, b"hello").unwrap();
    let second = wire_message(1, b"world").unwrap();
    let wire = [first, second].concat();
    assert!(decoder.feed(&wire[..3]).is_empty());
    assert_eq!(decoder.buffered_len(), 3);
    assert!(decoder.feed(&wire[3..8]).is_empty());
    assert_eq!(
        decoder.feed(&wire[8..]),
        vec![(0, b"hello".to_vec()), (1, b"world".to_vec())]
    );
    assert_eq!(decoder.buffered_len(), 0);

    let mut link = OutLink::new(wire.len());
    assert!(link.enqueue(0, b"hello").unwrap());
    assert!(link.enqueue(1, b"world").unwrap());
    assert!(!link.enqueue(1, b"overflow").unwrap());
    let mut drained = link.take(3);
    assert_eq!(link.pending(), wire.len() - 3);
    drained.extend(link.take(10_000));
    assert_eq!(drained, wire);
    assert_eq!(link.pending(), 0);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
