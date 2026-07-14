use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub type FactId = [u8; 32];

const DOMAIN: &[u8] = b"tinyp2p.language-lab.v1";
pub const NOW_ROLE: &[u8] = b"now";
pub const NOW_SCOPE: &[u8] = b"clock";
pub const SHIPPED_ROLE: &[u8] = b"shipped";
pub const SHIPPED_SCOPE: &[u8] = b"wire";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Kind {
    Need = 0,
    Offer = 1,
}

impl TryFrom<u8> for Kind {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Need),
            1 => Ok(Self::Offer),
            _ => Err(CodecError::BadAtomTag),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Effect {
    None = 0,
    Require = 1,
    Watch = 2,
    Suppress = 3,
}

impl TryFrom<u8> for Effect {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Require),
            2 => Ok(Self::Watch),
            3 => Ok(Self::Suppress),
            _ => Err(CodecError::BadAtomTag),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Target {
    Exact(Vec<u8>),
    SelfRef,
    Range(Vec<u8>, Vec<u8>),
}

impl Target {
    fn bounds(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::Exact(value) => Some((value, value)),
            Self::Range(low, high) => Some((low, high)),
            Self::SelfRef => None,
        }
    }

    pub fn low(&self) -> Option<&[u8]> {
        self.bounds().map(|(low, _)| low)
    }
}

pub const SELF: Target = Target::SelfRef;

pub fn exact(value: impl AsRef<[u8]>) -> Target {
    Target::Exact(value.as_ref().to_vec())
}

pub fn span(low: impl AsRef<[u8]>, high: impl AsRef<[u8]>) -> Target {
    Target::Range(low.as_ref().to_vec(), high.as_ref().to_vec())
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Atom {
    pub kind: Kind,
    pub role: Vec<u8>,
    pub scope: Vec<u8>,
    pub target: Target,
    pub value: Option<Vec<u8>>,
    pub effect: Effect,
}

impl Atom {
    pub fn offer(
        role: impl AsRef<[u8]>,
        scope: impl AsRef<[u8]>,
        target: Target,
        value: Option<impl AsRef<[u8]>>,
    ) -> Self {
        Self {
            kind: Kind::Offer,
            role: role.as_ref().to_vec(),
            scope: scope.as_ref().to_vec(),
            target,
            value: value.map(|item| item.as_ref().to_vec()),
            effect: Effect::None,
        }
    }

    pub fn need(
        role: impl AsRef<[u8]>,
        scope: impl AsRef<[u8]>,
        target: Target,
        effect: Effect,
    ) -> Self {
        Self {
            kind: Kind::Need,
            role: role.as_ref().to_vec(),
            scope: scope.as_ref().to_vec(),
            target,
            value: None,
            effect,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fact {
    pub tag: Vec<u8>,
    pub atoms: Vec<Atom>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    FrameTooLarge,
    TruncatedLength,
    TruncatedPart,
    EmptyFact,
    BadAtomHeader,
    BadAtomTag,
    EffectOnOffer,
    ReservedRole,
    BadAtomArity,
    NonCanonicalAtom,
    UnsortedAtoms,
    NonCanonicalFact,
}

impl Display for CodecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::FrameTooLarge => "frame too large",
            Self::TruncatedLength => "truncated frame length",
            Self::TruncatedPart => "truncated frame part",
            Self::EmptyFact => "empty fact",
            Self::BadAtomHeader => "bad atom header",
            Self::BadAtomTag => "bad atom tag",
            Self::EffectOnOffer => "effect on offer",
            Self::ReservedRole => "reserved role",
            Self::BadAtomArity => "bad atom arity",
            Self::NonCanonicalAtom => "non-canonical atom",
            Self::UnsortedAtoms => "unsorted or duplicate atoms",
            Self::NonCanonicalFact => "non-canonical fact",
        };
        formatter.write_str(message)
    }
}

impl Error for CodecError {}

pub fn frame(parts: &[&[u8]]) -> Result<Vec<u8>, CodecError> {
    let total = parts.iter().try_fold(0_usize, |size, part| {
        let _ = u32::try_from(part.len()).map_err(|_| CodecError::FrameTooLarge)?;
        size.checked_add(4 + part.len())
            .ok_or(CodecError::FrameTooLarge)
    })?;
    let mut framed = Vec::with_capacity(total);
    for part in parts {
        let size = u32::try_from(part.len()).map_err(|_| CodecError::FrameTooLarge)?;
        framed.extend_from_slice(&size.to_le_bytes());
        framed.extend_from_slice(part);
    }
    Ok(framed)
}

pub fn unframe(data: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
    let mut parts = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let length = data
            .get(offset..offset + 4)
            .ok_or(CodecError::TruncatedLength)?;
        let size = u32::from_le_bytes(length.try_into().expect("four-byte slice")) as usize;
        offset += 4;
        let end = offset.checked_add(size).ok_or(CodecError::TruncatedPart)?;
        let part = data.get(offset..end).ok_or(CodecError::TruncatedPart)?;
        parts.push(part.to_vec());
        offset = end;
    }
    Ok(parts)
}

pub fn encode_atom(atom: &Atom) -> Result<Vec<u8>, CodecError> {
    let (target_tag, target_parts): (u8, Vec<&[u8]>) = match &atom.target {
        Target::Exact(value) => (0, vec![value]),
        Target::SelfRef => (1, Vec::new()),
        Target::Range(low, high) if low == high => (0, vec![low]),
        Target::Range(low, high) => (2, vec![low, high]),
    };
    let header = [atom.kind as u8, atom.effect as u8, target_tag];
    let mut parts = vec![
        header.as_slice(),
        atom.role.as_slice(),
        atom.scope.as_slice(),
    ];
    parts.extend(target_parts);
    if let Some(value) = &atom.value {
        parts.push(value);
    }
    frame(&parts)
}

pub fn decode_atom(data: &[u8]) -> Result<Atom, CodecError> {
    let parts = unframe(data)?;
    if parts.len() < 3 || parts[0].len() != 3 {
        return Err(CodecError::BadAtomHeader);
    }
    let kind = Kind::try_from(parts[0][0])?;
    let effect = Effect::try_from(parts[0][1])?;
    let target_tag = parts[0][2];
    if target_tag > 2 {
        return Err(CodecError::BadAtomTag);
    }
    if kind == Kind::Offer && effect != Effect::None {
        return Err(CodecError::EffectOnOffer);
    }
    if parts[1].first() == Some(&0) && (kind, effect) != (Kind::Need, Effect::Watch) {
        return Err(CodecError::ReservedRole);
    }
    let target_count = [1, 0, 2][usize::from(target_tag)];
    if parts.len() != 3 + target_count && parts.len() != 4 + target_count {
        return Err(CodecError::BadAtomArity);
    }
    let target = match target_tag {
        0 => Target::Exact(parts[3].clone()),
        1 => Target::SelfRef,
        2 => Target::Range(parts[3].clone(), parts[4].clone()),
        _ => unreachable!(),
    };
    let value = (parts.len() == 4 + target_count).then(|| parts[3 + target_count].clone());
    let atom = Atom {
        kind,
        role: parts[1].clone(),
        scope: parts[2].clone(),
        target,
        value,
        effect,
    };
    if encode_atom(&atom)? != data {
        return Err(CodecError::NonCanonicalAtom);
    }
    Ok(atom)
}

pub fn make_fact(
    tag: impl AsRef<[u8]>,
    atoms: impl IntoIterator<Item = Atom>,
) -> Result<Fact, CodecError> {
    let mut encoded = atoms
        .into_iter()
        .map(|atom| encode_atom(&atom))
        .collect::<Result<Vec<_>, _>>()?;
    encoded.sort_unstable();
    encoded.dedup();
    let atoms = encoded
        .iter()
        .map(|item| decode_atom(item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Fact {
        tag: tag.as_ref().to_vec(),
        atoms,
    })
}

fn atom_blob(fact: &Fact) -> Result<Vec<u8>, CodecError> {
    let mut blob = Vec::new();
    for atom in &fact.atoms {
        let encoded = encode_atom(atom)?;
        blob.extend(frame(&[&encoded])?);
    }
    Ok(blob)
}

pub fn encode(fact: &Fact) -> Result<Vec<u8>, CodecError> {
    let mut encoded = frame(&[&fact.tag])?;
    encoded.extend(atom_blob(fact)?);
    Ok(encoded)
}

pub fn decode(data: &[u8]) -> Result<Fact, CodecError> {
    let parts = unframe(data)?;
    let Some(tag) = parts.first() else {
        return Err(CodecError::EmptyFact);
    };
    let atom_parts = &parts[1..];
    if atom_parts.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CodecError::UnsortedAtoms);
    }
    let atoms = atom_parts
        .iter()
        .map(|item| decode_atom(item))
        .collect::<Result<Vec<_>, _>>()?;
    let fact = Fact {
        tag: tag.clone(),
        atoms,
    };
    if encode(&fact)? != data {
        return Err(CodecError::NonCanonicalFact);
    }
    Ok(fact)
}

pub fn fact_id(fact: &Fact) -> Result<FactId, CodecError> {
    let blob = atom_blob(fact)?;
    let encoded = frame(&[DOMAIN, &fact.tag, &blob])?;
    Ok(Sha256::digest(encoded).into())
}

pub fn covers(offer: &Target, need: &Target) -> bool {
    let (Some((offer_low, offer_high)), Some((need_low, need_high))) =
        (offer.bounds(), need.bounds())
    else {
        return false;
    };
    if need_low == need_high {
        offer_low <= need_low && need_low <= offer_high
    } else if offer_low == offer_high {
        need_low <= offer_low && offer_low <= need_high
    } else {
        false
    }
}

pub fn materialize(atom: &Atom, owner: &FactId) -> Atom {
    let mut materialized = atom.clone();
    if materialized.target == Target::SelfRef {
        materialized.target = exact(owner);
    }
    materialized
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignalOwner {
    Now,
    Shipped,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Owner {
    Fact(FactId),
    Signal(SignalOwner),
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Row {
    pub owner: Owner,
    pub timestamp: u64,
    pub atom: Atom,
}

impl Row {
    pub fn fact(owner: FactId, atom: Atom) -> Self {
        Self {
            owner: Owner::Fact(owner),
            timestamp: 0,
            atom,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Verdict {
    Unknown,
    Valid,
    Invalid,
    Parked,
    Suppressed,
    Reap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Out {
    pub verdict: Verdict,
    pub offers: Vec<Atom>,
}

impl Default for Out {
    fn default() -> Self {
        Self {
            verdict: Verdict::Valid,
            offers: Vec::new(),
        }
    }
}

impl Out {
    pub fn valid(offers: impl IntoIterator<Item = Atom>) -> Self {
        Self {
            verdict: Verdict::Valid,
            offers: offers.into_iter().collect(),
        }
    }

    pub fn verdict(verdict: Verdict) -> Self {
        Self {
            verdict,
            offers: Vec::new(),
        }
    }
}

pub type Context = Vec<(Atom, Vec<Row>)>;

pub fn by<'a>(context: &'a Context, role: &'a [u8]) -> impl Iterator<Item = &'a Row> {
    context
        .iter()
        .filter(move |(need, _)| need.role == role)
        .flat_map(|(_, rows)| rows)
}

pub trait Root {
    fn extract(&self, fact: &Fact) -> bool;
    fn project(&self, fact: &Fact, context: &Context) -> Option<Out>;
}

#[derive(Clone, Debug, Default)]
pub struct Bucket {
    exact: BTreeMap<Vec<u8>, Vec<Row>>,
    ranges: Vec<Row>,
}

impl Bucket {
    pub fn add(&mut self, row: Row) {
        let (low, high) = row
            .atom
            .target
            .bounds()
            .expect("resident rows have materialized targets");
        if low == high {
            self.exact.entry(low.to_vec()).or_default().push(row);
        } else {
            self.ranges.push(row);
        }
    }

    pub fn remove(&mut self, row: &Row) {
        let Some((low, high)) = row.atom.target.bounds() else {
            return;
        };
        if low == high {
            let remove_key = if let Some(rows) = self.exact.get_mut(low) {
                if let Some(position) = rows.iter().position(|candidate| candidate == row) {
                    rows.remove(position);
                }
                rows.is_empty()
            } else {
                false
            };
            if remove_key {
                self.exact.remove(low);
            }
        } else if let Some(position) = self.ranges.iter().position(|candidate| candidate == row) {
            self.ranges.remove(position);
        }
    }

    pub fn matching(&self, target: &Target) -> Vec<Row> {
        let Some((low, high)) = target.bounds() else {
            return Vec::new();
        };
        if low == high {
            let mut matches = self.exact.get(low).cloned().unwrap_or_default();
            matches.extend(
                self.ranges
                    .iter()
                    .filter(|row| {
                        let (range_low, range_high) =
                            row.atom.target.bounds().expect("materialized range");
                        range_low <= low && low <= range_high
                    })
                    .cloned(),
            );
            matches
        } else if low <= high {
            self.exact
                .range(low.to_vec()..=high.to_vec())
                .flat_map(|(_, rows)| rows.iter().cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn all(&self) -> Vec<Row> {
        self.exact
            .values()
            .flatten()
            .chain(&self.ranges)
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AssertedKey {
    kind: Kind,
    role: Vec<u8>,
    scope: Vec<u8>,
}

impl AssertedKey {
    fn new(kind: Kind, role: &[u8], scope: &[u8]) -> Self {
        Self {
            kind,
            role: role.to_vec(),
            scope: scope.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Address {
    role: Vec<u8>,
    scope: Vec<u8>,
}

impl Address {
    fn new(role: &[u8], scope: &[u8]) -> Self {
        Self {
            role: role.to_vec(),
            scope: scope.to_vec(),
        }
    }
}

pub struct Node<R: Root> {
    root: R,
    pub durable: HashMap<FactId, Vec<u8>>,
    pub facts: HashMap<FactId, Fact>,
    rows: HashMap<AssertedKey, Bucket>,
    pub memo: HashMap<FactId, Verdict>,
    clean: HashMap<Address, Bucket>,
    owned: HashMap<FactId, Vec<Row>>,
    pub frontier: VecDeque<FactId>,
    queued: HashSet<FactId>,
}

impl<R: Root> Node<R> {
    pub fn new(root: R) -> Self {
        Self {
            root,
            durable: HashMap::new(),
            facts: HashMap::new(),
            rows: HashMap::new(),
            memo: HashMap::new(),
            clean: HashMap::new(),
            owned: HashMap::new(),
            frontier: VecDeque::new(),
            queued: HashSet::new(),
        }
    }

    pub fn admit(&mut self, data: &[u8]) -> Option<FactId> {
        let fact = decode(data).ok()?;
        let owner = fact_id(&fact).ok()?;
        if self.facts.contains_key(&owner) {
            return Some(owner);
        }
        if self.root.extract(&fact) {
            self.durable.insert(owner, data.to_vec());
        }
        for atom in &fact.atoms {
            let key = AssertedKey::new(atom.kind, &atom.role, &atom.scope);
            self.rows
                .entry(key)
                .or_default()
                .add(Row::fact(owner, materialize(atom, &owner)));
        }
        self.facts.insert(owner, fact);
        self.memo.insert(owner, Verdict::Unknown);
        self.enqueue(owner);
        Some(owner)
    }

    pub fn offers_for(&self, need: &Atom) -> Vec<Row> {
        self.rows
            .get(&AssertedKey::new(Kind::Offer, &need.role, &need.scope))
            .map_or_else(Vec::new, |bucket| bucket.matching(&need.target))
    }

    pub fn needs_for(&self, offer: &Atom) -> Vec<Row> {
        self.rows
            .get(&AssertedKey::new(Kind::Need, &offer.role, &offer.scope))
            .map_or_else(Vec::new, |bucket| bucket.matching(&offer.target))
    }

    pub fn valid_offers(&self, need: &Atom) -> Vec<Row> {
        self.clean
            .get(&Address::new(&need.role, &need.scope))
            .map_or_else(Vec::new, |bucket| bucket.matching(&need.target))
    }

    pub fn watched(&self, role: &[u8], scope: &[u8]) -> Vec<Row> {
        self.clean
            .get(&Address::new(role, scope))
            .map_or_else(Vec::new, Bucket::all)
    }

    pub fn turn(&mut self, now_ms: Option<u64>, shipped: &[FactId], bound: usize) {
        if let Some(now_ms) = now_ms {
            let now = now_ms.to_be_bytes();
            self.present(
                NOW_ROLE,
                NOW_SCOPE,
                vec![Row {
                    owner: Owner::Signal(SignalOwner::Now),
                    timestamp: now_ms,
                    atom: Atom::offer(NOW_ROLE, NOW_SCOPE, exact(now), None::<&[u8]>),
                }],
            );
        }
        self.present(
            SHIPPED_ROLE,
            SHIPPED_SCOPE,
            shipped
                .iter()
                .map(|owner| Row {
                    owner: Owner::Signal(SignalOwner::Shipped),
                    timestamp: 0,
                    atom: Atom::offer(SHIPPED_ROLE, SHIPPED_SCOPE, exact(owner), None::<&[u8]>),
                })
                .collect(),
        );
        let steps = bound.min(self.frontier.len());
        for _ in 0..steps {
            let owner = self
                .frontier
                .pop_front()
                .expect("bounded by frontier length");
            self.queued.remove(&owner);
            self.step(owner);
        }
    }

    pub fn run(&mut self) -> Result<(), &'static str> {
        for _ in 0..100_000 {
            if self.frontier.is_empty() {
                return Ok(());
            }
            self.turn(None, &[], 64);
        }
        Err("no quiescence")
    }

    fn step(&mut self, owner: FactId) {
        let Some(fact) = self.facts.get(&owner).cloned() else {
            return;
        };
        let needs = fact
            .atoms
            .iter()
            .filter(|atom| atom.kind == Kind::Need)
            .map(|atom| materialize(atom, &owner))
            .collect::<Vec<_>>();
        let output = if needs
            .iter()
            .filter(|need| need.effect == Effect::Suppress)
            .any(|need| !self.valid_offers(need).is_empty())
        {
            Out::verdict(Verdict::Suppressed)
        } else if needs
            .iter()
            .filter(|need| need.effect == Effect::Require)
            .any(|need| self.valid_offers(need).is_empty())
        {
            Out::verdict(Verdict::Parked)
        } else {
            let context = needs
                .iter()
                .filter(|need| matches!(need.effect, Effect::Require | Effect::Watch))
                .map(|need| (need.clone(), self.valid_offers(need)))
                .collect();
            self.root
                .project(&fact, &context)
                .unwrap_or_else(|| Out::verdict(Verdict::Parked))
        };
        self.settle(owner, &fact, output);
    }

    fn settle(&mut self, owner: FactId, fact: &Fact, output: Out) {
        self.memo.insert(owner, output.verdict);
        let old = self.owned.remove(&owner).unwrap_or_default();
        for row in &old {
            if let Some(bucket) = self
                .clean
                .get_mut(&Address::new(&row.atom.role, &row.atom.scope))
            {
                bucket.remove(row);
            }
        }
        let new = if output.verdict == Verdict::Valid {
            output
                .offers
                .iter()
                .map(|atom| Row::fact(owner, materialize(atom, &owner)))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for row in &new {
            self.clean
                .entry(Address::new(&row.atom.role, &row.atom.scope))
                .or_default()
                .add(row.clone());
        }
        if !new.is_empty() {
            self.owned.insert(owner, new.clone());
        }
        let old_set = old.into_iter().collect::<HashSet<_>>();
        let new_set = new.into_iter().collect::<HashSet<_>>();
        let changed = old_set
            .symmetric_difference(&new_set)
            .cloned()
            .collect::<Vec<_>>();
        for row in changed {
            self.wake(&row.atom, Some(owner));
        }
        if matches!(output.verdict, Verdict::Reap | Verdict::Suppressed) {
            self.evict(owner, fact);
        }
    }

    fn evict(&mut self, owner: FactId, fact: &Fact) {
        self.facts.remove(&owner);
        self.memo.remove(&owner);
        self.owned.remove(&owner);
        self.durable.remove(&owner);
        for atom in &fact.atoms {
            let key = AssertedKey::new(atom.kind, &atom.role, &atom.scope);
            if let Some(bucket) = self.rows.get_mut(&key) {
                bucket.remove(&Row::fact(owner, materialize(atom, &owner)));
            }
        }
    }

    fn present(&mut self, role: &[u8], scope: &[u8], rows: Vec<Row>) {
        let mut bucket = Bucket::default();
        for row in &rows {
            bucket.add(row.clone());
        }
        self.clean.insert(Address::new(role, scope), bucket);
        for row in rows {
            self.wake(&row.atom, None);
        }
    }

    fn wake(&mut self, offer: &Atom, skip: Option<FactId>) {
        for row in self.needs_for(offer) {
            if let Owner::Fact(owner) = row.owner
                && Some(owner) != skip
            {
                self.enqueue(owner);
            }
        }
    }

    fn enqueue(&mut self, owner: FactId) {
        if self.queued.insert(owner) {
            self.frontier.push_back(owner);
        }
    }
}
