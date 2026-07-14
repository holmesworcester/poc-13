use crate::kernel::{CodecError, FactId, Node, Owner, Root, Row, unframe};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const BOUND: usize = 64;

pub fn cycle<R: Root>(
    node: &mut Node<R>,
    inbox: &[Vec<u8>],
    now_ms: u64,
    shipped: &[FactId],
    bound: usize,
) {
    for data in inbox {
        node.admit(data);
    }
    node.turn(Some(now_ms), shipped, bound);
}

pub fn outbox<R: Root>(node: &Node<R>) -> Vec<Row> {
    let mut rows = node.watched(b"send", b"outbox");
    rows.extend(node.watched(b"ship", b"outbox"));
    rows
}

pub type Sent = HashMap<Vec<u8>, HashSet<FactId>>;

pub fn pump<R, Route, Deliver>(
    node: &Node<R>,
    mut route: Route,
    mut deliver: Deliver,
    shipped: &HashSet<FactId>,
    mut sent: Option<&mut Sent>,
) -> Result<HashSet<FactId>, CodecError>
where
    R: Root,
    Route: FnMut(&[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)>,
    Deliver: FnMut(&[u8], &[u8], Option<&[u8]>, &[Vec<u8>]) -> usize,
{
    let mut grouped = BTreeMap::<FactId, Vec<_>>::new();
    for row in outbox(node) {
        if let Owner::Fact(owner) = row.owner
            && !shipped.contains(&owner)
        {
            grouped.entry(owner).or_default().push(row.atom);
        }
    }
    let mut fired = HashSet::new();
    for (owner, mut atoms) in grouped {
        let Some(cid) = atoms
            .first()
            .and_then(|atom| atom.target.low())
            .map(<[u8]>::to_vec)
        else {
            continue;
        };
        let Some((address, secret)) = route(&cid) else {
            continue;
        };
        atoms.sort_by(|left, right| {
            (&left.role, left.value.as_deref().unwrap_or_default())
                .cmp(&(&right.role, right.value.as_deref().unwrap_or_default()))
        });
        let mut inners = Vec::new();
        let mut keys = Vec::new();
        let mut temporary_seen = HashSet::new();
        let seen = if let Some(all_sent) = sent.as_deref_mut() {
            all_sent.entry(cid.clone()).or_default()
        } else {
            &mut temporary_seen
        };
        for atom in atoms {
            match (atom.role.as_slice(), atom.value) {
                (b"send", Some(value)) => {
                    inners.push(value);
                    keys.push(None);
                }
                (b"ship", Some(value)) => {
                    for fact_key in unframe(&value)? {
                        let Ok(fact_id) = FactId::try_from(fact_key.as_slice()) else {
                            continue;
                        };
                        if let Some(data) = node.durable.get(&fact_id)
                            && !seen.contains(&fact_id)
                        {
                            inners.push(data.clone());
                            keys.push(Some(fact_id));
                        }
                    }
                }
                _ => {}
            }
        }
        if !inners.is_empty() {
            let delivered = deliver(&cid, &address, secret.as_deref(), &inners).min(inners.len());
            for fact_id in keys.into_iter().take(delivered).flatten() {
                seen.insert(fact_id);
            }
        }
        fired.insert(owner);
    }
    Ok(fired)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    MessageTooLarge,
}

pub fn wire_message(kind: u8, body: &[u8]) -> Result<Vec<u8>, WireError> {
    let size = body
        .len()
        .checked_add(1)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(WireError::MessageTooLarge)?;
    let mut message = Vec::with_capacity(4 + size as usize);
    message.extend_from_slice(&size.to_be_bytes());
    message.push(kind);
    message.extend_from_slice(body);
    Ok(message)
}

#[derive(Clone, Debug, Default)]
pub struct WireDecoder {
    buffer: Vec<u8>,
}

impl WireDecoder {
    pub fn feed(&mut self, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        self.buffer.extend_from_slice(data);
        let mut messages = Vec::new();
        let mut offset = 0;
        while self.buffer.len().saturating_sub(offset) >= 4 {
            let size = u32::from_be_bytes(
                self.buffer[offset..offset + 4]
                    .try_into()
                    .expect("four-byte slice"),
            ) as usize;
            let Some(end) = offset
                .checked_add(4)
                .and_then(|start| start.checked_add(size))
            else {
                break;
            };
            if end > self.buffer.len() {
                break;
            }
            if size > 0 {
                messages.push((
                    self.buffer[offset + 4],
                    self.buffer[offset + 5..end].to_vec(),
                ));
            }
            offset = end;
        }
        if offset > 0 {
            self.buffer.drain(..offset);
        }
        messages
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[derive(Clone, Debug)]
pub struct OutLink {
    capacity: usize,
    buffer: Vec<u8>,
    offset: usize,
}

impl OutLink {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    pub fn pending(&self) -> usize {
        self.buffer.len() - self.offset
    }

    pub fn enqueue(&mut self, kind: u8, body: &[u8]) -> Result<bool, WireError> {
        let message = wire_message(kind, body)?;
        if self
            .pending()
            .checked_add(message.len())
            .is_none_or(|size| size > self.capacity)
        {
            return Ok(false);
        }
        self.buffer.extend(message);
        Ok(true)
    }

    pub fn take(&mut self, size: usize) -> Vec<u8> {
        let end = self.buffer.len().min(self.offset.saturating_add(size));
        let data = self.buffer[self.offset..end].to_vec();
        self.offset = end;
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        } else if self.offset > 1 << 20 {
            self.buffer.drain(..self.offset);
            self.offset = 0;
        }
        data
    }
}
