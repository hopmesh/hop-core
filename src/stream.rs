//! Streaming sessions (SSE / WebSocket) carried as ordered sequences of bundles.
//! See DESIGN.md §20.
//!
//! A long-lived HTTP stream can't live on an intermittently-connected device, so
//! the **gateway holds the upstream connection** and relays it as a numbered
//! sequence of `StreamData` bundles. Bundles can arrive out of order, duplicated,
//! or after a gap (the device was offline), so each end runs:
//!
//! - a [`StreamReassembler`] that delivers chunks **in order**, dedups, buffers
//!   out-of-order arrivals, and reports the contiguous high-water mark to ACK;
//! - a [`StreamBuffer`] that holds **unacked** chunks so they can be resent when
//!   the peer reconnects after a gap, releasing them once acknowledged.
//!
//! Together these make partial stream data survive intermittent connectivity
//! without loss or reordering — the device simply catches up from where it left off.

use std::collections::BTreeMap;

/// Receives stream chunks and surfaces them in contiguous order.
#[derive(Default)]
pub struct StreamReassembler {
    /// Next sequence number to deliver (everything `< next` is delivered).
    next: u64,
    /// Out-of-order chunks held until the gap before them fills.
    buffer: BTreeMap<u64, Vec<u8>>,
    /// Sequence number carrying `fin`, once seen.
    fin_seq: Option<u64>,
    finished: bool,
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept one chunk. Returns the chunks (if any) that are now deliverable in
    /// order — possibly several at once when an arrival fills a gap, or none for a
    /// duplicate or a still-gapped arrival.
    pub fn accept(&mut self, seq: u64, bytes: Vec<u8>, fin: bool) -> Vec<Vec<u8>> {
        if seq < self.next || self.buffer.contains_key(&seq) {
            return Vec::new(); // duplicate / already delivered
        }
        if fin {
            self.fin_seq = Some(seq);
        }
        self.buffer.insert(seq, bytes);

        let mut delivered = Vec::new();
        while let Some(chunk) = self.buffer.remove(&self.next) {
            delivered.push(chunk);
            self.next += 1;
        }
        if let Some(f) = self.fin_seq {
            if self.next > f {
                self.finished = true;
            }
        }
        delivered
    }

    /// Highest contiguous sequence received (to put in a `StreamAck`), or `None`
    /// if nothing contiguous has arrived yet.
    pub fn ack_through(&self) -> Option<u64> {
        self.next.checked_sub(1)
    }

    /// Has the final (`fin`) chunk been delivered in order?
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Holds outbound chunks until the peer acknowledges them, so they can be resent
/// after the peer reconnects from a gap. Bounded — `push` refuses when full
/// (backpressure: the peer is too far behind).
pub struct StreamBuffer {
    next_seq: u64,
    unacked: BTreeMap<u64, Vec<u8>>,
    max_unacked: usize,
}

impl StreamBuffer {
    pub fn new(max_unacked: usize) -> Self {
        Self {
            next_seq: 0,
            unacked: BTreeMap::new(),
            max_unacked,
        }
    }

    /// Assign the next sequence number to `bytes` and buffer it. Returns the seq,
    /// or `None` if the unacked window is full (apply backpressure upstream).
    pub fn push(&mut self, bytes: Vec<u8>) -> Option<u64> {
        if self.unacked.len() >= self.max_unacked {
            return None;
        }
        let seq = self.next_seq;
        self.unacked.insert(seq, bytes);
        self.next_seq += 1;
        Some(seq)
    }

    /// Release everything the peer has acknowledged (contiguous through `ack`).
    pub fn ack(&mut self, ack: u64) {
        self.unacked.retain(|&seq, _| seq > ack);
    }

    /// Chunks still unacknowledged from `seq` onward, in order — to resend after a
    /// reconnect. (Pass the peer's last ACK + 1, or 0 to resend everything held.)
    pub fn resend_from(&self, seq: u64) -> Vec<(u64, Vec<u8>)> {
        self.unacked
            .range(seq..)
            .map(|(s, b)| (*s, b.clone()))
            .collect()
    }

    /// Number of chunks still awaiting acknowledgement.
    pub fn pending(&self) -> usize {
        self.unacked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivers_in_order_and_finishes() {
        let mut r = StreamReassembler::new();
        assert_eq!(r.accept(0, b"a".to_vec(), false), vec![b"a".to_vec()]);
        assert_eq!(r.accept(1, b"b".to_vec(), false), vec![b"b".to_vec()]);
        assert_eq!(r.ack_through(), Some(1));
        assert!(!r.is_finished());
        assert_eq!(r.accept(2, b"c".to_vec(), true), vec![b"c".to_vec()]);
        assert!(r.is_finished());
    }

    #[test]
    fn buffers_out_of_order_then_drains_on_gap_fill() {
        let mut r = StreamReassembler::new();
        // Chunks arrive 2, 1, then 0 — nothing deliverable until 0 fills the gap.
        assert!(r.accept(2, b"c".to_vec(), true).is_empty());
        assert!(r.accept(1, b"b".to_vec(), false).is_empty());
        assert_eq!(r.ack_through(), None);
        let drained = r.accept(0, b"a".to_vec(), false);
        assert_eq!(drained, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(r.ack_through(), Some(2));
        assert!(r.is_finished());
    }

    #[test]
    fn ignores_duplicates() {
        let mut r = StreamReassembler::new();
        assert_eq!(r.accept(0, b"a".to_vec(), false), vec![b"a".to_vec()]);
        assert!(
            r.accept(0, b"a".to_vec(), false).is_empty(),
            "already delivered"
        );
        assert!(r.accept(2, b"c".to_vec(), false).is_empty());
        assert!(
            r.accept(2, b"c".to_vec(), false).is_empty(),
            "buffered dup ignored"
        );
    }

    #[test]
    fn buffer_resends_unacked_after_reconnect() {
        let mut b = StreamBuffer::new(8);
        assert_eq!(b.push(b"0".to_vec()), Some(0));
        assert_eq!(b.push(b"1".to_vec()), Some(1));
        assert_eq!(b.push(b"2".to_vec()), Some(2));

        b.ack(0); // peer confirmed through seq 0
        assert_eq!(b.pending(), 2);

        // Peer reconnected having last acked 0 — resend from 1.
        let resend = b.resend_from(1);
        assert_eq!(resend, vec![(1, b"1".to_vec()), (2, b"2".to_vec())]);
    }

    #[test]
    fn buffer_applies_backpressure_when_full() {
        let mut b = StreamBuffer::new(2);
        assert_eq!(b.push(vec![0]), Some(0));
        assert_eq!(b.push(vec![1]), Some(1));
        assert_eq!(b.push(vec![2]), None, "window full → backpressure");
        b.ack(0);
        assert_eq!(b.push(vec![2]), Some(2), "room after ack");
    }
}
