//! Bounded, byte-accounted channels for host-side driver event loops.
//!
//! `sync_channel` bounds event count, but not the heap retained by those events and not one
//! producer's share of the queue. This wrapper reserves count and bytes before enqueueing and
//! releases the reservation as soon as the consumer receives the event.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::mpsc::{self, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Admission limits for one event channel.
#[derive(Clone, Copy, Debug)]
pub struct QueueLimits {
    pub max_events: usize,
    pub max_bytes: usize,
    pub max_event_bytes: usize,
    pub max_source_events: usize,
    pub max_source_bytes: usize,
}

/// Why an event was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueAdmissionError {
    EventTooLarge,
    QueueFull,
    SourceFull,
    Disconnected,
    TimedOut,
    NotReady,
}

#[derive(Clone, Copy, Default)]
struct SourceUsage {
    events: usize,
    bytes: usize,
}

struct QueueUsage<K> {
    events: usize,
    bytes: usize,
    sources: HashMap<K, SourceUsage>,
    receiver_alive: bool,
}

struct QueueState<K> {
    usage: Mutex<QueueUsage<K>>,
    available: Condvar,
}

impl<K> Default for QueueUsage<K> {
    fn default() -> Self {
        Self {
            events: 0,
            bytes: 0,
            sources: HashMap::new(),
            receiver_alive: true,
        }
    }
}

struct Queued<T, K: Eq + Hash> {
    event: Option<T>,
    source: K,
    bytes: usize,
    state: Arc<QueueState<K>>,
}

impl<T, K: Eq + Hash> Queued<T, K> {
    fn into_event(mut self) -> T {
        self.event.take().expect("queued event present")
    }
}

impl<T, K: Eq + Hash> Drop for Queued<T, K> {
    fn drop(&mut self) {
        let mut usage = self.state.usage.lock().expect("event queue usage lock");
        usage.events = usage.events.saturating_sub(1);
        usage.bytes = usage.bytes.saturating_sub(self.bytes);
        if let Some(source) = usage.sources.get_mut(&self.source) {
            source.events = source.events.saturating_sub(1);
            source.bytes = source.bytes.saturating_sub(self.bytes);
            if source.events == 0 {
                usage.sources.remove(&self.source);
            }
        }
        drop(usage);
        self.state.available.notify_all();
    }
}

/// Producer side of a bounded event channel.
pub struct ByteSender<T, K: Eq + Hash> {
    tx: SyncSender<Queued<T, K>>,
    state: Arc<QueueState<K>>,
    limits: QueueLimits,
}

/// Capacity charged before a producer materializes an event. Dropping it releases both the event
/// slot and bytes; sending consumes it directly, so queue admission is not charged a second time.
pub struct ByteReservation<T, K: Eq + Hash> {
    queued: Option<Queued<T, K>>,
    tx: SyncSender<Queued<T, K>>,
    limits: QueueLimits,
}

impl<T, K: Clone + Eq + Hash> ByteReservation<T, K> {
    pub fn bytes(&self) -> usize {
        self.queued.as_ref().map(|queued| queued.bytes).unwrap_or(0)
    }

    /// Increase a reservation before growing the producer's buffer. Existing bytes remain charged
    /// while this waits. A timeout or disconnected consumer leaves the original reservation intact.
    pub fn grow_to(&mut self, bytes: usize, timeout: Duration) -> Result<(), QueueAdmissionError> {
        let queued = self
            .queued
            .as_mut()
            .ok_or(QueueAdmissionError::Disconnected)?;
        if bytes <= queued.bytes {
            return Ok(());
        }
        if bytes > self.limits.max_event_bytes {
            return Err(QueueAdmissionError::EventTooLarge);
        }
        if bytes > self.limits.max_bytes {
            return Err(QueueAdmissionError::QueueFull);
        }
        if bytes > self.limits.max_source_bytes {
            return Err(QueueAdmissionError::SourceFull);
        }

        let deadline = Instant::now() + timeout;
        let mut usage = queued.state.usage.lock().expect("event queue usage lock");
        loop {
            if !usage.receiver_alive {
                return Err(QueueAdmissionError::Disconnected);
            }
            let additional = bytes - queued.bytes;
            let queue_full = usage.bytes.saturating_add(additional) > self.limits.max_bytes;
            let source_usage = usage
                .sources
                .get(&queued.source)
                .copied()
                .unwrap_or_default();
            let source_full =
                source_usage.bytes.saturating_add(additional) > self.limits.max_source_bytes;
            if !queue_full && !source_full {
                usage.bytes += additional;
                let source = usage.sources.entry(queued.source.clone()).or_default();
                source.bytes += additional;
                queued.bytes = bytes;
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(QueueAdmissionError::TimedOut);
            }
            let (next, result) = queued
                .state
                .available
                .wait_timeout(usage, deadline - now)
                .expect("event queue usage lock");
            usage = next;
            if result.timed_out() {
                return Err(QueueAdmissionError::TimedOut);
            }
        }
    }

    /// Release an over-reservation once the final event size is known.
    pub fn shrink_to(&mut self, bytes: usize) {
        let Some(queued) = self.queued.as_mut() else {
            return;
        };
        if bytes >= queued.bytes {
            return;
        }
        let released = queued.bytes - bytes;
        let mut usage = queued.state.usage.lock().expect("event queue usage lock");
        usage.bytes = usage.bytes.saturating_sub(released);
        if let Some(source) = usage.sources.get_mut(&queued.source) {
            source.bytes = source.bytes.saturating_sub(released);
        }
        queued.bytes = bytes;
        drop(usage);
        queued.state.available.notify_all();
    }

    pub fn send(mut self, event: T) -> Result<(), QueueAdmissionError> {
        let mut queued = self
            .queued
            .take()
            .ok_or(QueueAdmissionError::Disconnected)?;
        queued.event = Some(event);
        self.tx
            .send(queued)
            .map_err(|_| QueueAdmissionError::Disconnected)
    }

    pub fn try_send(mut self, event: T) -> Result<(), QueueAdmissionError> {
        let mut queued = self
            .queued
            .take()
            .ok_or(QueueAdmissionError::Disconnected)?;
        queued.event = Some(event);
        match self.tx.try_send(queued) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(QueueAdmissionError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(QueueAdmissionError::Disconnected),
        }
    }
}

impl<T, K: Eq + Hash> Clone for ByteSender<T, K> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            state: self.state.clone(),
            limits: self.limits,
        }
    }
}

impl<T, K: Clone + Eq + Hash> ByteSender<T, K> {
    fn reserve_inner(
        &self,
        source: K,
        bytes: usize,
        wait: bool,
        timeout: Option<Duration>,
    ) -> Result<ByteReservation<T, K>, QueueAdmissionError> {
        if bytes > self.limits.max_event_bytes {
            return Err(QueueAdmissionError::EventTooLarge);
        }
        if bytes > self.limits.max_bytes {
            return Err(QueueAdmissionError::QueueFull);
        }
        if bytes > self.limits.max_source_bytes {
            return Err(QueueAdmissionError::SourceFull);
        }
        let mut usage = self.state.usage.lock().expect("event queue usage lock");
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        loop {
            if !usage.receiver_alive {
                return Err(QueueAdmissionError::Disconnected);
            }
            let queue_full = usage.events >= self.limits.max_events
                || usage.bytes.saturating_add(bytes) > self.limits.max_bytes;
            let source_usage = usage.sources.get(&source).copied().unwrap_or_default();
            let source_full = source_usage.events >= self.limits.max_source_events
                || source_usage.bytes.saturating_add(bytes) > self.limits.max_source_bytes;
            if !queue_full && !source_full {
                break;
            }
            if !wait {
                return Err(if queue_full {
                    QueueAdmissionError::QueueFull
                } else {
                    QueueAdmissionError::SourceFull
                });
            }
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    return Err(QueueAdmissionError::TimedOut);
                }
                let (next, result) = self
                    .state
                    .available
                    .wait_timeout(usage, deadline - now)
                    .expect("event queue usage lock");
                usage = next;
                if result.timed_out() {
                    return Err(QueueAdmissionError::TimedOut);
                }
            } else {
                usage = self
                    .state
                    .available
                    .wait(usage)
                    .expect("event queue usage lock");
            }
        }
        let source_usage = usage.sources.get(&source).copied().unwrap_or_default();
        usage.events += 1;
        usage.bytes += bytes;
        usage.sources.insert(
            source.clone(),
            SourceUsage {
                events: source_usage.events + 1,
                bytes: source_usage.bytes + bytes,
            },
        );
        drop(usage);
        Ok(ByteReservation {
            queued: Some(Queued {
                event: None,
                source,
                bytes,
                state: self.state.clone(),
            }),
            tx: self.tx.clone(),
            limits: self.limits,
        })
    }

    pub fn try_reserve(
        &self,
        source: K,
        bytes: usize,
    ) -> Result<ByteReservation<T, K>, QueueAdmissionError> {
        self.reserve_inner(source, bytes, false, None)
    }

    pub fn reserve_timeout(
        &self,
        source: K,
        bytes: usize,
        timeout: Duration,
    ) -> Result<ByteReservation<T, K>, QueueAdmissionError> {
        self.reserve_inner(source, bytes, true, Some(timeout))
    }

    /// Admit without waiting. A full queue rejects the producer before another backlog item exists.
    pub fn try_send(&self, source: K, bytes: usize, event: T) -> Result<(), QueueAdmissionError> {
        self.try_reserve(source, bytes)?.try_send(event)
    }

    /// Wait for count, byte, and source capacity, then enqueue. An event that can never fit rejects.
    pub fn send(&self, source: K, bytes: usize, event: T) -> Result<(), QueueAdmissionError> {
        self.reserve_inner(source, bytes, true, None)?.send(event)
    }

    /// Current admitted events and bytes, including in-flight reservations not yet enqueued.
    pub fn usage(&self) -> (usize, usize) {
        let usage = self.state.usage.lock().expect("event queue usage lock");
        (usage.events, usage.bytes)
    }
}

/// Consumer side of a bounded event channel.
pub struct ByteReceiver<T, K: Eq + Hash> {
    rx: mpsc::Receiver<Queued<T, K>>,
    state: Arc<QueueState<K>>,
}

impl<T, K: Eq + Hash> ByteReceiver<T, K> {
    pub fn recv(&self) -> Result<T, RecvError> {
        self.rx.recv().map(Queued::into_event)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        self.rx.recv_timeout(timeout).map(Queued::into_event)
    }

    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.rx.try_recv().map(Queued::into_event)
    }
}

impl<T, K: Eq + Hash> Drop for ByteReceiver<T, K> {
    fn drop(&mut self) {
        let mut usage = self.state.usage.lock().expect("event queue usage lock");
        usage.receiver_alive = false;
        drop(usage);
        self.state.available.notify_all();
    }
}

/// Construct a count-bounded and byte-bounded channel.
pub fn byte_channel<T, K: Clone + Eq + Hash>(
    limits: QueueLimits,
) -> (ByteSender<T, K>, ByteReceiver<T, K>) {
    assert!(
        limits.max_events > 0,
        "event queue count limit must be nonzero"
    );
    assert!(
        limits.max_bytes > 0,
        "event queue byte limit must be nonzero"
    );
    assert!(
        limits.max_source_events > 0 && limits.max_source_bytes > 0,
        "event queue source limits must be nonzero"
    );
    let (tx, rx) = mpsc::sync_channel(limits.max_events);
    let state = Arc::new(QueueState {
        usage: Mutex::new(QueueUsage::default()),
        available: Condvar::new(),
    });
    (
        ByteSender {
            tx,
            state: state.clone(),
            limits,
        },
        ByteReceiver { rx, state },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> QueueLimits {
        QueueLimits {
            max_events: 4,
            max_bytes: 12,
            max_event_bytes: 8,
            max_source_events: 2,
            max_source_bytes: 8,
        }
    }

    #[test]
    fn bounds_events_bytes_and_each_source() {
        let (tx, rx) = byte_channel(limits());
        tx.try_send(1u8, 4, vec![1; 4]).unwrap();
        tx.try_send(1u8, 4, vec![2; 4]).unwrap();
        assert_eq!(
            tx.try_send(1u8, 1, vec![3]),
            Err(QueueAdmissionError::SourceFull)
        );
        tx.try_send(2u8, 4, vec![4; 4]).unwrap();
        assert_eq!(
            tx.try_send(3u8, 1, vec![5]),
            Err(QueueAdmissionError::QueueFull)
        );
        assert_eq!(tx.usage(), (3, 12));
        assert_eq!(rx.recv().unwrap(), vec![1; 4]);
        assert_eq!(tx.usage(), (2, 8));
        tx.try_send(3u8, 4, vec![5; 4]).unwrap();
    }

    #[test]
    fn rejects_one_oversized_event_before_accounting() {
        let (tx, _rx) = byte_channel::<Vec<u8>, u8>(limits());
        assert_eq!(
            tx.try_send(1, 9, vec![0; 9]),
            Err(QueueAdmissionError::EventTooLarge)
        );
        assert_eq!(tx.usage(), (0, 0));
    }

    #[test]
    fn blocking_send_waits_until_capacity_is_released() {
        let (tx, rx) = byte_channel(QueueLimits {
            max_events: 1,
            max_bytes: 4,
            max_event_bytes: 4,
            max_source_events: 1,
            max_source_bytes: 4,
        });
        tx.try_send(1u8, 4, vec![1; 4]).unwrap();
        let waiting = tx.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            done_tx.send(waiting.send(1u8, 4, vec![2; 4])).unwrap();
        });

        assert_eq!(
            done_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout),
            "the producer waits rather than shedding"
        );
        assert_eq!(rx.recv().unwrap(), vec![1; 4]);
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(1)), Ok(Ok(())));
        assert_eq!(rx.recv().unwrap(), vec![2; 4]);
        worker.join().unwrap();
        assert_eq!(tx.usage(), (0, 0));
    }

    #[test]
    fn blocking_send_rejects_capacity_that_can_never_fit() {
        let (tx, _rx) = byte_channel::<Vec<u8>, u8>(QueueLimits {
            max_events: 1,
            max_bytes: 4,
            max_event_bytes: 8,
            max_source_events: 1,
            max_source_bytes: 3,
        });
        assert_eq!(
            tx.send(1, 5, vec![0; 5]),
            Err(QueueAdmissionError::QueueFull)
        );
        assert_eq!(
            tx.send(1, 4, vec![0; 4]),
            Err(QueueAdmissionError::SourceFull)
        );
        assert_eq!(tx.usage(), (0, 0));
    }

    #[test]
    fn reservation_grows_shrinks_transfers_and_releases_without_double_accounting() {
        let (tx, rx) = byte_channel::<Vec<u8>, u8>(limits());
        let mut reservation = tx.try_reserve(1, 3).unwrap();
        assert_eq!(tx.usage(), (1, 3));
        reservation.grow_to(8, Duration::from_secs(1)).unwrap();
        assert_eq!(tx.usage(), (1, 8));
        reservation.shrink_to(5);
        assert_eq!(tx.usage(), (1, 5));
        reservation.send(vec![7; 5]).unwrap();
        assert_eq!(tx.usage(), (1, 5), "transfer does not charge twice");
        assert_eq!(rx.recv().unwrap(), vec![7; 5]);
        assert_eq!(tx.usage(), (0, 0));
    }

    #[test]
    fn reservation_timeout_and_cancellation_release_capacity_for_recovery() {
        let (tx, _rx) = byte_channel::<Vec<u8>, u8>(QueueLimits {
            max_events: 2,
            max_bytes: 8,
            max_event_bytes: 8,
            max_source_events: 2,
            max_source_bytes: 8,
        });
        let held = tx.try_reserve(1, 8).unwrap();
        assert_eq!(
            tx.reserve_timeout(2, 1, Duration::from_millis(25)).err(),
            Some(QueueAdmissionError::TimedOut)
        );
        assert_eq!(tx.usage(), (1, 8));
        drop(held);
        assert_eq!(tx.usage(), (0, 0));
        assert!(
            tx.try_reserve(2, 8).is_ok(),
            "capacity recovers after cancellation"
        );
    }

    #[test]
    fn one_hundred_twenty_eight_blocked_producers_never_exceed_the_shared_byte_ceiling() {
        let limits = QueueLimits {
            max_events: 128,
            max_bytes: 64,
            max_event_bytes: 16,
            max_source_events: 128,
            max_source_bytes: 64,
        };
        let (tx, rx) = byte_channel::<Vec<u8>, u8>(limits);
        let mut workers = Vec::new();
        for _ in 0..128 {
            let tx = tx.clone();
            workers.push(std::thread::spawn(move || {
                let reservation = tx.reserve_timeout(1, 16, Duration::from_secs(2))?;
                reservation.send(vec![1])
            }));
        }
        let mut received = 0;
        while received < 128 {
            assert!(tx.usage().1 <= limits.max_bytes);
            if rx.recv_timeout(Duration::from_secs(2)).is_ok() {
                received += 1;
            }
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert_eq!(tx.usage(), (0, 0));
    }
}
