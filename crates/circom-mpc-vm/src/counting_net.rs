//! [`CountingNet`]: a thin [`Network`] decorator that counts network rounds and bytes, so the
//! round claims (the per-gadget round-count tests in `vm::gadgets` and the compiler-tests crate)
//! are measured rather than asserted. Wrap any real 3-party run with it to get those counts.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use mpc_net::bytes::Bytes;
use mpc_net::{ConnectionStats, Network};

/// Wraps a [`Network`] and counts rounds: a round is one `send` followed by (at least) one `recv`
/// before the next `send`. Every rep3 primitive that communicates - `reshare_many`,
/// `broadcast_many`, and everything built on them (`mul_vec`, `open_vec`, `a2y2b_many`, ...) - sends
/// to its peers and then receives from them, so this scores each such call as exactly one round,
/// which is what every round count in this crate's tests means.
///
/// Uses atomics rather than `Cell` because [`Network`] requires `Send + Sync` (a party's own
/// send/recv sequence is single-threaded, so relaxed ordering is sufficient - this is a counter,
/// not a synchronization primitive).
pub struct CountingNet<N> {
    inner: N,
    rounds: AtomicUsize,
    sent_since_recv: AtomicBool,
}

impl<N> CountingNet<N> {
    /// Wraps `inner`, starting both counters at zero.
    pub fn new(inner: N) -> Self {
        Self {
            inner,
            rounds: AtomicUsize::new(0),
            sent_since_recv: AtomicBool::new(false),
        }
    }

    /// The number of rounds counted so far.
    pub fn rounds(&self) -> usize {
        self.rounds.load(Ordering::Relaxed)
    }

    /// Zeroes the round counter, without touching the underlying connection. `Rep3State::new`
    /// itself spends 2 rounds on its one-time correlated-randomness setup before any gadget or
    /// reshare runs - callers that want a gadget's or program's *own* round count (as opposed to
    /// the whole session's, setup included) should reset right after constructing the `Rep3State`.
    pub fn reset(&self) {
        self.rounds.store(0, Ordering::Relaxed);
        self.sent_since_recv.store(false, Ordering::Relaxed);
    }
}

impl<N: Network> Network for CountingNet<N> {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.sent_since_recv.store(true, Ordering::Relaxed);
        self.inner.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let data = self.inner.recv(from)?;
        // Only the first `recv` after a `send` closes a round - a maximal group of receives
        // following at least one send (e.g. `broadcast_many`'s two recvs) is one round, not two.
        if self.sent_since_recv.swap(false, Ordering::Relaxed) {
            self.rounds.fetch_add(1, Ordering::Relaxed);
        }
        Ok(data)
    }

    fn flush(&self) -> eyre::Result<()> {
        self.inner.flush()
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}
