//! Per-window loss estimation from the raw BPF counters.
//!
//! The eBPF program keeps, per (listen_port, receiver_index) session,
//! cumulative counters: packets received and the highest WireGuard
//! counter observed. For one observation window:
//!
//!   expected = max_counter_now - max_counter_then
//!   received = rx_packets_now - rx_packets_then
//!   loss     = 1 - received / expected
//!
//! Because `expected` is derived from the endpoints of the counter
//! range rather than from pairwise `counter == last + 1` checks,
//! packets reordered anywhere inside the window do not register as
//! losses. A new keypair session (rekey) shows up as a new
//! receiver_index and is baselined on its first appearance, so one
//! loss-free tick is skipped per rekey.

use std::collections::{HashMap, VecDeque};

use anyhow::{bail, Result};
use libbpf_rs::{Map, MapCore, MapFlags};

/// Map key layout; must match `struct stat_key` in src/bpf/types.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub port: u16,
    pub receiver_index: u32,
}

/// Aggregated (across CPUs) cumulative counters for one session.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub max_counter: u64,
    pub min_counter: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

pub fn monotonic_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: clock_gettime with a valid out pointer cannot fail here.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000u64 + ts.tv_nsec as u64
}

impl Key {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&self.port.to_le_bytes());
        b[4..8].copy_from_slice(&self.receiver_index.to_le_bytes());
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 8 {
            bail!("bad key size {}", bytes.len());
        }
        Ok(Key {
            port: u16::from_le_bytes([bytes[0], bytes[1]]),
            // struct stat_key is {u16 port, u16 pad, u32 receiver_index}:
            // port @0..2, pad @2..4, receiver_index @4..8.
            receiver_index: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// `struct stat_val` is 6 x u64 = 48 bytes.
fn aggregate(values: &[Vec<u8>]) -> Result<Option<Sample>> {
    let mut out: Option<Sample> = None;
    for v in values {
        if v.len() != 48 {
            bail!("bad value size {}", v.len());
        }
        let rx = u64::from_le_bytes(v[0..8].try_into().unwrap());
        if rx == 0 {
            continue; // per-CPU slot never used by this session
        }
        let bytes = u64::from_le_bytes(v[8..16].try_into().unwrap());
        let max_counter = u64::from_le_bytes(v[16..24].try_into().unwrap());
        let min_counter = u64::from_le_bytes(v[24..32].try_into().unwrap());
        let first = u64::from_le_bytes(v[32..40].try_into().unwrap());
        let last = u64::from_le_bytes(v[40..48].try_into().unwrap());
        let s = out.get_or_insert(Sample::default());
        s.rx_packets += rx;
        s.rx_bytes += bytes;
        s.max_counter = s.max_counter.max(max_counter);
        s.min_counter = if s.min_counter == 0 || min_counter == 0 {
            if s.min_counter == 0 {
                min_counter
            } else {
                s.min_counter
            }
        } else {
            s.min_counter.min(min_counter)
        };
        s.first_seen_ns = if s.first_seen_ns == 0 {
            first
        } else {
            s.first_seen_ns.min(first)
        };
        s.last_seen_ns = s.last_seen_ns.max(last);
    }
    Ok(out)
}

/// Read every session currently in the stats map, aggregated across CPUs.
pub fn snapshot(stats: &Map) -> Result<HashMap<Key, Sample>> {
    let mut out = HashMap::new();
    for key_bytes in stats.keys() {
        let key = Key::from_bytes(&key_bytes)?;
        let values = match stats.lookup_percpu(&key_bytes, MapFlags::ANY) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => return Err(anyhow::anyhow!(e)),
        };
        if let Some(sample) = aggregate(&values)? {
            out.insert(key, sample);
        }
    }
    Ok(out)
}

/// Delete sessions silent for longer than `max_idle_secs`.
pub fn gc_stale(stats: &Map, max_idle_secs: u64) -> Result<usize> {
    let now = monotonic_ns();
    if now == 0 {
        return Ok(0);
    }
    let snap = snapshot(stats)?;
    let max_idle_ns = max_idle_secs.saturating_mul(1_000_000_000);
    let mut removed = 0;
    for (key, sample) in &snap {
        if sample.last_seen_ns != 0 && now.saturating_sub(sample.last_seen_ns) > max_idle_ns {
            stats
                .delete(&key.to_bytes())
                .map_err(|e| anyhow::anyhow!(e))?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Rekey,
    Insufficient,
    Ok,
    Degraded,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Idle => "IDLE",
            State::Rekey => "REKEY",
            State::Insufficient => "LOW",
            State::Ok => "OK",
            State::Degraded => "DEGRADED",
        }
    }
}

pub struct Config {
    pub min_packets: u64,
    pub loss_threshold: f64,
    pub degrade_after: u32,
    pub recover_after: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_packets: 100,
            loss_threshold: 0.05,
            degrade_after: 2,
            recover_after: 3,
        }
    }
}

/// Per-interface window state.
pub struct Tracker {
    prev: HashMap<u32, Sample>,
    history: VecDeque<(u64, u64)>, // (expected, received), newest at back
    bad_streak: u32,
    good_streak: u32,
    degraded: bool,
    last_report_ns: u64,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub state: State,
    pub expected: u64,
    pub received: u64,
    pub lost: u64,
    pub loss: f64,
    pub roll_expected: u64,
    #[allow(dead_code)]
    pub roll_received: u64,
    pub roll_loss: f64,
    pub rate: f64,
    pub sessions: usize,
    pub loss_valid: bool,
    pub new_session: bool,
}

impl Tracker {
    pub fn new(now_ns: u64) -> Self {
        Self {
            prev: HashMap::new(),
            history: VecDeque::new(),
            bad_streak: 0,
            good_streak: 0,
            degraded: false,
            last_report_ns: now_ns,
        }
    }

    /// Advance by one window using the latest snapshot for `port`.
    pub fn step(
        &mut self,
        now_ns: u64,
        sessions: &HashMap<Key, Sample>,
        port: u16,
        cfg: &Config,
    ) -> Report {
        let mut expected_total = 0u64;
        let mut received_total = 0u64;
        let mut any_new = false;

        let mut next_prev: HashMap<u32, Sample> = HashMap::new();
        for (key, sample) in sessions {
            if key.port != port {
                continue;
            }
            next_prev.insert(key.receiver_index, *sample);
            match self.prev.get(&key.receiver_index) {
                Some(prev) => {
                    if sample.max_counter < prev.max_counter || sample.rx_packets < prev.rx_packets
                    {
                        // Counters moved backwards: the session was reaped
                        // and recreated (or the index was reused).
                        any_new = true;
                        continue;
                    }
                    expected_total += sample.max_counter - prev.max_counter;
                    received_total += sample.rx_packets - prev.rx_packets;
                }
                None => any_new = true,
            }
        }
        if self.prev.keys().any(|k| !next_prev.contains_key(k)) {
            any_new = true;
        }
        self.prev = next_prev;

        let elapsed = if self.last_report_ns != 0 {
            now_ns.saturating_sub(self.last_report_ns)
        } else {
            0
        };
        self.last_report_ns = now_ns;

        let loss = if expected_total > 0 {
            (1.0 - received_total as f64 / expected_total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        if expected_total > 0 {
            self.history.push_back((expected_total, received_total));
            while self.history.len() > 12 {
                self.history.pop_front();
            }
        }
        let (roll_expected, roll_received) = self
            .history
            .iter()
            .fold((0u64, 0u64), |(e, r), &(ce, cr)| (e + ce, r + cr));
        let roll_loss = if roll_expected > 0 {
            (1.0 - roll_received as f64 / roll_expected as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // Hysteresis: degrade after N consecutive bad windows, recover
        // after M consecutive good ones. A window with too few packets
        // never clears DEGRADED by itself (recovery-deadlock guard: tiny
        // keepalives show 0% loss even on a broken tunnel).
        let sufficient = expected_total >= cfg.min_packets;
        if sufficient {
            if loss >= cfg.loss_threshold {
                self.bad_streak += 1;
                self.good_streak = 0;
            } else {
                self.good_streak += 1;
                self.bad_streak = 0;
            }
        }
        if sufficient && self.bad_streak >= cfg.degrade_after {
            self.degraded = true;
        }
        if self.degraded && sufficient && self.good_streak >= cfg.recover_after {
            self.degraded = false;
        }

        let state = if expected_total == 0 && received_total == 0 {
            State::Idle
        } else if any_new && expected_total < cfg.min_packets {
            State::Rekey
        } else if self.degraded && !sufficient {
            // Stay DEGRADED until a full-size window proves recovery.
            State::Degraded
        } else if !sufficient {
            State::Insufficient
        } else if self.degraded {
            State::Degraded
        } else {
            State::Ok
        };

        let seconds = elapsed as f64 / 1e9;
        let rate = if seconds > 0.0 {
            received_total as f64 / seconds
        } else {
            0.0
        };

        Report {
            state,
            expected: expected_total,
            received: received_total,
            lost: expected_total.saturating_sub(received_total),
            loss,
            roll_expected,
            roll_received,
            roll_loss,
            rate,
            sessions: sessions.values().filter(|s| s.last_seen_ns != 0).count(),
            loss_valid: expected_total > 0 && sufficient,
            new_session: any_new,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_matches_bpf_layout() {
        let key = Key {
            port: 51822,
            receiver_index: 0xdead_beef,
        };
        let bytes = key.to_bytes();
        // Layout: u16 port, u16 pad, u32 receiver_index.
        assert_eq!(&bytes[0..2], &51822u16.to_le_bytes());
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(&bytes[4..8], &0xdead_beef_u32.to_le_bytes());
        assert_eq!(Key::from_bytes(&bytes).unwrap(), key);
    }

    #[test]
    fn rekey_starts_new_baseline() {
        let now = 10_000_000_000u64; // 10 s
        let cfg = Config {
            min_packets: 10,
            ..Config::default()
        };
        let mut tracker = Tracker::new(0);

        // Session 1: 100 packets, counter 1..=100.
        let mut snap = HashMap::new();
        snap.insert(
            Key {
                port: 51822,
                receiver_index: 111,
            },
            Sample {
                rx_packets: 100,
                rx_bytes: 1000,
                max_counter: 100,
                min_counter: 1,
                first_seen_ns: now,
                last_seen_ns: now,
            },
        );
        let r = tracker.step(now, &snap, 51822, &cfg);
        assert!(r.new_session);
        assert_eq!(r.expected, 0); // baseline only

        // Next window: 20 more packets, no loss.
        snap.get_mut(&Key {
            port: 51822,
            receiver_index: 111,
        })
        .unwrap()
        .rx_packets = 120;
        snap.get_mut(&Key {
            port: 51822,
            receiver_index: 111,
        })
        .unwrap()
        .max_counter = 120;
        let r = tracker.step(now + 2_000_000_000, &snap, 51822, &cfg);
        assert_eq!(r.expected, 20);
        assert_eq!(r.received, 20);
        assert_eq!(r.loss, 0.0);

        // Rekey: new receiver_index, counter restarts at 0.
        snap.clear();
        snap.insert(
            Key {
                port: 51822,
                receiver_index: 222,
            },
            Sample {
                rx_packets: 5,
                rx_bytes: 50,
                max_counter: 5,
                min_counter: 1,
                first_seen_ns: now + 4_000_000_000,
                last_seen_ns: now + 4_000_000_000,
            },
        );
        let r = tracker.step(now + 4_000_000_000, &snap, 51822, &cfg);
        assert!(r.new_session);
        assert_eq!(r.state, State::Idle); // baselining the new session

        // Another 20 packets on the new session.
        snap.get_mut(&Key {
            port: 51822,
            receiver_index: 222,
        })
        .unwrap()
        .rx_packets = 25;
        snap.get_mut(&Key {
            port: 51822,
            receiver_index: 222,
        })
        .unwrap()
        .max_counter = 25;
        let r = tracker.step(now + 6_000_000_000, &snap, 51822, &cfg);
        assert_eq!(r.expected, 20);
        assert_eq!(r.received, 20);
    }

    #[test]
    fn reordering_is_loss_free() {
        let now = 10_000_000_000u64;
        let cfg = Config {
            min_packets: 10,
            ..Config::default()
        };
        let mut tracker = Tracker::new(0);
        let mut snap = HashMap::new();
        let key = Key {
            port: 51822,
            receiver_index: 7,
        };
        snap.insert(
            key,
            Sample {
                rx_packets: 50,
                rx_bytes: 0,
                max_counter: 50,
                min_counter: 1,
                first_seen_ns: now,
                last_seen_ns: now,
            },
        );
        tracker.step(now, &snap, 51822, &cfg);

        // Counters 51..=60 arrive reordered, plus a late 48 below the
        // previous max: 11 received, max delta 10. Loss clamps to 0.
        let s = snap.get_mut(&key).unwrap();
        s.rx_packets = 61;
        s.max_counter = 60;
        let r = tracker.step(now + 5_000_000_000, &snap, 51822, &cfg);
        assert_eq!(r.expected, 10);
        assert_eq!(r.received, 11);
        assert_eq!(r.loss, 0.0);
        assert_eq!(r.lost, 0);
    }

    #[test]
    fn true_loss_is_detected() {
        let now = 10_000_000_000u64;
        let cfg = Config {
            min_packets: 10,
            ..Config::default()
        };
        let mut tracker = Tracker::new(0);
        let key = Key {
            port: 51822,
            receiver_index: 9,
        };
        let mut snap = HashMap::new();
        snap.insert(
            key,
            Sample {
                rx_packets: 50,
                rx_bytes: 0,
                max_counter: 50,
                min_counter: 1,
                first_seen_ns: now,
                last_seen_ns: now,
            },
        );
        tracker.step(now, &snap, 51822, &cfg);

        // Counter jumps to 70 but only 15 packets arrive: 20 expected, 5 lost.
        let s = snap.get_mut(&key).unwrap();
        s.rx_packets = 65;
        s.max_counter = 70;
        let r = tracker.step(now + 5_000_000_000, &snap, 51822, &cfg);
        assert_eq!(r.expected, 20);
        assert_eq!(r.received, 15);
        assert_eq!(r.lost, 5);
        assert!((r.loss - 0.25).abs() < 1e-9);
    }
}
