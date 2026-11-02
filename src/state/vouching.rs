//! Replay checks one signature per chain instead of one per entry.
//!
//! Checking Ed25519 signatures was 90% of what replay cost. Most of those checks proved nothing
//! new: every entry is still signed when it is written, and an entry's `prev` is the hash of the
//! whole entry before it, signature included. A good signature on the last entry of a chain
//! therefore commits to every entry behind it, so forging an earlier one means breaking SHA-256 or
//! the signature on the tip.
//!
//! Anything that does not fit that argument gets the check per entry it always had: a tip that
//! fails, so a damaged log is cut at exactly the entry that went wrong, and devices outside the
//! roster, whose entries must each be refused. Roster changes are checked for themselves as they
//! settle, because that happens before anyone knows which keys count.
//!
//! The one difference from checking everything is out of reach without the device's key: its
//! holder can leave a bad signature behind a good one. That gains nothing, since they signed the
//! entry after it, which covers this one.

use std::collections::{BTreeMap, BTreeSet};

use super::{Body, Entry, Problem, Refusal, State, verify_entry};
use crate::ids::DeviceId;

/// How far along its own log each device's signature has been checked, for one replay.
pub(super) type SignedThrough = BTreeMap<DeviceId, u64>;

/// Decides what one replay can take as signed, given the last valid entry of each log.
pub(super) type Vouch = fn(&State, &[&Entry]) -> SignedThrough;

#[cfg(test)]
thread_local! {
    /// Signature checks on this thread, so a test can see what replay spent.
    pub(super) static SIGNATURES_CHECKED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl State {
    pub(super) fn chains_signed_at_their_tips(&self, tips: &[&Entry]) -> SignedThrough {
        tips.iter()
            .filter(|tip| self.members.get(&tip.device).is_some_and(|member| verify_entry(&member.record.log, tip).is_ok()))
            .map(|tip| (tip.device, tip.seq))
            .collect()
    }

    /// Applies every entry in order, checking the signature of each one nothing has vouched for.
    pub(super) fn replay(&mut self, ordered: &[&Entry], mut stopped: BTreeSet<DeviceId>, signed_through: &SignedThrough) {
        for entry in ordered {
            if entry.seq == 0 && entry.kind == Body::GENESIS {
                continue;
            }
            if stopped.contains(&entry.device) {
                continue;
            }
            let vouched_for = signed_through.get(&entry.device).is_some_and(|through| entry.seq <= *through);
            match self.apply_checked(entry, vouched_for) {
                Ok(()) => {}
                Err(Refusal::Skip(reason)) => self.conflicts.push(Problem { device: entry.device, seq: entry.seq, reason }),
                Err(Refusal::Stop(reason)) => {
                    self.problems.push(Problem { device: entry.device, seq: entry.seq, reason });
                    stopped.insert(entry.device);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "vouching_tests.rs"]
mod tests;
