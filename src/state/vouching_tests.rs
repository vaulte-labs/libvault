//! Replay checks the signature at the end of each chain and lets the hash chain vouch for the
//! rest. That must change nothing for anyone who does not hold the device's key, so these compare
//! it with checking every signature, on logs damaged in every way that key's absence allows.

use std::fs;

use aws_lc_rs::signature::Ed25519KeyPair;

use super::super::tests::{Actor, Fixture};
use super::*;
use crate::Result;
use crate::ids::Generation;
use crate::item::{Kind, Meta, Secret};
use crate::record::Body;
use crate::state::{Anchor, Head, add_digest};
use crate::store::log;
use crate::store::log::{Entry, Parsed};

const ITEMS: usize = 6;
const ACTOR_ENTRIES: usize = 4;
const TRIALS: usize = 1500;

impl State {
    /// Replays with every signature checked, which is the behavior vouching must not change.
    fn from_logs_checking_every_signature(logs: &[(DeviceId, Parsed)]) -> Result<Self> {
        Self::replayed_vouching(logs, &Anchor::Nothing, false, |_, _| SignedThrough::new())
    }
}

/// Two devices with real histories, one on disk and one written out by hand.
fn two_devices() -> (Fixture, Actor, Vec<Entry>) {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(crate::FIRST_SPACE).unwrap().id;
    for index in 0..ITEMS {
        fixture.vault.add(&space, Meta::new(Kind::Env, format!("KEY{index}")), &Secret::Env { value: "value".to_owned() }).unwrap();
    }
    let actor = Actor::new();
    let after = fixture.state().roster_head();
    let digest = add_digest(&fixture.state().vault, &after, &actor.id(), &actor.fresh.record);
    let body = Body::DeviceAdd { after, device: actor.fresh.record.clone(), approvals: fixture.recovery_approval(&digest) };
    let mut entries = vec![actor.entry(fixture.state(), &body)];
    fixture.state().apply(&entries[0]).unwrap();
    for _ in 0..ACTOR_ENTRIES {
        let body = Body::Audit { epoch: Generation::first(*fixture.state().members.keys().next().unwrap()), sealed: vec![1] };
        let entry = actor.entry(fixture.state(), &body);
        fixture.state().apply(&entry).unwrap();
        entries.push(entry);
    }
    (fixture, actor, entries)
}

fn encoded(entries: &[Entry]) -> Vec<u8> {
    entries.iter().flat_map(Entry::encode).collect()
}

fn own_log(fixture: &Fixture) -> (DeviceId, Vec<u8>) {
    let vault = &fixture.vault;
    (vault.me, fs::read(log::path_for(&vault.home, &vault.me)).unwrap())
}

fn parsed(logs: &[(DeviceId, Vec<u8>)]) -> Vec<(DeviceId, Parsed)> {
    let mut parsed: Vec<_> = logs.iter().map(|(device, bytes)| (*device, log::parse(bytes))).collect();
    parsed.sort_by_key(|(device, _)| *device);
    parsed
}

/// Everything replay decides, as one comparable value.
fn outcome(state: &Result<State>) -> String {
    match state {
        Err(error) => format!("refused: {error}"),
        Ok(state) => {
            let items: Vec<_> = state.items.iter().map(|(key, versions)| (key, versions.len())).collect();
            let members: Vec<_> = state.members.iter().map(|(id, member)| (id, &member.standing)).collect();
            format!("{:?} {:?} {:?} {:?} {items:?} {members:?}", state.heads, state.roster_head(), state.problems, state.conflicts)
        }
    }
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % limit.max(1) as u64).unwrap()
    }
}

/// Carries a rewrite forward by fixing every later `prev`, which needs no key. Their signatures
/// no longer match, because only the device could make ones that do.
fn rechain(entries: &mut [Entry], from: usize) {
    for index in from.max(1)..entries.len() {
        entries[index].prev = entries[index - 1].hash();
    }
}

fn damage(logs: &mut [(DeviceId, Vec<u8>)], outsider: &Ed25519KeyPair, random: &mut Random) {
    let which = random.below(logs.len());
    let other = (which + 1) % logs.len();
    let foreign = log::parse(&logs[other].1).entries;
    let bytes = &mut logs[which].1;
    let mut entries = log::parse(bytes).entries;
    if entries.is_empty() || foreign.is_empty() {
        return;
    }
    let at = random.below(entries.len());
    match random.below(9) {
        0 => {
            let byte = random.below(bytes.len());
            bytes[byte] ^= 1 << random.below(8);
            return;
        }
        1 => {
            bytes.truncate(random.below(bytes.len()));
            return;
        }
        2 if entries.len() > 1 => {
            let next = (at + 1) % entries.len();
            entries.swap(at, next);
        }
        3 => drop(entries.remove(at)),
        4 => {
            let copy = entries[at].clone();
            entries.insert(at, copy);
        }
        5 => {
            entries[at].clock += 1;
            rechain(&mut entries, at + 1);
        }
        6 => {
            entries[at].body.push(0);
            rechain(&mut entries, at + 1);
        }
        7 => {
            let signature = outsider.sign(&entries[at].signed_bytes());
            entries[at].signature = signature.as_ref().try_into().unwrap();
            rechain(&mut entries, at + 1);
        }
        _ => entries.insert(at, foreign[random.below(foreign.len())].clone()),
    }
    *bytes = encoded(&entries);
}

#[test]
fn without_the_key_no_damage_tells_vouching_from_checking_every_signature() {
    let (fixture, actor, entries) = two_devices();
    let clean = vec![own_log(&fixture), (actor.id(), encoded(&entries))];
    let outsider = Actor::new();
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut refused = 0;
    for _ in 0..TRIALS {
        let mut logs = clean.clone();
        for _ in 0..=random.below(2) {
            damage(&mut logs, &outsider.log, &mut random);
        }
        let logs = parsed(&logs);
        let vouching = State::from_logs(&logs);
        let every_signature = State::from_logs_checking_every_signature(&logs);
        assert_eq!(outcome(&vouching), outcome(&every_signature));
        refused += usize::from(!every_signature.is_ok_and(|state| state.problems.is_empty()));
    }
    assert!(refused > TRIALS / 2, "only {refused} of {TRIALS} logs were damaged enough to notice");
}

#[test]
fn undamaged_logs_replay_the_same_both_ways() {
    let (fixture, actor, entries) = two_devices();
    let logs = parsed(&[own_log(&fixture), (actor.id(), encoded(&entries))]);
    let state = State::from_logs(&logs);
    assert_eq!(outcome(&state), outcome(&State::from_logs_checking_every_signature(&logs)));
    let state = state.unwrap();
    assert!(state.problems.is_empty(), "{:?}", state.problems);
    assert_eq!(state.heads[&actor.id()].seq, ACTOR_ENTRIES as u64);
}

fn signatures_checked(replay: impl FnOnce()) -> usize {
    let before = SIGNATURES_CHECKED.with(std::cell::Cell::get);
    replay();
    SIGNATURES_CHECKED.with(std::cell::Cell::get) - before
}

#[test]
fn a_long_chain_costs_one_signature_check() {
    let (fixture, actor, entries) = two_devices();
    let logs = parsed(&[own_log(&fixture), (actor.id(), encoded(&entries))]);
    let total: usize = logs.iter().map(|(_, parsed)| parsed.entries.len()).sum();
    let vouching = signatures_checked(|| drop(State::from_logs(&logs).unwrap()));
    let every = signatures_checked(|| drop(State::from_logs_checking_every_signature(&logs).unwrap()));
    // One per device, and the one roster change, which is always checked for itself.
    assert_eq!(vouching, 3, "of {total} entries");
    assert!(every >= total - 1, "{every} of {total}");
}

#[test]
fn a_tip_nobody_signed_falls_back_and_keeps_everything_before_it() {
    let (fixture, actor, mut entries) = two_devices();
    let good_until = entries[entries.len() - 2].seq;
    let forged = Actor::new().log.sign(&entries.last().unwrap().signed_bytes());
    entries.last_mut().unwrap().signature = forged.as_ref().try_into().unwrap();
    let logs = parsed(&[own_log(&fixture), (actor.id(), encoded(&entries))]);

    let checked = signatures_checked(|| {
        let state = State::from_logs(&logs).unwrap();
        assert_eq!(state.heads[&actor.id()].seq, good_until, "only the forged tip goes");
        assert!(state.problems.iter().any(|problem| problem.device == actor.id() && problem.reason == "bad entry signature"));
    });
    assert!(checked > ACTOR_ENTRIES, "that log went back to one check per entry, not {checked}");
}

#[test]
fn a_key_holder_gains_nothing_from_a_bad_signature_behind_a_good_one() {
    let (fixture, actor, mut entries) = two_devices();
    let middle = entries.len() / 2;
    entries[middle].signature = [0; 64];
    for index in middle + 1..entries.len() {
        entries[index].prev = entries[index - 1].hash();
        entries[index].signature = actor.log.sign(&entries[index].signed_bytes()).as_ref().try_into().unwrap();
    }
    let logs = parsed(&[own_log(&fixture), (actor.id(), encoded(&entries))]);

    // The one difference from checking every signature, and only the key's holder can reach it.
    // They signed the entry after it, and that signature covers this one, so nothing is forged.
    let state = State::from_logs(&logs).unwrap();
    assert_eq!(state.heads[&actor.id()].seq, ACTOR_ENTRIES as u64);
    let every = State::from_logs_checking_every_signature(&logs).unwrap();
    assert_eq!(every.heads[&actor.id()].seq, u64::try_from(middle).unwrap() - 1);
}

#[test]
fn only_a_member_can_vouch_for_a_chain() {
    let (fixture, _, _) = two_devices();
    let stranger = Actor::new();
    let body = Body::Audit { epoch: Generation::first(fixture.vault.me), sealed: vec![1] };
    let mut state = fixture.vault.state.clone();
    let mut entries = Vec::new();
    for _ in 0..3 {
        let entry = stranger.entry(&state, &body);
        state.heads.insert(stranger.id(), Head { seq: entry.seq, hash: entry.hash(), clock: entry.clock });
        state.clock = entry.clock;
        entries.push(entry);
    }
    let logs = parsed(&[own_log(&fixture), (stranger.id(), encoded(&entries))]);
    let state = State::from_logs(&logs).unwrap();
    assert!(!state.heads.contains_key(&stranger.id()));
    assert!(state.problems.iter().any(|problem| problem.device == stranger.id()));
    assert_eq!(outcome(&Ok(state)), outcome(&State::from_logs_checking_every_signature(&logs)));
}
