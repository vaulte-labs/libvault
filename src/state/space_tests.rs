//! Every ordering of roster changes and attacks, up to a depth, through the real `State::from_logs`.
//! Checking the shipped code rather than a model of it means nothing can drift between the two, and
//! its rules are simple enough that a small depth reaches every interaction between them. Rejected:
//! a Tamarin or `ProVerif` model, which nothing would tie to this code, for a toolchain this project
//! does not otherwise need. `scripts/state_space.sh` runs it deeper.
//!
//! An honest device refuses any logs whose roster loses the head it holds, so a step that would is
//! dropped here too. What remains is everything a device could really be shown.

use std::collections::BTreeMap;

use super::attacks::Forge;
use super::tests::Actor;
use super::*;
use crate::record::{Approval, Approver, Body};
use crate::recovery::{RecoveryDraft, RecoveryKey};

#[derive(Debug, Clone, Copy)]
enum Step {
    /// The recovery key enrolls a device, at the current head.
    Enroll(usize),
    /// A device is removed by another, with the recovery key.
    Remove { by: usize, target: usize },
    /// The recovery key is replaced.
    Rotate,
    /// A device writes an item, dated now.
    Write(usize),
    /// A device writes an item dated back at the beginning, as anyone holding a log key can.
    Backdate(usize),
    /// A device enrolls one of its own, approved by words that have been replaced.
    RetiredWords(usize),
    /// A device tries to remove another on its own say-so.
    Alone { by: usize, target: usize },
    /// A roster change aimed at a position already passed.
    Stale(usize),
}

const OWNER: usize = 0;
const ACTORS: usize = 3;

struct Cast {
    actors: Vec<Actor>,
    keys: Vec<RecoveryKey>,
}

#[derive(Clone)]
struct World {
    forge: Forge,
    /// Which of the cast's recovery keys is current.
    recovery: usize,
    clock: u64,
    /// What an honest device holds, which it will not give up.
    head: Hash,
    first_head: Hash,
    removed: BTreeMap<DeviceId, u64>,
}

fn approve(key: &RecoveryKey, digest: &Hash) -> Vec<Approval> {
    vec![Approval { by: Approver::Recovery, signature: key.sign(digest).unwrap() }]
}

fn apply(world: &mut World, cast: &Cast, step: Step) {
    world.clock += 10;
    let clock = world.clock;
    let state = world.forge.state();
    let (vault, after) = (world.forge.vault, state.roster_head());
    let key = &cast.keys[world.recovery];
    match step {
        Step::Enroll(who) => {
            let device = cast.actors[who].fresh.record.clone();
            let approvals = approve(key, &add_digest(&vault, &after, &cast.actors[who].id(), &device));
            world.forge.write(&cast.actors[who], clock, &Body::DeviceAdd { after, device, approvals });
        }
        Step::Remove { by, target } => {
            let device = cast.actors[target].id();
            let log = world.forge.logs.get(&device);
            let (entries_kept, last_kept) = (log.map_or(0, |log| log.len() as u64), log.and_then(|log| log.last()).map_or([0; 32], Entry::hash));
            let approvals = approve(key, &revoke_digest(&vault, &after, &cast.actors[by].id(), &device, entries_kept, &last_kept));
            world.forge.write(&cast.actors[by], clock, &Body::DeviceRevoke { after, device, entries_kept, last_kept, approvals });
        }
        Step::Rotate => {
            let next = (world.recovery + 1).min(cast.keys.len() - 1);
            let recovery = cast.keys[next].new_public(vault).unwrap();
            let digest = rotate_digest(&vault, &after, &cast.actors[OWNER].id(), &recovery);
            let mut approvals = approve(key, &digest);
            approvals.push(cast.actors[OWNER].approve(&digest));
            let proof = cast.keys[next].sign(&digest).unwrap();
            world.forge.write(&cast.actors[OWNER], clock, &Body::RecoveryRotate { after, recovery, proof, approvals });
            world.recovery = next;
        }
        Step::Write(who) => {
            let space = SpaceId::random();
            let version = Generation::first(cast.actors[who].id());
            world.forge.write(
                &cast.actors[who],
                clock,
                &Body::Space { space, version, epoch: Generation::first(world.forge.first_device), sealed: vec![1] },
            );
        }
        Step::Backdate(who) => {
            let space = SpaceId::random();
            let version = Generation::first(cast.actors[who].id());
            let last = world.forge.logs.get(&cast.actors[who].id()).and_then(|log| log.last()).map_or(0, |entry| entry.clock);
            world.forge.write(
                &cast.actors[who],
                last + 1,
                &Body::Space { space, version, epoch: Generation::first(world.forge.first_device), sealed: vec![1] },
            );
        }
        Step::RetiredWords(who) => {
            let device = cast.actors[who].fresh.record.clone();
            let approvals = approve(&cast.keys[0], &add_digest(&vault, &after, &cast.actors[who].id(), &device));
            let last = world.forge.logs.get(&cast.actors[who].id()).and_then(|log| log.last()).map_or(0, |entry| entry.clock);
            world.forge.write(&cast.actors[who], last + 1, &Body::DeviceAdd { after, device, approvals });
        }
        Step::Alone { by, target } => {
            let device = cast.actors[target].id();
            let digest = revoke_digest(&vault, &after, &cast.actors[by].id(), &device, 1, &[0; 32]);
            let approvals = vec![cast.actors[by].approve(&digest)];
            world.forge.write(&cast.actors[by], clock, &Body::DeviceRevoke { after, device, entries_kept: 1, last_kept: [0; 32], approvals });
        }
        Step::Stale(who) => {
            let device = cast.actors[who].fresh.record.clone();
            let after = world.first_head;
            let approvals = approve(key, &add_digest(&vault, &after, &cast.actors[who].id(), &device));
            world.forge.write(&cast.actors[who], 2, &Body::DeviceAdd { after, device, approvals });
        }
    }
}

/// Whether `step` could legitimately change who is on the roster, from where `world` stands.
fn may_change_roster(world: &World, step: Step) -> bool {
    match step {
        Step::Enroll(_) | Step::Remove { .. } | Step::Rotate => true,
        Step::Write(_) | Step::Backdate(_) | Step::Alone { .. } => false,
        Step::RetiredWords(_) => world.recovery == 0,
        Step::Stale(_) => world.head == world.first_head,
    }
}

/// Everything that must be true of any state a device could reach.
fn check(before: &World, world: &World, previous: &State, state: &State, step: Step, trail: &[Step]) {
    // Replay does not depend on the order logs are read in.
    let mut reversed: Vec<(DeviceId, Parsed)> =
        world.forge.logs.iter().map(|(device, entries)| (*device, Parsed { entries: entries.clone(), ..Parsed::default() })).collect();
    reversed.reverse();
    let other = State::from_logs(&reversed).unwrap();
    assert_eq!(state.roster, other.roster, "{trail:?}");
    assert_eq!(state.spaces.len(), other.spaces.len(), "{trail:?}");

    if !may_change_roster(before, step) {
        assert_eq!(state.roster, previous.roster, "the roster moved: {trail:?}");
        assert_eq!(state.recovery, previous.recovery, "the recovery key moved: {trail:?}");
        let standing = |state: &State| state.members.iter().map(|(id, member)| (*id, member.standing)).collect::<Vec<_>>();
        assert_eq!(standing(state), standing(previous), "the roster moved: {trail:?}");
    }
    for (device, kept) in &before.removed {
        assert_eq!(state.members[device].standing, Standing::Removed { entries_kept: *kept }, "a removal changed: {trail:?}");
    }
    for (device, member) in &state.members {
        if let Standing::Removed { entries_kept } = member.standing {
            let head = state.heads.get(device).map_or(0, |head| head.seq + 1);
            assert!(head <= entries_kept, "an entry past the cutoff took effect: {trail:?}");
        }
    }
    for version in state.spaces.values().flat_map(BTreeMap::keys) {
        assert!(state.members.contains_key(&version.author), "a space from a device never enrolled: {trail:?}");
    }
    assert_eq!(state.roster.last(), Some(&state.roster_head()), "{trail:?}");
}

fn walk(world: &World, cast: &Cast, steps: &[Step], depth: usize, trail: &mut Vec<Step>, visited: &mut usize) {
    if depth == 0 {
        return;
    }
    let previous = world.forge.state();
    for step in steps {
        let mut next = world.clone();
        apply(&mut next, cast, *step);
        trail.push(*step);
        let state = next.forge.state();
        // The pin: an honest device refuses this and stays where it was.
        if state.roster.contains(&world.head) {
            next.head = state.roster_head();
            for (id, member) in &state.members {
                if let Standing::Removed { entries_kept } = member.standing {
                    next.removed.insert(*id, entries_kept);
                }
            }
            check(world, &next, &previous, &state, *step, trail);
            *visited += 1;
            walk(&next, cast, steps, depth - 1, trail, visited);
        }
        trail.pop();
    }
}

fn run(depth: usize) -> usize {
    let (forge, owner) = Forge::new();
    let cast = Cast { actors: vec![owner, Actor::new(), Actor::new()], keys: vec![forge.recovery.clone(), RecoveryDraft::new().0] };
    let head = forge.state().roster_head();
    let world = World { forge, recovery: 0, clock: 100, head, first_head: head, removed: BTreeMap::new() };
    let mut steps = vec![Step::Rotate];
    for who in 1..ACTORS {
        steps.extend([Step::Enroll(who), Step::Backdate(who), Step::Write(who), Step::RetiredWords(who), Step::Stale(who)]);
        steps.extend([Step::Remove { by: OWNER, target: who }, Step::Alone { by: who, target: OWNER }]);
    }
    let mut visited = 0;
    walk(&world, &cast, &steps, depth, &mut Vec::new(), &mut visited);
    visited
}

#[test]
fn every_short_sequence_of_roster_changes_and_attacks_keeps_its_promises() {
    assert!(run(3) > 100, "too little was reachable for this to mean anything");
}

/// `scripts/state_space.sh`: minutes at depth 4, far longer past it.
#[test]
#[ignore = "only for scripts/state_space.sh"]
fn deep() {
    let depth = std::env::var("LV_STATE_SPACE_DEPTH").ok().and_then(|depth| depth.parse().ok()).unwrap_or(4);
    println!("{} states checked at depth {depth}", run(depth));
}
