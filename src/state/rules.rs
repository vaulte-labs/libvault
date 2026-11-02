//! The rules for who is on the roster, kept apart from replaying everything else.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, Hash, Holds, LOST_DEPARTURE, LOST_POSITION, Member, Parsed, Problem, Refusal, Standing, State, add_digest, revoke_digest, rotate_digest,
    verify_entry,
};
use crate::binding::{Binding, Recipient};
use crate::crypto::{self, Key, PublicKeys};
use crate::ids::{DeviceId, Generation};
use crate::record::{Approval, Approver, Body, RecoveryId};
use crate::recovery::RecoveryKey;
use crate::{Error, Result, recovery};

/// What a reader knows about which history is its own. Where someone holds as much authority as
/// the owner, a leaked set of words and a stolen device say, no signature can separate them, so
/// this comes first. It costs nothing: it only says what this reader sees.
#[derive(Clone, Copy)]
pub enum Anchor<'a> {
    Nothing,
    /// The words a person holds, so that current words are never turned away.
    Words(&'a RecoveryKey),
    /// The same, and if they have since been replaced, the history as it stood until then.
    WordsAsTheyStood(&'a RecoveryKey),
    /// The device reading, which has to stay in the history it keeps or it could not open at all,
    /// on any roster change its person settled on.
    Device {
        keys: &'a PublicKeys,
        settled: Option<&'a Hash>,
    },
    /// A person settling a conflict with the words of the side they chose.
    Settling {
        keys: &'a PublicKeys,
        words: &'a RecoveryKey,
    },
    /// A person choosing between histories signatures cannot separate, by a change on the one.
    Through {
        words: &'a RecoveryKey,
        change: &'a Hash,
    },
}

impl Anchor<'_> {
    fn fits(&self, state: &State) -> bool {
        let is_in = |keys: &PublicKeys| state.active_devices().any(|(_, member)| member.record.keys == *keys);
        let answers_to = |words: &RecoveryKey| words.matches(&state.recovery).unwrap_or(false);
        match self {
            Self::Nothing => true,
            Self::Words(words) | Self::WordsAsTheyStood(words) => answers_to(words),
            Self::Device { keys, settled } => is_in(keys) && settled.is_none_or(|head| state.roster.contains(head)),
            Self::Settling { keys, words } => is_in(keys) && answers_to(words),
            Self::Through { words, change } => answers_to(words) && state.roster.contains(change),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Signer {
    Device(DeviceId),
    Words(RecoveryId),
}

/// One roster change reachable from the first entry.
struct Step<'a> {
    change: Option<(&'a Entry, &'a Body)>,
    /// How many signed, and whether the words did.
    strength: (usize, bool),
    /// Who signed this change, and then every change on the best history after it.
    signers: BTreeSet<Signer>,
    /// Whose say this change ended, and then every change on the best history after it.
    retired: BTreeSet<Signer>,
    /// Who could sign the next change, and so who has a say where history forks here.
    electorate: BTreeSet<Signer>,
    children: Vec<usize>,
    best: Option<usize>,
    /// Kept only until the step is reached, because a copy per step adds up.
    state: Option<State>,
    fits: bool,
}

impl Step<'_> {
    fn new(state: State) -> Self {
        Self {
            change: None,
            strength: (0, false),
            signers: BTreeSet::new(),
            retired: BTreeSet::new(),
            electorate: BTreeSet::new(),
            children: Vec::new(),
            best: None,
            state: Some(state),
            fits: false,
        }
    }

    fn clock(&self) -> Option<(u64, DeviceId, u64)> {
        self.change.map(|(entry, _)| (entry.clock, entry.device, entry.seq))
    }
}

/// The roster change in an entry, if there is one. A batch holds at most one.
fn roster_change(entry: &Entry) -> Option<Body> {
    match Body::decode(entry.kind, &entry.body).ok()? {
        Body::Batch { bodies } => bodies.into_iter().find(|body| body.approvals().is_some()),
        body => body.approvals().is_some().then_some(body),
    }
}

/// The change this one says it follows.
fn follows(body: &Body) -> Option<Hash> {
    match body {
        Body::DeviceAdd { after, .. } | Body::ServerAdd { after, .. } | Body::DeviceRevoke { after, .. } | Body::RecoveryRotate { after, .. } => {
            Some(*after)
        }
        _ => None,
    }
}

impl State {
    /// Removed devices whose log here is not the one their removal kept, so nothing in it counts.
    /// A log too short to hold the last kept entry is no exception: a removed device can write a
    /// shorter history, and it counts only once the entries its removal named have arrived.
    pub(super) fn forked_past_removal(&mut self, logs: &[(DeviceId, Parsed)]) -> BTreeSet<DeviceId> {
        let mut forked = BTreeSet::new();
        for (device, parsed) in logs {
            let Some(kept) = self.members.get(device).and_then(Member::entries_kept).filter(|kept| *kept > 0) else { continue };
            if !self.is_what_its_removal_kept(device, parsed) {
                self.problems.push(Problem { device: *device, seq: kept - 1, reason: "contradicts what its removal kept" });
                forked.insert(*device);
            }
        }
        forked
    }

    /// How many of a removed device's entries still count.
    pub fn kept_entries(&self, device: &DeviceId) -> Option<u64> {
        self.members.get(device).and_then(Member::entries_kept)
    }

    /// Whether an entry enrolls its own device with an approval that checks out here. Anyone can
    /// make a device and sign for it, so this is what sets a real one apart from a pile of junk.
    pub fn approves_enrollment(&self, entry: &Entry) -> bool {
        let (digest, approvals) = match Body::decode(entry.kind, &entry.body) {
            Ok(Body::DeviceAdd { after, device, approvals }) => (add_digest(&self.vault, &after, &entry.device, &device), approvals),
            Ok(Body::ServerAdd { after, device, spaces, approvals }) => {
                (crate::digest::server_digest(&self.vault, &after, &entry.device, &device, spaces.as_deref()), approvals)
            }
            _ => return false,
        };
        let by_someone_here = |approval: &Approval| match approval.by {
            Approver::Recovery => recovery::verify(&self.recovery, &digest, &approval.signature).is_ok(),
            Approver::Device(id) => self.voters().any(|(active, member)| {
                *active == id && approval.signature.verify(&member.record.keys.signing, &member.record.keys.dsa, &digest).is_ok()
            }),
        };
        approvals.iter().any(by_someone_here)
    }

    /// Whether this is the history a device's removal kept.
    pub fn is_what_its_removal_kept(&self, device: &DeviceId, parsed: &Parsed) -> bool {
        let Some(kept) = self.members.get(device).and_then(Member::entries_kept).filter(|kept| *kept > 0) else { return false };
        parsed.entries.get(usize::try_from(kept - 1).unwrap_or(usize::MAX)).map(Entry::hash).as_ref() == self.kept_heads.get(device)
    }

    /// Generations safe to seal something new under. Not anything made before the last departure,
    /// by anyone, since whoever left could have been given it, and not anything by a device no
    /// longer here. That covers a rotation made by a device that had not heard, and it needs no
    /// wrap to be believed, which anyone can write.
    pub fn clean_epochs(&self) -> BTreeSet<Generation> {
        let is_active = |device: &DeviceId| self.members.get(device).is_some_and(|member| member.standing == Standing::Active);
        let since = &self.roster[self.last_departure..];
        self.made_after.iter().filter(|(epoch, after)| is_active(&epoch.author) && since.contains(after)).map(|(epoch, _)| *epoch).collect()
    }

    /// Everyone whose approval counts for the next change.
    fn electorate(&self) -> BTreeSet<Signer> {
        self.voters().map(|(id, _)| Signer::Device(*id)).chain([Signer::Words(self.recovery.id())]).collect()
    }

    /// Who signed a change that has passed `check_approvals`, which ignores the device a removal
    /// names and so has not checked what that device said.
    fn signers(&self, body: &Body) -> BTreeSet<Signer> {
        let target = if let Body::DeviceRevoke { device, .. } = body { Some(device) } else { None };
        let signer = |approval: &Approval| match approval.by {
            Approver::Recovery => Some(Signer::Words(self.recovery.id())),
            Approver::Device(id) => (Some(&id) != target && !self.is_server(&id)).then_some(Signer::Device(id)),
        };
        body.approvals().unwrap_or_default().iter().filter_map(signer).collect()
    }

    /// Whose say a change ends.
    fn retires(&self, body: &Body) -> BTreeSet<Signer> {
        match body {
            Body::DeviceRevoke { device, .. } => BTreeSet::from([Signer::Device(*device)]),
            Body::RecoveryRotate { .. } => BTreeSet::from([Signer::Words(self.recovery.id())]),
            _ => BTreeSet::new(),
        }
    }

    /// Finds every history the logs can support, then settles each fork by what stands behind the
    /// whole of each branch, because a first step says nothing about what came later: a stolen
    /// device can win any position it once held alone, and only the removal that followed tells
    /// the two apart. What counts is how many of those who could sign at the fork signed anything
    /// after it. Anyone enrolled after it has no say, or a device could invent its own majority.
    ///
    /// Where the count is even, signatures have run out. What is left is a guess at who is honest,
    /// so what follows only picks a default, and `lost_ties` notes that, for a device to keep what
    /// it has until its person decides. Those a rival branch retired count for less, then the
    /// branch where someone leaves, then the strength of the first step, then the clock, which a
    /// writer sets.
    pub(super) fn settle_roster(&mut self, ordered: &[&Entry], anchor: &Anchor) {
        let changes: Vec<(&Entry, Body)> = ordered.iter().filter_map(|entry| Some((*entry, roster_change(entry)?))).collect();
        let mut following: BTreeMap<Hash, Vec<(&Entry, &Body)>> = BTreeMap::new();
        for (entry, body) in &changes {
            if let Some(after) = follows(body) {
                following.entry(after).or_default().push((*entry, body));
            }
        }

        let mut steps = vec![Step::new(self.clone())];
        let mut at = 0;
        while at < steps.len() {
            // The last candidate takes the state itself, so that a long chain costs no copies.
            let mut state = steps[at].state.take();
            let reached = state.as_ref().expect("a step keeps its state until it is reached");
            let electorate = reached.electorate();
            let candidates = following.get(&reached.roster_head()).map_or(&[][..], Vec::as_slice);
            for (index, (entry, body)) in candidates.iter().enumerate() {
                let current = state.as_ref().expect("taken only by the last candidate");
                let approved = current.author_key(entry, body).and_then(|key| verify_entry(&key, entry)).is_ok();
                let (signers, retired) = (current.signers(body), current.retires(body));
                let mut next = if index + 1 == candidates.len() { state.take().expect("this is the last") } else { current.clone() };
                if approved && next.roster_step(entry, (*body).clone()).is_ok() {
                    next.settled.insert(entry.hash());
                    let words = signers.iter().any(|signer| matches!(signer, Signer::Words(_)));
                    let strength = (signers.len(), words);
                    let child = steps.len();
                    steps[at].children.push(child);
                    steps.push(Step { change: Some((entry, body)), strength, signers, retired, ..Step::new(next) });
                } else if state.is_none() {
                    // A step that fails changes nothing, so this is still the state as it was.
                    state = Some(next);
                }
            }
            steps[at].electorate = electorate;
            steps[at].fits = steps[at].children.is_empty() && state.is_some_and(|state| anchor.fits(&state));
            at += 1;
        }

        let mut lost_ties = BTreeSet::new();
        for at in (0..steps.len()).rev() {
            if steps[at].children.is_empty() {
                continue;
            }
            let mut retiring: BTreeMap<Signer, usize> = BTreeMap::new();
            for child in &steps[at].children {
                for signer in &steps[*child].retired {
                    *retiring.entry(*signer).or_default() += 1;
                }
            }
            // What decides, and then what is only a default once that has run out.
            let say = |child: usize| (steps[child].fits, steps[child].signers.intersection(&steps[at].electorate).count());
            let standing = |child: usize| {
                let step = &steps[child];
                let retired_by_a_rival = |signer: &&Signer| retiring.get(*signer).copied().unwrap_or(0) > usize::from(step.retired.contains(*signer));
                let unretired = step.signers.intersection(&steps[at].electorate).filter(|signer| !retired_by_a_rival(signer)).count();
                // Someone leaving anywhere on the branch, which by now holds all it retired.
                (say(child), unretired, !step.retired.is_empty(), step.strength)
            };
            let best =
                steps[at].children.iter().copied().max_by_key(|child| (standing(*child), Reverse(steps[*child].clock()))).expect("checked above");
            let tied = steps[at].children.iter().filter(|child| **child != best && say(**child) == say(best));
            lost_ties.extend(tied.filter_map(|child| steps[*child].change).map(|(entry, _)| entry.hash()));
            let (fits, signers, retired) = (steps[best].fits, steps[best].signers.clone(), steps[best].retired.clone());
            steps[at].best = Some(best);
            steps[at].fits = fits;
            steps[at].signers.extend(signers);
            steps[at].retired.extend(retired);
        }

        let mut path = Vec::new();
        let mut at = 0;
        while let Some(best) = steps[at].best {
            path.extend(steps[best].change);
            at = best;
        }
        let words_replaced = matches!(anchor, Anchor::WordsAsTheyStood(_)) && !steps[0].fits;
        self.follow(&path, words_replaced.then_some(anchor));
        self.lost_ties = lost_ties;
    }

    /// Takes the roster along `path`, which was checked on the way here. If `stop` is given, that
    /// is for a person who holds words and has found them replaced, and it ends at the last change
    /// they were current at. That can be the owner, when a stolen device replaced them alone, and
    /// nothing in the logs can tell that from the owner replacing them. Whoever else holds them gets
    /// what they could already read, and no device that heard of the change will take it back.
    fn follow(&mut self, path: &[(&Entry, &Body)], stop: Option<&Anchor>) {
        let mut last = stop.is_some_and(|anchor| anchor.fits(self)).then(|| self.clone());
        for (entry, body) in path {
            self.roster_step(entry, (*body).clone()).expect("a path holds only steps that were taken");
            self.settled.insert(entry.hash());
            if stop.is_some_and(|anchor| anchor.fits(self)) {
                last = Some(self.clone());
            }
        }
        if let Some(last) = last {
            *self = last;
            self.replaced_words = true;
        }
    }

    /// The last roster change a device wrote or approved, or that enrolled it, which it will not
    /// give up. Anything after that it has only been told, and a stronger history can replace that.
    pub fn last_vouched(&self, device: &DeviceId) -> Hash {
        self.vouched.get(device).copied().unwrap_or(self.genesis)
    }

    /// The change the next roster change must follow.
    pub fn roster_head(&self) -> Hash {
        *self.roster.last().expect("the roster starts at genesis")
    }

    /// Checked first, so two devices making the same change at once are told that is what happened.
    fn require_head(&self, after: &Hash) -> Result<(), Refusal> {
        if *after == self.roster_head() { Ok(()) } else { Err(Refusal::Skip(LOST_POSITION)) }
    }

    /// A roster change counts only if it is properly approved.
    fn accept_roster_change(&mut self, entry: &Entry, digest: &Hash, approvals: &[Approval], target: Option<&DeviceId>) -> Result<(), Refusal> {
        self.check_approvals(digest, approvals, target).map_err(Refusal::Skip)?;
        let hash = entry.hash();
        self.roster.push(hash);
        self.roster_writes.insert(entry.device, entry.seq);
        self.vouched.insert(entry.device, hash);
        for approval in approvals {
            if let Approver::Device(id) = approval.by
                && Some(&id) != target
            {
                self.vouched.insert(id, hash);
            }
        }
        Ok(())
    }

    /// Makes one roster change, if it follows the head and is properly approved.
    pub(super) fn roster_step(&mut self, entry: &Entry, body: Body) -> Result<(), Refusal> {
        match body {
            Body::DeviceAdd { after, device, approvals } => {
                let digest = add_digest(&self.vault, &after, &entry.device, &device);
                self.add_member(entry, &after, device, &digest, &approvals, None)?;
            }
            Body::ServerAdd { after, device, spaces, approvals } => {
                let digest = crate::digest::server_digest(&self.vault, &after, &entry.device, &device, spaces.as_deref());
                let holds = match spaces {
                    None => Holds::Everything,
                    Some(spaces) => {
                        let spaces: BTreeSet<_> = spaces.into_iter().collect();
                        if spaces.is_empty() || !spaces.iter().all(|space| self.spaces.contains_key(space)) {
                            return Err(Refusal::Skip("adds a server holding a space this vault does not have"));
                        }
                        Holds::Spaces(spaces)
                    }
                };
                self.add_member(entry, &after, device, &digest, &approvals, Some(holds))?;
            }
            Body::DeviceRevoke { after, device, entries_kept, last_kept, approvals } => {
                if after != self.roster_head() {
                    return Err(Refusal::Skip(LOST_DEPARTURE));
                }
                let digest = revoke_digest(&self.vault, &after, &entry.device, &device, entries_kept, &last_kept);
                match self.members.get(&device) {
                    None => return Err(Refusal::Skip("removes an unknown device")),
                    // A second removal could only move the cutoff, keeping what the first refused.
                    Some(member) if member.standing != Standing::Active => return Err(Refusal::Skip("removes a device already removed")),
                    Some(_) => {}
                }
                if self.roster_writes.get(&device).is_some_and(|seq| entries_kept <= *seq) {
                    return Err(Refusal::Skip("cuts off a roster change it follows"));
                }
                self.accept_roster_change(entry, &digest, &approvals, Some(&device))?;
                self.members.get_mut(&device).expect("checked above").standing = Standing::Removed { entries_kept };
                self.kept_heads.insert(device, last_kept);
                self.last_departure = self.roster.len() - 1;
                self.departures.insert(entry.hash());
            }
            Body::RecoveryRotate { after, recovery, proof, approvals } => {
                if after != self.roster_head() {
                    return Err(Refusal::Skip(LOST_DEPARTURE));
                }
                let digest = rotate_digest(&self.vault, &after, &entry.device, &recovery);
                recovery::verify(&recovery, &digest, &proof).map_err(|_| Refusal::Skip("the new recovery key did not sign this"))?;
                if !approvals.iter().any(|approval| matches!(approval.by, Approver::Device(_))) {
                    return Err(Refusal::Skip("the words alone cannot replace themselves"));
                }
                let binding = Binding::Epoch { vault: self.vault, epoch: Generation::first(entry.device), recipient: Recipient::Recovery };
                if crypto::wrap(recovery.wrap_to(), &binding, &Key::generate()).is_err() {
                    return Err(Refusal::Skip("names words nothing can be wrapped to"));
                }
                self.accept_roster_change(entry, &digest, &approvals, None)?;
                self.recovery = recovery;
                self.last_departure = self.roster.len() - 1;
                self.departures.insert(entry.hash());
            }
            _ => unreachable!("only roster changes come here"),
        }
        Ok(())
    }

    fn add_member(
        &mut self,
        entry: &Entry,
        after: &Hash,
        device: crate::record::DeviceRecord,
        digest: &Hash,
        approvals: &[Approval],
        server: Option<Holds>,
    ) -> Result<(), Refusal> {
        self.require_head(after)?;
        if self.members.contains_key(&device.id()) || self.members.values().any(|member| member.record.keys == device.keys) {
            return Err(Refusal::Skip("adds a device the roster already has"));
        }
        // Every rotation has to wrap to it, so one nobody can wrap to would stop them all.
        let binding = Binding::Epoch { vault: self.vault, epoch: Generation::first(device.id()), recipient: Recipient::Device(device.id()) };
        if crypto::wrap(device.keys.wrap_to(), &binding, &Key::generate()).is_err() {
            return Err(Refusal::Skip("adds a device nothing can be wrapped to"));
        }
        self.accept_roster_change(entry, digest, approvals, None)?;
        self.vouched.insert(device.id(), self.roster_head());
        self.members.insert(device.id(), Member { record: device, standing: Standing::Active, label: None, added_by: entry.device, server });
        Ok(())
    }

    /// Checks a roster change before it is written, so a refused change leaves no entry.
    pub fn verify_roster_change(&self, after: &Hash, digest: &Hash, approvals: &[Approval], target: Option<&DeviceId>) -> Result<()> {
        if *after != self.roster_head() {
            return Err(Error::NotApproved("the roster changed while this was waiting. Try again"));
        }
        self.check_approvals(digest, approvals, target).map_err(Error::NotApproved)
    }

    /// One device may act alone only while it is the only one. Past that, two devices must
    /// agree, or the recovery key. `target` is the device being removed, which gets no say, and
    /// neither does a server, which counts as no device here at all.
    fn check_approvals(&self, digest: &Hash, approvals: &[Approval], target: Option<&DeviceId>) -> Result<(), &'static str> {
        let required = if self.voters().count() >= 2 { 2 } else { 1 };
        let mut approved = BTreeSet::new();
        let mut by_recovery = false;
        for approval in approvals {
            match approval.by {
                Approver::Recovery => {
                    recovery::verify(&self.recovery, digest, &approval.signature).map_err(|_| "bad recovery signature")?;
                    by_recovery = true;
                }
                Approver::Device(id) if Some(&id) == target || self.is_server(&id) => {}
                Approver::Device(id) => {
                    let member = self.members.get(&id).filter(|member| member.standing == Standing::Active).ok_or("approved by an unknown device")?;
                    approval.signature.verify(&member.record.keys.signing, &member.record.keys.dsa, digest).map_err(|_| "bad approval signature")?;
                    approved.insert(id);
                }
            }
        }
        if by_recovery || approved.len() >= required { Ok(()) } else { Err("not enough approvals") }
    }
}
