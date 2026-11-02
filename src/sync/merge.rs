//! Bringing in logs from elsewhere: a backup folder today, a peer next. The rule that makes this
//! safe is that a log only ever grows. Anything shorter or different is refused, so the copies on
//! disk double as the high-water marks that stop a rollback, and nothing else needs tracking.

use std::collections::BTreeSet;
use std::fs;

use crate::Result;
use crate::ids::{DeviceId, Generation};
use crate::record::Body;
use crate::recovery::RecoveryKey;
use crate::state::{Anchor, PAST_THE_CUT, Problem, Standing, State, root};
use crate::store::log;
use crate::store::write_private;
use crate::store::{self, Logs, MAX_LOG_FILE};
use crate::vault::{Keys, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compared {
    Same,
    /// Theirs continues ours.
    Ahead,
    /// Ours continues theirs. They are out of date, or trying to roll us back.
    Behind,
    /// Neither continues the other, which an honest device cannot produce.
    Diverged,
}

pub(crate) fn compare(ours: &[u8], theirs: &[u8]) -> Compared {
    if theirs == ours {
        Compared::Same
    } else if theirs.starts_with(ours) {
        Compared::Ahead
    } else if ours.starts_with(theirs) {
        Compared::Behind
    } else {
        Compared::Diverged
    }
}

/// A real vault gains a device or two at a time.
const MAX_NEW_DEVICES: usize = 16;

/// How long a device must wait to lock this one again with a new generation.
const ASK_AGAIN_MS: u64 = 24 * 60 * 60 * 1000;

/// What arrived in a merge, sorted.
#[derive(Default)]
struct Offered {
    /// In the order they are tried, real devices first.
    ahead: Vec<(DeviceId, Vec<u8>)>,
    /// Logs that contradict the copy here, which only a removal can settle.
    forks: Vec<(DeviceId, Vec<u8>)>,
    own_log_diverged: bool,
}

/// What a merge did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Merged {
    pub devices_updated: usize,
    /// True when newer keys arrived that this device needs a touch to open, or it was removed.
    pub must_lock: bool,
}

fn first_entries(bytes: &[u8], count: u64) -> Vec<u8> {
    log::parse(bytes).entries.iter().take(usize::try_from(count).unwrap_or(usize::MAX)).flat_map(log::Entry::encode).collect()
}

impl Vault {
    /// Whether `bytes` starts a log in this vault, for a device not seen before. Without this, a
    /// log from another vault would look like a clean extension of nothing.
    fn belongs_here(&self, device: &DeviceId, bytes: &[u8]) -> bool {
        let first = log::parse(bytes);
        first.entries.first().is_some_and(|entry| entry.kind != Body::GENESIS && entry.prev == root(&self.state.genesis, device))
    }

    /// Takes in other devices' logs. Each is accepted whole or not at all, as far as it is believably
    /// dated, after replaying the result, so a hostile log cannot change anything on disk.
    ///
    /// The result must contain this device's roster head. Replay orders by a clock that writers
    /// set, so without this a retired key could backdate a change to before its own retirement.
    /// `accept` overrides that for one case only: the person holds the words of the other side
    /// of a real conflict, and chooses it.
    pub(crate) fn merge_logs(&mut self, incoming: Logs, accept: Option<&RecoveryKey>) -> Result<Merged> {
        let mut logs = self.all_logs()?;
        let mut refused = Vec::new();
        let Offered { mut ahead, forks, own_log_diverged } = self.logs_worth_trying(incoming, &logs, &mut refused);
        self.diverged |= own_log_diverged;
        self.cut_what_removals_cut(&mut ahead, &logs, accept, &mut refused);

        // Everything together first, because each replay costs the whole vault and usually all of
        // it is fine. One at a time only tells the good from the bad when something is not.
        let mut accepted = Vec::new();
        let mut merged_state = None;
        let together = ahead.iter().fold(logs.clone(), |mut together, (device, whole)| {
            together.insert(*device, whole.clone());
            together
        });
        if !ahead.is_empty()
            && let Ok(candidate) = self.replay_for(&together, accept)
            && ahead.iter().all(|(device, _)| !candidate.problems.iter().any(|problem| problem.device == *device))
            && self.keeps_head(&candidate, accept)
        {
            accepted.clone_from(&ahead);
            merged_state = Some(candidate);
            logs = together;
        }
        for (device, whole) in if merged_state.is_some() { &[][..] } else { &ahead[..] } {
            let ours = logs.insert(*device, whole.clone());
            // A log can be one no replay takes at all, and that is its problem alone.
            let Ok(candidate) = self.replay_for(&logs, accept) else {
                refused.push(Problem { device: *device, seq: 0, reason: "offered a log that cannot be replayed with the rest" });
                match ours {
                    Some(ours) => logs.insert(*device, ours),
                    None => logs.remove(device),
                };
                continue;
            };
            if let Some(problem) = candidate.problems.iter().find(|problem| problem.device == *device) {
                refused.push(*problem);
            } else if !self.keeps_head(&candidate, accept) {
                refused.push(Problem { device: *device, seq: 0, reason: "conflicts with a roster change on this device" });
            } else {
                accepted.push((*device, whole.clone()));
                merged_state = Some(candidate);
                continue;
            }
            match ours {
                Some(ours) => logs.insert(*device, ours),
                None => logs.remove(device),
            };
        }

        for (device, bytes) in &accepted {
            write_private(&log::path_for(&self.home, device), bytes)?;
            if *device == self.me {
                self.reopen_own_log()?;
            }
        }
        if let Some(state) = merged_state {
            self.state = state;
            self.observe_clock();
        }
        if !accepted.is_empty() {
            self.growth.note();
        }
        if accept.is_some_and(|key| key.matches(&self.state.recovery).unwrap_or(false)) {
            self.settle_on(self.state.roster_head())?;
        }
        let settled = self.take_what_removals_kept(forks)?;
        // What came before gives way once that log is taken. What this merge found stands.
        let taken = |problem: &Problem| settled.contains(&problem.device) || accepted.iter().any(|(device, _)| *device == problem.device);
        self.refused.retain(|problem| !taken(problem));
        self.refused.extend(refused.into_iter().filter(|problem| !settled.contains(&problem.device)));
        self.refused.sort_by_key(|problem| (problem.device, problem.seq, problem.reason));
        self.refused.dedup();
        Ok(Merged { devices_updated: accepted.len(), must_lock: !accepted.is_empty() && self.keys.is_some() && self.has_to_lock() })
    }

    /// Sorts what arrived into what could extend a log here and what is refused on sight. Devices
    /// not seen before are limited, since each could cost a replay and they cost nothing to invent.
    fn logs_worth_trying(&self, incoming: Logs, logs: &Logs, refused: &mut Vec<Problem>) -> Offered {
        let now = log::now_ms();
        let mut strangers = 0;
        let mut offered = Offered::default();
        // A real device goes first, or a pile of files nobody approved could use up the limit below
        // every time, and keep it from ever being heard.
        let mut incoming: Vec<_> = incoming.into_iter().collect();
        incoming.sort_by_cached_key(|(_, bytes)| !log::parse(bytes).entries.first().is_some_and(|entry| self.state.approves_enrollment(entry)));
        for (device, bytes) in incoming {
            // What is dated too far ahead waits, and what came before it is as good as ever.
            let parsed = log::parse(&bytes);
            let believable = parsed.entries.iter().take_while(|entry| log::is_plausible(entry.clock, now)).count();
            if believable < parsed.entries.len() {
                refused.push(Problem { device, seq: believable as u64, reason: "dated too far in the future" });
            }
            let whole = first_entries(&bytes[..parsed.valid_len], believable as u64);
            // Past this a folder would pass it over, and everything after it in the roster with it.
            if whole.len() as u64 > MAX_LOG_FILE {
                refused.push(Problem { device, seq: 0, reason: "offered a log too long to keep" });
                continue;
            }
            let ours = logs.get(&device).map_or(&[][..], Vec::as_slice);
            let seen = compare(ours, &whole);
            let verified = first_entries(ours, self.state.heads.get(&device).map_or(0, |head| head.seq + 1));
            let extends_what_replay_trusted = matches!(compare(&verified, &whole), Compared::Ahead);
            // Only this device writes its own log, so a copy from elsewhere is stale, unless it
            // holds more, which nothing on this machine could otherwise show, or this one has gone
            // bad on disk. That copy is this device's own work, so it comes back. One that went on
            // differently cannot.
            if device == self.me {
                if !matches!(seen, Compared::Same | Compared::Behind) && Self::is_signed_continuation(logs, device, &whole) {
                    if matches!(seen, Compared::Ahead) || extends_what_replay_trusted {
                        refused.push(Problem {
                            device,
                            seq: 0,
                            reason: "this device was rolled back or its log was damaged, and a signed copy put it right",
                        });
                        offered.ahead.push((device, whole));
                    } else {
                        refused.push(Problem {
                            device,
                            seq: 0,
                            reason: "this device was rolled back and has written since, so the others refuse it",
                        });
                        offered.own_log_diverged = true;
                    }
                }
                continue;
            }
            let reason = match seen {
                Compared::Same => continue,
                Compared::Behind => "offered an older copy of a log",
                // A copy here that went bad on disk is no contradiction: what replay trusted of it
                // is what counts, and the good copy puts the rest right. A removed device's log is
                // another matter, because then a removal says which history counts.
                Compared::Diverged
                    if extends_what_replay_trusted
                        && self.state.kept_entries(&device).is_none()
                        && (!verified.is_empty() || self.belongs_here(&device, &whole)) =>
                {
                    offered.ahead.push((device, whole));
                    continue;
                }
                Compared::Diverged => {
                    offered.forks.push((device, whole.clone()));
                    "a copy of this device's log that came in contradicts the one here"
                }
                Compared::Ahead if ours.is_empty() && !self.belongs_here(&device, &whole) => "offered a log from another vault",
                Compared::Ahead if ours.is_empty() && !self.state.members.contains_key(&device) && strangers == MAX_NEW_DEVICES => {
                    "more new devices than one sync can hold"
                }
                Compared::Ahead => {
                    strangers += usize::from(ours.is_empty() && !self.state.members.contains_key(&device));
                    offered.ahead.push((device, whole));
                    continue;
                }
            };
            refused.push(Problem { device, seq: 0, reason });
        }
        offered
    }

    /// Anyone can write to a folder, so this only counts once replay finds nothing wrong with it.
    fn is_signed_continuation(logs: &Logs, device: DeviceId, whole: &[u8]) -> bool {
        let mut logs = logs.clone();
        logs.insert(device, whole.to_vec());
        State::from_logs(&store::parse_all(&logs)).is_ok_and(|state| !state.problems.iter().any(|problem| problem.device == device))
    }

    /// What a removal cut counts for nothing, so a log is taken only up to there. A removed device
    /// can go on writing, and the only copy left may hold that: refusing it for what comes after
    /// would leave a device behind without what came before, and everything built on that.
    fn cut_what_removals_cut(&self, ahead: &mut Vec<(DeviceId, Vec<u8>)>, logs: &Logs, accept: Option<&RecoveryKey>, refused: &mut Vec<Problem>) {
        if ahead.is_empty() {
            return;
        }
        let mut together = logs.clone();
        together.extend(ahead.iter().cloned());
        // One at a time below finds which log cannot be replayed.
        let Ok(candidate) = self.replay_for(&together, accept) else { return };
        ahead.retain_mut(|(device, whole)| {
            let Some(kept) = candidate.kept_entries(device) else { return true };
            let cut = first_entries(whole, kept);
            if cut != *whole {
                refused.push(Problem { device: *device, seq: kept, reason: PAST_THE_CUT });
            }
            *whole = cut;
            matches!(compare(logs.get(device).map_or(&[][..], Vec::as_slice), whole), Compared::Ahead)
        });
    }

    /// A removal says which history of a device counts, so the copy holding that replaces one that
    /// does not. This is the one case a log may change other than by growing: a device can sign two
    /// histories, and whoever holds the one its removal did not keep would otherwise lose everything
    /// in it, the agreed part included, with no way to take the true one. Anyone can put a file in a
    /// folder, and one hash in the right place proves nothing, so the whole of it has to replay.
    fn take_what_removals_kept(&mut self, forks: Vec<(DeviceId, Vec<u8>)>) -> Result<BTreeSet<DeviceId>> {
        let mut taken = BTreeSet::new();
        for (device, whole) in forks {
            let Some(kept) = self.state.kept_entries(&device) else { continue };
            let path = log::path_for(&self.home, &device);
            let whole = first_entries(&whole, kept);
            if !self.state.is_what_its_removal_kept(&device, &log::parse(&whole))
                || self.state.is_what_its_removal_kept(&device, &log::parse(&fs::read(&path)?))
            {
                continue;
            }
            let mut logs = self.all_logs()?;
            logs.insert(device, whole.clone());
            let Ok(candidate) = self.replay_for(&logs, None) else { continue };
            if !candidate.problems.iter().any(|problem| problem.device == device) && self.keeps_head(&candidate, None) {
                let displaced = log::displaced_path(&self.home, &device);
                if !displaced.exists() {
                    write_private(&displaced, &fs::read(&path)?)?;
                }
                write_private(&path, &whole)?;
                self.state = candidate;
                self.observe_clock();
                taken.insert(device);
                self.growth.note();
            }
        }
        Ok(taken)
    }

    /// Removed devices whose log here is the one their removal kept, which a folder should hold
    /// too, whatever it has instead.
    pub(crate) fn logs_removals_kept(&self) -> BTreeSet<DeviceId> {
        let removed = self.state.members.iter().filter(|(_, member)| member.standing != Standing::Active).map(|(device, _)| *device);
        removed
            .filter(|device| {
                fs::read(log::path_for(&self.home, device)).is_ok_and(|bytes| self.state.is_what_its_removal_kept(device, &log::parse(&bytes)))
            })
            .collect()
    }

    /// Replays logs as this device would, or as its person chose, if they gave the words of a side.
    fn replay_for(&self, logs: &Logs, accept: Option<&RecoveryKey>) -> Result<State> {
        let keys = self.device.public();
        State::from_logs_as(&store::parse_all(logs), &accept.map_or(self.anchor(), |words| Anchor::Settling { keys, words }))
    }

    /// Whether this device can take `candidate`, given what it stands behind. A roster change it
    /// wrote, approved or was enrolled by stays, and what it was only told gives way to something
    /// with more behind it: retired words reaching a device that had not heard of their retirement
    /// must not cut it off from the real vault. Someone leaving is the exception both ways, because
    /// an addition lost can be made again and a removal lost leaves a device holding what comes
    /// next. So on an even count a departure moves a device off anything but another departure,
    /// and whatever the count, nothing but a departure moves it off one. A person with the words
    /// can choose otherwise, to settle a conflict, but never by leaving this device out.
    fn keeps_head(&self, candidate: &State, accept: Option<&RecoveryKey>) -> bool {
        let stays = candidate.members.get(&self.me).is_some_and(|member| member.standing == Standing::Active);
        if stays && accept.is_some_and(|key| key.matches(&candidate.recovery).unwrap_or(false)) {
            return true;
        }
        let at = self.state.roster.iter().zip(&candidate.roster).take_while(|(mine, theirs)| mine == theirs).count();
        let (mine, theirs) = (&self.state.roster[at..], &candidate.roster[at..]);
        let Some(first) = mine.first() else { return true };
        let mine_leaves = mine.iter().any(|change| self.state.departures.contains(change));
        let theirs_leaves = theirs.iter().any(|change| candidate.departures.contains(change));
        if candidate.lost_ties.contains(first) {
            theirs_leaves && !mine_leaves
        } else {
            candidate.roster.contains(&self.state.last_vouched(&self.me)) && (theirs_leaves || !mine_leaves)
        }
    }

    /// Whether this device must go back to its person: it was removed, everything it holds has been
    /// replaced, or another device's new generation holds something only a touch can open. That
    /// last one happens to honest devices racing each other, but any enrolled device can make one,
    /// so each gets this once a day. Otherwise it could end every grant and run here at will, and
    /// keep interrupting its own removal.
    fn has_to_lock(&mut self) -> bool {
        let removed = self.state.members.get(&self.me).is_some_and(|member| member.standing != Standing::Active);
        let Some(keys) = self.keys.as_ref() else { return removed };
        // A server holding chosen spaces has no epochs at all, and opening again would give it
        // none, so locking it would only end its agents' grants.
        if removed || (!keys.epochs.is_empty() && self.writing_epoch(&self.state.clean_epochs()).is_none()) {
            return true;
        }
        let new_space_keys =
            self.state.space_wraps.iter().filter(|wrap| wrap.device == self.me && !keys.spaces.contains_key(&(wrap.space, wrap.version)));
        let untried: BTreeSet<DeviceId> = self
            .my_wraps()
            .iter()
            .map(|(epoch, _)| epoch)
            .filter(|epoch| !keys.epochs.contains_key(epoch) && !keys.unreadable.contains(epoch))
            .map(|epoch| epoch.author)
            .chain(new_space_keys.map(|wrap| wrap.by))
            .collect();
        let now = log::now_ms();
        let may_lock: Vec<DeviceId> =
            untried.into_iter().filter(|device| self.last_asked.get(device).is_none_or(|at| now.saturating_sub(*at) >= ASK_AGAIN_MS)).collect();
        self.last_asked.extend(may_lock.iter().map(|device| (*device, now)));
        !may_lock.is_empty()
    }

    /// A generation here has not been tried, or this device was removed.
    pub(crate) fn keys_are_stale(&self) -> bool {
        let tried = |keys: &Keys, epoch: &Generation| keys.epochs.contains_key(epoch) || keys.unreadable.contains(epoch);
        let held = self.keys.as_ref().is_some_and(|keys| self.my_wraps().iter().all(|(epoch, _)| tried(keys, epoch)));
        let removed = self.state.members.get(&self.me).is_some_and(|member| member.standing != Standing::Active);
        removed || !held
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) fn tests_new_device_limit() -> usize {
        super::MAX_NEW_DEVICES
    }
}
