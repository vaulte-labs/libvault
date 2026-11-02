//! When this device's vault locks by itself. Each device keeps its own choice: a phone in a pocket
//! and a desktop at home want different things, and a stolen device's choice must not reach the
//! others. Restarting always locks, because the keys are only ever in memory.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Result;

const FILE: &str = "lock-settings.json";

/// How long the vault stays unlocked with nothing using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StayUnlocked {
    FiveMinutes,
    TenMinutes,
    OneHour,
    TwoHours,
    /// Until it is locked by hand, the screen locks if that is chosen, or the device restarts.
    Never,
}

impl StayUnlocked {
    pub(crate) fn idle_ms(self) -> Option<u64> {
        let minutes = match self {
            Self::FiveMinutes => 5,
            Self::TenMinutes => 10,
            Self::OneHour => 60,
            Self::TwoHours => 120,
            Self::Never => return None,
        };
        Some(minutes * 60 * 1000)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSettings {
    pub stay_unlocked: StayUnlocked,
    /// Whether locking the screen, or the device sleeping, locks the vault too.
    pub with_screen: bool,
}

impl Default for LockSettings {
    fn default() -> Self {
        Self { stay_unlocked: StayUnlocked::OneHour, with_screen: true }
    }
}

impl LockSettings {
    /// What this device chose. A missing or damaged file means the default, never staying open.
    pub(crate) fn read(home: &Path) -> Self {
        std::fs::read(home.join("local").join(FILE)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
    }

    pub(crate) fn write(self, home: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(&self).map_err(|_| crate::Error::Corrupt("lock settings could not be encoded"))?;
        crate::store::write_private(&home.join("local").join(FILE), &bytes)
    }

    /// Whether a vault unlocked and last used at `last_used` is due to lock at `now`.
    pub(crate) fn is_due(self, last_used: u64, now: u64, screen_locked: bool) -> bool {
        let idle = self.stay_unlocked.idle_ms().is_some_and(|limit| now.saturating_sub(last_used) > limit);
        idle || (self.with_screen && screen_locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 60 * 60 * 1000;

    #[test]
    fn each_choice_locks_after_its_own_time_unused() {
        let settings = |stay_unlocked| LockSettings { stay_unlocked, with_screen: false };
        assert!(!settings(StayUnlocked::OneHour).is_due(0, HOUR, false));
        assert!(settings(StayUnlocked::OneHour).is_due(0, HOUR + 1, false));
        assert!(settings(StayUnlocked::FiveMinutes).is_due(0, 5 * 60 * 1000 + 1, false));
        assert!(!settings(StayUnlocked::TwoHours).is_due(0, 2 * HOUR, false));
        assert!(!settings(StayUnlocked::Never).is_due(0, 1000 * HOUR, false));
    }

    #[test]
    fn the_screen_locks_the_vault_only_when_chosen() {
        let never = |with_screen| LockSettings { stay_unlocked: StayUnlocked::Never, with_screen };
        assert!(never(true).is_due(0, 0, true));
        assert!(!never(false).is_due(0, 0, true));
    }

    #[test]
    fn a_damaged_choice_falls_back_to_the_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("local")).unwrap();
        std::fs::write(dir.path().join("local").join(FILE), b"{\"stay_unlocked\":\"forever\"}").unwrap();
        assert_eq!(LockSettings::read(dir.path()), LockSettings::default());
        let chosen = LockSettings { stay_unlocked: StayUnlocked::Never, with_screen: false };
        chosen.write(dir.path()).unwrap();
        assert_eq!(LockSettings::read(dir.path()), chosen);
    }
}
