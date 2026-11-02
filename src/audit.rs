//! A record of who used what. Stored as log entries, so it syncs to other devices and a
//! compromised device cannot quietly erase its own trail.

use serde::{Deserialize, Serialize};

use crate::binding::Binding;
use crate::crypto;
use crate::item;
use crate::record::Body;
use crate::store::log::now_ms;
use crate::vault::Vault;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub action: String,
    pub target: String,
    pub actor: String,
}

impl Vault {
    /// A server holding chosen spaces has no epoch key, so it keeps no record of its own.
    pub fn record(&mut self, action: &str, target: &str, actor: &str) -> Result<()> {
        if self.state.spaces_held_by(&self.me).is_some() {
            return Ok(());
        }
        let event = Event { at_ms: now_ms(), action: action.to_owned(), target: target.to_owned(), actor: actor.to_owned() };
        let (epoch, key) = self.key_for_records()?;
        let sealed = crypto::seal(key, &Binding::Audit { vault: self.state.vault }, &item::encode(&event)?);
        self.commit(&[Body::Audit { epoch, sealed }])
    }

    /// Every recorded event, oldest first.
    pub fn audit(&self) -> Result<Vec<Event>> {
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let binding = Binding::Audit { vault: self.state.vault };
        let mut events: Vec<Event> = self
            .state
            .audit
            .iter()
            .filter_map(|(epoch, sealed)| item::decode(&crypto::open(keys.epochs.get(epoch)?, &binding, sealed).ok()?).ok())
            .collect();
        events.sort_by_key(|event| event.at_ms);
        Ok(events)
    }
}
