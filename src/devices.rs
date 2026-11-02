//! What a person calls a device. Removing one goes by that, so it has to say which device it means.

use crate::binding::Binding;
use crate::ids::DeviceId;
use crate::vault::{DeviceInfo, Vault};
use crate::{Error, Result, crypto, item};

/// Long enough that nobody can make a device id starting the same way as another's.
const SHORT_ID: usize = 16;

impl Vault {
    /// Enrolled devices and their names, this device included.
    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let last_change = |id: &DeviceId| self.state.heads.get(id).map_or(0, |head| crate::store::log::wall_ms(head.clock));
        Ok(self
            .state
            .active_devices()
            .map(|(id, _)| DeviceInfo { name: self.device_name(id), is_this_device: *id == self.me, last_change_ms: last_change(id) })
            .collect())
    }

    /// A device's name, when it has one this device can read.
    pub(crate) fn device_label(&self, id: &DeviceId) -> Option<String> {
        let (epoch, sealed) = self.state.members.get(id)?.label.as_ref()?;
        let key = self.keys.as_ref()?.epochs.get(epoch)?;
        let label: String = item::decode(&crypto::open(key, &Binding::Label { vault: self.state.vault, device: *id }, sealed).ok()?).ok()?;
        item::validate_text(&label).is_ok().then_some(label)
    }

    /// What a person sees a device as. It always says which device: one with no readable name
    /// could hide from removal behind it, and so could one that copies a lost device's name.
    pub(crate) fn device_name(&self, id: &DeviceId) -> String {
        let short = &id.to_string()[..SHORT_ID];
        match self.device_label(id) {
            Some(label) if self.state.active_devices().filter(|(other, _)| self.device_label(other).as_ref() == Some(&label)).count() > 1 => {
                format!("{label} ({short})")
            }
            Some(label) => label,
            None => format!("Unnamed device {short}"),
        }
    }

    /// Finds another device by the name a person knows it by, or by the start of its id, which a
    /// name cannot imitate. This device is never the answer, and a name two devices share is not a
    /// guess worth making when the next step removes one.
    pub(crate) fn device_named(&self, name: &str) -> Result<DeviceId> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let active = || self.state.active_devices().map(|(id, _)| *id);
        let mut named: Vec<DeviceId> = active().filter(|id| name.len() >= SHORT_ID && id.to_string().starts_with(name)).collect();
        if named.is_empty() {
            named = active().filter(|id| self.device_name(id) == name).collect();
        }
        if named.is_empty() {
            named = active().filter(|id| self.device_label(id).as_deref() == Some(name)).collect();
        }
        match named.iter().filter(|id| **id != self.me).collect::<Vec<_>>().as_slice() {
            [only] => Ok(**only),
            [] if named.is_empty() => Err(Error::NotFound(format!("device {name}"))),
            [] => Err(Error::Invalid("this is the device you are on. Use wipe instead")),
            _ => Err(Error::Invalid("two other devices have that name. Use the name with its id, as your list of devices shows it")),
        }
    }
}
