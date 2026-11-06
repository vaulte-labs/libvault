//! The places a person gave this device to sync with: `host:port` for a device, `relay:host:port`
//! for a relay. Kept on this device only.

use std::fs;
use std::path::Path;

use crate::store::write_private;
use crate::{Error, Result};

/// How a place names a relay rather than a device.
pub(crate) const RELAY_PREFIX: &str = "relay:";
const FILE: &str = "peers.json";

pub(crate) fn given(home: &Path) -> Result<Vec<String>> {
    match fs::read(home.join("local").join(FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt("the peer list is damaged")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

/// Adds `place`. Giving one twice changes nothing.
pub(crate) fn remember(home: &Path, place: &str) -> Result<()> {
    let mut places = given(home)?;
    if !places.iter().any(|existing| existing == place) {
        places.push(place.to_owned());
        let bytes = serde_json::to_vec(&places).map_err(|_| Error::Corrupt("the peer list could not be saved"))?;
        write_private(&home.join("local").join(FILE), &bytes)?;
    }
    Ok(())
}
