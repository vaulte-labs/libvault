//! Whether passkeys a site names are Vaulte's, answered while the vault is locked. A browser asked
//! to sign in with a site's credential ids has to choose between offering Vaulte and handing the
//! request to its own passkeys, and a person should not have to unlock only to learn it was never
//! Vaulte's.
//!
//! So this device keeps, beside its keys and never synced, a digest of each passkey's site and
//! credential id. A credential id is 32 random bytes that only its site hands out, so the digests
//! tell nothing to anyone without the ids, and a caller holding some learns only yes or no for
//! each. Names, accounts and sites stay sealed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::Broker;
use super::passkeys::{page, passkeys};
use super::policy::{Action, Caller};
use crate::Result;
use crate::crypto::{self, Hash};
use crate::item::Secret;
use crate::passkey;
use crate::protocol::Response;
use crate::vault::Vault;

fn path(home: &Path) -> PathBuf {
    home.join("local").join("passkey-ids")
}

fn digest(rp_id: &str, credential_id: &[u8]) -> Hash {
    crypto::hash(&[b"vaulte passkey id", rp_id.as_bytes(), &[0], credential_id])
}

/// Every passkey's digest, from an unlocked vault.
fn digests(vault: &Vault) -> Result<HashSet<Hash>> {
    Ok(passkeys(vault)?
        .iter()
        .filter_map(|(_, _, _, secret)| match secret {
            Secret::Passkey { rp_id, .. } => Some(digest(rp_id, &passkey::credential_id(secret)?)),
            _ => None,
        })
        .collect())
}

/// Writes the digests while the keys are out, for answering once the vault locks. Run on each lock
/// and each new passkey. When it cannot write, the last digests written answer: at worst Vaulte is
/// offered for a passkey since deleted, and unlocking then finds none and hands the site over.
// ponytail: refreshed on lock and on a new passkey here, so one synced in while unlocked is missing
// if the broker dies before locking; refresh after sync too if that shows up.
pub(super) fn remember(vault: &Vault) {
    if let Ok(digests) = digests(vault) {
        let bytes: Vec<u8> = digests.into_iter().flatten().collect();
        let _ = crate::store::write_private(&path(&vault.home), &bytes);
    }
}

fn remembered(home: &Path) -> HashSet<Hash> {
    let bytes = std::fs::read(path(home)).unwrap_or_default();
    bytes.as_chunks::<{ crypto::HASH_LEN }>().0.iter().copied().collect()
}

impl Broker {
    /// Which of `ids`, credential ids a site named, are passkeys saved here for `origin`. Never a
    /// prompt, and locked or not.
    pub(super) fn passkeys_held(&self, caller: &Caller, origin: &str, ids: &[Vec<u8>]) -> Result<Response> {
        self.check(caller, Action::ListPasskeys)?;
        let page = page(origin)?;
        let known = {
            let core = self.core();
            if core.vault.is_unlocked() { digests(&core.vault)? } else { remembered(&self.home) }
        };
        // A passkey is for the page's host or a domain above it, whichever its site chose.
        let sites: Vec<&str> = std::iter::successors(Some(page.host.as_str()), |host| host.split_once('.').map(|(_, rest)| rest))
            .filter(|site| passkey::fits(site, &page))
            .collect();
        let held = ids.iter().map(|id| sites.iter().any(|site| known.contains(&digest(site, id)))).collect();
        Ok(Response::PasskeysHeld { held })
    }
}
