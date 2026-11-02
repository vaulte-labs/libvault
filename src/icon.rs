//! A website's icon, saved once in the vault so that no device has to ask the website for it.
//!
//! If every device fetched icons, each would keep telling websites which accounts it holds, and a
//! hostile device could plant an address for all of them to call. Saving one copy costs a single
//! request, from the device that added the login, and then works offline everywhere.
//!
//! An icon is an item of its own kind, so it is encrypted, synced, backed up and rekeyed like
//! anything else, with no rules of its own in replay. It stays out of lists and lookups, and undo
//! passes over it, because nobody asked for an icon and nobody should undo one by accident.
//!
//! The broker holds the keys, so it never fetches an icon and never decodes one. It reads the
//! fixed header and stores the bytes. `icon_image` does the decoding, in the client.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::fill::Origin;
use crate::icon_image::{LARGEST_ICON, LARGEST_SIDE};
use crate::ids::{BatchId, ItemId, SpaceId};
use crate::item::{Kind, Meta, Secret};
use crate::vault::Vault;
use crate::{Error, Result};

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const SIZE_OFFSET: usize = 16;
const HEADER_LENGTH: usize = 24;

/// Icons are shared per site, and `www.` is the same site. The prefix keeps an icon's name apart
/// from a login named after the site, wherever items are looked up by name.
fn name_for(url: &str) -> Result<String> {
    let origin = Origin::parse(url).ok_or(Error::Invalid("that is not a web address"))?;
    Ok(format!("icon:{}", origin.host.strip_prefix("www.").unwrap_or(&origin.host)))
}

/// Reads the fixed header only, which is all that can be done without decoding the image.
fn check(png: &[u8]) -> Result<()> {
    if png.len() > LARGEST_ICON {
        return Err(Error::Invalid("an icon is at most 3 KB"));
    }
    let side = |at: usize| png.get(at..at + 4).and_then(|bytes| bytes.try_into().ok()).map(u32::from_be_bytes);
    let fits = |side: Option<u32>| side.is_some_and(|side| (1..=LARGEST_SIDE).contains(&side));
    if png.len() < HEADER_LENGTH || !png.starts_with(PNG_SIGNATURE) || &png[12..16] != b"IHDR" {
        return Err(Error::Invalid("an icon is a PNG"));
    }
    if !fits(side(SIZE_OFFSET)) || !fits(side(SIZE_OFFSET + 4)) {
        return Err(Error::Invalid("an icon is at most 64 pixels across"));
    }
    Ok(())
}

impl Vault {
    /// The icon saved for a site, as bytes that have not been decoded.
    pub fn icon(&self, space: &SpaceId, url: &str) -> Result<Option<Vec<u8>>> {
        let name = name_for(url)?;
        let Some(id) = self.icon_id(space, &name)? else { return Ok(None) };
        let secret = self.secret(space, &id)?;
        let Secret::Icon { png } = &secret else { return Ok(None) };
        STANDARD.decode(png).map(Some).map_err(|_| Error::Corrupt("an icon could not be read"))
    }

    fn icon_id(&self, space: &SpaceId, name: &str) -> Result<Option<ItemId>> {
        self.with_rows(space, |rows| crate::listing::named(&rows.icons, name).map(|row| row.id))
    }

    /// Saves a site's icon, unless it has one. The first one stays, because every new one would
    /// sit in the log forever.
    pub fn save_icon(&mut self, space: &SpaceId, url: &str, png: &[u8]) -> Result<()> {
        let name = name_for(url)?;
        check(png)?;
        if self.icon_id(space, &name)?.is_some() {
            return Ok(());
        }
        let key = self.writing_key(space)?;
        let secret = Secret::Icon { png: STANDARD.encode(png) };
        let body = self.put_body(&key, *space, ItemId::random(), BatchId::ICONS, &Meta::new(Kind::Icon, name), &secret)?;
        self.commit(&[body])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32, extra: usize) -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.resize(bytes.len() + extra, 0);
        bytes
    }

    #[test]
    fn a_small_png_passes() {
        assert!(check(&png(16, 16, 40)).is_ok());
        assert!(check(&png(64, 64, 40)).is_ok());
        assert!(check(&png(64, 1, 0)).is_ok());
    }

    #[test]
    fn the_size_limit_is_exact() {
        assert!(check(&png(32, 32, LARGEST_ICON - HEADER_LENGTH)).is_ok());
        assert!(check(&png(32, 32, LARGEST_ICON - HEADER_LENGTH + 1)).is_err());
    }

    #[test]
    fn a_wide_tall_or_empty_image_is_refused() {
        for (width, height) in [(65, 16), (16, 65), (0, 16), (16, 0), (u32::MAX, u32::MAX)] {
            assert!(check(&png(width, height, 40)).is_err(), "{width}x{height}");
        }
    }

    #[test]
    fn anything_that_is_not_a_png_is_refused() {
        assert!(check(b"").is_err());
        assert!(check(b"<svg onload=alert(1)>").is_err());
        assert!(check(&png(16, 16, 0)[..HEADER_LENGTH - 1]).is_err());
        let mut wrong_chunk = png(16, 16, 40);
        wrong_chunk[12] = b'X';
        assert!(check(&wrong_chunk).is_err());
        let mut wrong_signature = png(16, 16, 40);
        wrong_signature[0] = 0;
        assert!(check(&wrong_signature).is_err());
    }

    #[test]
    fn a_site_has_one_name_however_it_is_written() {
        let name = name_for("https://github.com").unwrap();
        assert_eq!(name, "icon:github.com");
        assert_eq!(name_for("https://www.github.com/login").unwrap(), name);
        assert_eq!(name_for("http://github.com").unwrap(), name);
        assert_ne!(name_for("https://gist.github.com").unwrap(), name);
        assert!(name_for("not a url").is_err());
    }
}
