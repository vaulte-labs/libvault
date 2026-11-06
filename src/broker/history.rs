//! An item's versions as an interface lists them: what each was called and what it changed, so a
//! person can pick the one to restore without opening any of them.

use crate::item::Meta;
use crate::items::HistoryEntry;
use crate::view::HistoryInfo;

pub(super) fn history_info(entries: &[HistoryEntry]) -> Vec<HistoryInfo> {
    let mut last_name = String::new();
    let newest = entries.len().saturating_sub(1);
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let before = index.checked_sub(1).map(|earlier| entries[earlier].meta.as_ref());
            if let Some(meta) = &entry.meta {
                last_name.clone_from(&meta.name);
            }
            HistoryInfo {
                at_ms: entry.clock >> 16,
                deleted: entry.meta.is_none(),
                name: last_name.clone(),
                changed: match (before, &entry.meta) {
                    (Some(Some(before)), Some(after)) => changed(before, after),
                    _ => Vec::new(),
                },
                current: index == newest && entry.meta.is_some(),
                restored: entry.restored,
                identical: entry.identical,
            }
        })
        .collect()
}

/// A version whose listing is unchanged, or changed only in what the secret implies, was written
/// for its secret.
fn changed(before: &Meta, after: &Meta) -> Vec<String> {
    let fields = [
        ("name", before.name != after.name),
        ("username", before.username != after.username),
        ("urls", before.urls != after.urls),
        ("hosts", before.hosts != after.hosts),
        ("two_factor", before.two_factor != after.two_factor),
    ];
    let changed: Vec<String> = fields.into_iter().filter(|(_, differs)| *differs).map(|(field, _)| field.to_owned()).collect();
    if changed.is_empty() { vec!["secret".to_owned()] } else { changed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::DeviceId;
    use crate::item::Kind;

    fn entry(meta: Option<Meta>) -> HistoryEntry {
        HistoryEntry { clock: 0, device: DeviceId::from([0; 16]), meta, restored: false, identical: false }
    }

    #[test]
    fn each_version_says_what_it_changed_and_only_the_newest_is_current() {
        let first = Meta::new(Kind::Login, "github.com");
        let renamed = Meta::new(Kind::Login, "GitHub");
        let listed = history_info(&[entry(Some(first.clone())), entry(Some(first)), entry(Some(renamed)), entry(None)]);
        assert_eq!(listed.iter().map(|version| version.changed.clone()).collect::<Vec<_>>(), [vec![], vec!["secret"], vec!["name"], vec![]]);
        assert_eq!(listed[3].name, "GitHub", "a deletion keeps the last name");
        assert!(listed.iter().all(|version| !version.current), "a deleted item has no current version");
        assert!(history_info(&[entry(Some(Meta::new(Kind::Env, "KEY")))])[0].current);
    }
}
