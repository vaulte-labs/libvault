//! Identifiers. Each is its own type, so passing a space where an item belongs does not compile.

macro_rules! id {
    ($($(#[$doc:meta])* $name:ident),+ $(,)?) => {$(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            #[allow(dead_code, reason = "not every id is generated locally")]
            pub(crate) fn random() -> Self {
                Self(crate::crypto::random())
            }

            pub(crate) fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl From<[u8; 16]> for $name {
            fn from(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&crate::store::log::hex(&self.0))
            }
        }
    )+};
}

id! {
    VaultId,
    DeviceId,
    SpaceId,
    ItemId,
    /// Groups the items one action changed, so one undo reverses them together.
    BatchId,
}

impl BatchId {
    /// The batch every icon is written in, which undo passes over. Nobody asked for an icon, so
    /// nobody should undo one by accident. Random ids never land on this.
    pub(crate) const ICONS: Self = Self([0; 16]);
}

/// One generation of a rotating key, such as an epoch or a version of a space. The author is part
/// of the identity: two offline devices that both rotate make two generations with the same
/// number, which then coexist instead of overwriting each other, and sort the same way everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation {
    pub number: u32,
    pub author: DeviceId,
}

impl Generation {
    pub(crate) fn first(author: DeviceId) -> Self {
        Self { number: 0, author }
    }

    pub(crate) fn after(self, author: DeviceId) -> Self {
        Self { number: self.number + 1, author }
    }
}
