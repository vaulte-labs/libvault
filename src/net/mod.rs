//! Reaching other devices: finding them, pairing, and an encrypted channel, directly or through a
//! relay. Everything sent is what a backup folder would hold, so a peer is trusted with nothing,
//! and incoming logs go through the same checks as any other source.

pub(crate) mod channel;
pub(crate) mod discovery;
pub(crate) mod join_code;
pub(crate) mod pair;
pub mod relay;
