//! Copies of the logs coming together, whatever carries them: a peer over a channel, a backup
//! folder, an archive or a pairing. Every copy goes through `merge`, so nothing that arrives one
//! way is trusted more than another.

pub(crate) mod exchange;
pub(crate) mod folder;
pub(crate) mod merge;
