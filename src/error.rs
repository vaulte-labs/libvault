use std::io;

/// Stable categories of failure. Every interface maps these the same way, and agents rely on
/// the process exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Error,
    Locked,
    /// Locked too, in that nothing happens without a person, but this one can be answered by asking
    /// them for a passphrase and trying again.
    NeedsPassphrase,
    Denied,
    NotFound,
    NeedsPerson,
    /// A secret has nowhere it may be sent. Each interface says how to allow one.
    NeedsHost,
    /// The broker running is older than the program asking, and did not know its request.
    Outdated,
}

impl ErrorCode {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Error | Self::NeedsHost | Self::Outdated => 1,
            Self::Locked | Self::NeedsPassphrase => 3,
            Self::Denied => 4,
            Self::NotFound => 5,
            Self::NeedsPerson => 6,
        }
    }
}

/// Everything a vault operation can report. Messages never contain secret values.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the vault is locked")]
    Locked,
    #[error("cancelled, nothing changed")]
    Cancelled,
    #[error("approval timed out, nothing changed")]
    TimedOut,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    Exists(String),
    #[error("a vault already exists here")]
    VaultExists,
    #[error("another process has this vault open")]
    Busy,
    #[error("no vault here. Create one first")]
    NoVault,
    #[error("no secure hardware on this device")]
    NoHardware,
    #[error("secure hardware error: {0}")]
    Hardware(&'static str),
    #[error("decryption failed")]
    Decrypt,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("{0}")]
    Unreadable(String),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Usage(&'static str),
    #[error("the broker is unavailable: {0}")]
    BrokerUnavailable(&'static str),
    #[error("no allowed host for {0}, so nothing could use it")]
    NoHost(String),
    #[error("that card number is not valid, so nothing was saved")]
    InvalidCard,
    #[error("that recovery key is not valid: {0}")]
    BadRecoveryKey(String),
    #[error("this recovery key does not open this vault")]
    WrongRecoveryKey,
    #[error("a recovery key needs a copy of the vault, and there is none here")]
    NoCopy,
    #[error("{0}")]
    Peer(&'static str),
    #[error("{0}")]
    LoginRefused(&'static str),
    #[error("the vault log is damaged: {0}")]
    Corrupt(&'static str),
    #[error("this vault needs a newer version of Vaulty")]
    Newer,
    #[error("not approved: {0}")]
    NotApproved(&'static str),
    #[error("a passphrase is needed to open this vault")]
    PassphraseNeeded,
    #[error("{0}")]
    NeedsPerson(&'static str),
    #[error("{message}")]
    Broker { code: ErrorCode, message: String },
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Locked | Self::TimedOut => ErrorCode::Locked,
            Self::PassphraseNeeded => ErrorCode::NeedsPassphrase,
            Self::Cancelled | Self::NotApproved(_) => ErrorCode::Denied,
            Self::NotFound(_) | Self::NoVault => ErrorCode::NotFound,
            Self::NeedsPerson(_) => ErrorCode::NeedsPerson,
            Self::NoHost(_) => ErrorCode::NeedsHost,
            Self::Broker { code, .. } => *code,
            _ => ErrorCode::Error,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
