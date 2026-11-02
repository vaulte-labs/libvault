//! Who may do what, as one pure table. Every request is an `Action`, and the match in `decide`
//! has no wildcard, so a new action cannot compile until it has a rule.

use super::grants::{Grant, sanitize, sanitize_host};

/// Who is asking. With no token, the caller is whoever runs as this user, which may be a person
/// or an agent, so anything sensitive still needs a touch.
#[derive(Debug, Clone)]
pub(super) enum Caller {
    Anyone,
    /// One of the vault's own apps, its signature checked by the kernel's token for its process.
    App,
    Session(Grant),
}

impl Caller {
    pub fn name(&self) -> &str {
        match self {
            Self::Anyone | Self::App => "this user",
            Self::Session(grant) => &grant.agent,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Action<'a> {
    /// Names and metadata, never values.
    Read,
    /// Signs in using the broker's own browser. The caller receives a session, never the password.
    Login {
        name: &'a str,
        site: &'a str,
        into: &'a str,
    },
    /// Hands plaintext to an interface to put on a page.
    Fill {
        name: &'a str,
        origin: &'a str,
    },
    CreateItem,
    ReplaceItem {
        name: &'a str,
    },
    /// Shows an item in another space too, which widens who can read it.
    LinkItem {
        name: &'a str,
        to: &'a str,
    },
    DeleteItem {
        name: &'a str,
    },
    Undo,
    Reveal {
        name: &'a str,
        space: &'a str,
    },
    /// A website's icon, which holds nothing secret but stays in the log for good.
    SaveIcon,
    /// Every login's sites and username, for the system's autofill to suggest.
    AutofillIdentities,
    /// Which passkeys fit a page: names only.
    ListPasskeys,
    /// Makes a passkey for a site, which then trusts this vault to say who is signing in.
    CreatePasskey {
        site: &'a str,
        user: &'a str,
    },
    /// Signs a sign-in with a passkey, which tells the site its user was just verified.
    UsePasskey {
        name: &'a str,
        site: &'a str,
    },
    /// When this device's vault locks by itself. Something that could set it to never would
    /// keep the keys out for as long as it liked.
    ChangeLockSettings,
    /// Every login's current two-factor code at once.
    Codes,
    /// A login's current two-factor code, which is worth as much as its password for a moment.
    Code {
        name: &'a str,
        space: &'a str,
    },
    AllowHost {
        name: &'a str,
        host: &'a str,
    },
    Import {
        count: usize,
        space: &'a str,
    },
    CreateSpace,
    IssueGrant {
        agent: &'a str,
        space: &'a str,
        duration: &'a str,
    },
    ManageGrants,
    ReadAudit,
    Stop,
    Lock,
    /// The words go in the prompt, because a touch alone says nothing about which device it is for.
    AddDevice {
        name: &'a str,
        words: &'a [String; 3],
    },
    /// `holds` is already in the words a person reads.
    AddServer {
        name: &'a str,
        holds: &'a str,
        words: &'a [String; 3],
    },
    /// Starts pairing. The change itself is approved later, once there is something to approve.
    BeginPairing,
    /// Another enrolled device asks this one to approve something.
    ApproveForDevice {
        what: &'a str,
    },
    RemoveDevice {
        name: &'a str,
    },
    RotateRecovery,
    ResolveConflict,
    ExportArchive {
        path: &'a str,
    },
    ExportPlaintext {
        path: &'a str,
    },
    AddBackup {
        folder: &'a str,
    },
    RemoveBackup {
        folder: &'a str,
    },
    Wipe,
    /// A program gets placeholders, and secrets only reach their allowed hosts.
    RunProxied {
        command: &'a str,
        space: &'a str,
    },
    /// A program gets real values. `command` is what the caller says it is, and the values go back
    /// to the caller, so the names of the values are what a person can actually judge.
    RunWithValues {
        command: &'a str,
        space: &'a str,
        names: &'a [&'a str],
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Allow,
    Refuse(&'static str),
    /// Needs a fresh approval, and this text says what for.
    Touch(String),
}

const PASSKEYS: &str = "a session cannot use passkeys. Ask for a sign-in instead";
const MANAGE_VAULT: &str = "a session cannot manage the vault";
const MAX_LISTED: usize = 3;

/// For actions that widen what a session can do, which a session must never do for itself.
fn people_only(caller: &Caller, refusal: &'static str, verdict: Verdict) -> Verdict {
    match caller {
        Caller::Anyone | Caller::App => verdict,
        Caller::Session(_) => Verdict::Refuse(refusal),
    }
}

/// The first few of `names`, and how many more.
fn listed(names: &[&str]) -> String {
    let shown: Vec<String> = names.iter().take(MAX_LISTED).map(|name| sanitize(name)).collect();
    match names.len().saturating_sub(MAX_LISTED) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    }
}

impl Action<'_> {
    /// What a person does all day once their vault is open. Anything that changes who or what can
    /// reach the vault is not on this list.
    fn is_everyday(&self) -> bool {
        matches!(
            self,
            Self::Reveal { .. }
                | Self::Fill { .. }
                | Self::Code { .. }
                | Self::Codes
                | Self::ReplaceItem { .. }
                | Self::DeleteItem { .. }
                | Self::Undo
        )
    }
}

/// The person unlocked the vault with a touch, and an app of its own is asking, so everyday use
/// needs no touch of its own until the vault locks again. Any other process the person runs could
/// be something else speaking for them, so it asks every time.
pub(super) fn decide(caller: &Caller, action: Action<'_>) -> Verdict {
    match (caller, verdict(caller, action)) {
        (Caller::App, Verdict::Touch(_)) if action.is_everyday() => Verdict::Allow,
        (_, verdict) => verdict,
    }
}

fn verdict(caller: &Caller, action: Action<'_>) -> Verdict {
    match action {
        Action::Read | Action::CreateItem => Verdict::Allow,
        // A grant covers using secrets. It never covers changing or reading them.
        Action::ReplaceItem { name } => Verdict::Touch(format!("replace {}", sanitize(name))),
        Action::DeleteItem { name } => Verdict::Touch(format!("delete {}", sanitize(name))),
        Action::LinkItem { name, to } => people_only(
            caller,
            "a session cannot show an item in another space",
            Verdict::Touch(format!("show {} in {} too", sanitize(name), sanitize(to))),
        ),
        Action::Undo => Verdict::Touch("undo your last change".to_owned()),
        Action::Reveal { name, space } => Verdict::Touch(format!("reveal {} from {}", sanitize(name), sanitize(space))),
        Action::SaveIcon => people_only(caller, "a session cannot add to the vault's icons", Verdict::Allow),
        // The person chose to let this device's AutoFill suggest their logins. An agent has no
        // such list to fill, and it would cross the space a grant gives.
        Action::AutofillIdentities => people_only(caller, "a session cannot list logins for AutoFill", Verdict::Allow),
        Action::ListPasskeys => people_only(caller, PASSKEYS, Verdict::Allow),
        Action::CreatePasskey { site, user } => {
            people_only(caller, PASSKEYS, Verdict::Touch(format!("save a passkey for {} on {}", sanitize(user), sanitize_host(site))))
        }
        Action::UsePasskey { name, site } => {
            people_only(caller, PASSKEYS, Verdict::Touch(format!("sign in to {} with {}", sanitize_host(site), sanitize(name))))
        }
        Action::ChangeLockSettings => {
            people_only(caller, "a session cannot change when the vault locks", Verdict::Touch("change when your vault locks".to_owned()))
        }
        Action::Codes => people_only(
            caller,
            "a session cannot read two-factor codes. Ask for a sign-in instead",
            Verdict::Touch("show your two-factor codes".to_owned()),
        ),
        Action::Code { name, space } => people_only(
            caller,
            "a session cannot read a two-factor code. Ask for a sign-in instead",
            Verdict::Touch(format!("show the two-factor code for {} from {}", sanitize(name), sanitize(space))),
        ),
        Action::AllowHost { name, host } => Verdict::Touch(format!("let {} go to {}", sanitize(name), sanitize_host(host))),
        Action::RunWithValues { command, space, names } => {
            Verdict::Touch(format!("give {} from {} to {}", listed(names), sanitize(space), sanitize(command)))
        }
        Action::RunProxied { command, space } => match caller {
            Caller::Anyone | Caller::App => Verdict::Touch(format!("run {} with {}", sanitize(command), sanitize(space))),
            Caller::Session(_) => Verdict::Allow,
        },
        Action::Import { count, space } => {
            people_only(caller, "a session cannot import", Verdict::Touch(format!("import {count} items into {}", sanitize(space))))
        }
        Action::IssueGrant { agent, space, duration } => people_only(
            caller,
            "a session cannot create sessions",
            Verdict::Touch(format!("let \"{}\" use {} for {duration}", sanitize(agent), sanitize(space))),
        ),
        Action::Login { name, site, into } => match caller {
            Caller::Anyone | Caller::App => {
                Verdict::Touch(format!("sign in to {} as {} and give the session to {}", sanitize_host(site), sanitize(name), sanitize(into)))
            }
            Caller::Session(_) => Verdict::Allow,
        },
        Action::Fill { name, origin } => people_only(
            caller,
            "a session cannot read a password. Ask for a sign-in instead",
            Verdict::Touch(format!("fill {} on {}", sanitize(name), sanitize_host(origin))),
        ),
        Action::BeginPairing | Action::Stop | Action::Lock => people_only(caller, MANAGE_VAULT, Verdict::Allow),
        Action::AddDevice { name, words } => {
            let [first, second, third] = words;
            people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("add {} if it shows {first} {second} {third}", sanitize(name))))
        }
        Action::AddServer { name, holds, words } => {
            let [first, second, third] = words;
            let prompt = format!("add {} as a server holding {holds} if it shows {first} {second} {third}", sanitize(name));
            people_only(caller, MANAGE_VAULT, Verdict::Touch(prompt))
        }
        Action::ApproveForDevice { what } => people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("approve: {}", sanitize(what)))),
        Action::RemoveDevice { name } => people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("remove {} from your vault", sanitize(name)))),
        Action::RotateRecovery => people_only(caller, MANAGE_VAULT, Verdict::Touch("replace your recovery key".to_owned())),
        Action::ResolveConflict => people_only(caller, MANAGE_VAULT, Verdict::Touch("accept the other device's roster".to_owned())),
        Action::ExportArchive { path } => {
            people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("export an encrypted copy of your vault to {}", sanitize(path))))
        }
        Action::ExportPlaintext { path } => {
            people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("export every secret in plaintext to {}", sanitize(path))))
        }
        Action::AddBackup { folder } => people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("back up your vault to {}", sanitize(folder)))),
        Action::RemoveBackup { folder } => people_only(caller, MANAGE_VAULT, Verdict::Touch(format!("stop backing up to {}", sanitize(folder)))),
        Action::Wipe => people_only(caller, MANAGE_VAULT, Verdict::Touch("erase your vault from this device".to_owned())),
        Action::CreateSpace => people_only(caller, "a session cannot create spaces", Verdict::Allow),
        Action::ManageGrants => people_only(caller, "a session cannot manage sessions", Verdict::Allow),
        Action::ReadAudit => people_only(caller, "a session cannot read the audit log", Verdict::Allow),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Caller {
        Caller::Session(Grant { id: String::new(), agent: "agent".to_owned(), space: [0; 16].into(), expires: u64::MAX })
    }

    fn touches(verdict: &Verdict) -> bool {
        matches!(verdict, Verdict::Touch(_))
    }

    #[test]
    fn nothing_that_exposes_or_changes_a_secret_is_free_for_anyone() {
        let sensitive = [
            Action::ReplaceItem { name: "KEY" },
            Action::DeleteItem { name: "KEY" },
            Action::Undo,
            Action::Reveal { name: "KEY", space: "a" },
            Action::AllowHost { name: "KEY", host: "evil.example" },
            Action::RunWithValues { command: "bun", space: "a", names: &["KEY"] },
        ];
        for action in sensitive {
            assert!(touches(&decide(&Caller::Anyone, action)), "{action:?}");
            assert!(touches(&decide(&session(), action)), "{action:?}");
        }
    }

    #[test]
    fn the_vaults_own_app_uses_an_open_vault_without_a_touch_and_changes_nothing_else_without_one() {
        let everyday = [
            Action::Reveal { name: "KEY", space: "a" },
            Action::Fill { name: "x", origin: "x.example" },
            Action::Code { name: "x", space: "a" },
            Action::ReplaceItem { name: "KEY" },
            Action::DeleteItem { name: "KEY" },
            Action::Undo,
        ];
        for action in everyday {
            assert_eq!(decide(&Caller::App, action), Verdict::Allow, "{action:?}");
        }
        let words = ["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let widening = [
            Action::LinkItem { name: "x", to: "Agents" },
            Action::ChangeLockSettings,
            Action::AllowHost { name: "KEY", host: "evil.example" },
            Action::RunWithValues { command: "bun", space: "a", names: &["KEY"] },
            Action::RunProxied { command: "bun", space: "a" },
            Action::Login { name: "x", site: "x.example", into: "y" },
            Action::Import { count: 1, space: "a" },
            Action::IssueGrant { agent: "x", space: "a", duration: "1 hour" },
            Action::AddDevice { name: "Phone", words: &words },
            Action::RemoveDevice { name: "Phone" },
            Action::RotateRecovery,
            Action::ExportPlaintext { path: "/tmp/x" },
            Action::ExportArchive { path: "/tmp/x" },
            Action::AddBackup { folder: "/tmp/x" },
            Action::Wipe,
        ];
        for action in widening {
            assert!(touches(&decide(&Caller::App, action)), "{action:?}");
        }
    }

    #[test]
    fn a_session_can_sign_in_but_never_receive_a_password() {
        assert_eq!(decide(&session(), Action::Login { name: "x", site: "x.example", into: "y" }), Verdict::Allow);
        assert!(touches(&decide(&Caller::Anyone, Action::Login { name: "x", site: "x.example", into: "y" })));
        assert!(matches!(decide(&session(), Action::Fill { name: "x", origin: "y" }), Verdict::Refuse(_)));
        assert!(matches!(decide(&session(), Action::Code { name: "x", space: "y" }), Verdict::Refuse(_)));
        assert!(touches(&decide(&Caller::Anyone, Action::Code { name: "x", space: "y" })));
        assert!(touches(&decide(&Caller::Anyone, Action::Fill { name: "x", origin: "y" })));
    }

    #[test]
    fn a_session_covers_proxied_use_and_nothing_more_than_that() {
        let run = Action::RunProxied { command: "bun", space: "a" };
        assert_eq!(decide(&session(), run), Verdict::Allow);
        assert!(touches(&decide(&Caller::Anyone, run)));
    }

    #[test]
    fn a_session_cannot_widen_its_own_access() {
        let widening = [
            Action::Import { count: 1, space: "a" },
            Action::IssueGrant { agent: "x", space: "a", duration: "1 hour" },
            Action::CreateSpace,
            Action::ManageGrants,
            Action::ReadAudit,
            Action::AddDevice { name: "x", words: &[String::new(), String::new(), String::new()] },
            Action::RemoveDevice { name: "x" },
            Action::BeginPairing,
            Action::ApproveForDevice { what: "x" },
            Action::RotateRecovery,
            Action::ResolveConflict,
            Action::ExportArchive { path: "x" },
            Action::ExportPlaintext { path: "x" },
            Action::AddBackup { folder: "x" },
            Action::RemoveBackup { folder: "x" },
            Action::Wipe,
        ];
        for action in widening {
            assert!(matches!(decide(&session(), action), Verdict::Refuse(_)), "{action:?}");
            assert!(!matches!(decide(&Caller::Anyone, action), Verdict::Refuse(_)), "{action:?}");
        }
    }

    fn prompt(action: Action<'_>) -> String {
        let Verdict::Touch(prompt) = decide(&Caller::Anyone, action) else { panic!("this needs a touch") };
        prompt
    }

    #[test]
    fn a_long_host_cannot_push_its_real_owner_out_of_a_prompt() {
        let host = "api.openai.com.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.attacker.example";
        for shown in [prompt(Action::AllowHost { name: "KEY", host }), prompt(Action::Fill { name: "GitHub", origin: host })] {
            assert!(shown.contains("attacker.example"), "{shown}");
            assert!(!shown.contains("api.openai.com"), "the part that looks safe must be what goes: {shown}");
        }
    }

    #[test]
    fn a_host_cannot_look_like_another_in_a_prompt() {
        let shown = prompt(Action::AllowHost { name: "KEY", host: "\u{430}pi.openai.com" });
        assert!(shown.is_ascii(), "{shown}");
    }

    #[test]
    fn adding_a_device_shows_the_words_at_the_moment_of_the_touch() {
        let words = ["apple".to_owned(), "river".to_owned(), "stone".to_owned()];
        let shown = prompt(Action::AddDevice { name: "iPad", words: &words });
        assert!(words.iter().all(|word| shown.contains(word.as_str())), "{shown}");
    }

    #[test]
    fn a_touch_for_real_values_names_them() {
        let shown = prompt(Action::RunWithValues { command: "git", space: "Work", names: &["PROD_DB", "API_KEY"] });
        assert!(shown.contains("PROD_DB") && shown.contains("API_KEY") && shown.contains("Work"), "{shown}");
        let many = prompt(Action::RunWithValues { command: "git", space: "Work", names: &["A", "B", "C", "D", "E"] });
        assert!(many.contains("A, B, C and 2 more"), "{many}");
    }

    #[test]
    fn a_touch_says_where_things_go() {
        assert!(prompt(Action::Login { name: "GitHub", site: "github.com", into: "http 127.0.0.1 9222" }).contains("9222"));
        assert!(prompt(Action::ExportPlaintext { path: "/Users/me/Desktop/all.json" }).contains("all.json"));
        assert!(prompt(Action::Reveal { name: "KEY", space: "Work" }).contains("Work"));
    }

    #[test]
    fn two_long_names_that_differ_at_the_end_look_different() {
        let (one, two) = ("production-database-password-for-eu", "production-database-password-for-us");
        assert_ne!(prompt(Action::Reveal { name: one, space: "a" }), prompt(Action::Reveal { name: two, space: "a" }));
    }

    #[test]
    fn a_session_cannot_stop_the_broker() {
        assert!(matches!(decide(&session(), Action::Stop), Verdict::Refuse(_)));
        assert_eq!(decide(&Caller::Anyone, Action::Stop), Verdict::Allow);
        assert!(matches!(decide(&session(), Action::Lock), Verdict::Refuse(_)));
        assert_eq!(decide(&Caller::Anyone, Action::Lock), Verdict::Allow);
    }

    #[test]
    fn prompts_cannot_be_forged_through_names() {
        let Verdict::Touch(prompt) = decide(&Caller::Anyone, Action::IssueGrant { agent: "x\"\nApple Update", space: "a", duration: "1 hour" })
        else {
            panic!("a grant needs a touch");
        };
        assert!(!prompt.contains('\n'));
        assert_eq!(prompt.matches('"').count(), 2);
    }
}
