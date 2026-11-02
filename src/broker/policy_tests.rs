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
        Action::DeleteItems { names: &["KEY"] },
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
        Action::DeleteItems { names: &["KEY"] },
        Action::Undo,
    ];
    for action in everyday {
        assert_eq!(decide(&Caller::App, action), Verdict::Allow, "{action:?}");
    }
    let words = ["a".to_owned(), "b".to_owned(), "c".to_owned()];
    let widening = [
        Action::LinkItem { name: "x", to: "Agents" },
        Action::MoveItem { name: "x", to: "Agents" },
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
    let Verdict::Touch(prompt) = decide(&Caller::Anyone, Action::IssueGrant { agent: "x\"\nApple Update", space: "a", duration: "1 hour" }) else {
        panic!("a grant needs a touch");
    };
    assert!(!prompt.contains('\n'));
    assert_eq!(prompt.matches('"').count(), 2);
}

#[test]
fn a_passkey_an_agent_asks_for_names_the_agent() {
    let create = Action::CreatePasskey { site: "github.com", user: "ada" };
    let Verdict::Touch(prompt) = decide(&session(), create) else { panic!("a passkey needs a touch") };
    assert_eq!(prompt, "let \"agent\" save a passkey for ada on github.com");
    assert_eq!(decide(&Caller::Anyone, create), Verdict::Touch("save a passkey for ada on github.com".to_owned()));
    assert!(touches(&decide(&session(), Action::UsePasskey { name: "ada on github.com", site: "github.com" })));
    assert!(matches!(decide(&session(), Action::ListPasskeys), Verdict::Refuse(_)));
}
