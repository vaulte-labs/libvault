//! Every flow in FLOWS.md through the public API, with failures as well as success.

mod support;

use std::fs;
use std::time::{Duration, Instant};

use libvault::item::{self, Meta, Secret};
use libvault::{Client, Connect, Cost, ErrorCode, ImportFile, Setup};
use support::{PASSPHRASE, Vault, code, env, options};

fn revealed(client: &mut Client, space: Option<&str>, name: &str) -> String {
    match &client.reveal(space, name).unwrap() {
        Secret::Env { value } => value.clone(),
        other => panic!("not an env var: {other:?}"),
    }
}

// Flow 1: onboarding.

#[test]
fn the_recovery_words_are_confirmed_before_anything_exists() {
    let setup = Setup::with_passphrase(PASSPHRASE, Cost::FAST).unwrap();
    let recovery = setup.recovery();
    let words = recovery.words();
    let split: Vec<&str> = words.split(' ').collect();
    assert_eq!(split.len(), 24);
    let positions = recovery.confirmation_positions();
    assert!(positions[0] != positions[1] && positions[1] != positions[2] && positions[0] != positions[2]);
    assert!(recovery.check_word(positions[0], split[positions[0]]));
    assert!(recovery.check_word(positions[0], &split[positions[0]].to_uppercase()));
    assert!(!recovery.check_word(positions[0], "wrong"));
}

#[test]
fn setup_refuses_to_replace_a_vault() {
    let vault = Vault::new();
    let again = Setup::with_passphrase(PASSPHRASE, Cost::FAST).unwrap().finish(&vault.home, "Other");
    assert!(matches!(again, Err(libvault::Error::VaultExists)));
}

#[test]
fn a_crashed_setup_leaves_nothing_the_next_one_trips_over() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".lv-setup-crashed")).unwrap();
    let home = dir.path().join("vault");
    Setup::with_passphrase(PASSPHRASE, Cost::FAST).unwrap().finish(&home, "Mac").unwrap();
    assert!(!dir.path().join(".lv-setup-crashed").exists());
    assert!(libvault::exists(&home));
}

// Flow 2: unlock and lock.

#[test]
fn a_refused_touch_changes_nothing() {
    let vault = Vault::new();
    vault.client().lock().unwrap();
    vault.deny_touches();
    assert_eq!(code(vault.client().add(None, Meta::env("KEY"), env("v"), false)), ErrorCode::Denied);
    vault.allow_touches();
    assert_eq!(code(vault.client().item(None, "KEY")), ErrorCode::NotFound);
}

#[test]
fn stopping_the_broker_drops_keys_and_the_next_call_recovers() {
    let vault = Vault::new();
    vault.add_env("KEY", "value", None);
    vault.client().stop().unwrap();
    assert!(!vault.client().status().unwrap().unlocked);
    assert_eq!(vault.client().items(None).unwrap().len(), 1);
}

#[test]
fn the_broker_answers_while_a_person_is_deciding() {
    let vault = Vault::new();
    vault.client().lock().unwrap();
    let pid = fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap();
    fs::write(vault.home.join("slow"), "").unwrap();

    let home = vault.home.clone();
    let unlocking = std::thread::spawn(move || Client::connect(&home, options(None)).unwrap().unlock());
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    let status = vault.client().status().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1), "status waited {:?} behind a prompt", started.elapsed());
    assert!(!status.unlocked);

    unlocking.join().unwrap().unwrap();
    fs::remove_file(vault.home.join("slow")).unwrap();
    assert!(vault.client().status().unwrap().unlocked);
    assert_eq!(fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap(), pid, "the broker must survive its own prompt");
}

#[test]
fn a_frozen_broker_is_replaced_instead_of_hanging_every_interface() {
    let vault = Vault::new();
    vault.add_env("KEY", "v", None);
    let pid = fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap();
    std::process::Command::new("/bin/kill").args(["-STOP", pid.trim()]).status().unwrap();

    let started = Instant::now();
    let status = vault.client().status().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    assert!(!status.unlocked, "a new broker starts locked");
    assert_ne!(fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap(), pid);
}

/// An `lvd` that reports `build` to `--build` and runs brokers that report it too, as another
/// interface's own `lvd` would.
fn lvd_reporting(vault: &Vault, build: &str) -> std::path::PathBuf {
    let daemon = vault.dir.path().join("other-lvd");
    let lvd = support::LVD;
    fs::write(&daemon, format!("#!/bin/sh\n[ \"$1\" = --build ] && {{ echo {build}; exit 0; }}\nLV_TEST_BUILD={build} exec {lvd} \"$@\"\n")).unwrap();
    fs::set_permissions(&daemon, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    daemon
}

fn broker_pid(vault: &Vault) -> String {
    fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap()
}

/// Started by another interface's `lvd`, and unlocked there.
fn broker_from(vault: &Vault, build: &str) -> String {
    let daemon = lvd_reporting(vault, build);
    Client::connect(&vault.home, Connect { daemon: Some(&daemon), ..options(None) }).unwrap().unlock().unwrap();
    broker_pid(vault)
}

#[test]
fn a_broker_of_the_same_release_serves_every_interface_whatever_lvd_it_brings() {
    let vault = Vault::new();
    let broker = broker_from(&vault, &format!("{}-another-build", env!("CARGO_PKG_VERSION")));
    for _ in 0..3 {
        let status = vault.client().status().unwrap();
        assert!(status.unlocked, "replacing it would have cut off the interface using it");
    }
    assert_eq!(broker_pid(&vault), broker);
}

#[test]
fn a_broker_left_over_from_an_older_release_is_replaced() {
    let vault = Vault::new();
    let old = broker_from(&vault, "0.0.1-old");
    assert_ne!(vault.client().status().unwrap().build, "0.0.1-old");
    assert_ne!(broker_pid(&vault), old);
}

#[test]
fn a_signed_broker_takes_over_from_an_unsigned_one_of_the_same_release() {
    let vault = Vault::new();
    vault.client().status().unwrap();
    let unsigned = broker_pid(&vault);
    let signed = lvd_reporting(&vault, &format!("{}-another-build+TEAM", env!("CARGO_PKG_VERSION")));
    let status = Client::connect(&vault.home, Connect { daemon: Some(&signed), ..options(None) }).unwrap().status().unwrap();
    assert!(status.build.ends_with("+TEAM"), "only a signed broker opens the shared socket: {}", status.build);
    assert_ne!(broker_pid(&vault), unsigned);
}

#[test]
fn an_unsigned_lvd_never_takes_over_from_a_signed_broker() {
    let vault = Vault::new();
    let signed = broker_from(&vault, &format!("{}-another-build+TEAM", env!("CARGO_PKG_VERSION")));
    assert!(vault.client().status().unwrap().unlocked);
    assert_eq!(broker_pid(&vault), signed);
}

#[test]
fn a_newer_broker_is_never_replaced_by_an_older_lvd() {
    let vault = Vault::new();
    let newer = broker_from(&vault, "999.0.0-new");
    assert_eq!(vault.client().status().unwrap().build, "999.0.0-new");
    assert_eq!(broker_pid(&vault), newer);
}

fn now_ms() -> u64 {
    u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

#[test]
fn the_device_list_says_when_each_device_last_changed_something() {
    let vault = Vault::new();
    std::thread::sleep(Duration::from_millis(20));
    let before = now_ms();
    vault.add_env("KEY", "v", None);
    let devices = vault.client().devices().unwrap();
    let this = devices.iter().find(|device| device.is_this_device).unwrap();
    assert!((before..=now_ms()).contains(&this.last_change_ms), "{} is not just now", this.last_change_ms);
}

fn send_frame(stream: &mut std::os::unix::net::UnixStream, value: &serde_json::Value) {
    use std::io::Write;
    let bytes = serde_json::to_vec(value).unwrap();
    stream.write_all(&u32::try_from(bytes.len()).unwrap().to_le_bytes()).unwrap();
    stream.write_all(&bytes).unwrap();
}

fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> Option<serde_json::Value> {
    use std::io::Read;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).ok()?;
    let mut bytes = vec![0u8; u32::from_le_bytes(length) as usize];
    stream.read_exact(&mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn envelope(request: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "session": null, "passphrase": null, "request": request })
}

#[test]
fn a_broker_says_when_it_does_not_know_a_request_and_keeps_serving() {
    let vault = Vault::new();
    vault.client().status().unwrap();
    let mut stream = std::os::unix::net::UnixStream::connect(vault.home.join("run/lv.sock")).unwrap();
    send_frame(&mut stream, &envelope(&serde_json::json!({ "op": "made_up_by_a_newer_program" })));
    let reply = read_frame(&mut stream).unwrap();
    assert_eq!((reply["result"].as_str(), reply["code"].as_str()), (Some("error"), Some("outdated")), "{reply}");
    send_frame(&mut stream, &envelope(&serde_json::json!({ "op": "status" })));
    assert_eq!(read_frame(&mut stream).unwrap()["result"], "status");
}

/// Stands in for a broker from before a request existed: it answers a status as `build` and
/// knows nothing else, until it is asked to stop.
fn old_broker(vault: &Vault, build: &str) -> std::thread::JoinHandle<()> {
    let socket = vault.home.join("run/lv.sock");
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let status = serde_json::json!({
        "result": "status", "unlocked": true, "hardware": false, "device_count": 1, "sync_port": null, "backups": [],
        "contacts": [], "last_copy": true, "problems": [], "build": build,
    });
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            while let Some(envelope) = read_frame(&mut stream) {
                match envelope["request"]["op"].as_str() {
                    Some("status") => send_frame(&mut stream, &status),
                    Some("stop") => {
                        send_frame(&mut stream, &serde_json::json!({ "result": "ok" }));
                        fs::remove_file(&socket).unwrap();
                        return;
                    }
                    _ => send_frame(&mut stream, &serde_json::json!({ "result": "error", "code": "outdated", "message": "older" })),
                }
            }
        }
    })
}

#[test]
fn a_broker_that_does_not_know_a_request_is_replaced_once_and_the_request_goes_again() {
    let vault = Vault::new();
    let old = old_broker(&vault, &format!("{}-older", env!("CARGO_PKG_VERSION")));
    let mut client = vault.client();
    client.add(None, Meta::env("PRESENT"), env("v"), false).unwrap();
    old.join().unwrap();
    assert_eq!(client.items(None).unwrap().len(), 1, "the new broker answers on the same client");
}

#[test]
fn an_unsigned_lvd_never_replaces_a_signed_broker_it_finds_outdated() {
    let vault = Vault::new();
    let old = old_broker(&vault, &format!("{}-older+TEAM", env!("CARGO_PKG_VERSION")));
    let mut client = vault.client();
    assert_eq!(code(client.items(None)), ErrorCode::Outdated);
    client.stop().unwrap();
    old.join().unwrap();
}

// Flow 3: add, edit, delete.

#[test]
fn listings_show_names_and_never_values() {
    let vault = Vault::new();
    vault.add_env("OPENAI_API_KEY", "sk-secret-value", None);
    let mut client = vault.client();
    let shown = format!("{:?} {:?} {:?}", client.items(None).unwrap(), client.item(None, "OPENAI_API_KEY").unwrap(), client.status().unwrap());
    assert!(shown.contains("OPENAI_API_KEY"));
    assert!(!shown.contains("sk-secret-value"));
}

#[test]
fn well_known_keys_get_their_host_automatically() {
    let vault = Vault::new();
    vault.add_env("OPENAI_API_KEY", "v", None);
    assert_eq!(vault.client().item(None, "OPENAI_API_KEY").unwrap().meta.hosts, ["api.openai.com"]);
}

#[test]
fn a_taken_name_needs_replace_and_replacing_can_be_undone() {
    let vault = Vault::new();
    vault.add_env("KEY", "old", None);
    let mut client = vault.client();
    assert_eq!(code(client.add(None, Meta::env("KEY"), env("new"), false)), ErrorCode::Error);
    assert_eq!(revealed(&mut client, None, "KEY"), "old");

    client.add(None, Meta::env("KEY"), env("new"), true).unwrap();
    assert_eq!(revealed(&mut client, None, "KEY"), "new");
    client.undo().unwrap();
    assert_eq!(revealed(&mut client, None, "KEY"), "old");
    assert_eq!(client.history(None, "KEY").unwrap().len(), 3);
}

#[test]
fn deleting_can_be_undone() {
    let vault = Vault::new();
    vault.add_env("KEY", "value", None);
    let mut client = vault.client();
    client.remove(None, "KEY").unwrap();
    assert_eq!(code(client.item(None, "KEY")), ErrorCode::NotFound);
    client.undo().unwrap();
    assert_eq!(revealed(&mut client, None, "KEY"), "value");
}

#[test]
fn the_same_name_in_two_spaces_holds_different_values() {
    let vault = Vault::new();
    vault.space("project-a");
    vault.space("project-b");
    vault.add_env("OPENAI_API_KEY", "key-a", Some("project-a"));
    vault.add_env("OPENAI_API_KEY", "key-b", Some("project-b"));
    let mut client = vault.client();
    assert_eq!(revealed(&mut client, Some("project-a"), "OPENAI_API_KEY"), "key-a");
    assert_eq!(revealed(&mut client, Some("project-b"), "OPENAI_API_KEY"), "key-b");
}

#[test]
fn folders_link_to_spaces_from_any_depth() {
    let vault = Vault::new();
    let nested = vault.dir.path().join("work/nested");
    fs::create_dir_all(&nested).unwrap();
    libvault::link_folder(nested.parent().unwrap(), "project-b").unwrap();
    assert_eq!(libvault::linked_space(&nested).as_deref(), Some("project-b"));
}

#[test]
fn a_name_that_could_spoof_a_terminal_is_refused() {
    let vault = Vault::new();
    let mut client = vault.client();
    for name in ["\u{1b}[2Jfake", "two\nlines", ""] {
        assert!(client.add(None, Meta::env(name), env("v"), false).is_err(), "{name:?}");
    }
    assert!(client.items(None).unwrap().is_empty());
    assert!(client.create_space("bad\nspace").is_err());
    vault.add_env("KEY", "v", None);
    assert!(client.allow(None, "KEY", "host\nname").is_err());
}

#[test]
fn a_card_with_a_bad_number_is_not_saved_and_a_good_one_lists_only_its_last_four() {
    let vault = Vault::new();
    let bad = item::card("Typo", "4242 4242 4242 4241", "12/30".to_owned(), "123".to_owned(), "A Person".to_owned());
    assert!(matches!(bad, Err(libvault::Error::InvalidCard)));
    let (meta, secret) = item::card("Visa", "4242 4242 4242 4242", "12/30".to_owned(), "123".to_owned(), "A Person".to_owned()).unwrap();
    let mut client = vault.client();
    client.add(None, meta, secret, false).unwrap();
    let shown = format!("{:?}", client.items(None).unwrap());
    assert!(shown.contains("Visa 4242"));
    assert!(!shown.contains("4242 4242"));
}

// Flow 4: import.

#[test]
fn importing_handles_duplicates_and_undoes_as_one() {
    let vault = Vault::new();
    vault.add_env("SAME", "value", None);
    vault.add_env("CLASH", "existing", None);
    let file = vault.file(".env", b"SAME=value\nCLASH=different\nNEW=1\nnot a line\n");

    let parsed = ImportFile::read(&file).unwrap();
    assert_eq!(parsed.unreadable, [4]);
    let mut client = vault.client();
    let imported = client.import(None, parsed.items).unwrap();
    assert_eq!((imported.added, imported.skipped, imported.renamed), (2, 1, 1));
    assert!(file.exists());

    assert_eq!(revealed(&mut client, None, "CLASH"), "existing");
    assert_eq!(revealed(&mut client, None, "CLASH_2"), "different");

    assert_eq!(client.undo().unwrap(), 2);
    assert_eq!(code(client.item(None, "NEW")), ErrorCode::NotFound);
    assert_eq!(revealed(&mut client, None, "CLASH"), "existing");
}

#[test]
fn an_apple_export_imports_its_logins_and_names_bad_rows() {
    let vault = Vault::new();
    let file = vault.file("passwords.csv", b"Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com,me,hunter2,,\nbad,row\n");
    let parsed = ImportFile::read(&file).unwrap();
    assert_eq!(parsed.unreadable, [3]);
    let mut client = vault.client();
    client.import(None, parsed.items).unwrap();
    assert_eq!(client.item(None, "GitHub").unwrap().meta.urls, ["https://github.com"]);
}

#[test]
fn a_hostile_export_cannot_put_escapes_into_a_list() {
    let vault = Vault::new();
    let file = vault.file("evil.csv", "Title,URL,Username,Password,Notes,OTPAuth\n\"a\u{1b}[2Jb\",https://x.example,me,p,,\n".as_bytes());
    let mut client = vault.client();
    client.import(None, ImportFile::read(&file).unwrap().items).unwrap();
    let items = client.items(None).unwrap();
    assert!(!items[0].meta.name.contains('\u{1b}'));
}

#[test]
fn an_unknown_csv_and_a_binary_file_are_refused_with_a_reason() {
    let vault = Vault::new();
    let csv = ImportFile::read(&vault.file("other.csv", b"site,login\na,b\n")).unwrap_err();
    assert!(csv.to_string().contains("2 columns"), "{csv}");
    assert!(ImportFile::read(&vault.file("binary.env", &[0xff, 0xfe, 0x00, 0x80])).is_err());
}

#[test]
fn a_refused_touch_imports_nothing() {
    let vault = Vault::new();
    let items = ImportFile::read(&vault.file(".env", b"NEW=1\n")).unwrap().items;
    vault.deny_touches();
    assert_eq!(code(vault.client().import(None, items)), ErrorCode::Denied);
    vault.allow_touches();
    assert_eq!(code(vault.client().item(None, "NEW")), ErrorCode::NotFound);
}

#[test]
fn scanning_counts_variables_without_reading_them_out() {
    let vault = Vault::new();
    let folder = vault.dir.path().join("project");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join(".env"), "KEY=super-secret\nOTHER=2\n").unwrap();
    let found = libvault::find_env_files(&folder);
    assert_eq!(found[0].variables, 2);
    assert!(!format!("{found:?}").contains("super-secret"));
}

// Flow 8: allow an agent.

#[test]
fn a_session_is_confined_to_its_space() {
    let vault = Vault::new();
    vault.space("project-a");
    vault.add_env("A_KEY", "a", Some("project-a"));
    vault.add_env("PERSONAL_KEY", "p", None);
    let mut client = vault.session_client(&vault.session("project-a", "claude"));

    assert_eq!(client.items(None).unwrap()[0].meta.name, "A_KEY");
    assert_eq!(code(client.items(Some("Personal"))), ErrorCode::Denied);
    assert_eq!(code(client.item(Some("Personal"), "PERSONAL_KEY")), ErrorCode::Denied);
    assert_eq!(client.spaces().unwrap(), ["project-a"]);
}

#[test]
fn a_session_never_covers_reveal_replace_delete_or_undo() {
    let vault = Vault::new();
    vault.space("project-a");
    vault.add_env("KEY", "the-secret", Some("project-a"));
    let mut session = vault.session_client(&vault.session("project-a", "claude"));
    session.add(None, Meta::env("NEW"), env("v"), false).unwrap();

    vault.deny_touches();
    assert_eq!(code(session.reveal(None, "KEY")), ErrorCode::Denied);
    assert_eq!(code(session.add(None, Meta::env("KEY"), env("evil"), true)), ErrorCode::Denied);
    assert_eq!(code(session.remove(None, "KEY")), ErrorCode::Denied);
    assert_eq!(code(session.undo()), ErrorCode::Denied);
    vault.allow_touches();
    assert_eq!(revealed(&mut vault.client(), Some("project-a"), "KEY"), "the-secret");
}

#[test]
fn a_session_cannot_widen_itself_or_read_the_audit_log() {
    let vault = Vault::new();
    vault.space("project-a");
    let mut session = vault.session_client(&vault.session("project-a", "claude"));
    assert_eq!(code(session.grant(None, "other", Duration::from_secs(60), None)), ErrorCode::Denied);
    assert_eq!(code(session.create_space("x")), ErrorCode::Denied);
    assert_eq!(code(session.import(None, vec![(Meta::env("A"), env("1"))])), ErrorCode::Denied);
    assert_eq!(code(session.audit()), ErrorCode::Denied);
    assert_eq!(code(session.grants()), ErrorCode::Denied);
    assert_eq!(code(session.end_grant("anything")), ErrorCode::Denied);
}

#[test]
fn locking_and_ending_a_grant_end_sessions() {
    let vault = Vault::new();
    vault.space("project-a");
    let first = vault.session("project-a", "one");
    let second = vault.session("project-a", "two");

    let mut client = vault.client();
    let id = client.grants().unwrap().into_iter().find(|grant| grant.agent == "one").unwrap().id;
    client.end_grant(&id).unwrap();
    assert_eq!(code(vault.session_client(&first).items(None)), ErrorCode::Denied);
    assert!(vault.session_client(&second).items(None).is_ok());

    client.lock().unwrap();
    assert_eq!(code(vault.session_client(&second).items(None)), ErrorCode::Denied);
}

#[test]
fn locking_the_screen_locks_the_vault_and_ends_sessions() {
    let vault = Vault::new();
    vault.space("project-a");
    let session = vault.session("project-a", "claude");
    assert!(vault.client().status().unwrap().unlocked);

    fs::write(vault.home.join("screen-locked"), "").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while vault.client().status().unwrap().unlocked {
        assert!(Instant::now() < deadline, "the vault stayed unlocked behind a locked screen");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(code(vault.session_client(&session).items(None)), ErrorCode::Denied);
}

#[test]
fn a_dead_session_cannot_disturb_the_vault_for_anyone_else() {
    let vault = Vault::new();
    vault.space("project-a");
    let live = vault.session("project-a", "live");
    assert_eq!(code(vault.session_client("lvs_expired").items(None)), ErrorCode::Denied);
    assert!(vault.session_client("lvs_expired").status().is_ok());
    assert!(vault.session_client(&live).items(None).is_ok(), "the live session must survive");
    assert!(vault.client().status().unwrap().unlocked);
}

#[test]
fn a_hostile_agent_name_reaches_the_audit_log_cleaned() {
    let vault = Vault::new();
    vault.space("project-a");
    vault.session("project-a", "evil\"\nTouch to install updates\u{202e}");
    let events = vault.client().audit().unwrap();
    let actor = &events.iter().find(|event| event.action == "grant").unwrap().actor;
    assert!(!actor.contains(['"', '\n', '\u{202e}']), "{actor:?}");
}

// Flow 10: reveal.

#[test]
fn every_use_is_audited_under_the_right_name() {
    let vault = Vault::new();
    vault.space("project-a");
    vault.add_env("KEY", "v", Some("project-a"));
    let session = vault.session("project-a", "claude");
    vault.session_client(&session).reveal(None, "KEY").unwrap();
    let events = vault.client().audit().unwrap();
    let reveal = events.iter().find(|event| event.action == "reveal").unwrap();
    assert_eq!(reveal.actor, "claude");
    assert_eq!(reveal.target, "KEY");
}

#[test]
fn nothing_written_to_disk_contains_plaintext_after_real_use() {
    let vault = Vault::new();
    vault.space("secret-project-name");
    vault.add_env("MY_KEY_NAME", "sk-plaintext", Some("secret-project-name"));
    let mut files = vec![vault.home.clone()];
    while let Some(path) = files.pop() {
        if path.is_dir() {
            files.extend(fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path()));
        } else if let Ok(bytes) = fs::read(&path) {
            for needle in [&b"sk-plaintext"[..], b"MY_KEY_NAME", b"secret-project-name"] {
                assert!(!bytes.windows(needle.len()).any(|window| window == needle), "{path:?}");
            }
        }
    }
}

#[test]
fn an_interface_whose_broker_went_away_is_told_so_plainly() {
    let vault = Vault::new();
    let mut client = vault.client();
    client.status().unwrap();
    vault.client().stop().unwrap();
    let error = client.status().unwrap_err();
    assert!(error.to_string().contains("it stopped, which locked the vault"), "{error}");
    assert!(vault.client().status().is_ok(), "the next connection starts a new one");
}

#[test]
fn a_stopped_broker_is_gone_by_the_time_stop_returns() {
    let vault = Vault::new();
    for _ in 0..40 {
        vault.client().stop().unwrap();
        let still_there = std::os::unix::net::UnixStream::connect(vault.home.join("run/lv.sock")).is_ok();
        assert!(!still_there, "connecting now would reach a broker that is about to exit");
    }
}

#[test]
fn a_broker_takes_nothing_from_the_environment_of_whoever_started_it() {
    let vault = Vault::new();
    vault.client().status().unwrap();
    let pid = fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap();
    // Linux goes further: a broker that is not dumpable shows its environment to nobody but root.
    if cfg!(target_os = "linux") {
        assert!(fs::read(format!("/proc/{}/environ", pid.trim())).is_err(), "its own user can read it");
        return;
    }
    let listed = std::process::Command::new("/bin/ps").args(["eww", "-p", pid.trim()]).output().unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.contains("LV_HOME"), "this must be able to see the environment: {listed}");
    assert!(!listed.contains(support::CANARY), "{listed}");
}

#[test]
fn sigterm_stops_a_broker_even_when_whatever_started_it_ignored_that() {
    let vault = Vault::new();
    // An ignored signal carries over to whatever a process starts, and `trap ''` ignores it.
    let mut broker = std::process::Command::new("/bin/sh")
        .args(["-c", "trap '' TERM; exec \"$0\"", support::LVD])
        .env("LV_HOME", &vault.home)
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = broker.id().to_string();
    let started = Instant::now();
    while fs::read_to_string(vault.home.join("run/lvd.pid")).ok().as_deref() != Some(pid.as_str()) {
        assert!(started.elapsed() < Duration::from_secs(5), "the broker never started");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::process::Command::new("/bin/kill").args(["-TERM", &pid]).status().unwrap();
    let started = Instant::now();
    while broker.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            broker.kill().unwrap();
            panic!("SIGTERM did not stop it, so neither would logging out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_session_cannot_stop_the_broker() {
    let vault = Vault::new();
    vault.space("project-a");
    let session = vault.session("project-a", "claude");
    assert_eq!(code(vault.session_client(&session).stop()), ErrorCode::Denied);
    assert!(vault.client().status().unwrap().unlocked, "the vault must still be open");
}

#[test]
fn loose_permissions_on_the_run_folder_are_tightened_when_the_broker_starts() {
    use std::os::unix::fs::PermissionsExt;
    let vault = Vault::new();
    vault.client().stop().unwrap();
    let run = vault.home.join("run");
    fs::set_permissions(&run, fs::Permissions::from_mode(0o755)).unwrap();
    vault.client().status().unwrap();
    assert_eq!(fs::metadata(&run).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(run.join("lv.sock")).unwrap().permissions().mode() & 0o777, 0o600);
}

// A lock always wins, whenever it lands and whatever else is waiting.

#[test]
fn a_fill_never_opens_a_locked_vault() {
    let vault = Vault::new();
    let mut meta = Meta::login("Site");
    meta.urls = vec!["https://example.com".to_owned()];
    vault.client().add(None, meta, Secret::Login { password: "p".to_owned(), totp: None }, false).unwrap();
    let mut client = vault.client();
    client.lock().unwrap();
    assert_eq!(code(client.fill("Personal", "Site", "https://example.com/")), ErrorCode::Locked);
    assert_eq!(code(client.fill("No Such Space", "Site", "https://example.com/")), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked, "a late fill reopened a locked vault");
}

/// Starts `during` with a slow touch, locks the vault while it waits, and returns how it ended.
fn locked_during<T: Send + 'static>(vault: &Vault, during: impl FnOnce(&mut Client) -> libvault::Result<T> + Send + 'static) -> libvault::Result<T> {
    fs::write(vault.home.join("slow"), "").unwrap();
    let mut asking = vault.client();
    let waiting = std::thread::spawn(move || during(&mut asking));
    std::thread::sleep(Duration::from_millis(600));
    vault.client().lock().unwrap();
    let outcome = waiting.join().unwrap();
    fs::remove_file(vault.home.join("slow")).unwrap();
    outcome
}

#[test]
fn a_lock_during_a_touch_wins() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    vault.client().unlock().unwrap();
    let outcome = locked_during(&vault, |client| client.reveal(None, "KEY"));
    assert_eq!(code(outcome), ErrorCode::Locked);
    assert!(!vault.client().status().unwrap().unlocked, "a touch finishing late reopened the vault");
}

#[test]
fn a_lock_during_a_fill_touch_wins() {
    let vault = Vault::new();
    let mut meta = Meta::login("Site");
    meta.urls = vec!["https://example.com".to_owned()];
    vault.client().add(None, meta, Secret::Login { password: "p".to_owned(), totp: None }, false).unwrap();
    let outcome = locked_during(&vault, |client| client.fill("Personal", "Site", "https://example.com/"));
    assert_eq!(code(outcome), ErrorCode::Locked);
    assert!(!vault.client().status().unwrap().unlocked);
}

#[test]
fn a_lock_during_an_unlock_prompt_wins() {
    let vault = Vault::new();
    let mut client = vault.client();
    client.lock().unwrap();
    let outcome = locked_during(&vault, Client::unlock);
    assert_eq!(code(outcome), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked, "an unlock finishing late overwrote the lock");
}

#[test]
fn a_session_cannot_lock_everyone_out() {
    let vault = Vault::new();
    vault.space("project-a");
    let session = vault.session("project-a", "claude");
    assert_eq!(code(vault.session_client(&session).lock()), ErrorCode::Denied);
    assert!(vault.client().status().unwrap().unlocked);
}

#[test]
fn a_dead_token_cannot_stop_the_broker() {
    let vault = Vault::new();
    vault.client().unlock().unwrap();
    let mut stale = vault.session_client("lvs_not_a_real_token");
    assert_eq!(code(stale.stop()), ErrorCode::Denied);
    assert!(vault.client().status().unwrap().unlocked, "the broker stopped for a token that means nothing");
}

// A software vault: with no hardware to ask, the passphrase is the touch. Only a person holds it,
// so a client without it gets nothing, locked or not.

fn no_passphrase(vault: &Vault) -> Client {
    Client::connect(&vault.home, Connect { passphrase: None, ..options(None) }).unwrap()
}

fn this_passphrase(vault: &Vault, passphrase: &str) -> Client {
    Client::connect(&vault.home, Connect { passphrase: Some(passphrase), ..options(None) }).unwrap()
}

#[test]
fn a_locked_software_vault_opens_for_nobody_without_its_passphrase() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    vault.client().lock().unwrap();
    let mut stranger = no_passphrase(&vault);
    assert_eq!(code(stranger.reveal(None, "KEY")), ErrorCode::NeedsPassphrase);
    assert_eq!(code(stranger.items(None)), ErrorCode::NeedsPassphrase);
    assert!(!stranger.status().unwrap().unlocked);
}

#[test]
fn every_approval_on_a_software_vault_takes_the_passphrase_even_when_it_is_open() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    vault.client().unlock().unwrap();
    assert_eq!(code(no_passphrase(&vault).reveal(None, "KEY")), ErrorCode::NeedsPassphrase, "that would be a touch nobody gave");
    assert!(no_passphrase(&vault).items(None).is_ok(), "names are listed while it is open");
}

#[test]
fn a_wrong_passphrase_changes_nothing_and_does_not_get_stuck() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    let mut client = vault.client();
    client.lock().unwrap();
    assert!(this_passphrase(&vault, "not it").unlock().is_err());
    assert!(!client.status().unwrap().unlocked);
    this_passphrase(&vault, PASSPHRASE).unlock().unwrap();
    assert!(client.status().unwrap().unlocked);
}

#[test]
fn a_broker_never_holds_a_passphrase_it_was_not_just_handed() {
    let vault = Vault::new();
    vault.client().unlock().unwrap();
    vault.client().stop().unwrap();
    let mut client = no_passphrase(&vault);
    assert!(!client.status().unwrap().unlocked);
    assert_eq!(code(client.unlock()), ErrorCode::NeedsPassphrase, "a broker started with no passphrase has none to use");
}

// Starting and keeping a broker.

#[test]
fn two_install_folders_of_one_build_share_a_broker() {
    let vault = Vault::new();
    let elsewhere = vault.dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let copy = elsewhere.join("lvd");
    fs::copy(support::LVD, &copy).unwrap();

    vault.client().unlock().unwrap();
    let first = fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap();
    let mut other = Client::connect(&vault.home, Connect { daemon: Some(&copy), ..options(None) }).unwrap();
    assert!(other.status().unwrap().unlocked, "another copy of the same build replaced a working broker");
    assert_eq!(fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap(), first);
}

#[test]
fn a_broker_stands_alone_from_whoever_started_it() {
    let vault = Vault::new();
    vault.client().status().unwrap();
    let pid = fs::read_to_string(vault.home.join("run/lvd.pid")).unwrap();
    let show = |column: &str| {
        let out = std::process::Command::new("/bin/ps").args(["-o", column, "-p", pid.trim()]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_eq!(show("pgid="), pid.trim(), "Ctrl-C at whoever started it would stop the broker too");
}

#[test]
fn a_sync_says_what_it_reached() {
    let vault = Vault::new();
    let report = vault.client().sync_now().unwrap();
    assert_eq!((report.peers_reached, report.peers_missed), (0, 0));

    let folder = vault.dir.path().join("usb");
    fs::create_dir(&folder).unwrap();
    vault.client().add_backup(&folder).unwrap();
    fs::remove_dir_all(&folder).unwrap();
    assert_eq!(vault.client().sync_now().unwrap().backup_problems.len(), 1, "a sync that failed cannot say all is well");
}

#[test]
fn settling_a_conflict_with_nothing_to_settle_says_so() {
    let vault = Vault::new();
    assert_eq!(vault.client().resolve_conflict(&vault.words).unwrap(), 0);
    assert_eq!(vault.client().resolve_conflict(&libvault::RecoveryDraft::new().words()).unwrap(), 0, "words from elsewhere settle nothing");
}

#[test]
fn only_a_host_can_be_allowed() {
    let vault = Vault::new();
    vault.add_env("KEY", "v", None);
    for url in ["https://example.com/path", "example.com/path", "http://example.com"] {
        assert_eq!(code(vault.client().allow(None, "KEY", url)), ErrorCode::Error, "{url} would never match");
    }
    vault.client().allow(None, "KEY", "api.example.com").unwrap();
}

#[test]
fn verifying_a_folder_with_no_backup_says_that() {
    let vault = Vault::new();
    let empty = vault.dir.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let error = vault.client().verify_backup(&empty).unwrap_err();
    assert!(error.to_string().contains("no backup"), "{error}");
}

#[test]
fn a_csv_with_no_header_never_shows_its_first_row() {
    let vault = Vault::new();
    let file = vault.file("logins.csv", b"github.com,me,hunter2-SECRET\n");
    let error = ImportFile::read(&file).unwrap_err();
    assert!(!error.to_string().contains("hunter2"), "{error}");
}

#[test]
fn any_version_comes_back_whatever_has_happened_since() {
    let vault = Vault::new();
    vault.add_env("KEEP", "first", None);
    let mut client = vault.client();
    client.add(None, Meta::env("KEEP"), env("second"), true).unwrap();
    client.remove(None, "KEEP").unwrap();
    vault.add_env("OTHER", "x", None);

    assert_eq!(client.history(None, "KEEP").unwrap().len(), 3, "a deleted item keeps its history");
    client.restore(None, "KEEP", 0).unwrap();
    assert!(matches!(&client.reveal(None, "KEEP").unwrap(), Secret::Env { value } if value == "first"));
    assert_eq!(client.history(None, "KEEP").unwrap().len(), 4, "restoring is a new write, and loses nothing");
    assert_eq!(code(client.restore(None, "KEEP", 1000)), ErrorCode::NotFound);
}

#[test]
fn restoring_takes_a_touch_even_with_a_session() {
    let vault = Vault::new();
    vault.space("project-a");
    vault.client().add(Some("project-a"), Meta::env("KEY"), env("v"), false).unwrap();
    let session = vault.session("project-a", "claude");
    vault.deny_touches();
    assert_eq!(code(vault.session_client(&session).restore(None, "KEY", 0)), ErrorCode::Denied);
}
