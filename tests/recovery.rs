//! Flows 5, 7, 14, 15, 16 and 19: everything that protects against losing a device, and the
//! attacks a backup folder or peer could try.

mod support;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use libvault::item::{Meta, Secret};
use libvault::{Client, ErrorCode, Recovery, RecoveryDraft};
use support::{Vault, backup_logs, code, env, restored};

fn value(client: &mut Client, space: Option<&str>, name: &str) -> String {
    match &client.reveal(space, name).unwrap() {
        Secret::Env { value } => value.clone(),
        other => panic!("not an env var: {other:?}"),
    }
}

/// A vault with a secret, backed up to a folder.
fn backed_up() -> (Vault, tempfile::TempDir) {
    let vault = Vault::new();
    vault.go_offline();
    vault.add_env("KEY", "the-secret", None);
    let backup = tempfile::tempdir().unwrap();
    vault.client().add_backup(backup.path()).unwrap();
    (vault, backup)
}

fn every_file_under(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let (mut files, mut pending) = (Vec::new(), vec![root.to_path_buf()]);
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(fs::read_dir(path).unwrap().flatten().map(|entry| entry.path()));
        } else {
            files.push(path);
        }
    }
    files
}

// Flow 14: backup.

#[test]
fn a_backup_holds_only_ciphertext_and_verifies() {
    let (vault, backup) = backed_up();
    let files = every_file_under(backup.path());
    assert_ne!(files.len(), 0);
    for file in files {
        let bytes = fs::read(&file).unwrap();
        // Quoted as it is in plaintext. Three bare bytes turn up in ciphertext by chance.
        for needle in [&b"the-secret"[..], b"\"KEY\"", b"Test Mac"] {
            assert!(!bytes.windows(needle.len()).any(|window| window == needle), "{file:?}");
        }
    }
    let report = vault.client().verify_backup(backup.path()).unwrap();
    assert!(report.current);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(report.devices, 1);
}

#[test]
fn the_last_copy_is_one_answer_and_a_folder_that_has_gone_does_not_count() {
    let vault = Vault::new();
    vault.go_offline();
    assert!(vault.client().status().unwrap().last_copy);

    let folder = tempfile::tempdir().unwrap();
    vault.client().add_backup(folder.path()).unwrap();
    assert!(!vault.client().status().unwrap().last_copy);

    fs::remove_dir_all(folder.path()).unwrap();
    assert!(vault.client().status().unwrap().last_copy, "a backup that cannot be reached is not a copy");
}

#[test]
fn a_new_change_reaches_the_backup() {
    let (vault, backup) = backed_up();
    vault.add_env("LATER", "v", None);
    let mut client = vault.client();
    client.sync_now().unwrap();
    assert!(client.verify_backup(backup.path()).unwrap().current);
}

#[test]
fn a_folder_that_vanishes_is_reported_and_work_carries_on() {
    let vault = Vault::new();
    let backup = tempfile::tempdir().unwrap();
    let path = backup.path().join("usb");
    fs::create_dir(&path).unwrap();
    vault.client().add_backup(&path).unwrap();
    fs::remove_dir_all(&path).unwrap();

    vault.add_env("KEY", "v", None);
    let mut client = vault.client();
    client.sync_now().unwrap();
    let status = client.status().unwrap();
    assert!(status.backups[0].problem.is_some());
    assert!(!path.exists(), "an unplugged drive's path must not be recreated");
}

#[test]
fn a_session_cannot_touch_backups_devices_exports_or_recovery() {
    let vault = Vault::new();
    vault.space("project-a");
    let mut session = vault.session_client(&vault.session("project-a", "claude"));
    let folder = vault.dir.path();
    assert_eq!(code(session.add_backup(folder)), ErrorCode::Denied);
    assert_eq!(code(session.export_archive(&folder.join("a"))), ErrorCode::Denied);
    assert_eq!(code(session.export_plaintext(&folder.join("b"), None)), ErrorCode::Denied);
    assert_eq!(code(session.rotate_recovery(&RecoveryDraft::new(), None)), ErrorCode::Denied);
    assert_eq!(code(session.remove_device("Test Mac", None)), ErrorCode::Error);
    assert_eq!(code(session.wipe("Test Mac")), ErrorCode::Denied);
}

// Flow 15: recover.

#[test]
fn a_new_machine_recovers_everything_from_a_backup_and_the_words() {
    let (vault, backup) = backed_up();
    let new = restored(backup.path(), &vault.words, "New Mac");
    let mut client = new.client();
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    let names: Vec<String> = client.devices().unwrap().into_iter().map(|device| device.name).collect();
    assert!(names.contains(&"Test Mac".to_owned()) && names.contains(&"New Mac".to_owned()), "{names:?}");
}

#[test]
fn a_new_machine_recovers_from_an_exported_archive() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    let archive = vault.dir.path().join("vault.vaulty");
    vault.client().export_archive(&archive).unwrap();
    assert_eq!(value(&mut restored(&archive, &vault.words, "New Mac").client(), None, "KEY"), "the-secret");
}

#[test]
fn recovery_refuses_the_wrong_key_a_typo_and_an_empty_folder() {
    let (vault, backup) = backed_up();
    let other = RecoveryDraft::new().words();
    assert!(matches!(Recovery::open(backup.path(), &other), Err(libvault::Error::WrongRecoveryKey)));

    let typo = vault.words.replacen(vault.words.split(' ').next().unwrap(), "notaword", 1);
    assert!(matches!(Recovery::open(backup.path(), &typo), Err(libvault::Error::BadRecoveryKey(_))));

    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(Recovery::open(empty.path(), &vault.words), Err(libvault::Error::NoCopy)));
}

#[test]
fn a_stray_tail_on_a_log_does_not_stop_recovery_or_come_with_it() {
    let (vault, backup) = backed_up();
    let log = backup_logs(backup.path())[0].clone();
    let whole = fs::read(&log).unwrap();
    // Version 2 of the format, or just three bytes someone added to a folder.
    fs::write(&log, [&whole[..], b"LV\x02"].concat()).unwrap();

    let second = restored(backup.path(), &vault.words, "New Mac");
    assert_eq!(value(&mut second.client(), None, "KEY"), "the-secret");
    let restored_log = second.home.join("log").join(log.file_name().unwrap());
    assert_eq!(fs::read(restored_log).unwrap(), whole, "junk restored with a log would contradict every peer");
}

#[test]
fn a_copy_of_a_first_entry_under_another_name_does_not_stop_recovery() {
    let (vault, backup) = backed_up();
    let log = backup_logs(backup.path())[0].clone();
    fs::copy(&log, log.with_file_name(format!("{}.lvl", "ab".repeat(16)))).unwrap();
    let second = restored(backup.path(), &vault.words, "New Mac");
    assert_eq!(value(&mut second.client(), None, "KEY"), "the-secret");
}

#[test]
fn what_a_copy_has_wrong_is_shown_before_it_is_trusted() {
    let (vault, backup) = backed_up();
    let log = backup_logs(backup.path())[0].clone();
    fs::copy(&log, log.with_file_name(format!("{}.lvl", "ab".repeat(16)))).unwrap();
    let recovery = Recovery::open(backup.path(), &vault.words).unwrap();
    assert!(!recovery.problems().is_empty(), "a copy with a stray log must say so");
}

#[test]
fn a_recovered_machine_named_like_the_old_one_gets_a_name_of_its_own() {
    let (vault, backup) = backed_up();
    let second = restored(backup.path(), &vault.words, "Test Mac");
    let names: Vec<String> = second.client().devices().unwrap().into_iter().map(|device| device.name).collect();
    assert!(names.contains(&"Test Mac 2".to_owned()), "{names:?}");
}

#[test]
fn a_plain_file_named_like_a_vault_folder_does_not_stop_recovery() {
    let (first, backup) = backed_up();
    fs::write(backup.path().join("vaulty-planted"), b"not a folder").unwrap();
    assert!(Recovery::open(backup.path(), &first.words).is_ok());
}

#[test]
fn recovery_refuses_to_replace_a_vault() {
    let (vault, backup) = backed_up();
    let again = Recovery::open(backup.path(), &vault.words).unwrap();
    let result = again.finish_with_passphrase(support::PASSPHRASE, libvault::Cost::FAST, &vault.home, "Other");
    assert!(matches!(result, Err(libvault::Error::VaultExists)));
}

// Flow 13: sync through a folder.

#[test]
fn two_devices_converge_through_a_shared_folder() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();

    second.add_env("FROM_SECOND", "two", None);
    second.client().sync_now().unwrap();
    first.client().sync_now().unwrap();
    assert_eq!(value(&mut first.client(), None, "FROM_SECOND"), "two");

    first.add_env("FROM_FIRST", "one", None);
    first.client().sync_now().unwrap();
    second.client().sync_now().unwrap();
    assert_eq!(value(&mut second.client(), None, "FROM_FIRST"), "one");
}

#[test]
fn a_conflicting_edit_keeps_the_newest_and_the_other_stays_in_history() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();

    first.client().add(None, Meta::env("KEY"), env("from-first"), true).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    second.client().add(None, Meta::env("KEY"), env("from-second"), true).unwrap();
    for _ in 0..2 {
        first.client().sync_now().unwrap();
        second.client().sync_now().unwrap();
    }
    assert_eq!(value(&mut first.client(), None, "KEY"), "from-second");
    assert_eq!(value(&mut second.client(), None, "KEY"), "from-second");
    assert_eq!(first.client().history(None, "KEY").unwrap().len(), 3);
}

#[test]
fn sync_runs_while_locked() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    second.add_env("FROM_SECOND", "two", None);
    second.client().sync_now().unwrap();

    let mut client = first.client();
    client.lock().unwrap();
    client.sync_now().unwrap();
    assert!(!client.status().unwrap().unlocked, "syncing must not need keys");
    assert_eq!(value(&mut client, None, "FROM_SECOND"), "two");
}

#[test]
fn a_folder_offering_an_older_log_is_refused_and_reported() {
    let (first, backup) = backed_up();
    let first_log = backup_logs(backup.path()).pop().unwrap();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    second.add_env("SECOND_KEY", "v", None);
    second.client().sync_now().unwrap();
    first.client().sync_now().unwrap();

    // Replace the second device's log with its earlier self, as a hostile folder would. Either
    // device's background sync may write the whole log back between a read and this, which is what
    // should happen to a folder that is behind, so this goes on until a read has seen the old one.
    let second_log = backup_logs(backup.path()).into_iter().find(|path| *path != first_log).unwrap();
    let bytes = fs::read(&second_log).unwrap();
    // The same sync that reports it heals the folder, after which there is nothing to report.
    let mut client = first.client();
    let reported = (0..100).any(|_| {
        fs::write(&second_log, &bytes[..bytes.len() / 2]).unwrap();
        client.sync_now().unwrap();
        !client.status().unwrap().problems.is_empty()
    });
    assert!(reported);
    assert_eq!(value(&mut client, None, "SECOND_KEY"), "v", "synced data must not go backwards");
}

#[test]
fn a_device_rolled_back_on_disk_hears_it_from_a_copy_of_its_own_log() {
    let (first, backup) = backed_up();
    let own_log = fs::read_dir(first.home.join("log")).unwrap().next().unwrap().unwrap().path();
    let earlier = fs::read(&own_log).unwrap();
    first.add_env("LATER", "v", None);
    first.client().sync_now().unwrap();
    first.client().stop().unwrap();

    fs::write(&own_log, earlier).unwrap();
    // The copy is out of reach at first, so only what is on this machine can speak.
    let away = backup.path().with_extension("away");
    fs::rename(backup.path(), &away).unwrap();
    let mut client = first.client();
    assert_eq!(client.status().unwrap().problems, Vec::<String>::new(), "nothing on this machine can tell");
    fs::rename(&away, backup.path()).unwrap();
    client.sync_now().unwrap();
    let problems = client.status().unwrap().problems;
    assert!(problems.iter().any(|problem| problem.contains("rolled back")), "{problems:?}");
    assert_eq!(backup_logs(backup.path()).len(), 1);
}

// Whoever can write to a backup folder is an attacker here: iCloud Drive, a shared disk, a USB drive.

fn vault_folder(backup: &Path) -> PathBuf {
    backup_logs(backup)[0].parent().unwrap().to_path_buf()
}

#[test]
fn a_link_planted_in_a_folder_cannot_redirect_a_write() {
    let (vault, backup) = backed_up();
    let victim = vault.file("victim", b"precious");
    let log = backup_logs(backup.path())[0].clone();
    symlink(&victim, log.with_extension("tmp")).unwrap();

    vault.add_env("LATER", "v", None);
    vault.client().sync_now().unwrap();

    assert_eq!(fs::read(&victim).unwrap(), b"precious", "a backup write followed a link out of the folder");
    assert!(vault.client().verify_backup(backup.path()).unwrap().current, "the backup must still be written");
}

#[test]
fn a_link_in_place_of_the_log_folder_is_refused() {
    let (vault, backup) = backed_up();
    let elsewhere = tempfile::tempdir().unwrap();
    let folder = vault_folder(backup.path());
    fs::remove_dir_all(&folder).unwrap();
    symlink(elsewhere.path(), &folder).unwrap();

    vault.add_env("LATER", "v", None);
    vault.client().sync_now().unwrap();

    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0, "a backup was written through a link");
    assert!(vault.client().status().unwrap().backups[0].problem.is_some(), "the refusal must show");
}

#[test]
fn a_pipe_or_a_link_in_a_folder_cannot_hang_or_flood_the_broker() {
    let (vault, backup) = backed_up();
    let folder = vault_folder(backup.path());
    let name = |digit: char| folder.join(format!("{}.lvl", digit.to_string().repeat(32)));
    assert!(Command::new("/usr/bin/mkfifo").arg(name('a')).status().unwrap().success());
    symlink("/dev/zero", name('b')).unwrap();

    let home = vault.home.clone();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut client = Client::connect(&home, support::options(None)).unwrap();
        done.send(client.sync_now()).unwrap();
    });
    finished.recv_timeout(Duration::from_secs(5)).expect("the broker hung on a file in a backup folder").unwrap();
    assert_eq!(value(&mut vault.client(), None, "KEY"), "the-secret");
}

#[test]
fn a_tampered_log_in_a_folder_changes_nothing() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    // Otherwise a sync in the background takes the good log, or mends the folder.
    first.client().stop().unwrap();
    second.client().add_backup(backup.path()).unwrap();
    second.add_env("SECOND_KEY", "v", None);
    second.client().sync_now().unwrap();
    second.client().stop().unwrap();

    let logs = backup_logs(backup.path());
    let second_log = logs.iter().max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap()).unwrap();
    let mut bytes = fs::read(second_log).unwrap();
    let last = bytes.len() - 100;
    bytes[last] ^= 1;
    fs::write(second_log, &bytes).unwrap();

    let mut client = first.client();
    client.sync_now().unwrap();
    assert_ne!(client.status().unwrap().problems.len(), 0);
    assert_eq!(code(client.item(None, "SECOND_KEY")), ErrorCode::NotFound);
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
}

#[test]
fn a_log_from_another_vault_is_refused() {
    let (first, backup) = backed_up();
    let (other, other_backup) = backed_up();
    let foreign = backup_logs(other_backup.path()).remove(0);
    let target = backup_logs(backup.path())[0].parent().unwrap().join(foreign.file_name().unwrap());
    fs::copy(&foreign, target).unwrap();
    let mut client = first.client();
    client.sync_now().unwrap();
    assert_ne!(client.status().unwrap().problems.len(), 0);
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    drop(other);
}

#[test]
fn a_device_log_from_another_vault_is_refused_even_when_it_is_not_a_genesis_log() {
    let (first, backup) = backed_up();
    let (other, other_backup) = backed_up();
    let outsider = restored(other_backup.path(), &other.words, "Outsider");
    outsider.add_env("OUTSIDE", "v", None);
    let log = fs::read_dir(outsider.home.join("log"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
        .unwrap();
    let target = backup_logs(backup.path())[0].parent().unwrap().join(log.file_name().unwrap());
    fs::copy(&log, target).unwrap();

    let mut client = first.client();
    client.sync_now().unwrap();
    let problems = client.status().unwrap().problems;
    assert!(problems.iter().any(|problem| problem.contains("another vault")), "{problems:?}");
    assert_eq!(code(client.item(None, "OUTSIDE")), ErrorCode::NotFound);
}

#[test]
fn a_sync_that_brings_no_new_keys_leaves_the_vault_unlocked() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();
    assert_eq!(value(&mut first.client(), None, "KEY"), "the-secret");
    second.add_env("LATER", "v", None);
    second.client().sync_now().unwrap();

    let mut client = first.client();
    client.sync_now().unwrap();
    assert!(client.status().unwrap().unlocked, "new items alone must not lock anyone out");
}

#[test]
fn a_sync_that_brings_new_keys_locks_until_a_touch_opens_them() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();
    first.client().unlock().unwrap();

    second.client().rotate_recovery(&RecoveryDraft::new(), Some(&second.words)).unwrap();
    second.client().sync_now().unwrap();

    let mut client = first.client();
    client.sync_now().unwrap();
    assert!(!client.status().unwrap().unlocked);
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
}

// Flow 7: remove a device.

#[test]
fn a_removed_device_cannot_write_anything_new_through_a_folder() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();

    second.client().remove_device("Test Mac", Some(&second.words)).unwrap();
    second.client().sync_now().unwrap();

    // The removed device has not heard yet, and carries on writing.
    first.client().remove_backup(backup.path()).unwrap();
    first.add_env("WRITTEN_AFTER", "evil", None);
    first.client().add_backup(backup.path()).unwrap();

    let mut client = second.client();
    client.sync_now().unwrap();
    assert_eq!(code(client.item(None, "WRITTEN_AFTER")), ErrorCode::NotFound);
    assert_ne!(client.status().unwrap().problems.len(), 0);
}

#[test]
fn the_remaining_device_can_still_open_everything_after_a_restart() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.add_env("LAST_THING_SECOND_WROTE", "kept", None);
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();

    // Removing the second device must keep the last thing it wrote before leaving.
    let third = restored(backup.path(), &first.words, "Third Mac");
    third.client().add_backup(backup.path()).unwrap();
    third.client().remove_device("New Mac", Some(&third.words)).unwrap();
    third.client().stop().unwrap();

    let mut client = third.client();
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    assert_eq!(value(&mut client, None, "LAST_THING_SECOND_WROTE"), "kept");
    client.add(None, Meta::env("AFTER_RESTART"), env("v"), false).unwrap();
    assert_eq!(value(&mut client, None, "AFTER_RESTART"), "v");
}

#[test]
fn removing_a_device_rotates_keys_so_it_cannot_read_anything_new() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();

    let exposed = second.client().remove_device("Test Mac", Some(&second.words)).unwrap();
    assert_eq!(exposed, ["KEY"]);
    second.add_env("AFTER", "new-secret", None);
    second.client().sync_now().unwrap();
    assert_eq!(value(&mut second.client(), None, "KEY"), "the-secret");

    let mut removed = first.client();
    removed.sync_now().unwrap();
    let denied = removed.reveal(None, "AFTER");
    assert!(denied.is_err(), "a removed device must not read new items");
}

#[test]
fn a_removal_needs_a_second_approval_and_a_device_cannot_remove_itself() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    let mut client = second.client();
    let without = client.remove_device("Test Mac", None);
    assert_eq!(code(without), ErrorCode::Denied);
    assert_eq!(client.devices().unwrap().len(), 2);
    assert_eq!(code(client.remove_device("New Mac", Some(&second.words))), ErrorCode::Error);
    assert_eq!(code(client.remove_device("Nobody", Some(&second.words))), ErrorCode::NotFound);
    let wrong = RecoveryDraft::new().words();
    assert!(client.remove_device("Test Mac", Some(&wrong)).is_err());
}

// Concurrent roster changes, which plain epoch numbers would corrupt.

/// Two devices that have each replaced the recovery key without seeing the other.
fn rotated_apart() -> (Vault, Vault, String, String, tempfile::TempDir) {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();
    assert_eq!(first.client().devices().unwrap().len(), 2);

    // Stop the folder so each rotates without seeing the other.
    first.client().remove_backup(backup.path()).unwrap();
    second.client().remove_backup(backup.path()).unwrap();
    let (first_draft, second_draft) = (RecoveryDraft::new(), RecoveryDraft::new());
    first.client().rotate_recovery(&first_draft, Some(&first.words)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    second.client().rotate_recovery(&second_draft, Some(&second.words)).unwrap();
    first.add_env("FROM_FIRST", "one", None);
    second.add_env("FROM_SECOND", "two", None);

    let exchange = tempfile::tempdir().unwrap();
    first.client().add_backup(exchange.path()).unwrap();
    second.client().add_backup(exchange.path()).unwrap();
    for _ in 0..2 {
        first.client().sync_now().unwrap();
        second.client().sync_now().unwrap();
    }
    (first, second, first_draft.words().to_string(), second_draft.words().to_string(), exchange)
}

#[test]
fn the_winner_of_a_roster_conflict_keeps_everything_both_devices_wrote() {
    let (first, _second, _, _, _exchange) = rotated_apart();
    let mut client = first.client();
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    assert_eq!(value(&mut client, None, "FROM_FIRST"), "one");
    assert_eq!(value(&mut client, None, "FROM_SECOND"), "two", "losing a roster conflict must not lose the rest of a log");
    assert_ne!(client.status().unwrap().problems.len(), 0, "the refused change must be reported");
}

#[test]
fn two_devices_that_remove_each_other_part_ways_and_both_say_so() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();

    first.client().remove_backup(backup.path()).unwrap();
    second.client().remove_backup(backup.path()).unwrap();
    first.client().remove_device("New Mac", Some(&first.words)).unwrap();
    second.client().remove_device("Test Mac", Some(&second.words)).unwrap();
    first.add_env("FROM_FIRST", "one", None);
    second.add_env("FROM_SECOND", "two", None);

    let exchange = tempfile::tempdir().unwrap();
    first.client().add_backup(exchange.path()).unwrap();
    second.client().add_backup(exchange.path()).unwrap();
    for _ in 0..2 {
        first.client().sync_now().unwrap();
        second.client().sync_now().unwrap();
    }

    for (vault, own, other) in [(&first, "FROM_FIRST", "FROM_SECOND"), (&second, "FROM_SECOND", "FROM_FIRST")] {
        let mut client = vault.client();
        assert_eq!(value(&mut client, None, "KEY"), "the-secret");
        assert_eq!(code(client.item(None, other)), ErrorCode::NotFound, "each is on its own");
        client.item(None, own).unwrap();
        assert_ne!(client.status().unwrap().problems.len(), 0, "a split must say so");
    }
}

#[test]
fn the_loser_of_a_roster_conflict_loses_nothing_and_says_so() {
    let (_first, second, _, _, _exchange) = rotated_apart();
    let mut client = second.client();
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    assert_eq!(value(&mut client, None, "FROM_SECOND"), "two");
    assert_ne!(client.status().unwrap().problems.len(), 0);
}

#[test]
fn a_person_settles_a_roster_conflict_with_the_winning_words() {
    let (first, second, first_words, _, exchange) = rotated_apart();
    let mut client = second.client();
    assert_eq!(client.resolve_conflict(&RecoveryDraft::new().words()).unwrap(), 0);
    assert_eq!(code(client.item(None, "FROM_FIRST")), ErrorCode::NotFound, "the wrong words settle nothing");

    assert_ne!(client.resolve_conflict(&first_words).unwrap(), 0, "and the right ones must say they did");
    assert_eq!(value(&mut client, None, "FROM_FIRST"), "one");
    assert_eq!(value(&mut client, None, "FROM_SECOND"), "two");

    // The vault can now be written from both devices, and the winning words open all of it.
    client.add(None, Meta::env("AFTER_MERGE"), env("v"), false).unwrap();
    for _ in 0..2 {
        second.client().sync_now().unwrap();
        first.client().sync_now().unwrap();
    }
    assert_eq!(value(&mut first.client(), None, "AFTER_MERGE"), "v");
    let recovered = restored(exchange.path(), &first_words, "Third Mac");
    assert_eq!(value(&mut recovered.client(), None, "FROM_SECOND"), "two");
}

// The recovery key stays valid throughout, so only the roster chain can tell these apart.
#[test]
fn two_devices_making_roster_changes_at_once_are_ordered_and_one_is_refused() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "Second Mac");
    second.client().add_backup(backup.path()).unwrap();
    let third = restored(backup.path(), &first.words, "Third Mac");
    first.client().sync_now().unwrap();
    second.client().sync_now().unwrap();
    third.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();
    second.client().sync_now().unwrap();
    assert_eq!(first.client().devices().unwrap().len(), 3);

    first.client().remove_backup(backup.path()).unwrap();
    second.client().remove_backup(backup.path()).unwrap();
    first.client().remove_device("Third Mac", Some(&first.words)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    second.client().remove_device("Third Mac", Some(&second.words)).unwrap();

    let exchange = tempfile::tempdir().unwrap();
    first.client().add_backup(exchange.path()).unwrap();
    second.client().add_backup(exchange.path()).unwrap();
    for _ in 0..2 {
        first.client().sync_now().unwrap();
        second.client().sync_now().unwrap();
    }
    let status = first.client().status().unwrap();
    assert!(status.problems.iter().any(|problem| problem.contains("did not count")), "{:?}", status.problems);
    assert_eq!(value(&mut first.client(), None, "KEY"), "the-secret");
}

// A leaked recovery key is why it gets rotated at all, so the old words must buy nothing, even
// from someone who enrolled before the rotation and only shows up afterwards with an old clock.
#[test]
fn a_device_enrolled_with_retired_words_is_refused() {
    let (vault, backup) = backed_up();
    let old_copy = tempfile::tempdir().unwrap();
    let archive = old_copy.path().join("old.vaulty");
    vault.client().export_archive(&archive).unwrap();
    let attacker = restored(&archive, &vault.words, "Attacker");

    vault.client().rotate_recovery(&RecoveryDraft::new(), None).unwrap();
    vault.add_env("AFTER_ROTATION", "new-secret", None);
    let mut client = vault.client();
    client.sync_now().unwrap();

    // The attacker's enrollment predates the rotation by its own clock, and replay sorts by clock.
    let attacker_log = fs::read_dir(attacker.home.join("log"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
        .unwrap();
    let target = backup_logs(backup.path())[0].parent().unwrap().join(attacker_log.file_name().unwrap());
    fs::copy(&attacker_log, target).unwrap();

    client.sync_now().unwrap();
    assert_eq!(client.devices().unwrap().len(), 1, "the attacker must not be enrolled");
    assert_ne!(client.status().unwrap().problems.len(), 0);
    assert_eq!(value(&mut client, None, "AFTER_ROTATION"), "new-secret");
}

// Flow 16: replace the recovery key.

#[test]
fn replacing_the_recovery_key_retires_the_old_words() {
    let (vault, backup) = backed_up();
    let draft = RecoveryDraft::new();
    let new_words = draft.words().to_string();
    let mut client = vault.client();
    client.rotate_recovery(&draft, None).unwrap();
    client.sync_now().unwrap();

    assert!(matches!(Recovery::open(backup.path(), &vault.words), Err(libvault::Error::WrongRecoveryKey)));
    assert_eq!(value(&mut restored(backup.path(), &new_words, "New Mac").client(), None, "KEY"), "the-secret");
}

#[test]
fn a_finished_rotation_is_not_rotated_again() {
    let (first, _backup) = backed_up();
    first.client().rotate_recovery(&RecoveryDraft::new(), None).unwrap();
    first.client().sync_now().unwrap();
    let own_log = fs::read_dir(first.home.join("log")).unwrap().next().unwrap().unwrap().path();
    let settled = fs::metadata(&own_log).unwrap().len();

    first.client().sync_now().unwrap();
    assert_eq!(fs::metadata(&own_log).unwrap().len(), settled, "older generations still name the old words, as they should");
}

#[test]
fn a_refused_touch_keeps_the_old_recovery_key() {
    let (vault, backup) = backed_up();
    vault.client().unlock().unwrap();
    vault.deny_touches();
    assert_eq!(code(vault.client().rotate_recovery(&RecoveryDraft::new(), None)), ErrorCode::Denied);
    vault.allow_touches();
    assert!(Recovery::open(backup.path(), &vault.words).is_ok());
}

// Flow 5: export.

#[test]
fn a_plaintext_export_is_complete_private_and_never_overwrites() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    let path = vault.dir.path().join("export.json");
    vault.client().export_plaintext(&path, None).unwrap();

    let exported: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(exported[0]["name"], "KEY");
    assert_eq!(exported[0]["secret"]["value"], "the-secret");
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

    let again = vault.client().export_plaintext(&path, None);
    assert!(again.is_err());
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap(), exported);
}

#[test]
fn with_two_devices_a_plaintext_export_needs_more_than_a_touch() {
    let (first, backup) = backed_up();
    let second = restored(backup.path(), &first.words, "New Mac");
    let path = second.dir.path().join("export.json");
    let mut client = second.client();
    assert_eq!(code(client.export_plaintext(&path, None)), ErrorCode::Denied);
    assert!(client.export_plaintext(&path, Some(&RecoveryDraft::new().words())).is_err(), "only this vault's words stand in");
    assert!(!path.exists());
    client.export_plaintext(&path, Some(&second.words)).unwrap();
    assert!(path.exists());
}

#[test]
fn a_refused_touch_exports_nothing() {
    let vault = Vault::new();
    vault.client().unlock().unwrap();
    let path = vault.dir.path().join("export.json");
    vault.deny_touches();
    assert_eq!(code(vault.client().export_plaintext(&path, None)), ErrorCode::Denied);
    assert_eq!(code(vault.client().export_archive(&path)), ErrorCode::Denied);
    assert!(!path.exists());
}

// Flow 19: leave.

#[test]
fn wiping_needs_this_devices_name_and_erases_it() {
    let vault = Vault::new();
    vault.add_env("KEY", "v", None);
    let mut client = vault.client();
    assert_eq!(code(client.wipe("Wrong Name")), ErrorCode::Error);
    assert!(vault.home.exists());
    client.wipe("Test Mac").unwrap();
    assert!(!vault.home.exists());
}
