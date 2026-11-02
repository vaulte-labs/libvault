//! One item in more than one space, with a copy in each and every change reaching them all.

mod support;

use std::fs;

use libvault::item::{Meta, Secret};
use libvault::{Client, ErrorCode};
use support::{Vault, code, env};

fn login(password: &str) -> Secret {
    Secret::Login { password: password.to_owned(), totp: None }
}

/// A login in Personal, shown in Agents too.
fn linked() -> (Vault, Client) {
    let vault = Vault::new();
    vault.space("Agents");
    let mut client = vault.client();
    client.add(None, Meta::login("github.com"), login("first"), false).unwrap();
    client.link(None, "github.com", "Agents").unwrap();
    (vault, client)
}

#[test]
fn a_linked_item_is_in_both_spaces_and_each_change_reaches_both() {
    let (_vault, mut client) = linked();
    assert_eq!(client.item(None, "github.com").unwrap().also_in, ["Agents"]);
    assert_eq!(client.item(Some("Agents"), "github.com").unwrap().also_in, ["Personal"]);
    let meta = client.item(None, "github.com").unwrap().meta;
    client.edit(None, "github.com", meta, Some(login("second"))).unwrap();
    assert_eq!(client.reveal(Some("Agents"), "github.com").unwrap(), login("second"));
    client.undo().unwrap();
    assert_eq!(client.reveal(Some("Agents"), "github.com").unwrap(), login("first"), "one undo takes back every copy");
    assert_eq!(client.reveal(None, "github.com").unwrap(), login("first"));
}

#[test]
fn a_list_names_the_other_spaces_of_a_linked_item_and_none_for_a_namesake() {
    let (vault, mut client) = linked();
    vault.space("Work");
    client.add(Some("Work"), Meta::login("github.com"), login("unrelated"), false).unwrap();
    let mut also_in = |space| client.items(space).unwrap().into_iter().map(|item| item.also_in).collect::<Vec<_>>();
    assert_eq!(also_in(None), [["Agents"]]);
    assert_eq!(also_in(Some("Agents")), [["Personal"]]);
    assert_eq!(also_in(Some("Work")), [Vec::<String>::new()], "same name, different item");
}

#[test]
fn an_agent_given_one_space_sees_its_copy_and_nothing_of_the_others() {
    let (vault, mut client) = linked();
    client.add(None, Meta::env("PERSONAL_ONLY"), env("v"), false).unwrap();
    let mut agent = vault.session_client(&vault.session("Agents", "agent"));
    let names: Vec<String> = agent.items(None).unwrap().into_iter().map(|item| item.meta.name).collect();
    assert_eq!(names, ["github.com"]);
    assert_eq!(agent.item(None, "github.com").unwrap().also_in, Vec::<String>::new(), "the other spaces are none of its business");
}

#[test]
fn removing_it_from_one_space_leaves_the_other_and_later_changes_stay_out() {
    let (_vault, mut client) = linked();
    client.remove(Some("Agents"), "github.com").unwrap();
    let meta = client.item(None, "github.com").unwrap().meta;
    client.edit(None, "github.com", meta, Some(login("after"))).unwrap();
    assert_eq!(client.reveal(None, "github.com").unwrap(), login("after"));
    assert_eq!(code(client.item(Some("Agents"), "github.com")), ErrorCode::NotFound);
    assert_eq!(client.item(None, "github.com").unwrap().also_in, Vec::<String>::new());
}

#[test]
fn showing_an_item_in_another_space_takes_a_touch_and_no_agent_can() {
    let vault = Vault::new();
    vault.space("Agents");
    vault.client().add(None, Meta::login("github.com"), login("p"), false).unwrap();
    let mut agent = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(agent.link(None, "github.com", "Agents")), ErrorCode::Denied);
    fs::write(vault.home.join("deny"), "").unwrap();
    assert_eq!(code(vault.client().link(None, "github.com", "Agents")), ErrorCode::Denied);
    assert_eq!(code(vault.client().item(Some("Agents"), "github.com")), ErrorCode::NotFound);
}

#[test]
fn a_name_taken_in_either_space_is_refused_and_nothing_changes() {
    let (_vault, mut client) = linked();
    client.add(Some("Agents"), Meta::env("TAKEN"), env("v"), false).unwrap();
    let mut meta = client.item(None, "github.com").unwrap().meta;
    meta.name = "TAKEN".to_owned();
    assert_eq!(code(client.edit(None, "github.com", meta, None)), ErrorCode::Error);
    assert_eq!(client.item(None, "github.com").unwrap().meta.name, "github.com");
    client.add(None, Meta::env("ELSEWHERE"), env("v"), false).unwrap();
    client.add(Some("Agents"), Meta::env("ELSEWHERE"), env("w"), false).unwrap();
    assert_eq!(code(client.link(None, "ELSEWHERE", "Agents")), ErrorCode::Error);
}

#[test]
fn restoring_an_old_version_restores_every_copy() {
    let (_vault, mut client) = linked();
    let meta = client.item(None, "github.com").unwrap().meta;
    client.edit(None, "github.com", meta, Some(login("second"))).unwrap();
    client.restore(None, "github.com", 0).unwrap();
    assert_eq!(client.reveal(Some("Agents"), "github.com").unwrap(), login("first"));
}
