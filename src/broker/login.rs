//! Signing in for an agent without the agent seeing a password. The broker signs in using its own
//! browser, checks the page's origin before each value, puts that value in the one field it checked,
//! and hands over only the session. Passwords reach only the page that matches the saved login.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use tungstenite::Message;

use super::Broker;
use super::browser::{Browser, Tab};
use super::handlers::resolve_space;
use super::policy::{Action, Caller};
use super::proxy::reflected_forms;
use crate::fill::{Origin, matches};
use crate::item::{Kind, Secret};
use crate::protocol::{LoginInto, Response};
use crate::store::log::hex;
use crate::{Error, Result, Totp, crypto};

/// Steps through a sign-in: at most a username page, a password page and a code page, and one
/// spare for a redirect in between.
const MAX_STEPS: usize = 5;
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE_POLL: Duration = Duration::from_millis(100);
const STABLE_FOR: Duration = Duration::from_millis(300);
const DEVTOOLS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DEVTOOLS_BODY: usize = 64 * 1024;
const MAX_DEVTOOLS_REPLY: u64 = 256 * 1024;
const HAND_OVER_TIMEOUT: Duration = Duration::from_secs(10);

/// Describes the page's visible fields, and remembers them in this world, where the page cannot
/// reach them. It reads the page and reports, and takes no input.
const INSPECT: &str = r#"(() => {
  const usable = e => { const r = e.getBoundingClientRect(), s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !e.disabled && !e.readOnly; };
  const inputs = [...document.querySelectorAll('input')].filter(usable);
  const label = e => (e.name + ' ' + e.id + ' ' + e.autocomplete).toLowerCase();
  const password = inputs.find(e => e.type === 'password');
  const code = inputs.find(e => e.autocomplete === 'one-time-code' || /otp|totp|2fa|mfa|one.?time|verification.?code|auth.?code/.test(label(e)));
  const user = inputs.find(e => e !== password && e !== code && (e.type === 'email' || /user|email|login|identifier/.test(label(e)))) || inputs.find(e => e !== code && e.type === 'text');
  const captcha = !!document.querySelector('iframe[src*="recaptcha"],iframe[src*="hcaptcha"],iframe[src*="turnstile"],.g-recaptcha,.h-captcha,.cf-turnstile');
  globalThis.lvFields = { password, code, user };
  return JSON.stringify({ ready: document.readyState === 'complete', password: !!password, code: !!code, user: !!user, captcha });
})()"#;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[allow(clippy::struct_excessive_bools, reason = "these mirror what the page script reports")]
struct Page {
    #[serde(default)]
    href: String,
    ready: bool,
    password: bool,
    code: bool,
    user: bool,
    captcha: bool,
}

/// What is on the page, and the world that saw it. The address comes from the browser, last.
fn inspect(tab: &mut Tab<'_>) -> Result<(Page, u64)> {
    let world = tab.world()?;
    let mut page: Page = serde_json::from_str(&tab.evaluate(world, INSPECT)?).map_err(|_| Error::Peer("the page could not be read"))?;
    page.href = tab.url()?;
    Ok((page, world))
}

/// Waits for the page to stop changing, then reports what is on it.
fn settle(tab: &mut Tab<'_>) -> Result<Page> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let mut last = inspect(tab).ok().map(|(page, _)| page);
    let mut stable_since = Instant::now();
    loop {
        std::thread::sleep(SETTLE_POLL);
        // A page mid-navigation has nothing to report yet.
        let current = inspect(tab).ok().map(|(page, _)| page);
        if current != last {
            last = current;
            stable_since = Instant::now();
        } else if let Some(page) = current.filter(|page| page.ready)
            && stable_since.elapsed() >= STABLE_FOR
        {
            return Ok(page);
        }
        if Instant::now() > deadline {
            return last.ok_or(Error::Peer("the page never finished loading"));
        }
    }
}

/// Puts a value in a field, only if the page is still one this login belongs on and this sign-in
/// may still go on. It goes to that element and nowhere else, so that whatever else on the page holds
/// focus never sees it. Returns the world, for submitting what it filled.
fn enter(tab: &mut Tab<'_>, credentials: &Credentials<'_>, field: &str, value: &str) -> Result<u64> {
    (credentials.may_go_on)()?;
    let (page, world) = inspect(tab)?;
    let origin = Origin::parse(&page.href).ok_or(Error::LoginRefused("the page has no origin"))?;
    if !matches(credentials.saved, &origin) {
        return Err(Error::LoginRefused("the sign-in moved to a site this login is not saved for"));
    }
    if !tab.set_field(world, field, value)? {
        return Err(Error::LoginRefused("the field disappeared"));
    }
    Ok(world)
}

struct Credentials<'a> {
    saved: &'a str,
    username: Option<&'a str>,
    password: &'a str,
    totp: Option<Totp>,
    /// Whether this may still go on. A lock always wins, and so does the end of a grant.
    may_go_on: &'a dyn Fn() -> Result<()>,
}

/// Walks the sign-in. A refused password is never retried, since that can lock the account.
fn sign_in(tab: &mut Tab<'_>, credentials: &Credentials<'_>) -> Result<()> {
    tab.goto(credentials.saved)?;
    let (mut typed_user, mut typed_password, mut typed_code) = (false, false, false);
    for _ in 0..MAX_STEPS {
        let page = settle(tab)?;
        if page.captcha {
            return Err(Error::NeedsPerson("this site is asking for a CAPTCHA, so a person has to sign in"));
        }
        let world = if page.password {
            if typed_password {
                return Err(Error::LoginRefused("the site refused the password. Nothing was retried"));
            }
            if let (true, Some(username)) = (page.user, credentials.username) {
                enter(tab, credentials, "user", username)?;
            }
            typed_password = true;
            enter(tab, credentials, "password", credentials.password)?
        } else if page.code {
            let totp = credentials.totp.as_ref().ok_or(Error::NeedsPerson("this site wants a code, and none is saved"))?;
            if typed_code {
                return Err(Error::LoginRefused("the site refused the code. Nothing was retried"));
            }
            typed_code = true;
            enter(tab, credentials, "code", &totp.now())?
        } else if typed_password {
            return Ok(());
        } else if let (true, false, Some(username)) = (page.user, typed_user, credentials.username) {
            typed_user = true;
            enter(tab, credentials, "user", username)?
        } else {
            return Err(Error::NeedsPerson("the sign-in page was not one this can follow, so a person has to sign in"));
        };
        tab.submit(world)?;
    }
    Err(Error::NeedsPerson("the sign-in took more steps than expected, so a person has to finish it"))
}

/// The cookies that are the session: those for the saved site, or a domain above it that it
/// shares them with. A sign-in can pass through other sites, whose cookies are nobody's business
/// here, and a site can keep the password itself in a cookie, which is the one thing an agent must
/// not end up with.
fn session_cookies(cookies: &Value, saved: &str, password: &str) -> Value {
    let host = Origin::parse(saved).map(|origin| origin.host).unwrap_or_default();
    let belongs = |domain: &str| {
        let domain = domain.trim_start_matches('.');
        domain == host || domain.ends_with(&format!(".{host}")) || (domain.contains('.') && host.ends_with(&format!(".{domain}")))
    };
    let forms = reflected_forms(password);
    let holds_password = |value: &str| forms.iter().any(|form| value.contains(form.as_str()));
    let keep =
        |cookie: &&Value| belongs(cookie["domain"].as_str().unwrap_or_default()) && !holds_password(cookie["value"].as_str().unwrap_or_default());
    Value::Array(cookies.as_array().map(|cookies| cookies.iter().filter(keep).cloned().collect()).unwrap_or_default())
}

fn playwright_state(cookies: &Value) -> Value {
    let cookies: Vec<Value> = cookies
        .as_array()
        .map(|cookies| {
            cookies
                .iter()
                .map(|cookie| {
                    json!({
                        "name": cookie["name"], "value": cookie["value"], "domain": cookie["domain"], "path": cookie["path"],
                        "expires": cookie["expires"], "httpOnly": cookie["httpOnly"], "secure": cookie["secure"],
                        "sameSite": cookie["sameSite"].as_str().unwrap_or("Lax"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({ "cookies": cookies, "origins": [] })
}

/// Asks a local debugging endpoint for its socket address. Chrome leaves the connection open,
/// so this reads exactly the advertised length, with a timeout so a bad endpoint cannot stall.
fn devtools_socket(endpoint: &str) -> Result<String> {
    let not_devtools = || Error::Peer("that is not a DevTools address");
    let origin = Origin::parse(endpoint).filter(|origin| origin.scheme == "http");
    let origin = origin.ok_or(Error::Invalid("the agent's browser must be a local DevTools address, like http://127.0.0.1:9222"))?;
    let authority = format!("{}:{}", origin.host, origin.port);
    // What was checked is what is reached, whatever else the address was written to look like.
    let mut stream = TcpStream::connect(&authority)?;
    stream.set_read_timeout(Some(DEVTOOLS_TIMEOUT))?;
    stream.write_all(format!("GET /json/version HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())?;

    // The agent chose this address, so what answers may be hostile. It gets a fixed allowance.
    let mut reader = BufReader::new(stream.take(MAX_DEVTOOLS_REPLY));
    let mut length = None;
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let mut body = vec![0u8; length.ok_or_else(not_devtools)?.min(MAX_DEVTOOLS_BODY)];
    reader.read_exact(&mut body)?;
    let version: Value = serde_json::from_slice(&body).map_err(|_| not_devtools())?;
    version["webSocketDebuggerUrl"].as_str().map(str::to_owned).ok_or_else(not_devtools)
}

/// Whether a debugger address, which whoever answered at `endpoint` wrote, is that same endpoint.
fn is_same_place(url: &str, endpoint: &Origin) -> bool {
    url.strip_prefix("ws://")
        .and_then(|rest| Origin::parse(&format!("http://{rest}")))
        .is_some_and(|socket| socket.host == endpoint.host && socket.port == endpoint.port)
}

/// The agent's browser and its debugger address. Cookies stay on this machine: `endpoint` must
/// be local.
fn agent_browser(endpoint: &str) -> Result<(Origin, String)> {
    let origin = Origin::parse(endpoint).ok_or(Error::Invalid("that address cannot be read"))?;
    if !matches!(origin.host.as_str(), "127.0.0.1" | "localhost") {
        return Err(Error::Invalid("a session can only be handed to a browser on this machine"));
    }
    let url = devtools_socket(endpoint)?;
    if !is_same_place(&url, &origin) {
        return Err(Error::Invalid("a session can only be handed to a browser on this machine"));
    }
    Ok((origin, url))
}

/// Whether a session could go where it was asked to, known before anything is typed.
fn check_destination(into: &LoginInto) -> Result<()> {
    match into {
        LoginInto::Browser(endpoint) => agent_browser(endpoint).map(|_| ()),
        LoginInto::StateFile(path) if path.is_relative() => Err(Error::Invalid("a session file needs a full path")),
        LoginInto::StateFile(path) if path.exists() => Err(Error::Exists(path.display().to_string())),
        LoginInto::StateFile(_) => Ok(()),
    }
}

/// Puts the session in the agent's browser.
fn hand_over(endpoint: &str, cookies: &Value) -> Result<()> {
    let (origin, url) = agent_browser(endpoint)?;
    let stream = TcpStream::connect((origin.host.as_str(), origin.port))?;
    stream.set_read_timeout(Some(DEVTOOLS_TIMEOUT))?;
    stream.set_write_timeout(Some(DEVTOOLS_TIMEOUT))?;
    let (mut socket, _) = tungstenite::client(url.as_str(), stream).map_err(|_| Error::Peer("the agent's browser refused the connection"))?;
    let call = json!({ "id": 1, "method": "Storage.setCookies", "params": { "cookies": cookies } });
    socket.send(Message::text(call.to_string())).map_err(|_| Error::Peer("the agent's browser stopped responding"))?;
    let deadline = Instant::now() + HAND_OVER_TIMEOUT;
    while Instant::now() < deadline {
        let message = socket.read().map_err(|_| Error::Peer("the agent's browser stopped responding"))?;
        let Message::Text(text) = message else { continue };
        let reply: Value = serde_json::from_str(text.as_str()).unwrap_or_default();
        if reply["id"] == 1 {
            return if reply.get("error").is_some() { Err(Error::Peer("the agent's browser refused the session")) } else { Ok(()) };
        }
    }
    Err(Error::Peer("the agent's browser stopped responding"))
}

impl Broker {
    /// Signs in with a saved login and hands over the session. The password goes only to pages
    /// that match the login, in a browser nothing else can reach.
    pub(super) fn login(&self, caller: &Caller, space: Option<&str>, name: &str, into: &LoginInto) -> Result<Response> {
        let (id, item) = {
            let core = self.unlocked()?;
            let id = resolve_space(&core.vault, caller, space)?;
            (id, core.vault.find(&id, name)?)
        };
        if item.meta.kind != Kind::Login {
            return Err(Error::Invalid("that is not a login"));
        }
        let saved = item.meta.urls.first().ok_or(Error::Invalid("that login has no site saved"))?.clone();
        let into_shown = match into {
            LoginInto::Browser(endpoint) => endpoint.clone(),
            LoginInto::StateFile(path) => path.display().to_string(),
        };
        check_destination(into)?;
        let site = Origin::parse(&saved).map(|origin| origin.host).unwrap_or_default();
        self.check(caller, Action::Login { name, site: &site, into: &into_shown })?;

        let (secret, locks) = {
            let core = self.open_core()?;
            (core.vault.secret(&id, &item.id)?, core.locks)
        };
        let Secret::Login { password, totp } = &secret else { return Err(Error::Invalid("that is not a login")) };
        let totp = totp.as_deref().map(Totp::parse).transpose()?;
        let may_go_on = || {
            let mut core = self.open_core()?;
            let grant_stands = if let Caller::Session(grant) = caller { core.grants.is_live(&grant.id) } else { true };
            if core.locks == locks && grant_stands { Ok(()) } else { Err(Error::Locked) }
        };
        let credentials = Credentials { saved: &saved, username: item.meta.username.as_deref(), password, totp, may_go_on: &may_go_on };
        // Before anything is typed, so an attempt that fails halfway is on the record too.
        self.open_core()?.vault.record("login", name, caller.name())?;

        let profile = self.home.join("run").join(format!("browser-{}", hex(&crypto::random::<8>())));
        let mut browser = Browser::launch(profile)?;
        sign_in(&mut browser.open_tab()?, &credentials)?;
        let cookies = session_cookies(&browser.call("Storage.getCookies", &json!({}), None)?["cookies"], &saved, password);
        drop(browser);

        // A page with no form on it says little: a site that signed someone in gives a session.
        if cookies.as_array().is_none_or(Vec::is_empty) {
            return Err(Error::Peer("the site gave no session, so the sign-in did not work"));
        }
        may_go_on()?;
        match into {
            LoginInto::Browser(endpoint) => hand_over(endpoint, &cookies)?,
            LoginInto::StateFile(path) => write_state(path, &playwright_state(&cookies))?,
        }
        Ok(Response::LoggedIn { cookies: cookies.as_array().map_or(0, Vec::len) })
    }
}

fn write_state(path: &Path, state: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|_| Error::Peer("the session could not be saved"))?;
    crate::export::write_new(path, &bytes)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn a_debugger_address_must_be_the_one_that_was_asked() {
        let endpoint = Origin::parse("http://127.0.0.1:9222").unwrap();
        assert!(is_same_place("ws://127.0.0.1:9222/devtools/browser/x", &endpoint));
        for elsewhere in [
            "ws://attacker.example:9222/devtools/browser/x",
            "ws://127.0.0.1.attacker.example:9222/x",
            "ws://127.0.0.1@attacker.example:9222/x",
            "ws://127.0.0.1:9223/x",
            "wss://127.0.0.1:9222/x",
            "nonsense",
        ] {
            assert!(!is_same_place(elsewhere, &endpoint), "{elsewhere}");
        }
    }

    #[test]
    fn an_endless_reply_from_a_debugger_address_is_cut_off() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            while stream.write_all(&[b'a'; 4096]).is_ok() {}
        });
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(devtools_socket(&endpoint).is_err()));
        assert_eq!(finished.recv_timeout(Duration::from_secs(5)), Ok(true), "it would read until memory ran out");
    }
}
