//! Signing up for an agent, in a real browser the agent drives, at a local site that records what
//! it is sent and checks passkeys as a site would. Skipped on a machine with no Chrome.

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use libvault::item::{Kind, Secret};
use libvault::{ErrorCode, LoginInto, SignUpWith};
use serde_json::{Value, json};
use support::chrome::{AgentBrowser, has_browser};
use support::{Vault, code};

const SIGN_UP: &str = "<!doctype html><form method=post action=/made>\
    <input type=email name=email value=agent@example.com>\
    <input type=password name=password><input type=password name=confirm><button>Go</button></form>";

/// Makes a passkey, then signs in with it and checks the signature against the key it was given,
/// with nothing but what any page has.
const PASSKEYS: &str = r"<!doctype html><script>
let key;
const url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
globalThis.make = async () => {
  const made = await navigator.credentials.create({ publicKey: {
    rp: { name: 'Test', id: 'localhost' }, user: { id: new TextEncoder().encode('user-1'), name: 'ada', displayName: 'Ada' },
    challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } });
  key = await crypto.subtle.importKey('spki', made.response.getPublicKey(), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return made instanceof PublicKeyCredential && made.id === url(made.rawId);
};
const raw = (der) => {
  const b = new Uint8Array(der); let at = 2;
  const part = () => { at++; const length = b[at++]; let value = b.slice(at, at + length); at += length; while (value.length > 32) value = value.slice(1); const out = new Uint8Array(32); out.set(value, 32 - value.length); return out; };
  const signature = new Uint8Array(64); signature.set(part()); signature.set(part(), 32); return signature;
};
globalThis.check = async () => {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signed = await navigator.credentials.get({ publicKey: { rpId: 'localhost', challenge } }).catch((error) => error.name);
  if (typeof signed === 'string') return signed;
  const data = JSON.parse(new TextDecoder().decode(signed.response.clientDataJSON));
  const hash = await crypto.subtle.digest('SHA-256', signed.response.clientDataJSON);
  const message = new Uint8Array([...new Uint8Array(signed.response.authenticatorData), ...new Uint8Array(hash)]);
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw(signed.response.signature), message);
  const counter = new DataView(signed.response.authenticatorData).getUint32(33);
  return valid && data.type === 'webauthn.get' && data.origin === location.origin && data.challenge === url(challenge) && counter === 0 ? 'verified' : 'invalid';
};
</script>";

struct Site {
    port: u16,
    posts: Arc<Mutex<Vec<String>>>,
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("http://localhost:{}{path}", self.port)
    }

    fn origin(&self) -> String {
        self.url("")
    }
}

fn serve(mut stream: TcpStream, posts: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    let _ = reader.read_line(&mut request_line);
    let (mut length, mut line) = (0, String::new());
    while reader.read_line(&mut line).is_ok_and(|read| read > 0) && line != "\r\n" {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        line.clear();
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    if length > 0 {
        posts.lock().unwrap().push(String::from_utf8_lossy(&body).into_owned());
    }
    let page = match request_line.split(' ').nth(1).unwrap_or("/") {
        "/signup" => SIGN_UP,
        "/passkeys" => PASSKEYS,
        _ => "<!doctype html><h1>Welcome</h1>",
    };
    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}", page.len());
    let _ = stream.write_all(reply.as_bytes());
}

fn site() -> Site {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let posts = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&posts);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || serve(stream, &recorded));
        }
    });
    Site { port, posts }
}

fn form_value(body: &str, name: &str) -> String {
    let value = body.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}="))).unwrap_or_default();
    // Enough decoding for what a generated password holds.
    let mut decoded = String::new();
    let mut rest = value;
    while let Some(at) = rest.find('%') {
        decoded.push_str(&rest[..at]);
        decoded.push(char::from(u8::from_str_radix(&rest[at + 1..at + 3], 16).unwrap()));
        rest = &rest[at + 3..];
    }
    decoded + rest
}

#[test]
fn an_agent_signs_up_with_a_password_it_never_receives() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site());
    vault.space("agents");
    let token = vault.session("agents", "claude");
    let agent = AgentBrowser::launch_at(&site.url("/signup"));
    agent.wait_for("document.readyState === 'complete' && !!document.forms[0]");
    vault.deny_touches();

    let name = vault.session_client(&token).sign_up(None, &site.origin(), &agent.address(), SignUpWith::Password).unwrap();
    assert_eq!(name, "localhost");
    agent.evaluate("document.forms[0].submit()");
    agent.wait_for("document.querySelector('h1') !== null");

    vault.allow_touches();
    let posted = site.posts.lock().unwrap()[0].clone();
    let revealed = vault.client().reveal(Some("agents"), "localhost").unwrap();
    let Secret::Login { password, .. } = &revealed else { panic!("a login") };
    assert!(password.len() >= 20);
    assert_eq!((form_value(&posted, "password"), form_value(&posted, "confirm")), (password.clone(), password.clone()));
    let saved = vault.client().items(Some("agents")).unwrap().into_iter().find(|item| item.meta.name == "localhost").unwrap();
    assert_eq!(saved.meta.username.as_deref(), Some("agent@example.com"));
    assert!(vault.client().audit().unwrap().iter().any(|event| event.action == "signup" && event.actor == "claude"));
}

#[test]
fn signing_up_needs_the_page_open_and_saves_nothing_without_it() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site());
    let agent = AgentBrowser::launch_at(&site.url("/welcome"));
    agent.wait_for("document.readyState === 'complete'");
    let mut client = vault.client();
    assert_eq!(code(client.sign_up(None, "github.com", &agent.address(), SignUpWith::Password)), ErrorCode::NotFound);
    assert_eq!(code(client.sign_up(None, &site.origin(), &agent.address(), SignUpWith::Password)), ErrorCode::Error, "no password field");
    assert_eq!(code(client.sign_up(None, &site.origin(), "http://192.0.2.1:9222", SignUpWith::Password)), ErrorCode::Error);
    assert!(client.items(None).unwrap().is_empty());
}

/// Runs `sign_up` or `login` beside the page, which acts once the broker is listening.
fn beside<T: Send>(agent: &AgentBrowser, vault_call: impl FnOnce() -> T + Send, page: &str) -> (T, Value) {
    std::thread::scope(|scope| {
        let call = scope.spawn(vault_call);
        agent.wait_for("typeof globalThis.lvAnswer === 'function'");
        let shown = agent.evaluate(page);
        (call.join().unwrap(), shown)
    })
}

#[test]
fn an_agent_makes_a_passkey_and_signs_in_with_it_each_after_a_touch() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site());
    let token = vault.session("Personal", "claude");
    let agent = AgentBrowser::launch_at(&site.url("/passkeys"));
    agent.wait_for("typeof globalThis.make === 'function'");

    let (name, made) = beside(&agent, || vault.session_client(&token).sign_up(None, &site.origin(), &agent.address(), SignUpWith::Passkey), "make()");
    assert_eq!((name.unwrap(), made), ("ada on localhost".to_owned(), json!(true)));
    assert_eq!(agent.evaluate("typeof globalThis.lvAnswer"), json!("undefined"), "the page is left as it was");
    let saved = vault.client().items(None).unwrap().into_iter().find(|item| item.meta.kind == Kind::Passkey).unwrap();
    assert_eq!(saved.meta.username.as_deref(), Some("ada"));

    let into = LoginInto::Browser(agent.address());
    let (signed_in, checked) = beside(&agent, || vault.session_client(&token).login(None, "ada on localhost", into), "check()");
    assert_eq!((signed_in.unwrap(), checked), (0, json!("verified")));
    let events = vault.client().audit().unwrap();
    assert!(events.iter().any(|event| event.action == "passkey" && event.actor == "claude"));
    assert!(events.iter().any(|event| event.action == "login" && event.target == "ada on localhost" && event.actor == "claude"));
}

#[test]
fn a_refused_passkey_saves_nothing_and_the_page_hears_no() {
    if !has_browser() {
        return;
    }
    let (vault, site) = (Vault::new(), site());
    let token = vault.session("Personal", "claude");
    let agent = AgentBrowser::launch_at(&site.url("/passkeys"));
    agent.wait_for("typeof globalThis.make === 'function'");
    vault.deny_touches();

    let make = "make().catch((error) => error.name)";
    let (result, shown) = beside(&agent, || vault.session_client(&token).sign_up(None, &site.origin(), &agent.address(), SignUpWith::Passkey), make);
    assert_eq!((code(result), shown), (ErrorCode::Denied, json!("NotAllowedError")));
    vault.allow_touches();
    assert!(vault.client().items(None).unwrap().is_empty());
}
