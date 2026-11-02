//! Flow 9 with a real `curl`, a real `lvd` and a fake upstream that echoes what it receives, which
//! is the worst case for a proxy that must not hand a secret back.

mod support;

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use libvault::item::Meta;
use libvault::run::{RunOptions, run};
use libvault::{Error, ErrorCode};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use support::{Vault, env};

const HOST: &str = "api.test.example";

struct Upstream {
    port: u16,
    /// Every request head it received.
    seen: Arc<Mutex<Vec<String>>>,
}

/// An HTTPS server for `HOST`, trusted only through the test hook.
fn upstream(home: &Path) -> Upstream {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let certificate = ca.self_signed(&ca_key).unwrap();
    fs::write(home.join("test-upstream-ca"), certificate.der()).unwrap();

    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_owned()]).unwrap().signed_by(&key, &Issuer::new(ca, ca_key)).unwrap();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth();
    let config = Arc::new(config.with_single_cert(vec![leaf.der().clone()], private).unwrap());

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (config, recorded) = (Arc::clone(&config), Arc::clone(&recorded));
            std::thread::spawn(move || echo(stream, config, &recorded));
        }
    });
    Upstream { port, seen }
}

/// The credential a request carried, as the server would see it.
fn credential(head: &str) -> String {
    head.lines().find_map(|line| line.strip_prefix("authorization: Bearer ")).unwrap_or_default().trim().to_owned()
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes.iter().map(|byte| if upper { format!("{byte:02X}") } else { format!("{byte:02x}") }).collect()
}

fn percent(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| if byte.is_ascii_alphanumeric() { char::from(*byte).to_string() } else { format!("%{byte:02X}") }).collect()
}

fn rfc3986(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) { char::from(*byte).to_string() } else { format!("%{byte:02X}") })
        .collect()
}

fn with_length(headers: &str, body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

/// Each path is one way a real server hands back what it was sent.
fn reply_to(head: &str) -> String {
    let path = head.split(' ').nth(1).unwrap_or("/");
    let value = credential(head);
    let bytes = value.as_bytes();
    match path.split('?').next().unwrap_or(path) {
        "/in-headers" => {
            with_length(&format!("X-Echo: {value}\r\nLocation: https://elsewhere.example/?key={value}\r\nSet-Cookie: k={value}\r\n"), "ok")
        }
        "/in-status" => format!("HTTP/1.1 200 {value}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
        "/trailer" => format!(
            "HTTP/1.1 200 OK\r\nTrailer: X-Echo\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\nX-Echo: {value}\r\n\r\n"
        ),
        "/compressed" => with_length("Content-Encoding: gzip\r\n", &format!("compressed-{}", value.chars().rev().collect::<String>())),
        "/upgrade" => format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: upgrade\r\n\r\n{value}"),
        "/encoded" => with_length(
            "",
            &[
                hex(bytes, false),
                hex(bytes, true),
                percent(bytes),
                rfc3986(bytes),
                value.replace('&', "&amp;").replace('"', "&quot;").replace('/', "&#x2F;"),
                URL_SAFE_NO_PAD.encode(bytes),
                STANDARD.encode([b"x", bytes].concat()),
                STANDARD.encode([b"xy", bytes].concat()),
                serde_json::to_string(&value).unwrap().replace('/', "\\/"),
            ]
            .join("\n"),
        ),
        _ => with_length("", head),
    }
}

fn echo(stream: TcpStream, config: Arc<ServerConfig>, seen: &Mutex<Vec<String>>) {
    let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), stream);
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read_exact(&mut byte).is_err() {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    seen.lock().unwrap().push(text.clone());
    let _ = tls.write_all(reply_to(&text).as_bytes());
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn add(vault: &Vault, name: &str, value: &str, hosts: &[&str]) {
    let mut meta = Meta::env(name);
    meta.hosts = hosts.iter().map(|host| (*host).to_owned()).collect();
    vault.client().add(None, meta, env(value), false).unwrap();
}

fn sh(script: &str) -> Vec<std::ffi::OsString> {
    ["/bin/sh", "-c", script].map(Into::into).to_vec()
}

fn curl(port: u16, extra: &str, out: &Path) -> String {
    curl_path(port, "/echo", extra, out)
}

fn curl_path(port: u16, path: &str, extra: &str, out: &Path) -> String {
    format!("curl -s --max-time 10 {extra} -o {} 'https://{HOST}:{port}{path}'", out.display())
}

#[test]
fn a_program_uses_a_secret_it_never_holds() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    add(&vault, "TEST_KEY", "real-secret-value", &[HOST]);
    let (out, seen_env) = (vault.dir.path().join("out"), vault.dir.path().join("env"));

    let script = format!("printf %s \"$TEST_KEY\" > {}; {}", seen_env.display(), curl(server.port, "-H \"Authorization: Bearer $TEST_KEY\"", &out));
    let code = run(&mut vault.client(), &sh(&script), &RunOptions::default()).unwrap();
    assert_eq!(code, 0);

    let held = fs::read_to_string(&seen_env).unwrap();
    assert!(held.starts_with("lv_ph_"), "the child must hold a placeholder, got {held:?}");
    assert!(!held.contains("real-secret-value"));

    let received = server.seen.lock().unwrap().join("\n");
    assert!(received.contains("Bearer real-secret-value"), "the server must get the real key: {received}");

    let echoed = fs::read_to_string(&out).unwrap();
    assert!(!echoed.contains("real-secret-value"), "the echo must not reach the child: {echoed}");
    assert!(echoed.contains("[hidden by vlt]"));
}

#[test]
fn an_echoed_basic_auth_header_does_not_leak_the_encoded_secret() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    add(&vault, "TEST_KEY", "real-secret-value", &[HOST]);
    let out = vault.dir.path().join("out");

    run(&mut vault.client(), &sh(&curl(server.port, "-u \"user:$TEST_KEY\"", &out)), &RunOptions::default()).unwrap();

    let received = server.seen.lock().unwrap().join("\n");
    let token =
        received.lines().find_map(|line| line.strip_prefix("authorization: Basic ")).expect("the server must get basic auth").trim().to_owned();
    assert!(!fs::read_to_string(&out).unwrap().contains(&token), "the encoded secret reached the child");
}

#[test]
fn a_placeholder_for_another_host_stays_a_placeholder() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    add(&vault, "TEST_KEY", "real-secret-value", &[HOST]);
    add(&vault, "OTHER_KEY", "other-secret-value", &["api.elsewhere.example"]);
    let out = vault.dir.path().join("out");

    run(&mut vault.client(), &sh(&curl(server.port, "-H \"X-Other: $OTHER_KEY\"", &out)), &RunOptions::default()).unwrap();

    let received = server.seen.lock().unwrap().join("\n");
    assert!(received.contains("x-other: lv_ph_"), "{received}");
    assert!(!received.contains("other-secret-value"));
}

#[test]
fn a_variable_with_no_allowed_host_blocks_the_run_and_is_named() {
    let vault = Vault::new();
    add(&vault, "DATABASE_URL", "postgres://secret", &[]);
    let error = run(&mut vault.client(), &sh("true"), &RunOptions::default()).unwrap_err();
    assert!(matches!(&error, Error::Broker { message, .. } if message.contains("DATABASE_URL")), "{error}");
}

#[test]
fn real_values_need_a_touch_even_with_a_session_and_a_refusal_runs_nothing() {
    let vault = Vault::new();
    vault.space("project-a");
    let mut meta = Meta::env("DATABASE_URL");
    meta.hosts.clear();
    vault.client().add(Some("project-a"), meta, env("postgres://secret"), false).unwrap();
    let session = vault.session("project-a", "claude");
    let marker = vault.dir.path().join("ran");

    vault.deny_touches();
    let options = RunOptions { env: vec!["DATABASE_URL".to_owned()], ..RunOptions::default() };
    let script = format!("touch {}", marker.display());
    let error = run(&mut vault.session_client(&session), &sh(&script), &options).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(!marker.exists(), "nothing may run after a refusal");
}

#[test]
fn a_session_covers_proxied_runs_without_a_touch() {
    let vault = Vault::new();
    vault.space("project-a");
    let mut meta = Meta::env("TEST_KEY");
    meta.hosts = vec![HOST.to_owned()];
    vault.client().add(Some("project-a"), meta, env("v"), false).unwrap();
    let session = vault.session("project-a", "claude");
    vault.deny_touches();
    assert_eq!(run(&mut vault.session_client(&session), &sh("true"), &RunOptions::default()).unwrap(), 0);
    assert_eq!(
        run(&mut vault.client(), &sh("true"), &RunOptions { space: Some("project-a".to_owned()), ..RunOptions::default() })
            .map_err(|error| error.code()),
        Err(ErrorCode::Denied)
    );
}

#[test]
fn the_exit_code_passes_through_and_a_run_leaves_nothing_behind() {
    let vault = Vault::new();
    add(&vault, "TEST_KEY", "v", &[HOST]);
    let mut client = vault.client();
    assert_eq!(run(&mut client, &sh("exit 7"), &RunOptions::default()).unwrap(), 7);
    drop(client);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let leftovers: Vec<_> = fs::read_dir(vault.home.join("run")).unwrap().flatten().filter(|entry| entry.path().is_dir()).collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

// A hostile program holding a placeholder. The server here is honest but reflects what it is sent,
// and each of these is a way the secret could come back past the scrubber.

const SECRET: &str = "sk/live+Secret=Value_0123456789\"end";

fn stolen(path: &str, extra: &str) -> (String, Vec<String>) {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    add(&vault, "TEST_KEY", SECRET, &[HOST]);
    let (body, headers) = (vault.dir.path().join("out"), vault.dir.path().join("headers"));
    let auth = format!("-D {} -H \"Authorization: Bearer $TEST_KEY\" {extra}", headers.display());
    run(&mut vault.client(), &sh(&curl_path(server.port, path, &auth, &body)), &RunOptions::default()).unwrap();
    let read = |path: &Path| fs::read(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default();
    let got = format!("{}\n{}", read(&body), read(&headers));
    let seen = server.seen.lock().unwrap().clone();
    (got, seen)
}

fn encodings_of(secret: &str) -> Vec<String> {
    let bytes = secret.as_bytes();
    let plain = [hex(bytes, false), hex(bytes, true), percent(bytes), URL_SAFE_NO_PAD.encode(bytes), STANDARD.encode(bytes), secret.to_owned()];
    plain.into_iter().collect()
}

fn assert_clean(got: &str) {
    for form in encodings_of(SECRET) {
        assert!(!got.contains(&form), "the secret came back as {form}:\n{got}");
    }
    assert!(!got.contains(&SECRET[..20]), "the secret came back:\n{got}");
}

#[test]
fn a_secret_reflected_in_response_headers_is_hidden() {
    let (got, seen) = stolen("/in-headers", "");
    assert!(seen[0].contains(SECRET), "the server must get the real key");
    assert_clean(&got);
}

#[test]
fn a_secret_reflected_in_the_status_line_is_hidden() {
    assert_clean(&stolen("/in-status", "").0);
}

#[test]
fn a_secret_reflected_in_a_trailer_is_hidden() {
    assert_clean(&stolen("/trailer", "--raw").0);
}

#[test]
fn a_secret_reflected_in_a_common_encoding_is_hidden() {
    let (got, _) = stolen("/encoded", "");
    let html = SECRET.replace('"', "&quot;").replace('/', "&#x2F;");
    for form in [
        hex(SECRET.as_bytes(), false),
        hex(SECRET.as_bytes(), true),
        percent(SECRET.as_bytes()),
        rfc3986(SECRET.as_bytes()),
        URL_SAFE_NO_PAD.encode(SECRET),
        html,
    ] {
        assert!(!got.contains(&form), "the secret came back as {form}:\n{got}");
    }
    assert!(!got.contains("sk\\/live"), "JSON escaping hid it from the scrubber:\n{got}");
    let shifted = [STANDARD.encode([b"x", SECRET.as_bytes()].concat()), STANDARD.encode([b"xy", SECRET.as_bytes()].concat())];
    for form in shifted {
        assert!(!got.contains(&form[4..form.len() - 4]), "base64 at another offset hid it:\n{got}");
    }
}

#[test]
fn a_reply_the_scrubber_cannot_read_never_reaches_the_program() {
    let (got, _) = stolen("/compressed", "");
    assert!(!got.contains("compressed-"), "a compressed reply went past the scrubber:\n{got}");
}

#[test]
fn a_connection_upgraded_after_carrying_a_secret_is_refused() {
    let (got, _) = stolen("/upgrade", "-H 'Connection: Upgrade' -H 'Upgrade: echo'");
    assert_clean(&got);
    assert!(got.contains("502"), "{got}");
}

/// A request with no secret in it, on a host that may have kept one from an earlier request.
fn later_request(path: &str, extra: &str) -> (String, Vec<String>) {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    add(&vault, "TEST_KEY", SECRET, &[HOST]);
    let headers = vault.dir.path().join("headers");
    let script = curl_path(server.port, path, &format!("-D {} {extra}", headers.display()), &vault.dir.path().join("out"));
    run(&mut vault.client(), &sh(&script), &RunOptions::default()).unwrap();
    let seen = server.seen.lock().unwrap().clone();
    (fs::read_to_string(&headers).unwrap_or_default(), seen)
}

#[test]
fn nothing_can_be_upgraded_past_the_scrubber_even_with_no_secret_in_the_request() {
    let (got, _) = later_request("/upgrade", "-H 'Connection: Upgrade' -H 'Upgrade: echo'");
    assert!(got.contains("502"), "{got}");
}

#[test]
fn a_range_is_never_passed_on_because_a_kept_secret_could_come_back_in_slices() {
    let (_, seen) = later_request("/echo", "-H 'Range: bytes=0-3'");
    assert!(!seen[0].to_ascii_lowercase().contains("range:"), "{}", seen[0]);
}

#[test]
fn a_routing_header_cannot_send_a_request_somewhere_else() {
    let (_, seen) =
        later_request("/echo", "-H 'X-Forwarded-Host: attacker.example' -H 'X-Original-URL: /steal' -H 'Forwarded: host=attacker.example'");
    assert!(!seen[0].contains("attacker.example") && !seen[0].contains("/steal"), "{}", seen[0]);
}

// Where a program may put a placeholder. On an honest API a URL or an ordinary header can be
// somewhere a value is kept and shown, such as a file name in a public repository.

fn placed(path: &str, header: &str) -> String {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    add(&vault, "TEST_KEY", SECRET, &[HOST]);
    let out = vault.dir.path().join("out");
    let script = format!("curl -s --max-time 10 -H \"{header}\" -o {} \"https://{HOST}:{}{path}\"", out.display(), server.port);
    run(&mut vault.client(), &sh(&script), &RunOptions::default()).unwrap();
    server.seen.lock().unwrap().join("\n")
}

#[test]
fn a_placeholder_in_a_url_stays_a_placeholder() {
    let seen = placed("/repos/me/public/contents/$TEST_KEY?q=$TEST_KEY", "X-Other: 1");
    assert!(!seen.contains(SECRET) && seen.contains("lv_ph_"), "{seen}");
}

#[test]
fn a_placeholder_in_an_ordinary_header_stays_a_placeholder() {
    let seen = placed("/echo", "User-Agent: $TEST_KEY");
    assert!(!seen.contains(SECRET) && seen.contains("lv_ph_"), "{seen}");
}

#[test]
fn a_placeholder_in_a_header_made_for_a_key_is_filled_in() {
    assert!(placed("/echo", "X-Api-Key: $TEST_KEY").contains(SECRET));
    assert!(placed("/echo", "Cookie: session=$TEST_KEY").contains(SECRET));
}

#[test]
fn a_range_request_cannot_read_a_reflection_in_pieces() {
    let (_, seen) = stolen("/echo", "-H 'Range: bytes=0-3' -H 'If-Range: x'");
    let head = seen[0].to_ascii_lowercase();
    assert!(!head.contains("range:"), "the scrubber never sees a whole secret in a slice of a reply:\n{head}");
}

// The request has to go where the allowed host says, not where the program says.

#[test]
fn a_host_header_cannot_send_a_secret_to_another_site_on_the_same_server() {
    let (_, seen) = stolen("/echo", "-H 'Host: attacker.example'");
    assert!(seen[0].contains(&format!("host: {HOST}")), "{}", seen[0]);
    assert!(!seen[0].contains("attacker.example"), "{}", seen[0]);
}

#[test]
fn an_absolute_request_line_cannot_send_a_secret_to_another_site() {
    let (_, seen) = stolen("/echo", "--request-target 'https://attacker.example/steal'");
    assert!(seen[0].starts_with("GET /steal "), "{}", seen[0]);
    assert!(!seen[0].contains("attacker.example"), "{}", seen[0]);
}

// A run ends when the access it was started under ends.

/// Runs a program that makes a request, waits, then makes another, with `between` in the gap.
/// Returns how many requests reached the server carrying the real secret.
fn requests_with_the_secret(vault: &Vault, server: &Upstream, session: Option<&str>, between: impl FnOnce()) -> usize {
    let (reached, resume, out) = (vault.dir.path().join("reached"), vault.dir.path().join("resume"), vault.dir.path().join("out"));
    let request = curl(server.port, "-H \"Authorization: Bearer $TEST_KEY\"", &out);
    let script = format!("{request}; touch {}; while [ ! -f {} ]; do sleep 0.05; done; {request}", reached.display(), resume.display());
    let mut client = match session {
        Some(token) => vault.session_client(token),
        None => vault.client(),
    };
    let running = std::thread::spawn(move || run(&mut client, &sh(&script), &RunOptions::default()).unwrap());
    while !reached.exists() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    between();
    std::thread::sleep(std::time::Duration::from_millis(100));
    fs::write(&resume, "").unwrap();
    running.join().unwrap();
    server.seen.lock().unwrap().iter().filter(|head| head.contains("real-secret-value")).count()
}

fn project(vault: &Vault) -> String {
    vault.space("project-a");
    let mut meta = Meta::env("TEST_KEY");
    meta.hosts = vec![HOST.to_owned()];
    vault.client().add(Some("project-a"), meta, env("real-secret-value"), false).unwrap();
    vault.session("project-a", "claude")
}

#[test]
fn locking_ends_a_running_program_s_access() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    let session = project(&vault);
    let used = requests_with_the_secret(&vault, &server, Some(&session), || vault.client().lock().unwrap());
    assert_eq!(used, 1, "the secret was still in use after locking");
}

#[test]
fn revoking_a_grant_ends_a_running_program_s_access() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    let session = project(&vault);
    let used = requests_with_the_secret(&vault, &server, Some(&session), || {
        let id = vault.client().grants().unwrap()[0].id.clone();
        vault.client().end_grant(&id).unwrap();
    });
    assert_eq!(used, 1, "the secret was still in use after the grant ended");
}

#[test]
fn an_expired_grant_ends_a_running_program_s_access() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    project(&vault);
    let session = vault.client().grant(Some("project-a"), "claude", std::time::Duration::from_secs(1), None).unwrap().0;
    let used = requests_with_the_secret(&vault, &server, Some(&session), || std::thread::sleep(std::time::Duration::from_secs(4)));
    assert_eq!(used, 1, "the secret was still in use after the grant expired");
}

#[test]
fn a_grant_that_is_still_good_keeps_working() {
    let vault = Vault::new();
    let server = upstream(&vault.home);
    let session = project(&vault);
    assert_eq!(requests_with_the_secret(&vault, &server, Some(&session), || {}), 2);
}
