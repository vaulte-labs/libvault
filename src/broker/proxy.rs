//! Lets a program use a secret it never holds. The child gets a placeholder and this proxy as
//! `HTTPS_PROXY`. Traffic to a secret's allowed hosts is terminated here, where the placeholder
//! becomes the real value in request headers and the value is scrubbed from responses. All other
//! traffic is tunnelled untouched, so a placeholder sent elsewhere is worthless.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard};
use std::task::{Context, Poll};

use base64::Engine;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, COOKIE, FORWARDED, HOST, HeaderMap, HeaderName, HeaderValue, IF_RANGE, RANGE,
    TRANSFER_ENCODING,
};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::ext::ReasonPhrase;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::AbortHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

use crate::scrub::Scrubber;
use crate::{Error, Result};

type Reply = Response<BoxBody<Bytes, hyper::Error>>;
type Upstream = Arc<tokio::sync::Mutex<Option<SendRequest<Incoming>>>>;

const INTERCEPTED_PORT: u16 = 443;
/// Shorter encoded forms would hide ordinary text.
const MIN_ENCODED_FORM: usize = 8;

/// One secret and where it may go.
#[derive(Debug)]
pub struct Substitution {
    pub placeholder: String,
    pub secret: Zeroizing<String>,
    pub hosts: Vec<String>,
}

struct Shared {
    /// Empty once the run has ended, which is all it takes: with nothing to substitute, a request
    /// goes out as it came in, and a placeholder is worth nothing.
    substitutions: RwLock<Vec<Substitution>>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    upstream: Arc<ClientConfig>,
    /// Only under `test-hooks`: reach every intercepted host on loopback, at any port.
    local_upstream: bool,
}

impl Shared {
    fn substitutions(&self) -> RwLockReadGuard<'_, Vec<Substitution>> {
        self.substitutions.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn intercepts(&self, host: &str, port: u16) -> bool {
        (port == INTERCEPTED_PORT || self.local_upstream)
            && self.substitutions().iter().any(|s| s.hosts.iter().any(|allowed| allowed.eq_ignore_ascii_case(host)))
    }

    /// Replaces each placeholder allowed on `host`. Placeholders for other hosts stay as they are.
    fn substitute(&self, text: &str, host: &str) -> Option<String> {
        let mut replaced = None;
        for substitution in self.substitutions().iter() {
            if !substitution.hosts.iter().any(|allowed| allowed.eq_ignore_ascii_case(host)) {
                continue;
            }
            let current = replaced.as_deref().unwrap_or(text);
            if current.contains(&substitution.placeholder) {
                replaced = Some(current.replace(&substitution.placeholder, &substitution.secret));
            }
        }
        replaced
    }

    /// Fills in a header, including inside basic auth.
    fn substitute_header(&self, value: &str, host: &str) -> Option<String> {
        if let Some(basic) = value.strip_prefix("Basic ") {
            let decoded = Zeroizing::new(String::from_utf8(STANDARD.decode(basic).ok()?).ok()?);
            let replaced = Zeroizing::new(self.substitute(&decoded, host)?);
            return Some(format!("Basic {}", STANDARD.encode(replaced.as_bytes())));
        }
        self.substitute(value, host)
    }

    /// Hides each secret for `host` as it was sent, and in the forms servers commonly reflect it.
    /// This catches echoes, not a server determined to transform a value, which is why only hosts
    /// you allow ever receive one.
    fn scrubber(&self, host: &str) -> Scrubber {
        let substitutions = self.substitutions();
        let allowed = substitutions.iter().filter(|s| s.hosts.iter().any(|allowed| allowed.eq_ignore_ascii_case(host)));
        Scrubber::new(allowed.flat_map(|s| reflected_forms(&s.secret)).collect::<Vec<_>>())
    }

    /// A certificate for `host`, made on first use and signed by this run's CA.
    fn tls_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut leaves = self.leaves.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(config) = leaves.get(host) {
            return Ok(Arc::clone(config));
        }
        let failed = |_| Error::Hardware("the proxy could not issue a certificate");
        let key = KeyPair::generate().map_err(failed)?;
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(failed)?;
        // Strict clients such as Python 3.13 require these.
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params.signed_by(&key, &self.issuer).map_err(failed)?;
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private)
            .map_err(|_| Error::Hardware("the proxy could not issue a certificate"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        leaves.insert(host.to_owned(), Arc::clone(&config));
        Ok(config)
    }
}

/// Every run of base64 that holds `bytes` wherever they fall in what was encoded. An encoded
/// character can mix in the bytes either side, so the ones at each end are left out.
fn base64_forms(bytes: &[u8], engine: &GeneralPurpose) -> Vec<String> {
    (0..3)
        .filter_map(|offset| {
            let text = engine.encode([&vec![0u8; offset][..], bytes].concat());
            let start = (offset * 8).div_ceil(6);
            let end = text.len() - usize::from(!(offset + bytes.len()).is_multiple_of(3));
            text.get(start..end).filter(|form| form.len() >= MIN_ENCODED_FORM).map(str::to_owned)
        })
        .collect()
}

/// A secret as a server might hand it back: as sent, or run through a common encoding.
pub(super) fn reflected_forms(secret: &str) -> Vec<String> {
    let bytes = secret.as_bytes();
    let hex = crate::store::log::hex(bytes);
    let percent = |keep: &str, upper: bool| {
        let escape = |byte: &u8| match (byte.is_ascii_alphanumeric() || keep.as_bytes().contains(byte), upper) {
            (true, _) => char::from(*byte).to_string(),
            (false, true) => format!("%{byte:02X}"),
            (false, false) => format!("%{byte:02x}"),
        };
        bytes.iter().map(escape).collect::<String>()
    };
    let json = serde_json::to_string(secret).unwrap_or_default();
    let json = json.trim_matches('"').to_owned();
    let html =
        secret.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;").replace('/', "&#x2F;");
    let mut forms = vec![
        secret.to_owned(),
        hex.to_ascii_uppercase(),
        hex,
        percent("", true),
        percent("", false),
        percent("-._~", true),
        percent("-._~", false),
        html,
        json.replace('/', "\\/"),
        json,
    ];
    forms.extend(base64_forms(bytes, &STANDARD_NO_PAD));
    forms.extend(base64_forms(bytes, &URL_SAFE_NO_PAD));
    forms
}

/// A running proxy. Dropping it stops it.
pub struct Proxy {
    pub port: u16,
    pub ca_pem: String,
    task: AbortHandle,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proxy({})", self.port)
    }
}

impl Proxy {
    /// Erases the secrets and stops taking connections, for when the access behind a run ends.
    /// A connection already open has nothing left to substitute.
    pub fn stop(&self) {
        self.task.abort();
        self.shared.substitutions.write().unwrap_or_else(PoisonError::into_inner).clear();
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Makes a CA for one run. Name constraints limit it to the run's own hosts, so even a stolen
/// CA key could not impersonate anything else, and it expires within a day.
fn run_ca(substitutions: &[Substitution]) -> Result<(String, Issuer<'static, KeyPair>)> {
    let failed = |_| Error::Hardware("the proxy could not create its CA");
    let mut hosts: Vec<String> = substitutions.iter().flat_map(|s| s.hosts.clone()).collect();
    hosts.sort();
    hosts.dedup();

    let key = KeyPair::generate().map_err(failed)?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "vlt run");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints =
        Some(NameConstraints { permitted_subtrees: hosts.into_iter().map(GeneralSubtree::DnsName).collect(), excluded_subtrees: Vec::new() });
    let now = std::time::SystemTime::now();
    params.not_before = (now - std::time::Duration::from_secs(300)).into();
    params.not_after = (now + std::time::Duration::from_hours(24)).into();

    let certificate = params.self_signed(&key).map_err(failed)?;
    Ok((certificate.pem(), Issuer::new(params, key)))
}

/// The certificate a test's fake upstream is signed by, when there is one.
fn test_upstream_ca(home: &Path) -> Option<CertificateDer<'static>> {
    if cfg!(feature = "test-hooks") { std::fs::read(home.join("test-upstream-ca")).ok().map(Into::into) } else { None }
}

pub(super) fn upstream_tls(test_ca: Option<CertificateDer<'static>>) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Hardware("TLS setup failed"))?;
    let mut config = if let Some(ca) = test_ca {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).map_err(|_| Error::Hardware("bad test CA"))?;
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let verifier = rustls_platform_verifier::Verifier::new(provider).map_err(|_| Error::Hardware("the system trust store is unavailable"))?;
        builder.dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn start(runtime: &Handle, home: &Path, substitutions: Vec<Substitution>) -> Result<Proxy> {
    let (ca_pem, issuer) = run_ca(&substitutions)?;
    let test_ca = test_upstream_ca(home);
    let local_upstream = test_ca.is_some();
    let shared = Arc::new(Shared {
        substitutions: RwLock::new(substitutions),
        issuer,
        leaves: Mutex::default(),
        upstream: upstream_tls(test_ca)?,
        local_upstream,
    });
    let listener = runtime.block_on(TcpListener::bind(("127.0.0.1", 0)))?;
    let port = listener.local_addr()?.port();
    let task = runtime.spawn(accept(listener, Arc::clone(&shared))).abort_handle();
    Ok(Proxy { port, ca_pem, task, shared })
}

async fn accept(listener: TcpListener, shared: Arc<Shared>) {
    while let Ok((stream, _)) = listener.accept().await {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let service = service_fn(move |request| connect(request, Arc::clone(&shared)));
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).with_upgrades().await;
        });
    }
}

fn empty(status: StatusCode) -> Reply {
    let mut reply = Response::new(Empty::new().map_err(|never: Infallible| match never {}).boxed());
    *reply.status_mut() = status;
    reply
}

/// Only HTTPS comes through here: `HTTP_PROXY` is left unset, so nothing secret can go in clear.
#[allow(clippy::unused_async, reason = "hyper's service_fn takes a future")]
async fn connect(request: Request<Incoming>, shared: Arc<Shared>) -> Result<Reply, Infallible> {
    if request.method() != Method::CONNECT {
        return Ok(empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Some(authority) = request.uri().authority().cloned() else { return Ok(empty(StatusCode::BAD_REQUEST)) };
    let host = authority.host().to_owned();
    let port = authority.port_u16().unwrap_or(INTERCEPTED_PORT);
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(request).await else { return };
        let client = TokioIo::new(upgraded);
        if shared.intercepts(&host, port) {
            intercept(client, host, port, shared).await;
        } else {
            tunnel(client, &host, port).await;
        }
    });
    Ok(empty(StatusCode::OK))
}

async fn tunnel(mut client: TokioIo<hyper::upgrade::Upgraded>, host: &str, port: u16) {
    if let Ok(mut server) = TcpStream::connect((host, port)).await {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    }
}

/// Where a request is going, as the proxy decided from `CONNECT`, whatever the request itself says.
#[derive(Debug, Clone)]
struct Destination {
    host: String,
    port: u16,
}

impl Destination {
    fn authority(&self) -> String {
        if self.port == INTERCEPTED_PORT { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }
}

async fn intercept(client: TokioIo<hyper::upgrade::Upgraded>, host: String, port: u16, shared: Arc<Shared>) {
    let Ok(config) = shared.tls_for(&host) else { return };
    let Ok(tls) = TlsAcceptor::from(config).accept(client).await else { return };
    let upstream: Upstream = Arc::default();
    let destination = Destination { host, port };
    let service = service_fn(move |request| forward(request, destination.clone(), Arc::clone(&upstream), Arc::clone(&shared)));
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await;
}

/// Whether a header is one that carries a credential. Nothing else is filled in, and never the URL:
/// the program chooses where a placeholder goes, and on an honest API a URL can be a place that
/// keeps what it is given and shows it to others, like a file name in a public repository.
fn carries_a_credential(name: &HeaderName) -> bool {
    name == AUTHORIZATION || name == COOKIE || ["key", "token", "secret"].iter().any(|word| name.as_str().contains(word))
}

/// Points a request at `destination`, whatever it said: with the secret in hand, a `Host` header
/// or a full URL naming someone else would reach another site on the same server or CDN. Then
/// fills in placeholders.
fn rewrite(request: &mut Request<Incoming>, destination: &Destination, shared: &Shared) {
    let host = destination.host.as_str();
    for (_, value) in request.headers_mut().iter_mut().filter(|(name, _)| carries_a_credential(name)) {
        let Some(replaced) = value.to_str().ok().and_then(|text| shared.substitute_header(text, host)) else { continue };
        if let Ok(mut header) = HeaderValue::from_str(&replaced) {
            header.set_sensitive(true);
            *value = header;
        }
    }
    if let Some(uri) = request.uri().path_and_query().and_then(|path| path.as_str().parse::<Uri>().ok()) {
        *request.uri_mut() = uri;
    }
    let headers = request.headers_mut();
    // Scrubbing needs to see plain bytes, and whole ones: a slice at a time no secret is complete.
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    for name in [RANGE, IF_RANGE, FORWARDED, HeaderName::from_static("x-forwarded-host"), HeaderName::from_static("x-original-url")] {
        headers.remove(name);
    }
    if let Ok(value) = HeaderValue::from_str(&destination.authority()) {
        headers.insert(HOST, value);
    }
}

/// Whether the scrubber could read this reply. Servers usually honor `identity`, and one that does
/// not gets a refusal: its bytes would go past the scrubber unread.
fn is_readable(headers: &HeaderMap) -> bool {
    let plain = |value: &HeaderValue, allowed: &str| value.to_str().is_ok_and(|text| text.trim().eq_ignore_ascii_case(allowed));
    headers.get_all(CONTENT_ENCODING).iter().all(|value| plain(value, "identity"))
        && headers.get_all(TRANSFER_ENCODING).iter().all(|value| plain(value, "chunked"))
}

/// Takes secrets out of what a server said about its reply. A redirect or a cookie that quotes a
/// request is as much an echo as a body that does.
fn scrub_headers(headers: &mut HeaderMap, scrubber: &mut Scrubber) {
    for value in headers.values_mut() {
        let mut clean = scrubber.push(value.as_bytes());
        clean.extend(scrubber.finish());
        if clean != value.as_bytes() {
            *value = HeaderValue::from_bytes(&clean).unwrap_or(HeaderValue::from_static("[hidden by vlt]"));
        }
    }
}

async fn open_upstream(host: &str, port: u16, shared: &Shared) -> Option<SendRequest<Incoming>> {
    let stream = TcpStream::connect((if shared.local_upstream { "127.0.0.1" } else { host }, port)).await.ok()?;
    let name = ServerName::try_from(host.to_owned()).ok()?;
    let tls = TlsConnector::from(Arc::clone(&shared.upstream)).connect(name, stream).await.ok()?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.ok()?;
    tokio::spawn(connection);
    Some(sender)
}

async fn forward(mut request: Request<Incoming>, destination: Destination, upstream: Upstream, shared: Arc<Shared>) -> Result<Reply, Infallible> {
    // In this order: a run stopping in between then costs the secret, never the scrubbing.
    let mut scrubber = shared.scrubber(&destination.host);
    rewrite(&mut request, &destination, &shared);
    let Destination { host, port } = destination;

    let mut slot = upstream.lock().await;
    let ready = match slot.as_mut() {
        Some(sender) => sender.ready().await.is_ok(),
        None => false,
    };
    if !ready {
        *slot = open_upstream(&host, port, &shared).await;
    }
    let Some(sender) = slot.as_mut() else { return Ok(empty(StatusCode::BAD_GATEWAY)) };
    let Ok(response) = sender.send_request(request).await else { return Ok(empty(StatusCode::BAD_GATEWAY)) };
    drop(slot);

    // Past an upgrade the bytes are not HTTP, so nothing could be scrubbed from them.
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Ok(empty(StatusCode::BAD_GATEWAY));
    }

    let (mut parts, body) = response.into_parts();
    if !is_readable(&parts.headers) {
        return Ok(empty(StatusCode::BAD_GATEWAY));
    }
    // Scrubbing can change the length, so the response goes out chunked.
    parts.headers.remove(CONTENT_LENGTH);
    parts.extensions.remove::<ReasonPhrase>();
    scrub_headers(&mut parts.headers, &mut scrubber);
    Ok(Response::from_parts(parts, ScrubbedBody { inner: body, scrubber, finished: false }.boxed()))
}

/// A response body with secret values removed as it streams.
struct ScrubbedBody {
    inner: Incoming,
    scrubber: Scrubber,
    finished: bool,
}

impl Body for ScrubbedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = &mut *self;
        loop {
            if this.finished {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.finished = true;
                    let rest = this.scrubber.finish();
                    if !rest.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(rest.into()))));
                    }
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers are headers that come late, and nothing a program needs.
                    if let Ok(data) = frame.into_data() {
                        let clean = this.scrubber.push(&data);
                        if !clean.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(clean.into()))));
                        }
                    }
                }
            }
        }
    }
}

/// Mozilla's roots in PEM, plus this run's CA, for tools that replace their whole trust store.
pub fn trust_bundle(ca_pem: &str) -> String {
    let mut bundle = String::from(ca_pem);
    for certificate in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let encoded = STANDARD.encode(AsRef::<[u8]>::as_ref(&CertificateDer::from(certificate.as_ref())));
        bundle.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            bundle.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            bundle.push('\n');
        }
        bundle.push_str("-----END CERTIFICATE-----\n");
    }
    bundle
}
