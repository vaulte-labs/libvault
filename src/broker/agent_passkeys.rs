//! Passkeys in an agent's browser. The broker answers the page's `navigator.credentials` itself,
//! as the extension does for a person, so a passkey is the vault's own and its private key never
//! enters that browser: the page gets the public half or a signature. Each one takes a touch.

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};

use super::Broker;
use super::agent_browser::AgentBrowser;
use super::browser::Tab;
use super::handlers::space_name;
use super::policy::Caller;
use crate::fill::{Origin, matches};
use crate::ids::SpaceId;
use crate::items::Summary;
use crate::passkey;
use crate::protocol::{PasskeyRequest, Response};
use crate::{Error, Result};

const BINDING: &str = "lvPasskey";
/// Long enough for the agent to reach the page's passkey button and a person to approve.
const WAIT: Duration = Duration::from_secs(120);
const NEVER_ASKED: Error = Error::NeedsPerson("nothing on the page asked for a passkey in time. Click its passkey button while this waits");

/// Runs in the page's own world, which is the only place that can answer `navigator.credentials`.
/// It holds nothing and decides nothing; the page could do all of this itself.
const HOOK: &str = r"(() => {
  if (globalThis.lvAnswer) return;
  const credentials = navigator.credentials;
  const b64 = (data) => { const view = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength); let text = ''; for (const byte of view) text += String.fromCharCode(byte); return btoa(text); };
  const url = (text) => text.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  const bytes = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0)).buffer;
  const waiting = new Map();
  let asked = 0;
  globalThis.lvAnswer = (id, answer) => { waiting.get(id)?.(answer); waiting.delete(id); };
  globalThis.lvRestore = () => { delete credentials.create; delete credentials.get; delete globalThis.lvAnswer; };
  const ask = async (request) => {
    const id = ++asked;
    const answer = await new Promise((resolve) => { waiting.set(id, resolve); globalThis.lvPasskey(JSON.stringify({ id, ...request })); });
    if (answer.error) throw new DOMException(answer.error, 'NotAllowedError');
    return answer;
  };
  const made = (answer, response, json) => {
    const rawId = bytes(answer.credential_id), id = url(answer.credential_id);
    const field = (value) => ({ value, enumerable: true });
    return Object.create(PublicKeyCredential.prototype, {
      id: field(id), rawId: field(rawId), type: field('public-key'), authenticatorAttachment: field('platform'), response: field(response),
      getClientExtensionResults: { value: () => ({}) },
      toJSON: { value: () => ({ id, rawId: id, type: 'public-key', authenticatorAttachment: 'platform', response: json, clientExtensionResults: {} }) },
    });
  };
  const field = (value) => ({ value, enumerable: true });
  Object.defineProperty(credentials, 'create', { configurable: true, value: async (options) => {
    const key = options?.publicKey;
    if (!key) return Object.getPrototypeOf(credentials).create.call(credentials, options);
    if (!key.pubKeyCredParams.some((parameter) => parameter.alg === -7)) throw new DOMException('Only ES256 passkeys can be made here.', 'NotSupportedError');
    const answer = await ask({ kind: 'create', challenge: url(b64(key.challenge)), rp_id: key.rp.id ?? location.hostname, user_name: key.user.name, user_handle: b64(key.user.id), exclude: (key.excludeCredentials ?? []).map((c) => b64(c.id)) });
    const [clientDataJSON, attestationObject, authenticatorData, publicKey] = [answer.client_data, answer.attestation_object, answer.authenticator_data, answer.public_key].map(bytes);
    const response = Object.create(AuthenticatorAttestationResponse.prototype, {
      clientDataJSON: field(clientDataJSON), attestationObject: field(attestationObject),
      getAuthenticatorData: { value: () => authenticatorData }, getPublicKey: { value: () => publicKey },
      getPublicKeyAlgorithm: { value: () => -7 }, getTransports: { value: () => ['internal'] },
    });
    return made(answer, response, { clientDataJSON: url(answer.client_data), attestationObject: url(answer.attestation_object), authenticatorData: url(answer.authenticator_data), publicKey: url(answer.public_key), publicKeyAlgorithm: -7, transports: ['internal'] });
  } });
  Object.defineProperty(credentials, 'get', { configurable: true, value: async (options) => {
    const key = options?.publicKey;
    if (!key) return Object.getPrototypeOf(credentials).get.call(credentials, options);
    const answer = await ask({ kind: 'get', challenge: url(b64(key.challenge)), allow: (key.allowCredentials ?? []).map((c) => b64(c.id)) });
    const [clientDataJSON, authenticatorData, signature, userHandle] = [answer.client_data, answer.authenticator_data, answer.signature, answer.user_handle].map(bytes);
    const response = Object.create(AuthenticatorAssertionResponse.prototype, {
      clientDataJSON: field(clientDataJSON), authenticatorData: field(authenticatorData), signature: field(signature), userHandle: field(userHandle),
    });
    return made(answer, response, { clientDataJSON: url(answer.client_data), authenticatorData: url(answer.authenticator_data), signature: url(answer.signature), userHandle: url(answer.user_handle) });
  } });
})()";

/// What the page asked for. Byte strings are standard base64, as the page sends them.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Ask {
    Create { challenge: String, rp_id: String, user_name: String, user_handle: String, exclude: Vec<String> },
    Get { challenge: String, allow: Vec<String> },
}

#[derive(Debug, Deserialize)]
struct PageCall {
    id: u64,
    #[serde(flatten)]
    ask: Ask,
}

fn decode(text: &str) -> Result<Vec<u8>> {
    STANDARD.decode(text).map_err(|_| Error::Invalid("the page sent something that is not base64"))
}

/// What the browser hashes and the site checks: the ceremony, the site's challenge and the page's
/// origin, which comes from the browser.
fn client_data(kind: &str, challenge: &str, origin: &Origin) -> String {
    json!({ "type": kind, "challenge": challenge, "origin": origin.to_string(), "crossOrigin": false }).to_string()
}

/// Hooks the page, has `answer` reply to each call until one finishes, and unhooks. A call
/// `answer` has no reply for gets a refusal, and the wait goes on.
fn on_page<T>(
    tab: &mut Tab<'_, AgentBrowser>,
    may_go_on: &dyn Fn() -> Result<()>,
    mut answer: impl FnMut(&Origin, Ask) -> Result<Option<(Value, T)>>,
) -> Result<T> {
    tab.call("Runtime.addBinding", &json!({ "name": BINDING }))?;
    let script = tab.call("Page.addScriptToEvaluateOnNewDocument", &json!({ "source": HOOK }))?;
    tab.call("Runtime.evaluate", &json!({ "expression": HOOK }))?;
    let outcome = answer_calls(tab, may_go_on, &mut answer);
    let _ = tab.call("Page.removeScriptToEvaluateOnNewDocument", &json!({ "identifier": script["identifier"] }));
    let _ = tab.call("Runtime.evaluate", &json!({ "expression": "globalThis.lvRestore?.()" }));
    outcome
}

fn answer_calls<T>(
    tab: &mut Tab<'_, AgentBrowser>,
    may_go_on: &dyn Fn() -> Result<()>,
    answer: &mut impl FnMut(&Origin, Ask) -> Result<Option<(Value, T)>>,
) -> Result<T> {
    let deadline = Instant::now() + WAIT;
    loop {
        let session = tab.session.clone();
        let payload = tab.browser.called(&session, BINDING, deadline, may_go_on)?.ok_or(NEVER_ASKED)?;
        // The page can call this too, with anything it likes.
        let Ok(PageCall { id, ask }) = serde_json::from_str(&payload) else { continue };
        let origin = Origin::parse(&tab.url()?).ok_or(Error::Invalid("the page has no origin"))?;
        let (reply, outcome) = match answer(&origin, ask) {
            Ok(Some((reply, done))) => (reply, Some(Ok(done))),
            Ok(None) => (json!({ "error": "Vaulte is waiting for something else." }), None),
            Err(error) => (json!({ "error": error.to_string() }), Some(Err(error))),
        };
        tab.call("Runtime.evaluate", &json!({ "expression": format!("globalThis.lvAnswer?.({id}, {reply})") }))?;
        if let Some(outcome) = outcome {
            return outcome;
        }
    }
}

impl Broker {
    /// Makes a passkey when the page on `site` asks for one, after a touch, and returns its name.
    pub(super) fn sign_up_with_passkey(&self, caller: &Caller, space: Option<&str>, site: &Origin, into: &str) -> Result<String> {
        let may_go_on = self.while_open(caller)?;
        let mut browser = AgentBrowser::connect(into)?;
        let mut tab = browser.tab(&site.host, |page| matches(&site.to_string(), page))?;
        on_page(&mut tab, &may_go_on, |page, ask| {
            let Ask::Create { challenge, rp_id, user_name, user_handle, exclude } = ask else { return Ok(None) };
            let request = PasskeyRequest {
                space: space.map(str::to_owned),
                origin: page.to_string(),
                rp_id,
                user_name,
                user_handle: decode(&user_handle)?,
                exclude: exclude.iter().map(|id| decode(id)).collect::<Result<_>>()?,
            };
            let Response::NewPasskey(created) = self.create_passkey(caller, &request)? else { return Err(Error::Peer("no passkey was made")) };
            let reply = json!({
                "client_data": STANDARD.encode(client_data("webauthn.create", &challenge, page)),
                "credential_id": STANDARD.encode(&created.credential_id),
                "attestation_object": STANDARD.encode(&created.attestation_object),
                "authenticator_data": STANDARD.encode(&created.authenticator_data),
                "public_key": STANDARD.encode(&created.public_key),
            });
            Ok(Some((reply, created.name)))
        })
    }

    /// Signs the page's sign-in with a saved passkey, after a touch naming it and the site. The
    /// site's session lands in the agent's browser on its own.
    pub(super) fn sign_in_with_passkey(&self, caller: &Caller, space: &SpaceId, item: &Summary, into: &str) -> Result<Response> {
        let may_go_on = self.while_open(caller)?;
        let (space, secret) = {
            let core = self.open_core()?;
            (space_name(&core.vault, space), core.vault.secret(space, &item.id)?)
        };
        let credential_id = passkey::credential_id(&secret).ok_or(Error::Invalid("that is not a passkey"))?;
        let site = item.meta.urls.first().and_then(|url| Origin::parse(url)).ok_or(Error::Invalid("that passkey has no site saved"))?;
        self.open_core()?.vault.record("login", &item.meta.name, caller.name())?;
        let mut browser = AgentBrowser::connect(into)?;
        let mut tab = browser.tab(&site.host, |page| passkey::fits(&site.host, page))?;
        on_page(&mut tab, &may_go_on, |page, ask| {
            let Ask::Get { challenge, allow } = ask else { return Ok(None) };
            if !allow.is_empty() && !allow.iter().any(|id| decode(id).is_ok_and(|id| id == credential_id)) {
                return Err(Error::NotApproved("the site asked for another passkey"));
            }
            let data = client_data("webauthn.get", &challenge, page);
            let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data.as_bytes());
            let Response::PasskeyAssertion(signed) = self.sign_passkey(caller, &space, &item.meta.name, &page.to_string(), hash.as_ref())? else {
                return Err(Error::Peer("nothing was signed"));
            };
            let reply = json!({
                "client_data": STANDARD.encode(&data),
                "credential_id": STANDARD.encode(&signed.credential_id),
                "authenticator_data": STANDARD.encode(&signed.authenticator_data),
                "signature": STANDARD.encode(&signed.signature),
                "user_handle": STANDARD.encode(&signed.user_handle),
            });
            Ok(Some((reply, Response::LoggedIn { cookies: 0 })))
        })
    }
}
