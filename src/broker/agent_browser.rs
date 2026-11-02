//! The browser an agent drives, reached at a debugging address on this machine. The agent chose
//! that address, so whatever answers there may be hostile: every reply has a fixed allowance, and
//! nothing goes there that the agent may not have.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

use super::browser::{Devtools, Tab};
use crate::fill::Origin;
use crate::{Error, Result};

const DEVTOOLS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DEVTOOLS_BODY: usize = 64 * 1024;
const MAX_DEVTOOLS_REPLY: u64 = 256 * 1024;
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one read waits, so that a wait notices a lock or its deadline.
const POLL: Duration = Duration::from_millis(250);
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Page calls held while waiting for a reply. A page can call as often as it likes.
const MAX_HELD: usize = 16;
const GONE: Error = Error::Peer("the agent's browser stopped responding");

fn unreachable(endpoint: &str, error: &std::io::Error) -> Error {
    Error::Unreadable(format!("the agent's browser at {endpoint} could not be reached: {}", crate::error::reason(error)))
}

/// Asks a local debugging endpoint for its socket address. Chrome leaves the connection open,
/// so this reads exactly the advertised length, with a timeout so a bad endpoint cannot stall.
fn devtools_socket(endpoint: &str) -> Result<String> {
    let not_devtools = || Error::Peer("that is not a DevTools address");
    let origin = Origin::parse(endpoint).filter(|origin| origin.scheme == "http");
    let origin = origin.ok_or(Error::Invalid("the agent's browser must be a local DevTools address, like http://127.0.0.1:9222"))?;
    let authority = format!("{}:{}", origin.host, origin.port);
    // What was checked is what is reached, whatever else the address was written to look like.
    let mut stream = TcpStream::connect(&authority).map_err(|error| unreachable(endpoint, &error))?;
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
pub(super) fn locate(endpoint: &str) -> Result<(Origin, String)> {
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

/// A debugging connection to the agent's browser.
#[derive(Debug)]
pub(super) struct AgentBrowser {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    /// Calls from pages that arrived while waiting for a reply, oldest first.
    held: VecDeque<Value>,
}

impl AgentBrowser {
    pub fn connect(endpoint: &str) -> Result<Self> {
        let (origin, url) = locate(endpoint)?;
        let stream = TcpStream::connect((origin.host.as_str(), origin.port)).map_err(|error| unreachable(endpoint, &error))?;
        stream.set_read_timeout(Some(DEVTOOLS_TIMEOUT))?;
        stream.set_write_timeout(Some(DEVTOOLS_TIMEOUT))?;
        let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        let (socket, _) = tungstenite::client::client_with_config(url.as_str(), stream, Some(config))
            .map_err(|_| Error::Peer("the agent's browser refused the connection"))?;
        socket.get_ref().set_read_timeout(Some(POLL))?;
        Ok(Self { socket, next_id: 0, held: VecDeque::new() })
    }

    /// The next message, or none if nothing came within a poll or it was not JSON.
    fn read(&mut self) -> Result<Option<Value>> {
        match self.socket.read() {
            Ok(Message::Text(text)) => Ok(serde_json::from_str(text.as_str()).ok()),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(error)) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(None),
            Err(_) => Err(GONE),
        }
    }

    fn hold(&mut self, message: Value) {
        if message["method"] == "Runtime.bindingCalled" && self.held.len() < MAX_HELD {
            self.held.push_back(message);
        }
    }

    /// Attaches to a tab whose page `fits`, by the address the browser gives for it.
    pub fn tab(&mut self, site: &str, fits: impl Fn(&Origin) -> bool) -> Result<Tab<'_, Self>> {
        let targets = self.call("Target.getTargets", &json!({}), None)?;
        let target = targets["targetInfos"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|target| target["type"] == "page" && target["url"].as_str().and_then(Origin::parse).is_some_and(|origin| fits(&origin)))
            .ok_or_else(|| Error::NotFound(format!("a page on {site} in the agent's browser")))?;
        let attached = self.call("Target.attachToTarget", &json!({ "targetId": target["targetId"], "flatten": true }), None)?;
        let session = attached["sessionId"].as_str().ok_or(GONE)?.to_owned();
        Ok(Tab { browser: self, session })
    }

    /// Waits for a page in `session` to call `binding`, and returns what it sent, or none by
    /// `deadline`. Stops as soon as `may_go_on` says to.
    pub fn called(&mut self, session: &str, binding: &str, deadline: Instant, may_go_on: &dyn Fn() -> Result<()>) -> Result<Option<String>> {
        loop {
            let ours = |message: &Value| message["sessionId"] == session && message["params"]["name"] == binding;
            if let Some(index) = self.held.iter().position(ours) {
                let message = self.held.remove(index).unwrap_or_default();
                return Ok(Some(message["params"]["payload"].as_str().unwrap_or_default().to_owned()));
            }
            may_go_on()?;
            if Instant::now() > deadline {
                return Ok(None);
            }
            if let Some(message) = self.read()? {
                self.hold(message);
            }
        }
    }
}

impl Devtools for AgentBrowser {
    fn call(&mut self, method: &str, params: &Value, session: Option<&str>) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        self.socket.send(Message::text(message.to_string())).map_err(|_| GONE)?;
        let deadline = Instant::now() + CALL_TIMEOUT;
        while Instant::now() < deadline {
            let Some(reply) = self.read()? else { continue };
            if reply["id"] == id {
                return if reply.get("error").is_some() { Err(Error::Peer("the agent's browser refused that")) } else { Ok(reply["result"].clone()) };
            }
            self.hold(reply);
        }
        Err(GONE)
    }
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
