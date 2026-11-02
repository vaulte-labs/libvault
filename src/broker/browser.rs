//! A browser the broker drives and nothing else can reach. It runs with
//! `--remote-debugging-pipe`, so there is no port for another process to attach to, and a
//! throwaway profile that is erased when it closes.

use std::io::{BufRead, BufReader, PipeWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::{Error, Result};

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_MESSAGE: u64 = 16 * 1024 * 1024;
const NO_BROWSER: Error = Error::Peer("no Chromium-based browser found. Install Chrome");
const FAILED: Error = Error::Peer("the sign-in browser stopped responding");

/// Browsers to try, in order. There is no setting for this, in a file or the environment: whatever
/// runs here receives passwords, and anything running as this user could change a setting.
#[cfg(target_os = "macos")]
const KNOWN: &[&str] = &[
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
];
#[cfg(not(target_os = "macos"))]
const KNOWN: &[&str] = &["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];

/// Whether a browser is what its path says. On a machine where this user is an admin, the path
/// alone proves nothing, and whatever is there is about to be typed a password. Anything signed by
/// a developer Apple has identified passes, which is the bar a replaced Chrome would have to clear.
/// Strict about symlinks, not about Finder metadata: copying a genuine Chrome can leave a
/// `com.apple.FinderInfo` attribute on it, which carries no code and would fail a plain `--strict`.
#[cfg(target_os = "macos")]
fn is_genuine(path: &Path) -> bool {
    let bundle = path.ancestors().find(|folder| folder.extension().is_some_and(|extension| extension == "app")).unwrap_or(path);
    let verified = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict=symlinks", "-R=anchor apple generic"])
        .arg(bundle)
        .stderr(Stdio::null())
        .status();
    verified.is_ok_and(|status| status.success())
}

#[cfg(not(target_os = "macos"))]
fn is_genuine(path: &Path) -> bool {
    path.exists()
}

fn find_browser() -> Result<PathBuf> {
    let found = KNOWN.iter().map(Path::new).find(|path| path.exists()).ok_or(NO_BROWSER)?;
    if is_genuine(found) {
        Ok(found.to_path_buf())
    } else {
        Err(Error::Peer("the browser here is not signed as it should be, so it gets no password"))
    }
}

#[derive(Debug)]
pub(super) struct Browser {
    child: Child,
    writer: PipeWriter,
    replies: Receiver<Value>,
    next_id: u64,
    profile: PathBuf,
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// Hands on each message from the browser. What a page does can grow a message without limit, so
/// one that outgrows anything asked for here ends the conversation.
fn read_messages(reader: impl Read, sender: &mpsc::Sender<Value>) {
    let mut reader = BufReader::new(reader);
    let mut message = Vec::new();
    while (&mut reader).take(MAX_MESSAGE).read_until(0, &mut message).is_ok_and(|read| read > 0) && message.pop() == Some(0) {
        if !serde_json::from_slice::<Value>(&message).is_ok_and(|value| sender.send(value).is_ok()) {
            return;
        }
        message.clear();
    }
}

/// Something that speaks the debugging protocol: the broker's own browser, or an agent's.
pub(super) trait Devtools {
    /// Calls the browser and returns the result. `session` targets a tab.
    fn call(&mut self, method: &str, params: &Value, session: Option<&str>) -> Result<Value>;
}

impl Browser {
    pub fn launch(profile: PathBuf) -> Result<Self> {
        crate::store::private_dir(&profile)?;
        let mut command = Command::new(find_browser()?);
        command
            .args([
                "--remote-debugging-pipe",
                "--headless=new",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("about:blank")
            // It is about to be typed a password, so it inherits nothing, as `lvd` does not.
            .env_clear()
            .envs(std::env::var_os("HOME").map(|home| ("HOME", home)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (child, reader, writer) = crate::sys::spawn_with_pipes(&mut command)?;
        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || read_messages(reader, &sender));
        Ok(Self { child, writer, replies, next_id: 0, profile })
    }

    /// Opens a tab at `about:blank` and attaches to it.
    pub fn open_tab(&mut self) -> Result<Tab<'_, Self>> {
        let target = self.call("Target.createTarget", &json!({ "url": "about:blank" }), None)?;
        let attached = self.call("Target.attachToTarget", &json!({ "targetId": target["targetId"], "flatten": true }), None)?;
        let session = attached["sessionId"].as_str().ok_or(FAILED)?.to_owned();
        Ok(Tab { browser: self, session })
    }
}

impl Devtools for Browser {
    /// Ignores events.
    fn call(&mut self, method: &str, params: &Value, session: Option<&str>) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        let mut bytes = serde_json::to_vec(&message).map_err(|_| FAILED)?;
        bytes.push(0);
        self.writer.write_all(&bytes).map_err(|_| FAILED)?;

        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let reply = self.replies.recv_timeout(remaining).map_err(|_| FAILED)?;
            if reply["id"] == id {
                return if reply.get("error").is_some() { Err(FAILED) } else { Ok(reply["result"].clone()) };
            }
        }
    }
}

/// One attached tab.
/// Runs on the element itself. The setter is this world's own, so a page cannot have replaced it,
/// and the events are what a framework listens for to notice a value it did not set.
const SET_VALUE: &str = "function (value) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(this, value);
  this.dispatchEvent(new Event('input', { bubbles: true }));
  this.dispatchEvent(new Event('change', { bubbles: true }));
  return 'ok';
}";

const SUBMIT: &str = "(() => {
  const form = (lvFields.password || lvFields.code || lvFields.user || {}).form;
  if (!form) return '';
  form.requestSubmit();
  return 'ok';
})()";

#[derive(Debug)]
pub(super) struct Tab<'a, D: Devtools> {
    pub(super) browser: &'a mut D,
    pub(super) session: String,
}

impl<D: Devtools> Tab<'_, D> {
    pub fn call(&mut self, method: &str, params: &Value) -> Result<Value> {
        self.browser.call(method, params, Some(&self.session))
    }

    pub fn goto(&mut self, url: &str) -> Result<()> {
        self.call("Page.navigate", &json!({ "url": url })).map(drop)
    }

    fn main_frame(&mut self) -> Result<Value> {
        Ok(self.call("Page.getFrameTree", &json!({}))?["frameTree"]["frame"].clone())
    }

    /// Where this tab is, according to the browser. Anything read from inside a page is whatever
    /// that page wants it to be. Read this after `world`, so a page that moved on takes the world
    /// with it, and using the world fails.
    pub fn url(&mut self) -> Result<String> {
        self.main_frame()?["url"].as_str().map(str::to_owned).ok_or(FAILED)
    }

    /// A JavaScript world of this broker's own on the current page: it shares the page's elements
    /// and none of its scripts, so a page cannot replace what runs there. It ends with the page.
    pub fn world(&mut self) -> Result<u64> {
        let frame = self.main_frame()?;
        let world = self.call("Page.createIsolatedWorld", &json!({ "frameId": frame["id"], "worldName": "lv" }))?;
        world["executionContextId"].as_u64().ok_or(FAILED)
    }

    /// Runs a fixed expression and returns its string result. What comes back is treated as data
    /// about that page, never as something to act on beyond what it says about fields.
    pub fn evaluate(&mut self, world: u64, expression: &str) -> Result<String> {
        let result = self.call("Runtime.evaluate", &json!({ "expression": expression, "contextId": world, "returnByValue": true }))?;
        Ok(result["result"]["value"].as_str().unwrap_or_default().to_owned())
    }

    /// Puts a value in a field found in `world`. It goes to that element, by reference, from a
    /// world no page script can reach. Typing would go to whatever holds focus when it lands, and
    /// a page can give that to a frame from another site at any moment. The page's own world sees
    /// the value when it reads the field, as it would if a person had typed it.
    pub fn set_field(&mut self, world: u64, field: &str, value: &str) -> Result<bool> {
        let found = self.call("Runtime.evaluate", &json!({ "expression": format!("lvFields.{field}"), "contextId": world }))?;
        let Some(element) = found["result"]["objectId"].as_str() else { return Ok(false) };
        let call = json!({ "objectId": element, "functionDeclaration": SET_VALUE, "arguments": [{ "value": value }], "returnByValue": true });
        Ok(self.call("Runtime.callFunctionOn", &call)?["result"]["value"].as_str() == Some("ok"))
    }

    /// Submits the form of what was just filled, or presses Enter where there is none. Enter goes
    /// wherever focus is, which is why nothing secret ever does.
    pub fn submit(&mut self, world: u64) -> Result<()> {
        if self.evaluate(world, SUBMIT)? == "ok" { Ok(()) } else { self.press_enter() }
    }

    fn press_enter(&mut self) -> Result<()> {
        let key = json!({ "type": "keyDown", "key": "Enter", "code": "Enter", "text": "\r", "windowsVirtualKeyCode": 13 });
        self.call("Input.dispatchKeyEvent", &key)?;
        self.call("Input.dispatchKeyEvent", &json!({ "type": "keyUp", "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13 })).map(drop)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn a_message_past_the_limit_ends_the_conversation() {
        let mut bytes = b"{\"id\":1}\0\"".to_vec();
        bytes.resize(bytes.len() + usize::try_from(MAX_MESSAGE).unwrap(), b'a');
        bytes.extend(b"\"\0{\"id\":2}\0");
        let (sender, replies) = mpsc::channel();
        read_messages(bytes.as_slice(), &sender);
        drop(sender);
        assert_eq!(replies.iter().collect::<Vec<_>>(), [json!({ "id": 1 })]);
    }

    #[test]
    fn a_program_pretending_to_be_a_browser_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("Google Chrome");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        assert!(!is_genuine(&fake));
        if let Some(chrome) = KNOWN.iter().map(Path::new).find(|path| path.exists()) {
            assert!(is_genuine(chrome));
        }
    }
}
