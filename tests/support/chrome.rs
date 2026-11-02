//! A browser an agent would drive, debuggable over a local port.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tungstenite::Message;

pub const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

pub fn has_browser() -> bool {
    Path::new(CHROME).exists()
}

pub struct AgentBrowser {
    child: Child,
    _profile: tempfile::TempDir,
    pub port: u16,
    path: String,
}

impl AgentBrowser {
    pub fn launch() -> Self {
        Self::launch_at("about:blank")
    }

    /// Opens with one tab at `url`.
    #[allow(clippy::zombie_processes, reason = "Drop waits for it")]
    pub fn launch_at(url: &str) -> Self {
        let profile = tempfile::tempdir().unwrap();
        let child = Command::new(CHROME)
            .args(["--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check"])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let active = profile.path().join("DevToolsActivePort");
        for _ in 0..400 {
            let text = std::fs::read_to_string(&active).unwrap_or_default();
            let mut lines = text.lines();
            if let (Some(Ok(port)), Some(path)) = (lines.next().map(str::parse), lines.next()) {
                return Self { child, _profile: profile, port, path: path.to_owned() };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the agent's browser never opened its port");
    }

    pub fn address(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Calls `method` on the first page, over a connection of its own.
    fn on_page(&self, method: &str, params: &Value) -> Value {
        let (mut socket, _) = tungstenite::connect(format!("ws://127.0.0.1:{}{}", self.port, self.path)).unwrap();
        let mut call = |id: u64, method: &str, params: Value, session: Option<&str>| {
            let mut message = json!({ "id": id, "method": method, "params": params });
            if let Some(session) = session {
                message["sessionId"] = json!(session);
            }
            socket.send(Message::text(message.to_string())).unwrap();
            loop {
                if let Message::Text(text) = socket.read().unwrap() {
                    let reply: Value = serde_json::from_str(text.as_str()).unwrap();
                    if reply["id"] == id {
                        return reply["result"].clone();
                    }
                }
            }
        };
        let targets = call(1, "Target.getTargets", json!({}), None);
        let page = targets["targetInfos"].as_array().unwrap().iter().find(|target| target["type"] == "page").unwrap().clone();
        let session = call(2, "Target.attachToTarget", json!({ "targetId": page["targetId"], "flatten": true }), None);
        call(3, method, params.clone(), session["sessionId"].as_str())
    }

    /// Runs `expression` in the page as the page itself would, and waits for any promise.
    pub fn evaluate(&self, expression: &str) -> Value {
        let result = self.on_page("Runtime.evaluate", &json!({ "expression": expression, "awaitPromise": true, "returnByValue": true }));
        result["result"]["value"].clone()
    }

    /// Waits until `expression` is true on the page.
    pub fn wait_for(&self, expression: &str) {
        for _ in 0..400 {
            if self.evaluate(expression) == json!(true) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("never true: {expression}");
    }

    pub fn cookies(&self) -> String {
        let (mut socket, _) = tungstenite::connect(format!("ws://127.0.0.1:{}{}", self.port, self.path)).unwrap();
        socket.send(Message::text(r#"{"id":1,"method":"Storage.getCookies"}"#)).unwrap();
        loop {
            if let Message::Text(text) = socket.read().unwrap() {
                let reply: Value = serde_json::from_str(text.as_str()).unwrap();
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
    }
}
