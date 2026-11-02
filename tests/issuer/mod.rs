//! Stands in for the account service Vaulte runs, speaking the same JSON, so a relay that asks for
//! passes can be tested with nothing but this machine. The real one is a Cloudflare Worker.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use blind_rsa_signatures::{BlindMessage, DefaultRng, KeyPairSha384PSSRandomized};
use libvault::RelayIssuer;
use serde_json::{Value, json};

pub struct Issuer {
    pub url: String,
    root: Arc<Ed25519KeyPair>,
    paid: Arc<Mutex<BTreeSet<String>>>,
}

impl Issuer {
    pub fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let root = Arc::new(Ed25519KeyPair::generate().unwrap());
        let paid = Arc::new(Mutex::new(BTreeSet::new()));
        let keys = Arc::new(KeyPairSha384PSSRandomized::generate(&mut DefaultRng, 2048).unwrap());
        let (serving_root, serving_paid) = (Arc::clone(&root), Arc::clone(&paid));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = answer(stream, &serving_root, &keys, &serving_paid);
            }
        });
        Self { url, root, paid }
    }

    pub fn issuer(&self) -> RelayIssuer {
        let root: Vec<String> = self.root.public_key().as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
        RelayIssuer { url: self.url.clone(), root: root.concat() }
    }

    pub fn pay(&self, account: &str) {
        self.paid.lock().unwrap().insert(account.to_owned());
    }
}

fn answer(stream: TcpStream, root: &Ed25519KeyPair, keys: &KeyPairSha384PSSRandomized, paid: &Mutex<BTreeSet<String>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let path = line.split_whitespace().nth(1).unwrap_or_default().to_owned();
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header.trim().is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let asked: Value = serde_json::from_slice(&body).unwrap_or_default();
    let month = libvault::relay::pass::Month::now().month;
    let (status, reply) = match path.as_str() {
        "/key" => {
            let key = keys.pk.to_der().unwrap();
            let cert = root.sign(&libvault::relay::pass::key_statement(month, &key));
            (200, json!({ "month": month, "key": STANDARD.encode(&key), "cert": STANDARD.encode(cert.as_ref()) }))
        }
        "/accounts" => (200, json!({ "account": "1111 2222 3333 4444" })),
        "/passes" if !paid.lock().unwrap().contains(asked["account"].as_str().unwrap_or_default()) => (402, json!({})),
        "/passes" => {
            let blinded = BlindMessage(STANDARD.decode(asked["blinded"].as_str().unwrap()).unwrap());
            (200, json!({ "signature": STANDARD.encode(keys.sk.blind_sign(&blinded).unwrap().0) }))
        }
        "/status" => (200, json!({ "paid_until": 4_000_000_000_u64 })),
        "/checkout" => (200, json!({ "url": "https://checkout.example/pay" })),
        _ => (404, json!({})),
    };
    let reply = reply.to_string();
    let mut stream = stream;
    write!(stream, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len())
}
