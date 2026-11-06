//! What `cargo fuzz` calls: every parser that takes bytes from outside, and nothing else. Each takes
//! bytes and returns nothing, so this feature cannot become another way to reach a secret.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::ids::DeviceId;
use crate::{Totp, env_file, fill, import, item, net, protocol, record, scrub, state, store, sync};

pub fn log(data: &[u8]) {
    let parsed = store::log::parse(data);
    assert!(parsed.valid_len <= data.len());
    let whole: Vec<u8> = parsed.entries.iter().flat_map(store::log::Entry::encode).collect();
    assert_eq!(whole, data[..parsed.valid_len], "an entry must have one encoding");
}

pub fn body(data: &[u8]) {
    let Some((kind, bytes)) = data.split_first() else { return };
    if let Ok(body) = record::Body::decode(*kind, bytes) {
        assert_eq!(body.encode(), bytes, "a record must have one encoding");
    }
}

pub fn archive(data: &[u8]) {
    let _ = store::decode_archive(data);
}

fn sample_logs(data: &[u8]) -> BTreeMap<DeviceId, Vec<u8>> {
    BTreeMap::from([(DeviceId::from([1; 16]), data.get(..data.len().min(32)).unwrap_or_default().to_vec())])
}

pub fn tails(data: &[u8]) {
    let _ = sync::exchange::decode_tails(data, &sample_logs(data));
}

pub fn lengths(data: &[u8]) {
    let _ = sync::exchange::decode_lengths(data);
}

pub fn join_request(data: &[u8]) {
    let _ = net::pair::decode_request(data);
}

pub fn ask(data: &[u8]) {
    crate::broker::fuzz_ask(data);
}

pub fn beacon(data: &[u8]) {
    let _ = net::discovery::Beacon::decode(data);
}

pub fn padded_item(data: &[u8]) {
    let _ = item::decode::<item::Meta>(data);
    let _ = item::decode::<item::Secret>(data);
}

pub fn broker_frame(data: &[u8]) {
    let Ok(length) = u32::try_from(data.len()) else { return };
    let mut framed = length.to_le_bytes().to_vec();
    framed.extend_from_slice(data);
    let _ = protocol::read_frame::<protocol::Envelope>(&mut framed.as_slice());
    let _ = protocol::read_frame::<protocol::Response>(&mut framed.as_slice());
}

pub fn origin(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let middle = text.char_indices().map(|(at, _)| at).find(|at| *at >= text.len() / 2).unwrap_or(text.len());
    let (saved, page) = text.split_at(middle);
    if let Some(parsed) = fill::Origin::parse(page) {
        // A login is for its own site and no other owner's: the host it names, or one that shares
        // its registrable domain, never an address.
        if fill::matches(saved, &parsed)
            && let Some(saved) = fill::Origin::parse(saved)
        {
            fn site(host: &str) -> Option<&str> {
                host.parse::<std::net::IpAddr>().is_err().then(|| psl::domain_str(host)).flatten()
            }
            assert!(
                parsed.host == saved.host || site(&parsed.host).is_some_and(|page| site(&saved.host) == Some(page)),
                "{saved:?} matched {parsed:?}"
            );
        }
    }
}

pub fn totp(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(totp) = Totp::parse(text)
    {
        let _ = totp.code(1_700_000_000);
    }
}

pub fn env_file(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = env_file::parse(text);
    }
}

pub fn icon(data: &[u8]) {
    if let Some(icon) = crate::icon_image::saved(data) {
        assert_eq!(icon.rgba.len(), icon.width as usize * icon.height as usize * 4);
    }
    // Whatever a website sends, what comes out is an icon that reads back.
    if let Ok(png) = crate::icon_image::prepare(data) {
        assert!(crate::icon_image::saved(&png).is_some());
    }
}

pub fn apple_passwords(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = import::parse_apple_passwords(text);
    }
}

/// However a secret is split across chunks, it must not come out whole.
pub fn scrubber(data: &[u8]) {
    let Some((split, rest)) = data.split_first() else { return };
    let (secret, stream) = rest.split_at(rest.len().min(usize::from(split & 0x1f)));
    if secret.len() < 2 {
        return;
    }
    let stream = [stream, secret, stream].concat();
    let mut scrub = scrub::Scrubber::new([secret]);
    let mut out = Vec::new();
    for chunk in stream.chunks(usize::from(split >> 5) + 1) {
        out.extend(scrub.push(chunk));
    }
    out.extend(scrub.finish());
    // The marker's own text can sit beside bytes that spell a short secret, as `]` and a byte
    // after it do. That says nothing about the secret, so only an appearance clear of every marker
    // is the secret coming through.
    let markers: Vec<std::ops::Range<usize>> =
        (0..out.len()).filter(|at| out[*at..].starts_with(scrub::REPLACEMENT)).map(|at| at..at + scrub::REPLACEMENT.len()).collect();
    let touches_a_marker = |at: usize| markers.iter().any(|marker| at < marker.end && marker.start < at + secret.len());
    let through = (0..out.len().saturating_sub(secret.len() - 1)).find(|at| out[*at..].starts_with(secret) && !touches_a_marker(*at));
    assert!(through.is_none(), "a secret came through");
}

/// Replays logs of arbitrary bytes. Signatures pass under `cfg(fuzzing)`, so this reaches the rules
/// themselves instead of stopping at the first signature.
pub fn replay(data: &[u8]) {
    let mut logs = Vec::new();
    for (index, part) in data.split(|byte| *byte == 0xfe).enumerate().take(4) {
        let parsed = store::log::parse(part);
        let device = parsed.entries.first().map_or_else(|| DeviceId::from([u8::try_from(index).unwrap_or(0); 16]), |entry| entry.device);
        logs.push((device, parsed));
    }
    if let Ok(first) = state::State::from_logs(&logs) {
        assert_eq!(first.roster_head(), state::State::from_logs(&logs).unwrap().roster_head(), "replay must be deterministic");
    }
}

/// Feeds arbitrary frames to each side of a handshake, as a stranger on the network would.
pub fn noise_frames(data: &[u8]) {
    thread_local!(static LISTENER: TcpListener = TcpListener::bind(("127.0.0.1", 0)).unwrap());
    LISTENER.with(|listener| {
        let Ok(mut stranger) = TcpStream::connect(listener.local_addr().unwrap()) else { return };
        let Ok((stream, _)) = listener.accept() else { return };
        // Closing with a reset leaves nothing behind. Thousands of closes a second would otherwise
        // run the whole machine out of ports.
        for socket in [&stranger, &stream] {
            let _ = socket2::SockRef::from(socket).set_linger(Some(std::time::Duration::ZERO));
        }
        let _ = stranger.write_all(data);
        let _ = stranger.shutdown(std::net::Shutdown::Write);
        let channel = net::channel::Channel::respond(stream, &[7; 32], b"fuzz", None);
        if let Ok(mut channel) = channel {
            let _ = channel.recv(1024);
        }
        let _ = stranger.read(&mut [0u8; 1]);
    });
}
