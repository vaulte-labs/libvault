//! Runs a program with a space's secrets, for any interface that launches things.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};

use crate::scrub::Scrubber;
use crate::{Client, Error, Result};

#[derive(Debug, Default)]
pub struct RunOptions {
    pub space: Option<String>,
    /// Variables to give the program for real, after a touch.
    pub env: Vec<String>,
    /// Gives the real value of every variable that has no allowed host.
    pub env_all: bool,
}

fn scrub_stream(mut from: impl Read + Send + 'static, mut to: impl Write + Send + 'static, secrets: Vec<String>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut scrubber = Scrubber::new(&secrets);
        let mut buffer = [0u8; 8192];
        while let Ok(read @ 1..) = from.read(&mut buffer) {
            if to.write_all(&scrubber.push(&buffer[..read])).is_err() {
                break;
            }
            let _ = to.flush();
        }
        let _ = to.write_all(&scrubber.finish());
    })
}

fn exit_code(status: ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt;
    let code = status.code().or_else(|| status.signal().map(|signal| 128 + signal)).unwrap_or(1);
    u8::try_from(code).unwrap_or(1)
}

/// Runs `command` and returns its exit code. The proxy lives exactly as long as this call:
/// the broker tears it down when this client disconnects, however that happens.
pub fn run(client: &mut Client, command: &[OsString], options: &RunOptions) -> Result<u8> {
    let (program, arguments) = command.split_first().ok_or(Error::Usage("nothing to run"))?;
    let display = program.to_string_lossy().rsplit('/').next().unwrap_or_default().to_owned();
    let (env, scrub) = client.start_run(options.space.as_deref(), &display, &options.env, options.env_all)?;

    let mut child = Command::new(program);
    child.args(arguments).envs(env.iter().map(|(name, value)| (name, value)));
    let not_started =
        |error: std::io::Error| Error::Unreadable(format!("{} could not be started: {}", program.to_string_lossy(), crate::error::reason(&error)));
    let code = if scrub.is_empty() {
        let mut child = child.spawn().map_err(not_started)?;
        crate::sys::ignore_interrupt();
        exit_code(child.wait()?)
    } else {
        let mut child = child.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(not_started)?;
        crate::sys::ignore_interrupt();
        let stdout = child.stdout.take().map(|stream| scrub_stream(stream, std::io::stdout(), scrub.clone()));
        let stderr = child.stderr.take().map(|stream| scrub_stream(stream, std::io::stderr(), scrub.clone()));
        let status = child.wait()?;
        for reader in [stdout, stderr].into_iter().flatten() {
            let _ = reader.join();
        }
        exit_code(status)
    };
    Ok(code)
}
