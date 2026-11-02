//! The only calls into the operating system that need `unsafe`, besides the enclave bridge.
#![allow(unsafe_code)]

use std::ptr::NonNull;

use zeroize::Zeroize;

/// Stops same-user debuggers and core dumps from reading keys out of memory.
#[cfg(feature = "broker")]
pub(crate) fn harden_process() {
    let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `no_core` is a valid rlimit for the duration of the call.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core) };

    #[cfg(target_os = "macos")]
    // SAFETY: PT_DENY_ATTACH takes no pointers and affects only this process.
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }

    #[cfg(target_os = "linux")]
    // SAFETY: takes plain integers and affects only this process.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    ignore_signal(libc::SIGHUP);
}

/// Key bytes, held in memory locked out of swap and erased as they are let go. Locking every page
/// the broker uses would take more than an ordinary user may lock, about 16 MiB against Linux's
/// usual 8, so keys share chunks of their own, which stay far below that.
pub(crate) struct Locked(NonNull<[u8; 32]>);

// SAFETY: a `Locked` alone holds its slot, so it can move or be shared as the array could.
unsafe impl Send for Locked {}
// SAFETY: as above.
unsafe impl Sync for Locked {}

impl Locked {
    pub fn new(bytes: [u8; 32]) -> Self {
        let mut locked = Self(keys::take());
        *locked.get_mut() = bytes;
        locked
    }

    pub fn get(&self) -> &[u8; 32] {
        // SAFETY: the slot is this value's alone from `take` until drop, and always initialized.
        unsafe { self.0.as_ref() }
    }

    pub fn get_mut(&mut self) -> &mut [u8; 32] {
        // SAFETY: as in `get`, and `&mut self` makes this the only reference.
        unsafe { self.0.as_mut() }
    }
}

impl Clone for Locked {
    fn clone(&self) -> Self {
        let mut copy = Self(keys::take());
        copy.get_mut().copy_from_slice(self.get());
        copy
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        self.get_mut().zeroize();
        keys::give(self.0);
    }
}

/// Where `Locked` slots come from. Chunks are never given back, so a slot stays mapped, locked
/// and erased while nobody holds it.
mod keys {
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};

    const SLOT: usize = 32;
    /// Room for 2048 keys, and a whole number of pages on any system.
    const CHUNK: usize = 64 * 1024;

    pub(super) struct Free(pub(super) Vec<NonNull<[u8; SLOT]>>);
    // SAFETY: these slots are held by nobody, so whichever thread takes one owns it.
    unsafe impl Send for Free {}

    pub(super) static FREE: Mutex<Free> = Mutex::new(Free(Vec::new()));
    /// Chunks the system would not lock, which still hold keys, out of swap or not.
    static UNLOCKED: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn take() -> NonNull<[u8; SLOT]> {
        let mut free = FREE.lock().unwrap_or_else(PoisonError::into_inner);
        if free.0.is_empty() {
            grow(&mut free.0);
        }
        free.0.pop().expect("a new chunk has free slots")
    }

    pub(super) fn give(slot: NonNull<[u8; SLOT]>) {
        FREE.lock().unwrap_or_else(PoisonError::into_inner).0.push(slot);
    }

    /// Whether every key so far sits in locked memory.
    #[cfg(test)]
    pub(crate) fn all_locked() -> bool {
        UNLOCKED.load(Ordering::Relaxed) == 0
    }

    fn grow(free: &mut Vec<NonNull<[u8; SLOT]>>) {
        // SAFETY: an anonymous private mapping takes no file, and returns fresh zeroed memory or
        // MAP_FAILED, which is checked.
        let chunk = unsafe { libc::mmap(std::ptr::null_mut(), CHUNK, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
        assert!(chunk != libc::MAP_FAILED, "no memory left for keys");
        // SAFETY: `chunk` is the mapping of CHUNK bytes made just above.
        if unsafe { libc::mlock(chunk, CHUNK) } != 0 {
            UNLOCKED.fetch_add(1, Ordering::Relaxed);
        }
        let base = chunk.cast::<[u8; SLOT]>();
        // SAFETY: every slot lies inside the mapping, which is never unmapped, and mmap never
        // returns null for a request with no address.
        free.extend((0..CHUNK / SLOT).map(|index| unsafe { NonNull::new_unchecked(base.add(index)) }));
    }
}

fn ignore_signal(signal: i32) {
    // SAFETY: ignoring a signal is always valid.
    unsafe { libc::signal(signal, libc::SIG_IGN) };
}

/// Ctrl-C reaches a child through the terminal. Ignoring it here keeps this process, and so the
/// child's proxy, alive while the child exits. Call only after the child has started, because
/// ignored signals are inherited.
pub(crate) fn ignore_interrupt() {
    ignore_signal(libc::SIGINT);
}

/// Starts `command` with a pipe to read on fd 3 and one to write on fd 4, as Chromium's
/// `--remote-debugging-pipe` expects. Returns the child and this side's reader and writer.
#[cfg(feature = "broker")]
pub(crate) fn spawn_with_pipes(
    command: &mut std::process::Command,
) -> std::io::Result<(std::process::Child, std::io::PipeReader, std::io::PipeWriter)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let (child_reads, parent_writes) = std::io::pipe()?;
    let (parent_reads, child_writes) = std::io::pipe()?;
    let (read_fd, write_fd) = (child_reads.as_raw_fd(), child_writes.as_raw_fd());
    // SAFETY: between fork and exec this calls only fcntl and dup2, which are async-signal-safe.
    // Duplicating high first means neither source can be overwritten by the other's target.
    unsafe {
        command.pre_exec(move || {
            let read_high = libc::fcntl(read_fd, libc::F_DUPFD, 10);
            let write_high = libc::fcntl(write_fd, libc::F_DUPFD, 10);
            if read_high < 0 || write_high < 0 || libc::dup2(read_high, 3) < 0 || libc::dup2(write_high, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    Ok((child, parent_reads, parent_writes))
}

/// Which user is on the other end of a local socket.
#[cfg(all(feature = "broker", not(target_os = "linux")))]
pub(crate) fn peer_user(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let (mut user, mut group) = (0, 0);
    // SAFETY: the descriptor is open for the life of `stream`, and both pointers are valid out
    // parameters for the duration of the call.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut user, &raw mut group) };
    (result == 0).then_some(user)
}

/// Which user is on the other end of a local socket.
#[cfg(all(feature = "broker", target_os = "linux"))]
pub(crate) fn peer_user(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut credentials = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>()).ok()?;
    // SAFETY: the descriptor is open for the life of `stream`, and `credentials` and `length` are
    // valid for the size this passes.
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut credentials).cast(), &raw mut length) };
    (result == 0).then_some(credentials.uid)
}

/// The kernel's token for the process on the other end. Unlike a process id, which can be reused,
/// it names that one process for good.
#[cfg(all(feature = "broker", target_os = "macos"))]
pub(crate) fn peer_audit_token(stream: &std::os::unix::net::UnixStream) -> Option<[u8; 32]> {
    use std::os::fd::AsRawFd;
    let mut token = [0u8; 32];
    let mut length = libc::socklen_t::try_from(token.len()).ok()?;
    // SAFETY: the descriptor is open for the life of `stream`, and `token` and `length` are valid
    // for the size this passes.
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN, token.as_mut_ptr().cast(), &raw mut length) };
    (result == 0 && usize::try_from(length) == Ok(token.len())).then_some(token)
}

/// The user this process runs as.
#[cfg(feature = "broker")]
pub(crate) fn this_user() -> u32 {
    // SAFETY: getuid takes nothing and cannot fail.
    unsafe { libc::getuid() }
}

/// A name for this device, used until the person renames it.
pub(crate) fn host_name() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: the pointer and length describe `buffer`, which outlives the call.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len());
    std::str::from_utf8(&buffer[..end]).ok().map(|name| name.trim_end_matches(".local").to_owned())
}

#[cfg(all(test, feature = "broker"))]
mod tests {
    use super::*;

    #[test]
    fn the_other_end_of_a_local_socket_is_known() {
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(peer_user(&ours), Some(this_user()));
    }
}

#[cfg(test)]
mod locked_tests {
    use super::*;

    #[test]
    fn a_key_sits_in_locked_memory_and_is_erased_once_let_go() {
        let key = Locked::new([7; 32]);
        assert_eq!(key.get(), &[7; 32]);
        assert_eq!(key.clone().get(), &[7; 32]);
        assert!(keys::all_locked(), "the system refused to lock a chunk of keys");
        let slot = key.0;
        drop(key);
        // Holding the free list, nothing can take the slot back while it is read.
        let free = keys::FREE.lock().unwrap();
        assert!(free.0.contains(&slot));
        // SAFETY: the slot stays mapped, and the lock keeps anyone else from writing it.
        assert_eq!(unsafe { slot.as_ref() }, &[0; 32]);
    }

    /// Linux reports locked memory, so this checks it from the outside.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_counts_the_keys_as_locked() {
        let _key = Locked::new([1; 32]);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let locked: u64 = status.lines().find_map(|line| line.strip_prefix("VmLck:")).unwrap().trim().trim_end_matches(" kB").trim().parse().unwrap();
        assert!(locked >= 64, "{locked} kB locked");
    }
}
