//! Ending a process: whether this person may, asked of the process's own
//! descriptor the way the kernel will ask it, and doing it through a pidfd so
//! that a PID reused in between can never be the one ended.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use peios::access::AccessCheck;
use peios::file::{SecInfo, fd_get_sd};
use peios::process::{Process, ProcessAccess};
use peios::security::{AccessMask, Privileges};
use peios::token::{Token, TokenAccess};

/// A handle on one process for as long as it is held, whatever happens to its
/// PID.
pub fn pidfd(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a PID and flags and returns a new descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor pidfd_open just made, owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Send `signal` to the process `pidfd` holds.
pub fn signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: a live pidfd, a signal number, no siginfo, no flags.
    let ret = unsafe {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), signal, std::ptr::null::<libc::siginfo_t>(), 0)
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Whether this person may end the process `pid`, or why not, in words.
///
/// The kernel decides by the process's descriptor, then whether the caller's
/// PIP reaches it, with an enabled SeDebugPrivilege standing in for the
/// descriptor. The same is asked here: a protected process is closed to a
/// program that isn't signed, the descriptor is checked as this person, and
/// SeDebugPrivilege is looked for in their token.
pub fn may_end(pid: u32, protected: bool, kernel: bool) -> Result<(), String> {
    if kernel {
        return Err("A kernel thread can't be ended.".into());
    }
    if protected {
        return Err("It is protected: only processes signed at its level may end it.".into());
    }
    let fd = pidfd(pid).map_err(|_| "It has ended, or you may not see it.".to_string())?;
    let debugging = Token::open_self(false, TokenAccess::QUERY)
        .and_then(|token| token.privileges())
        .is_ok_and(|privileges| privileges.enabled.contains(Privileges::DEBUG));
    let descriptor = match fd_get_sd(fd.as_fd(), SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL) {
        Ok(descriptor) => descriptor,
        Err(_) if debugging => return Ok(()),
        Err(_) => return Err("Its permissions don't let you end it.".into()),
    };
    let allowed = AccessCheck::new(
        &descriptor,
        AccessMask::from_bits_retain(ProcessAccess::TERMINATE.bits()),
        Process::generic_mapping(),
    )
    .check()
    .is_ok_and(|decision| decision.allowed);
    if allowed || debugging {
        Ok(())
    } else {
        Err("Its permissions don't let you end it.".into())
    }
}
