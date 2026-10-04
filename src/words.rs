//! What Task Manager says, in words a person reads.

use peinit::client::{ServicePart, State};
use peios::process::{Mitigations, Psb};
use peios::security::IntegrityLevel;

use crate::procs::Closed;

/// A count of bytes, as memory is read: in the largest unit it makes sense in.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// A CPU share, in percent.
pub fn share(percent: f64) -> String {
    if percent < 0.05 {
        "0%".into()
    } else if percent < 10.0 {
        format!("{percent:.1}%")
    } else {
        format!("{percent:.0}%")
    }
}

/// How long something has run, from seconds.
pub fn running_for(seconds: u64) -> String {
    let (days, hours, minutes) = (seconds / 86_400, seconds / 3600 % 24, seconds / 60 % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => "under a minute".into(),
        (0, 0, m) => plural(m, "minute"),
        (0, h, m) => format!("{}, {}", plural(h, "hour"), plural(m, "minute")),
        (d, h, _) => format!("{}, {}", plural(d, "day"), plural(h, "hour")),
    }
}

fn plural(n: u64, what: &str) -> String {
    if n == 1 { format!("1 {what}") } else { format!("{n} {what}s") }
}

/// What kind of sign-in a session is, from its logon type and where its
/// processes are: a remote one is a desktop where it runs a job (the
/// desktop's session is one), SSH where it is under sshd.
pub fn session_kind(logon_type: Option<u32>, desktop: bool, ssh: bool) -> &'static str {
    match logon_type {
        Some(2) => "At the machine",
        Some(10) if desktop => "On the desktop",
        Some(10) if ssh => "Over SSH",
        Some(10) => "Remotely",
        Some(3) => "Over the network",
        Some(8) => "Over the network, by password",
        Some(4) => "To run a task",
        Some(5) => "As a service",
        Some(9) => "With other credentials",
        Some(_) => "Some other way",
        None if desktop => "On the desktop",
        None if ssh => "Over SSH",
        None => "",
    }
}

/// When something happened, on this machine's clock: the time alone today,
/// the day and time before that.
pub fn when(at: std::time::SystemTime) -> String {
    let seconds = at.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // The kernel makes SYSTEM's and Anonymous's sessions before the clock
    // is set.
    if seconds == 0 {
        return "When the machine started".into();
    }
    let Ok(stamp) = jiff::Timestamp::from_second(seconds as i64) else { return String::new() };
    let zone = jiff::tz::TimeZone::system();
    let then = stamp.to_zoned(zone.clone());
    let today = jiff::Timestamp::now().to_zoned(zone).date();
    if then.date() == today {
        format!("Today, {}", then.strftime("%H:%M"))
    } else {
        then.strftime("%-d %b, %H:%M").to_string()
    }
}

/// The authentication package that made a session, as a person would know it.
pub fn package(name: &str) -> String {
    match name {
        "lpsd" => "This machine's own users (lpsd)".into(),
        "attested" => "Started by the service manager".into(),
        "Negotiate" => "The kernel".into(),
        other => other.to_string(),
    }
}

/// A submitted job's state, as PSPU §7 names it.
pub fn job_state(state: &str) -> &'static str {
    match state {
        "created" => "Starting",
        "running" => "Running",
        "completed" => "Finished",
        "failed" => "Failed",
        "abandoned" => "Abandoned",
        _ => "Unknown",
    }
}

/// How far a job says it has got.
pub fn progress(progress: &peinit::client::Progress) -> String {
    let unit = progress.unit.as_deref().map(|unit| format!(" {unit}")).unwrap_or_default();
    match progress.total {
        Some(total) if progress.bounded && total > 0 => {
            format!("{}%", progress.current.saturating_mul(100) / total)
        }
        Some(total) => format!("{} of {total}{unit}", progress.current),
        None => format!("{}{unit}", progress.current),
    }
}

/// Why a call failed, in words, for the errors a person can act on.
pub fn io_error(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => "you may not".into(),
        Some(libc::ESRCH) => "it has already ended".into(),
        _ => error.to_string(),
    }
}

/// What a process is doing, from the state letter `stat` gives.
pub fn process_state(state: char) -> &'static str {
    match state {
        'R' => "Running",
        'S' => "Waiting",
        'D' => "Waiting on a device",
        'T' | 't' => "Stopped",
        'Z' => "Ended, not yet collected",
        'I' => "Idle",
        'X' => "Ending",
        _ => "Unknown",
    }
}

/// Why something about a process couldn't be seen.
pub fn closed(closed: Closed) -> &'static str {
    match closed {
        Closed::Refused => "Its permissions don't let you see this.",
        Closed::Protected => "It is a protected process, which only processes signed at its level may look into.",
        Closed::Gone => "It has ended.",
        Closed::Unreadable => "This could not be read.",
    }
}

/// A process's protection, from its PSB.
pub fn protection(psb: &Psb) -> String {
    match (psb.pip_type, psb.pip_trust) {
        (0, _) => "None".into(),
        (Psb::PIP_PROTECTED, Psb::PIP_TRUST_PEIOS_TCB) => "Protected: signed as part of Peios".into(),
        (Psb::PIP_PROTECTED, trust) => format!("Protected, at trust {trust}"),
        (kind, trust) => format!("Type {kind}, at trust {trust}"),
    }
}

/// The mitigations a process has on, each with what it does.
pub fn mitigations(on: Mitigations) -> Vec<(&'static str, &'static str)> {
    [
        (Mitigations::WXP, "Write-XOR-execute", "no memory is both writable and executable"),
        (Mitigations::LSV, "Signed libraries only", "only signed libraries load"),
        (Mitigations::TLP, "Trusted library paths", "libraries load only from approved folders"),
        (Mitigations::CFIF, "Forward-edge CFI", "indirect jumps land only where they may"),
        (Mitigations::CFIB, "Shadow stack", "returns go only where they came from"),
        (Mitigations::PIE, "Position-independent only", "only position-independent programs run"),
        (Mitigations::SML, "Speculation locked", "speculation mitigations can't be turned off"),
        (Mitigations::NO_CHILD, "No child processes", "it may start no other process"),
        (Mitigations::UI_ACCESS, "UI access", "it may reach windows above its integrity"),
    ]
    .into_iter()
    .filter(|(bit, ..)| on.contains(*bit))
    .map(|(_, name, what)| (name, what))
    .collect()
}

/// An integrity level by its name.
pub fn integrity(level: IntegrityLevel) -> String {
    match level.0 {
        0 => "Untrusted".into(),
        4096 => "Low".into(),
        8192 => "Medium".into(),
        8448 => "Medium plus".into(),
        12288 => "High".into(),
        16384 => "System".into(),
        20480 => "Protected process".into(),
        other => format!("Level {other}"),
    }
}

/// Which of a service's processes this is.
pub fn part(part: Option<ServicePart>) -> &'static str {
    match part {
        // The main process's cgroup holds everything it starts too; which one
        // is the main process itself is peinit's to say.
        Some(ServicePart::Main) => "started by its main process",
        Some(ServicePart::Hooks) => "a hook",
        Some(ServicePart::Health) => "a health check",
        Some(ServicePart::Checks) => "a check before it starts",
        None => "one of its processes",
    }
}

/// A service's state, as Services Manager says it.
pub fn service_state(state: State) -> &'static str {
    match state {
        State::Inactive => "Stopped",
        State::Starting => "Starting",
        State::Active => "Running",
        State::Reloading => "Reloading",
        State::Stopping => "Stopping",
        State::Completed => "Finished",
        State::Backoff => "Waiting to restart",
        State::Failed => "Failed",
        State::Abandoned => "Abandoned",
        State::Skipped => "Skipped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_reads_in_the_unit_that_fits() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(300 * 1024 * 1024), "300 MB");
        assert_eq!(bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    #[test]
    fn shares_and_spans_read_naturally() {
        assert_eq!(share(0.01), "0%");
        assert_eq!(share(3.25), "3.2%");
        assert_eq!(share(42.4), "42%");
        assert_eq!(running_for(30), "under a minute");
        assert_eq!(running_for(61), "1 minute");
        assert_eq!(running_for(3 * 3600 + 120), "3 hours, 2 minutes");
        assert_eq!(running_for(86_400 + 3600), "1 day, 1 hour");
    }
}
