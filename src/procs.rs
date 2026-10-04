//! The processes running now, read from `/proc` as whoever is looking.
//!
//! What a person may read of another process is its descriptor's to say, and
//! the kernel says it file by file:
//!
//! - `stat` and `cgroup` need `PROCESS_QUERY_LIMITED`, which the default
//!   process descriptor gives Everyone: the name, CPU, memory and which
//!   service or job a process is.
//! - `token` needs `PROCESS_QUERY_INFORMATION` on the process and
//!   `TOKEN_QUERY` on its token: who it runs as, and in which logon session.
//!   By default that is its own user, Administrators and SYSTEM.
//! - `psb` needs `PROCESS_QUERY_LIMITED` and, alone of them, not PIP
//!   dominance, so a protected process can still say that it is one.
//!
//! A process that refuses a file is still listed, with what could be read
//! and why the rest could not.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;

use peinit::client::{CgroupMember, cgroup_member};
use peios::process::{Process, Psb};
use peios::security::{IntegrityLevel, Sid};
use peios::token::{SessionId, Token};

/// PF_KTHREAD, in `stat`'s flags: a kernel thread, which no person runs.
const PF_KTHREAD: u64 = 0x0020_0000;

/// One process, as far as this person may see it.
#[derive(Debug, Clone, PartialEq)]
pub struct Proc {
    pub pid: u32,
    /// Its name, state, parent, CPU and memory, or why they couldn't be read.
    pub stat: Result<Stat, Closed>,
    /// Which service or job it belongs to by peinit's account. `None` for one
    /// outside peinit's tree, or whose cgroup couldn't be read.
    pub member: Option<CgroupMember>,
    /// Who it runs as, or why that couldn't be read.
    pub owner: Result<Owner, Closed>,
    /// Its PIP and mitigations, if they could be read.
    pub psb: Option<Psb>,
}

/// What `/proc/<pid>/stat` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub name: String,
    pub state: char,
    pub ppid: u32,
    pub kernel: bool,
    /// User and system time together, in clock ticks.
    pub ticks: u64,
    pub threads: u64,
    /// When it started, in clock ticks after boot.
    pub started: u64,
    /// Resident memory, in pages.
    pub resident: u64,
}

/// Who a process runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub user: Sid,
    pub session: SessionId,
    pub integrity: Option<IntegrityLevel>,
}

/// Why something about a process couldn't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Closed {
    /// Its descriptor doesn't let this person see it.
    Refused,
    /// It is protected, and the person's PIP doesn't reach it.
    Protected,
    /// It ended while being read.
    Gone,
    /// Something else went wrong; not worth more than a word.
    Unreadable,
}

impl Closed {
    fn of(error: &io::Error, protected: bool) -> Closed {
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::ESRCH) => Closed::Gone,
            Some(libc::EACCES | libc::EPERM) if protected => Closed::Protected,
            Some(libc::EACCES | libc::EPERM) => Closed::Refused,
            _ => Closed::Unreadable,
        }
    }
}

/// Read `/proc/<pid>/stat`'s line. `None` if it isn't one.
///
/// The name sits between the first `(` and the *last* `)`, since a process
/// may put either in it; the fields after are space-separated.
pub fn parse_stat(line: &str) -> Option<Stat> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    let name = line.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = line.get(close + 1..)?.split_whitespace().collect();
    // `rest[0]` is field 3, state; field N is `rest[N - 3]`.
    let field = |n: usize| rest.get(n - 3).and_then(|v| v.parse::<u64>().ok());
    Some(Stat {
        name,
        state: rest.first()?.chars().next()?,
        ppid: u32::try_from(field(4)?).ok()?,
        kernel: field(9)? & PF_KTHREAD != 0,
        ticks: field(14)?.checked_add(field(15)?)?,
        threads: field(20)?,
        started: field(22)?,
        resident: field(24)?,
    })
}

/// Every process, as this person may see it.
pub fn read_all() -> Vec<Proc> {
    let Ok(dir) = fs::read_dir("/proc") else { return Vec::new() };
    let mut procs: Vec<Proc> = dir
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(read_one)
        .collect();
    procs.sort_by_key(|p| p.pid);
    procs
}

/// One process; `None` if it ended before anything was read.
pub fn read_one(pid: u32) -> Option<Proc> {
    let psb = Process::psb(Some(pid)).ok();
    let protected = psb.is_some_and(|psb| psb.is_protected());
    let mut stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(line) => parse_stat(&line).ok_or(Closed::Unreadable),
        Err(e) => Err(Closed::of(&e, protected)),
    };
    // The kernel keeps 15 bytes of a name. Where that is all there is, the
    // program's own name is read from its command line, if the person may.
    if let Ok(stat) = &mut stat
        && stat.name.len() == 15
        && let Some(full) = full_name(pid, &stat.name)
    {
        stat.name = full;
    }
    if stat == Err(Closed::Gone) {
        return None;
    }
    let member = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|text| cgroup_member(&text));
    Some(Proc { pid, stat, member, owner: owner(pid, protected), psb })
}

/// The program's name from the first word of its command line, where it
/// begins with the 15 bytes the kernel kept.
fn full_name(pid: u32, short: &str) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first = bytes.split(|&b| b == 0).next()?;
    full_from_argv0(&String::from_utf8_lossy(first), short)
}

pub fn full_from_argv0(argv0: &str, short: &str) -> Option<String> {
    let base = argv0.rsplit('/').next()?;
    (base.len() > short.len() && base.starts_with(short)).then(|| base.to_string())
}

fn owner(pid: u32, protected: bool) -> Result<Owner, Closed> {
    let file = fs::File::open(format!("/proc/{pid}/token")).map_err(|e| Closed::of(&e, protected))?;
    let token = Token::from(OwnedFd::from(file));
    Ok(Owner {
        user: token.user().map_err(|_| Closed::Unreadable)?,
        session: token.auth_id().map_err(|_| Closed::Unreadable)?,
        integrity: token.integrity().ok(),
    })
}

/// A process's command line, read when it is picked: it needs
/// `PROCESS_QUERY_INFORMATION`, and is long.
pub fn command_line(pid: u32, protected: bool) -> Result<String, Closed> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).map_err(|e| Closed::of(&e, protected))?;
    let words: Vec<String> = bytes
        .split(|&b| b == 0)
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .collect();
    Ok(words.join(" "))
}

/// The CPU time the whole machine has spent, and of that the time it spent
/// idle, in clock ticks: the first line of `/proc/stat`. A process's share
/// is its ticks against the whole.
pub fn machine_ticks() -> Option<(u64, u64)> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    parse_machine_ticks(text.lines().next()?)
}

pub fn parse_machine_ticks(line: &str) -> Option<(u64, u64)> {
    let mut fields = line.split_whitespace();
    (fields.next()? == "cpu").then_some(())?;
    // user nice system idle iowait irq softirq steal; guest time is already
    // counted in user and nice.
    let ticks: Vec<u64> = fields.take(8).map(|v| v.parse::<u64>().ok()).collect::<Option<_>>()?;
    let idle = ticks.get(3)? + ticks.get(4)?;
    Some((ticks.iter().sum(), idle))
}

/// The machine's memory, in bytes, from `/proc/meminfo`: total, and
/// available.
pub fn memory() -> Option<(u64, u64)> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.trim().strip_suffix("kB")?.trim().parse::<u64>().ok())
            .map(|n| n * 1024)
    };
    Some((kib("MemTotal:")?, kib("MemAvailable:")?))
}

/// The CPU share each process had between two reads, in percent of the
/// whole machine.
pub fn shares(before: &HashMap<u32, u64>, now: &[Proc], machine: u64) -> HashMap<u32, f64> {
    if machine == 0 {
        return HashMap::new();
    }
    now.iter()
        .filter_map(|p| {
            let used = p.stat.as_ref().ok()?.ticks.checked_sub(*before.get(&p.pid)?)?;
            Some((p.pid, used as f64 * 100.0 / machine as f64))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stat_line_with_brackets_and_spaces_in_its_name_reads_whole() {
        let line = "620 (sshd: a (b) c) S 1 620 620 0 -1 4194560 300 0 0 0 7 3 0 0 20 0 2 0 512 \
                    9000000 1234 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0";
        let stat = parse_stat(line).unwrap();
        assert_eq!(stat.name, "sshd: a (b) c");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 1);
        assert!(!stat.kernel);
        assert_eq!(stat.ticks, 10);
        assert_eq!(stat.threads, 2);
        assert_eq!(stat.started, 512);
        assert_eq!(stat.resident, 1234);
    }

    #[test]
    fn a_kernel_thread_says_so_in_its_flags() {
        let line = "15 (ksoftirqd/0) S 2 0 0 0 -1 69238848 0 0 0 0 0 4 0 0 20 0 1 0 3 0 0 \
                    18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0";
        assert!(parse_stat(line).unwrap().kernel);
    }

    #[test]
    fn a_cut_name_is_made_whole_from_the_command_line_only_where_it_agrees() {
        assert_eq!(
            full_from_argv0("/usr/bin/gxwi-task-manager", "gxwi-task-manag"),
            Some("gxwi-task-manager".into())
        );
        // A program that renamed itself, or an argv[0] that says something else.
        assert_eq!(full_from_argv0("sshd: /usr/sbin/sshd -D", "sshd"), None);
        assert_eq!(full_from_argv0("/usr/bin/other-program-name", "gxwi-task-manag"), None);
    }

    #[test]
    fn a_short_or_broken_line_reads_as_nothing() {
        assert_eq!(parse_stat("12 (x) S 1"), None);
        assert_eq!(parse_stat("no brackets here"), None);
    }

    #[test]
    fn the_machine_s_ticks_add_its_first_eight_counters() {
        assert_eq!(parse_machine_ticks("cpu  10 1 5 100 2 0 1 0 7 0"), Some((119, 102)));
        assert_eq!(parse_machine_ticks("cpu0 10 1 5 100 2 0 1 0"), None);
    }

    #[test]
    fn a_share_is_ticks_used_against_the_machine_s() {
        let proc_with = |pid, ticks| Proc {
            pid,
            stat: Ok(Stat {
                name: String::new(),
                state: 'S',
                ppid: 1,
                kernel: false,
                ticks,
                threads: 1,
                started: 0,
                resident: 0,
            }),
            member: None,
            owner: Err(Closed::Refused),
            psb: None,
        };
        let before = HashMap::from([(10, 100), (11, 50)]);
        let now = [proc_with(10, 150), proc_with(11, 50), proc_with(12, 9)];
        let shares = shares(&before, &now, 200);
        assert_eq!(shares.get(&10), Some(&25.0));
        assert_eq!(shares.get(&11), Some(&0.0));
        // New since the last read: no share yet.
        assert_eq!(shares.get(&12), None);
    }
}
