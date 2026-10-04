//! The window: what is running now, grouped by the service or job it belongs
//! to, by the person it runs as, or not at all; and, beside it, the process
//! picked, in full.
//!
//! Everything is read as the person looking. What they may not see of a
//! process is said where it would have been, with why, and a note above the
//! list says how much of the machine that leaves out.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::Weak;
use std::time::{Duration, Instant, SystemTime};

use libgxwi::{Facts, Fields, Live, Surface, Value, escape};
use peinit::client::{
    Admission, CgroupMember, Command, ControlClient, Status, SubmittedJob, Summary, admission,
};
use peios::security::Sid;
use peios::token::LogonSessionInfo;

use crate::procs::{self, Closed, Proc};
use crate::{ending, words};

pub struct Manager {
    pub window: Weak<Surface<Manager>>,
    seen: Seen,
    view: View,
    /// The signed-in session picked, by its id.
    session: Option<u64>,
    /// The job picked, by its id.
    job_picked: Option<String>,
    grouping: Grouping,
    sort: Sort,
    picked: Option<u32>,
    /// The picked process's command line, read when it was picked.
    command: Option<(u32, Result<String, Closed>)>,
    /// Whether this person may end the picked process, or why not.
    may_end: Option<(u32, Result<(), String>)>,
    /// The picked process's service as peinit says it is now: its main
    /// process, its state, and what this person may do to it.
    status: Option<(u32, String, Result<Status, String>)>,
    doing: Doing,
    /// What came of the last thing done: what was done, or why it wasn't.
    said: Option<Result<String, String>>,
}

/// What is being done to the picked process.
enum Doing {
    Looking,
    /// Asking before it is ended.
    AskingEnd,
    /// Asking before its service is stopped.
    AskingStopService,
    /// Asking before its job is stopped.
    AskingStopJob,
    /// Asked to end, through a handle held on it since.
    Ending { pid: u32, pidfd: OwnedFd, since: Instant },
}

/// How long a process asked to end is given before it may be ended at once.
const GRACE: Duration = Duration::from_secs(5);

/// What was read of the machine, the last time it was looked at.
#[derive(Debug, Clone)]
pub struct Seen {
    pub procs: Vec<Proc>,
    /// Each process's CPU since the look before, in percent of the machine.
    pub shares: HashMap<u32, f64>,
    /// The whole machine's CPU since the look before, in percent.
    pub cpu: Option<f64>,
    /// Memory: total, and available.
    pub memory: Option<(u64, u64)>,
    pub services: Result<Vec<Summary>, String>,
    pub jobs: Result<Vec<SubmittedJob>, String>,
    /// The main processes of services, for a process whose own cgroup is
    /// closed to the person: peinit says which service it is.
    pub mains: HashMap<u32, String>,
    /// What the people processes run as are called.
    pub names: HashMap<Sid, String>,
    /// The kernel's list of logon sessions, or why it couldn't be read: it
    /// is Administrators' and SYSTEM's.
    pub sessions: Result<Vec<LogonSessionInfo>, String>,
    /// Seconds since the machine started, and clock ticks a second.
    pub uptime: Option<f64>,
    pub ticks_per_second: u64,
    pub page_size: u64,
}

impl Default for Seen {
    fn default() -> Seen {
        Seen {
            procs: Vec::new(),
            shares: HashMap::new(),
            cpu: None,
            memory: None,
            services: Ok(Vec::new()),
            jobs: Ok(Vec::new()),
            mains: HashMap::new(),
            names: HashMap::new(),
            sessions: Ok(Vec::new()),
            uptime: None,
            ticks_per_second: 100,
            page_size: 4096,
        }
    }
}

/// Which list is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Processes,
    Jobs,
    SignedIn,
}

/// One signed-in session, with what is known of it: everything, from the
/// kernel's list, or only what the person's own processes say of it.
struct Signed {
    id: u64,
    user: Sid,
    logon_type: Option<u32>,
    package: Option<String>,
    created: Option<SystemTime>,
    pids: Vec<u32>,
}

/// How the processes are grouped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grouping {
    Service,
    Person,
    None,
}

/// What the rows are sorted by within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Name,
    Pid,
    Cpu,
    Memory,
}

/// What a group of rows is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Group {
    Service(String),
    Job(String),
    /// Started outside any service or job: peinit itself, and what the
    /// kernel starts.
    Elsewhere,
    /// Neither its cgroup nor peinit says where it belongs.
    Unknown,
    Person(Sid),
    /// Whose it is can't be seen.
    Nobody(Closed),
    Kernel,
    All,
}

impl Manager {
    pub fn new(seen: Seen) -> Manager {
        Manager {
            window: Weak::new(),
            seen,
            view: View::Processes,
            session: None,
            job_picked: None,
            grouping: Grouping::Service,
            sort: Sort::Name,
            picked: None,
            command: None,
            may_end: None,
            status: None,
            doing: Doing::Looking,
            said: None,
        }
    }

    pub fn picked(&self) -> Option<u32> {
        self.picked
    }

    pub fn heard(&mut self, seen: Seen) {
        self.seen = seen;
        // The picked process's service may have changed state since.
        if let Some(pid) = self.picked {
            self.status = self.service_of(pid).map(|name| (pid, name.clone(), ask_status(&name)));
        }
    }

    /// The service the process `pid` belongs to, if it belongs to one.
    fn service_of(&self, pid: u32) -> Option<String> {
        match &self.proc(pid)?.member {
            Some(CgroupMember::Service { service, .. }) => Some(service.clone()),
            Some(CgroupMember::Job(_)) => None,
            None => self.seen.mains.get(&pid).cloned(),
        }
    }

    /// The picked process's service's status, if it is `pid`'s.
    fn status_for(&self, pid: u32) -> Option<&Result<Status, String>> {
        self.status.as_ref().filter(|(at, ..)| *at == pid).map(|(_, _, status)| status)
    }

    /// Whether `pid` is its service's main process, by peinit's word.
    fn is_main(&self, pid: u32) -> bool {
        self.status_for(pid)
            .and_then(|status| status.as_ref().ok())
            .and_then(|status| status.job.as_ref()?.pid)
            == Some(pid)
    }

    /// The job the process `p` belongs to, as peinit lists it to this person.
    fn job_of(&self, p: &Proc) -> Option<&SubmittedJob> {
        match &p.member {
            Some(CgroupMember::Job(id)) => self.job(id),
            _ => None,
        }
    }

    fn proc(&self, pid: u32) -> Option<&Proc> {
        self.seen.procs.iter().find(|p| p.pid == pid)
    }

    /// What a process is called: its name, or the service peinit says it
    /// is, or that it can't be seen.
    fn name(&self, p: &Proc) -> String {
        match &p.stat {
            Ok(stat) => stat.name.clone(),
            // The first process is always init, which is peinit.
            Err(_) if p.pid == 1 => "peinit".into(),
            Err(_) => match self.seen.mains.get(&p.pid) {
                Some(service) => self.service(service).and_then(|s| s.display_name.clone()).unwrap_or_else(|| service.clone()),
                None if p.psb.is_some_and(|psb| psb.is_protected()) => "Protected process".into(),
                None => "Process you can't see".into(),
            },
        }
    }

    /// Whose a process is, in words.
    fn runs_as(&self, p: &Proc) -> String {
        match &p.owner {
            Ok(owner) => self.seen.names.get(&owner.user).cloned().unwrap_or_else(|| owner.user.to_string()),
            Err(Closed::Protected) => "Protected".into(),
            Err(_) => String::new(),
        }
    }

    fn service(&self, name: &str) -> Option<&Summary> {
        self.seen.services.as_ref().ok()?.iter().find(|s| s.service == name)
    }

    fn job(&self, id: &str) -> Option<&SubmittedJob> {
        self.seen.jobs.as_ref().ok()?.iter().find(|j| j.id == id)
    }

    fn kernel(p: &Proc) -> bool {
        p.stat.as_ref().is_ok_and(|stat| stat.kernel)
    }

    fn group_of(&self, p: &Proc) -> Group {
        if Self::kernel(p) {
            return Group::Kernel;
        }
        match self.grouping {
            Grouping::None => Group::All,
            Grouping::Person => match &p.owner {
                Ok(owner) => Group::Person(owner.user),
                Err(why) => Group::Nobody(*why),
            },
            Grouping::Service => match &p.member {
                Some(CgroupMember::Service { service, .. }) => Group::Service(service.clone()),
                Some(CgroupMember::Job(id)) => Group::Job(id.clone()),
                None => match self.seen.mains.get(&p.pid) {
                    Some(service) => Group::Service(service.clone()),
                    None if p.stat.is_ok() || p.pid == 1 => Group::Elsewhere,
                    None => Group::Unknown,
                },
            },
        }
    }

    fn memory(&self, p: &Proc) -> Option<u64> {
        Some(p.stat.as_ref().ok()?.resident * self.seen.page_size)
    }

    fn share(&self, p: &Proc) -> Option<f64> {
        self.seen.shares.get(&p.pid).copied()
    }

    /// Whether a process is one of those `filter` asks for.
    fn matches(&self, p: &Proc, filter: &str) -> bool {
        let filter = filter.trim().to_lowercase();
        if filter.is_empty() {
            return true;
        }
        let service = match &p.member {
            Some(CgroupMember::Service { service, .. }) => service.clone(),
            Some(CgroupMember::Job(id)) => self.job(id).map(|j| j.description.clone()).unwrap_or_default(),
            None => self.seen.mains.get(&p.pid).cloned().unwrap_or_default(),
        };
        [self.name(p), p.pid.to_string(), self.runs_as(p), service]
            .iter()
            .any(|text| text.to_lowercase().contains(&filter))
    }

    fn heading(&self, group: &Group) -> (String, String) {
        match group {
            Group::Service(name) => match self.service(name) {
                Some(s) => (
                    s.display_name.clone().unwrap_or_else(|| name.clone()),
                    format!("Service {name} · {}", words::service_state(s.state)),
                ),
                None => (name.clone(), format!("Service {name}")),
            },
            Group::Job(id) => match self.job(id) {
                Some(job) => {
                    let title = if job.description.is_empty() { "A job".into() } else { job.description.clone() };
                    let runs_as = job
                        .identity
                        .parse::<Sid>()
                        .ok()
                        .and_then(|sid| self.seen.names.get(&sid).cloned())
                        .map_or_else(|| "Job".to_string(), |name| format!("Job · runs as {name}"));
                    (title, runs_as)
                }
                // peinit lists a job only to whoever may query it, which by
                // default is who submitted it and Administrators.
                None => ("A job".into(), "peinit doesn't tell you which: only who submitted it may ask".into()),
            },
            Group::Elsewhere => ("Not in a service".into(), "Started by peinit itself, or before it".into()),
            Group::Unknown => (
                "Can't tell".into(),
                "Neither the process nor peinit says what these belong to".into(),
            ),
            Group::Person(sid) => (
                self.seen.names.get(sid).cloned().unwrap_or_else(|| sid.to_string()),
                sid.to_string(),
            ),
            Group::Nobody(Closed::Protected) => ("Protected processes".into(), "Who they run as can't be seen".into()),
            Group::Nobody(_) => ("Someone you can't see".into(), "Only their owner and Administrators may see whose these are".into()),
            Group::Kernel => ("Kernel".into(), "The kernel's own threads".into()),
            Group::All => (String::new(), String::new()),
        }
    }

    fn sorted<'a>(&self, mut rows: Vec<&'a Proc>) -> Vec<&'a Proc> {
        match self.sort {
            Sort::Name => rows.sort_by_cached_key(|p| (self.name(p).to_lowercase(), p.pid)),
            Sort::Pid => rows.sort_by_key(|p| p.pid),
            Sort::Cpu => rows.sort_by(|a, b| self.share(b).unwrap_or(0.0).total_cmp(&self.share(a).unwrap_or(0.0))),
            Sort::Memory => rows.sort_by_key(|p| std::cmp::Reverse(self.memory(p).unwrap_or(0))),
        }
        rows
    }

    fn row(&self, p: &Proc) -> String {
        let closed = p.stat.is_err();
        format!(
            "<li><button type=\"button\" fx-click=\"pick\" fx-value-pid=\"{pid}\" aria-selected=\"{picked}\"{class}>\
             <span class=\"name\">{name}</span><span class=\"pid\">{pid}</span><span class=\"owner\">{owner}</span>\
             <span class=\"num\">{cpu}</span><span class=\"num\">{memory}</span></button></li>",
            pid = p.pid,
            picked = self.picked == Some(p.pid),
            class = if closed { " class=\"off\"" } else { "" },
            name = escape(&self.name(p)),
            owner = escape(&self.runs_as(p)),
            cpu = self.share(p).map(words::share).unwrap_or_default(),
            memory = self.memory(p).map(words::bytes).unwrap_or_default(),
        )
    }

    fn listing(&self, fields: &Fields) -> String {
        let filter = fields.get("filter");
        let show_kernel = !fields.get("kernel").is_empty();
        let mut groups: HashMap<Group, Vec<&Proc>> = HashMap::new();
        for p in &self.seen.procs {
            if (Self::kernel(p) && !show_kernel) || !self.matches(p, filter) {
                continue;
            }
            groups.entry(self.group_of(p)).or_default().push(p);
        }
        if groups.is_empty() {
            return "<p class=\"more\">No process matches.</p>".into();
        }
        let mut out = String::from("<ul class=\"entries\">");
        // Groups by what they are called, the kernel last.
        let mut ordered: Vec<(Group, Vec<&Proc>)> = groups.into_iter().collect();
        ordered.sort_by_cached_key(|(group, _)| {
            let last = matches!(group, Group::Kernel | Group::Unknown | Group::Nobody(_) | Group::Elsewhere);
            (last, matches!(group, Group::Kernel), self.heading(group).0.to_lowercase())
        });
        for (group, rows) in ordered {
            if group != Group::All {
                let (title, about) = self.heading(&group);
                let cpu: f64 = rows.iter().filter_map(|p| self.share(p)).sum();
                let memory: u64 = rows.iter().filter_map(|p| self.memory(p)).sum();
                out.push_str(&format!(
                    "<li class=\"group\"><span class=\"name\">{title} <small>{count}</small></span>\
                     <span class=\"about\">{about}</span><span class=\"num\">{cpu}</span><span class=\"num\">{memory}</span></li>",
                    title = escape(&title),
                    count = rows.len(),
                    about = escape(&about),
                    cpu = words::share(cpu),
                    memory = if memory > 0 { words::bytes(memory) } else { String::new() },
                ));
            }
            for p in self.sorted(rows) {
                out.push_str(&self.row(p));
            }
        }
        out.push_str("</ul>");
        out
    }

    /// What the person can't see of the machine, said once above the list.
    fn notes(&self) -> String {
        let mut notes = Vec::new();
        let people = self.seen.procs.iter().filter(|p| !Self::kernel(p));
        let hidden = people.clone().filter(|p| matches!(p.owner, Err(Closed::Refused))).count();
        if hidden > 0 {
            notes.push(format!(
                "You can't see who runs {} or what they were started with: only their owner and \
                 Administrators may.",
                if hidden == 1 { "1 process".to_string() } else { format!("{hidden} processes") }
            ));
        }
        let protected = people.filter(|p| p.stat.is_err() && p.psb.is_some_and(|psb| psb.is_protected())).count();
        if protected > 0 {
            notes.push(format!(
                "{} protected: signed as part of Peios, and closed to every process not signed at its level, \
                 Administrators' included.",
                if protected == 1 { "1 process is".to_string() } else { format!("{protected} processes are") }
            ));
        }
        if let Err(why) = &self.seen.services {
            notes.push(format!("Which service each process belongs to couldn't be asked of peinit: {why}"));
        }
        notes.iter().map(|note| format!("<p class=\"said\" role=\"status\">{}</p>", escape(note))).collect()
    }

    fn details(&self) -> String {
        let Some(pid) = self.picked else {
            return "<aside class=\"details\"><p class=\"more\">Pick a process to see it in full.</p></aside>".into();
        };
        let Some(p) = self.proc(pid) else {
            return format!("<aside class=\"details\"><h2>Process {pid}</h2><p class=\"note\">It has ended.</p></aside>");
        };
        let mut facts: Vec<(String, String)> = Vec::new();
        let mut note = String::new();
        match &p.stat {
            Ok(stat) => {
                facts.push(("State".into(), escape(words::process_state(stat.state))));
                if let Some(uptime) = self.seen.uptime {
                    let started = stat.started as f64 / self.seen.ticks_per_second as f64;
                    let ran = (uptime - started).max(0.0) as u64;
                    facts.push(("Running for".into(), escape(&words::running_for(ran))));
                }
                facts.push(("CPU".into(), self.share(p).map(words::share).unwrap_or_else(|| "…".into())));
                facts.push(("Memory".into(), self.memory(p).map(words::bytes).unwrap_or_default()));
                facts.push(("Threads".into(), stat.threads.to_string()));
                if stat.ppid != 0 {
                    let parent = self.proc(stat.ppid).map(|parent| self.name(parent)).unwrap_or_default();
                    facts.push((
                        "Started by".into(),
                        format!(
                            "<button type=\"button\" class=\"link\" fx-click=\"pick\" fx-value-pid=\"{ppid}\">{name} ({ppid})</button>",
                            ppid = stat.ppid,
                            name = escape(&parent),
                        ),
                    ));
                }
            }
            Err(why) => note = format!("<p class=\"note\">{}</p>", escape(words::closed(*why))),
        }
        // Where the whole process is closed, why is said once, above, and
        // not again beside each thing it closes.
        let said = p.stat.as_ref().err().copied();
        if let Some((for_pid, command)) = &self.command
            && *for_pid == pid
            && !matches!((command, said), (Err(why), Some(also)) if *why == also)
        {
            facts.push((
                "Command".into(),
                match command {
                    Ok(line) if line.is_empty() => "<span class=\"unsaid\">None</span>".into(),
                    Ok(line) => format!("<code>{}</code>", escape(line)),
                    Err(why) => format!("<span class=\"unsaid\">{}</span>", escape(words::closed(*why))),
                },
            ));
        }
        match &p.member {
            Some(CgroupMember::Service { service, part }) => {
                let shown = self.service(service).and_then(|s| s.display_name.clone()).unwrap_or_else(|| service.clone());
                let which = if self.is_main(pid) { "its main process" } else { words::part(*part) };
                facts.push(("Belongs to".into(), format!("{} — {}", escape(&shown), which)));
                if let Some(Ok(status)) = self.status_for(pid) {
                    if let Some(text) = &status.status_text {
                        facts.push(("Service says".into(), escape(text)));
                    }
                    if let Some(progress) = &status.progress {
                        facts.push(("Progress".into(), escape(&words::progress(progress))));
                    }
                }
            }
            Some(CgroupMember::Job(id)) => {
                let what = self.job(id).map(|j| j.description.clone()).filter(|d| !d.is_empty());
                facts.push(("Belongs to".into(), escape(&what.unwrap_or_else(|| format!("Job {id}")))));
            }
            None => {
                if let Some(service) = self.seen.mains.get(&pid) {
                    let shown = self.service(service).and_then(|s| s.display_name.clone()).unwrap_or_else(|| service.clone());
                    facts.push(("Belongs to".into(), format!("{} — its main process", escape(&shown))));
                } else if pid == 1 {
                    facts.push(("Belongs to".into(), "Nothing: it is the service manager, which starts every service".into()));
                }
            }
        }
        match &p.owner {
            Ok(owner) => {
                let name = self.seen.names.get(&owner.user).cloned().unwrap_or_else(|| owner.user.to_string());
                facts.push((
                    "Runs as".into(),
                    format!("{}<br><code class=\"sid\">{}</code>", escape(&name), escape(&owner.user.to_string())),
                ));
                facts.push(("Signed-in session".into(), owner.session.0.to_string()));
                if let Some(level) = owner.integrity {
                    facts.push(("Integrity".into(), escape(&words::integrity(level))));
                }
            }
            Err(why) if Some(*why) == said => {}
            Err(why) => facts.push(("Runs as".into(), format!("<span class=\"unsaid\">{}</span>", escape(words::closed(*why))))),
        }
        let mut mitigations = String::new();
        match &p.psb {
            Some(psb) => {
                facts.push(("Protection".into(), escape(&words::protection(psb))));
                let on = words::mitigations(psb.mitigations);
                mitigations = if on.is_empty() {
                    "<h3>Mitigations</h3><p class=\"more\">None.</p>".into()
                } else {
                    format!(
                        "<h3>Mitigations</h3><ul class=\"plain mitigations\">{}</ul>",
                        on.iter()
                            .map(|(name, what)| format!("<li><span>{name}</span><small>{what}</small></li>"))
                            .collect::<String>()
                    )
                };
            }
            None => facts.push(("Protection".into(), "<span class=\"unsaid\">Its permissions don't let you see this.</span>".into())),
        }
        let dl: String = facts.iter().map(|(k, v)| format!("<dt>{k}</dt><dd>{v}</dd>")).collect();
        format!(
            "<aside class=\"details\"><h2>{name}</h2><p class=\"id\">Process {pid}</p>{note}{actions}<dl>{dl}</dl>{mitigations}</aside>",
            name = escape(&self.name(p)),
            actions = self.actions(p),
        )
    }

    fn footer(&self) -> String {
        let count = self.seen.procs.iter().filter(|p| !Self::kernel(p)).count();
        let cpu = self.seen.cpu.map(|cpu| format!("CPU {}", words::share(cpu))).unwrap_or_default();
        let memory = self
            .seen
            .memory
            .map(|(total, free)| format!("Memory {} of {}", words::bytes(total.saturating_sub(free)), words::bytes(total)))
            .unwrap_or_default();
        format!(
            "<div class=\"status\"><span>{count} processes</span><span>{cpu}</span><span>{memory}</span></div>"
        )
    }

    fn pick(&mut self, pid: u32) {
        if self.picked != Some(pid) {
            self.doing = Doing::Looking;
            self.said = None;
        }
        self.picked = Some(pid);
        let protected = self.proc(pid).and_then(|p| p.psb).is_some_and(|psb| psb.is_protected());
        let kernel = self.proc(pid).is_some_and(Self::kernel);
        self.command = Some((pid, procs::command_line(pid, protected)));
        self.may_end = Some((pid, ending::may_end(pid, protected, kernel)));
        self.status = self.service_of(pid).map(|name| (pid, name.clone(), ask_status(&name)));
    }

    /// What may be done to the picked process, and what is being done.
    fn actions(&self, p: &Proc) -> String {
        let said = match &self.said {
            Some(Ok(done)) => format!("<p class=\"note\" role=\"status\">{}</p>", escape(done)),
            Some(Err(why)) => format!("<p class=\"note bad\" role=\"alert\">{}</p>", escape(why)),
            None => String::new(),
        };
        let main = self.is_main(p.pid);
        let service_name = self.status.as_ref().filter(|(at, ..)| *at == p.pid).map(|(_, name, _)| {
            self.service(name).and_then(|s| s.display_name.clone()).unwrap_or_else(|| name.clone())
        });
        let body = match &self.doing {
            Doing::AskingEnd => format!(
                "<div class=\"asking\"><p>End {name}? Anything it hasn't saved is lost.{service}</p>\
                 <button type=\"button\" class=\"danger\" fx-click=\"end-confirm\">End process</button>\
                 <button type=\"button\" fx-click=\"cancel\">Cancel</button></div>",
                name = escape(&self.name(p)),
                service = if main {
                    " It is its service's main process: peinit will take it as having crashed, and may start it \
                     again. Stop service stops it for good."
                } else {
                    ""
                },
            ),
            Doing::AskingStopService => format!(
                "<div class=\"asking\"><p>Stop {name}? It and everything it started end, and it stays stopped until \
                 it is started again.</p>\
                 <button type=\"button\" class=\"danger\" fx-click=\"stop-service-confirm\">Stop service</button>\
                 <button type=\"button\" fx-click=\"cancel\">Cancel</button></div>",
                name = escape(service_name.as_deref().unwrap_or("its service")),
            ),
            Doing::AskingStopJob => {
                let what = self.job_of(p).map(|job| job.description.clone()).filter(|d| !d.is_empty());
                format!(
                    "<div class=\"asking\"><p>Stop {what}? Everything in it ends.</p>\
                     <button type=\"button\" class=\"danger\" fx-click=\"stop-job-confirm\">Stop job</button>\
                     <button type=\"button\" fx-click=\"cancel\">Cancel</button></div>",
                    what = escape(&what.map_or_else(|| "its job".to_string(), |d| format!("“{d}”"))),
                )
            }
            Doing::Ending { pid, since, .. } if *pid == p.pid => {
                if since.elapsed() >= GRACE {
                    "<div class=\"asking\"><p>It was asked to end and hasn't. Ending it at once gives it no chance to finish what it is doing.</p>\
                     <button type=\"button\" class=\"danger\" fx-click=\"end-now\">End it now</button>\
                     <button type=\"button\" fx-click=\"cancel\">Leave it</button></div>"
                        .into()
                } else {
                    "<p class=\"note\" role=\"status\">Asked it to end…</p>".into()
                }
            }
            _ => {
                // Each thing is offered only where it would be done, and
                // where it wouldn't, why not is said instead.
                let mut buttons = Vec::new();
                let mut why_not = Vec::new();
                match self.may_end.as_ref().filter(|(pid, _)| *pid == p.pid) {
                    Some((_, Ok(()))) => buttons.push("<button type=\"button\" fx-click=\"end\">End process</button>"),
                    Some((_, Err(why))) => why_not.push(why.clone()),
                    None => {}
                }
                match self.status_for(p.pid) {
                    Some(Ok(status)) if admission(Command::Stop, status.summary.state) == Admission::Acts => {
                        if status.granted.iter().any(|right| right == "stop") {
                            buttons.push("<button type=\"button\" fx-click=\"stop-service\">Stop service</button>");
                        } else {
                            why_not.push("Its service's permissions don't let you stop it.".into());
                        }
                    }
                    Some(Err(why)) => why_not.push(format!("Whether you may stop its service couldn't be asked: {why}")),
                    _ => {}
                }
                if let Some(job) = self.job_of(p).filter(|job| job.state == "running" || job.state == "created") {
                    if job.granted.iter().any(|right| right == "stop") {
                        buttons.push("<button type=\"button\" fx-click=\"stop-job\">Stop job</button>");
                    } else {
                        why_not.push("Its job's permissions don't let you stop it.".into());
                    }
                }
                let buttons = if buttons.is_empty() {
                    String::new()
                } else {
                    format!("<div class=\"actions\">{}</div>", buttons.concat())
                };
                let why_not: String = why_not.iter().map(|why| format!("<p class=\"may\">{}</p>", escape(why))).collect();
                format!("{buttons}{why_not}")
            }
        };
        format!("{said}{body}")
    }

    fn act(&mut self, name: &str) {
        // A job picked in Jobs is stopped from its own pane.
        if self.view == View::Jobs {
            match name {
                "stop-job" => {
                    self.said = None;
                    self.doing = Doing::AskingStopJob;
                }
                "stop-job-confirm" => {
                    self.doing = Doing::Looking;
                    if let Some(id) = self.job_picked.clone() {
                        self.stop_job(&id);
                    }
                }
                "cancel" => self.doing = Doing::Looking,
                _ => {}
            }
            return;
        }
        let Some(pid) = self.picked else { return };
        match name {
            "end" => {
                self.said = None;
                self.doing = Doing::AskingEnd;
            }
            "end-confirm" => {
                self.doing = Doing::Looking;
                match ending::pidfd(pid).and_then(|fd| ending::signal(&fd, libc::SIGTERM).map(|()| fd)) {
                    Ok(pidfd) => self.doing = Doing::Ending { pid, pidfd, since: Instant::now() },
                    Err(e) => self.said = Some(Err(format!("It couldn't be ended: {}.", words::io_error(&e)))),
                }
            }
            "end-now" => {
                if let Doing::Ending { pidfd, .. } = &self.doing {
                    self.said = Some(match ending::signal(pidfd, libc::SIGKILL) {
                        Ok(()) => Ok("Ended at once.".into()),
                        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok("It has ended.".into()),
                        Err(e) => Err(format!("It couldn't be ended: {}.", words::io_error(&e))),
                    });
                }
                self.doing = Doing::Looking;
            }
            "stop-service" => {
                self.said = None;
                self.doing = Doing::AskingStopService;
            }
            "stop-service-confirm" => {
                self.doing = Doing::Looking;
                if let Some((_, name, _)) = self.status.clone().filter(|(at, ..)| *at == pid) {
                    let done = ControlClient::connect_default()
                        .map_err(|e| e.to_string())
                        .and_then(|mut client| client.command(Command::Stop, &name).map_err(|e| e.to_string()));
                    self.said = Some(match done {
                        Ok(_) => Ok("Asked peinit to stop its service.".into()),
                        Err(why) => Err(format!("Its service couldn't be stopped: {why}")),
                    });
                    self.status = Some((pid, name.clone(), ask_status(&name)));
                }
            }
            "stop-job" => {
                self.said = None;
                self.doing = Doing::AskingStopJob;
            }
            "stop-job-confirm" => {
                self.doing = Doing::Looking;
                let id = self.proc(pid).and_then(|p| self.job_of(p)).map(|job| job.id.clone());
                if let Some(id) = id {
                    self.stop_job(&id);
                }
            }
            "cancel" => self.doing = Doing::Looking,
            _ => {}
        }
    }
}

/// What peinit says of `service` now, asked as this person.
fn ask_status(service: &str) -> Result<Status, String> {
    let mut client = ControlClient::connect_default().map_err(|e| e.to_string())?;
    client.status_of(service).map_err(|e| e.to_string())
}

impl Manager {
    /// Who is signed in: the kernel's list where the person may read it,
    /// with the processes each session has that the person may see; or else
    /// the sessions of the processes they may see, which are their own.
    fn signed(&self) -> Vec<Signed> {
        let mut pids: HashMap<u64, Vec<u32>> = HashMap::new();
        for p in &self.seen.procs {
            if let Ok(owner) = &p.owner {
                pids.entry(owner.session.0).or_default().push(p.pid);
            }
        }
        match &self.seen.sessions {
            Ok(listing) => listing
                .iter()
                .map(|s| Signed {
                    id: s.id.0,
                    user: s.user,
                    logon_type: Some(s.logon_type),
                    package: Some(s.auth_package.clone()).filter(|p| !p.is_empty()),
                    created: Some(s.created_at),
                    pids: pids.remove(&s.id.0).unwrap_or_default(),
                })
                .collect(),
            Err(_) => {
                let mut seen: Vec<Signed> = Vec::new();
                for p in &self.seen.procs {
                    let Ok(owner) = &p.owner else { continue };
                    if seen.iter().any(|s| s.id == owner.session.0) {
                        continue;
                    }
                    seen.push(Signed {
                        id: owner.session.0,
                        user: owner.user,
                        logon_type: None,
                        package: None,
                        created: None,
                        pids: pids.remove(&owner.session.0).unwrap_or_default(),
                    });
                }
                seen
            }
        }
    }

    /// Whether a session is a person's, and not a service's or the kernel's
    /// own.
    fn a_persons(s: &Signed) -> bool {
        s.id != LogonSessionInfo::SYSTEM.0 && s.id != LogonSessionInfo::ANONYMOUS.0 && s.logon_type != Some(5)
    }

    /// What kind of sign-in a session is: the kernel says console, remote,
    /// service and so on; where its processes are says desktop from SSH.
    fn kind(&self, s: &Signed) -> &'static str {
        let members = s.pids.iter().filter_map(|pid| self.proc(*pid)?.member.as_ref());
        let mut desktop = false;
        let mut ssh = false;
        for member in members {
            match member {
                CgroupMember::Job(_) => desktop = true,
                CgroupMember::Service { service, .. } if service == "sshd" => ssh = true,
                _ => {}
            }
        }
        words::session_kind(s.logon_type, desktop, ssh)
    }

    fn who(&self, sid: &Sid) -> String {
        self.seen.names.get(sid).cloned().unwrap_or_else(|| sid.to_string())
    }

    fn sessions_listing(&self, fields: &Fields) -> String {
        let all = !fields.get("services").is_empty();
        let filter = fields.get("filter").trim().to_lowercase();
        let signed: Vec<Signed> = self
            .signed()
            .into_iter()
            .filter(|s| all || Self::a_persons(s))
            .filter(|s| filter.is_empty() || self.who(&s.user).to_lowercase().contains(&filter) || s.id.to_string() == filter)
            .collect();
        if signed.is_empty() {
            return "<p class=\"more\">Nobody is signed in that you can see.</p>".into();
        }
        let mut sorted = signed;
        sorted.sort_by_key(|s| (self.who(&s.user).to_lowercase(), s.id));
        let rows: String = sorted
            .iter()
            .map(|s| {
                format!(
                    "<li><button type=\"button\" fx-click=\"pick-session\" fx-value-id=\"{id}\" aria-selected=\"{picked}\">\
                     <span class=\"name\">{who}</span><span class=\"kind\">{kind}</span><span class=\"since\">{since}</span>\
                     <span class=\"num\">{count}</span></button></li>",
                    id = s.id,
                    picked = self.session == Some(s.id),
                    who = escape(&self.who(&s.user)),
                    kind = self.kind(s),
                    since = s.created.map(|at| escape(&words::when(at))).unwrap_or_default(),
                    count = s.pids.len(),
                )
            })
            .collect();
        format!("<ul class=\"entries\">{rows}</ul>")
    }

    fn sessions_notes(&self) -> String {
        match &self.seen.sessions {
            Ok(_) => String::new(),
            Err(why) => format!(
                "<p class=\"said\" role=\"status\">{} These are the sessions your own processes are in.</p>",
                escape(why)
            ),
        }
    }

    fn session_details(&self) -> String {
        let Some(id) = self.session else {
            return "<aside class=\"details\"><p class=\"more\">Pick a session to see it in full.</p></aside>".into();
        };
        let Some(s) = self.signed().into_iter().find(|s| s.id == id) else {
            return format!("<aside class=\"details\"><h2>Session {id}</h2><p class=\"note\">It has ended.</p></aside>");
        };
        let mut facts: Vec<(String, String)> = vec![("Signed in".into(), self.kind(&s).into())];
        if let Some(at) = s.created {
            facts.push(("Since".into(), escape(&words::when(at))));
        }
        if let Some(package) = &s.package {
            facts.push(("Through".into(), escape(&words::package(package))));
        }
        facts.push(("SID".into(), format!("<code class=\"sid\">{}</code>", escape(&s.user.to_string()))));
        if let Some(job) = self
            .seen
            .jobs
            .as_ref()
            .ok()
            .and_then(|jobs| jobs.iter().find(|j| j.logon_session == Some(id) && j.state == "running"))
        {
            facts.push(("Desktop".into(), escape(&job.description)));
        }
        let dl: String = facts.iter().map(|(k, v)| format!("<dt>{k}</dt><dd>{v}</dd>")).collect();
        let processes = if s.pids.is_empty() {
            "<p class=\"more\">None you can see. A session lasts while anything holds it, \
             such as a sign-in still under way.</p>"
                .to_string()
        } else {
            format!(
                "<ul class=\"plain\">{}</ul>",
                s.pids
                    .iter()
                    .filter_map(|pid| self.proc(*pid))
                    .map(|p| format!(
                        "<li><button type=\"button\" class=\"link\" fx-click=\"show-process\" fx-value-pid=\"{pid}\">{name}</button> <span class=\"pid\">{pid}</span></li>",
                        pid = p.pid,
                        name = escape(&self.name(p)),
                    ))
                    .collect::<String>()
            )
        };
        format!(
            "<aside class=\"details\"><h2>{who}</h2><p class=\"id\">Session {id}</p><dl>{dl}</dl>\
             <h3>Processes</h3>{processes}</aside>",
            who = escape(&self.who(&s.user)),
        )
    }
}

impl Manager {
    fn jobs_listing(&self, fields: &Fields) -> String {
        let jobs = match &self.seen.jobs {
            Ok(jobs) => jobs,
            Err(why) => return format!("<p class=\"more\">peinit couldn't be asked for its jobs: {}</p>", escape(why)),
        };
        let filter = fields.get("filter").trim().to_lowercase();
        let mut shown: Vec<&SubmittedJob> = jobs
            .iter()
            .filter(|job| {
                filter.is_empty()
                    || job.description.to_lowercase().contains(&filter)
                    || job.image_path.to_lowercase().contains(&filter)
                    || self.sid_name(&job.identity).to_lowercase().contains(&filter)
            })
            .collect();
        if shown.is_empty() {
            return "<p class=\"more\">No job that you may see.</p>".into();
        }
        shown.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let rows: String = shown
            .iter()
            .map(|job| {
                format!(
                    "<li><button type=\"button\" fx-click=\"pick-job\" fx-value-id=\"{id}\" aria-selected=\"{picked}\"{off}>\
                     <span class=\"name\">{what}</span><span class=\"kind\">{state}</span><span class=\"owner\">{who}</span>\
                     <span class=\"num\">{progress}</span></button></li>",
                    id = escape(&job.id),
                    picked = self.job_picked.as_deref() == Some(job.id.as_str()),
                    off = if job.state == "running" || job.state == "created" { "" } else { " class=\"off\"" },
                    what = escape(&job_title(job)),
                    state = words::job_state(&job.state),
                    who = escape(&self.sid_name(&job.identity)),
                    progress = job.progress.as_ref().map(words::progress).unwrap_or_default(),
                )
            })
            .collect();
        format!("<ul class=\"entries\">{rows}</ul>")
    }

    /// What a SID string is called, as far as is known.
    fn sid_name(&self, sid: &str) -> String {
        sid.parse::<Sid>().ok().and_then(|sid| self.seen.names.get(&sid).cloned()).unwrap_or_else(|| sid.to_string())
    }

    fn jobs_notes(&self) -> String {
        "<p class=\"said\" role=\"status\">peinit lists only the jobs you may see: by default, those you asked \
         for, and every job to Administrators. One that ended stays a minute.</p>"
            .into()
    }

    fn job_details(&self) -> String {
        let Some(id) = &self.job_picked else {
            return "<aside class=\"details\"><p class=\"more\">Pick a job to see it in full.</p></aside>".into();
        };
        let Some(job) = self.job(id) else {
            return "<aside class=\"details\"><h2>A job</h2><p class=\"note\">It has gone: peinit keeps an ended job for a minute.</p></aside>".into();
        };
        let mut facts: Vec<(String, String)> = vec![("State".into(), words::job_state(&job.state).into())];
        if let Some(text) = &job.status_text {
            facts.push(("Says".into(), escape(text)));
        }
        if let Some(progress) = &job.progress {
            facts.push(("Progress".into(), escape(&words::progress(progress))));
        }
        facts.push(("Program".into(), format!("<code>{}</code>", escape(&job.image_path))));
        if let Some(pid) = job.pid.filter(|pid| self.proc(*pid).is_some()) {
            facts.push((
                "Process".into(),
                format!("<button type=\"button\" class=\"link\" fx-click=\"show-process\" fx-value-pid=\"{pid}\">{pid}</button>"),
            ));
        }
        facts.push(("Runs as".into(), escape(&self.sid_name(&job.identity))));
        facts.push(("Asked for by".into(), escape(&self.sid_name(&job.submitter))));
        for (label, at) in [("Started", &job.started_at), ("Ended", &job.ended_at)] {
            if let Some(at) = at.as_deref().and_then(|at| at.parse::<jiff::Timestamp>().ok()) {
                facts.push((label.into(), escape(&words::when(at.into()))));
            }
        }
        if let Some(code) = job.exit_code {
            facts.push(("Exit code".into(), code.to_string()));
        }
        if let Some(signal) = job.exit_signal {
            facts.push(("Ended by signal".into(), signal.to_string()));
        }
        let running = job.state == "running" || job.state == "created";
        let action = match &self.doing {
            Doing::AskingStopJob if running => format!(
                "<div class=\"asking\"><p>Stop {}? Everything in it ends.</p>\
                 <button type=\"button\" class=\"danger\" fx-click=\"stop-job-confirm\">Stop job</button>\
                 <button type=\"button\" fx-click=\"cancel\">Cancel</button></div>",
                escape(&format!("“{}”", job_title(job))),
            ),
            _ if !running => String::new(),
            _ if job.granted.iter().any(|right| right == "stop") => {
                "<div class=\"actions\"><button type=\"button\" fx-click=\"stop-job\">Stop job</button></div>".into()
            }
            _ => "<p class=\"may\">Its permissions don't let you stop it.</p>".into(),
        };
        let said = match &self.said {
            Some(Ok(done)) => format!("<p class=\"note\" role=\"status\">{}</p>", escape(done)),
            Some(Err(why)) => format!("<p class=\"note bad\" role=\"alert\">{}</p>", escape(why)),
            None => String::new(),
        };
        let dl: String = facts.iter().map(|(k, v)| format!("<dt>{k}</dt><dd>{v}</dd>")).collect();
        format!(
            "<aside class=\"details\"><h2>{title}</h2><p class=\"id\">Job {id}</p>{said}{action}<dl>{dl}</dl></aside>",
            title = escape(&job_title(job)),
            id = escape(&job.id),
        )
    }

    fn stop_job(&mut self, id: &str) {
        let done = ControlClient::connect_default()
            .map_err(|e| e.to_string())
            .and_then(|mut client| client.job_stop(id).map_err(|e| e.to_string()));
        self.said = Some(match done {
            Ok(_) => Ok("Asked peinit to stop the job.".into()),
            Err(why) => Err(format!("The job couldn't be stopped: {why}")),
        });
    }
}

/// What a job is called: its description, or its program.
fn job_title(job: &SubmittedJob) -> String {
    if job.description.is_empty() {
        job.image_path.rsplit('/').next().unwrap_or("A job").to_string()
    } else {
        job.description.clone()
    }
}

impl Live for Manager {
    fn render(&self, facts: &Facts) -> String {
        let tab = |grouping: Grouping, label: &str| {
            format!(
                "<button type=\"button\" class=\"tab\" fx-click=\"group\" fx-value-by=\"{label}\" aria-pressed=\"{}\">{label}</button>",
                self.grouping == grouping
            )
        };
        let sorter = |sort: Sort, label: &str, by: &str| {
            format!(
                "<button type=\"button\" class=\"sort\" fx-click=\"sort\" fx-value-by=\"{by}\" aria-pressed=\"{}\">{label}</button>",
                self.sort == sort
            )
        };
        let view = |view: View, label: &str| {
            format!(
                "<button type=\"button\" class=\"tab\" fx-click=\"view\" fx-value-by=\"{label}\" aria-pressed=\"{}\">{label}</button>",
                self.view == view
            )
        };
        let views = format!(
            "<div class=\"tabs\" role=\"group\" aria-label=\"Show\">{}{}{}</div>",
            view(View::Processes, "Processes"),
            view(View::Jobs, "Jobs"),
            view(View::SignedIn, "Signed in"),
        );
        let refresh = "<button type=\"button\" fx-click=\"refresh\" fx-key=\"F5\" title=\"Read again (F5)\">Refresh</button>";
        match self.view {
            View::Processes => format!(
                "<div class=\"bar\">{views}<span class=\"label\">Group by</span><div class=\"tabs\" role=\"group\" aria-label=\"Group by\">{service}{person}{none}</div>\
                 <input name=\"filter\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Find by name, PID, person or service\" aria-label=\"Find\">\
                 <label class=\"check\"><input type=\"checkbox\" name=\"kernel\"> Kernel threads</label>{refresh}</div>{notes}\
                 <div class=\"body\"><div class=\"list\"><div class=\"head\">{name}{pid}<span>Runs as</span>{cpu}{memory}</div>{listing}</div>{details}</div>{footer}",
                service = tab(Grouping::Service, "Service"),
                person = tab(Grouping::Person, "Person"),
                none = tab(Grouping::None, "None"),
                notes = self.notes(),
                name = sorter(Sort::Name, "Name", "name"),
                pid = sorter(Sort::Pid, "PID", "pid"),
                cpu = sorter(Sort::Cpu, "CPU", "cpu"),
                memory = sorter(Sort::Memory, "Memory", "memory"),
                listing = self.listing(facts.fields),
                details = self.details(),
                footer = self.footer(),
            ),
            View::Jobs => format!(
                "<div class=\"bar\">{views}\
                 <input name=\"filter\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Find by description, program or person\" aria-label=\"Find\">{refresh}</div>{notes}\
                 <div class=\"body\"><div class=\"list jobs\"><div class=\"head\"><span>Job</span><span>State</span><span>Runs as</span><span class=\"right\">Progress</span></div>{listing}</div>{details}</div>{footer}",
                notes = self.jobs_notes(),
                listing = self.jobs_listing(facts.fields),
                details = self.job_details(),
                footer = self.footer(),
            ),
            View::SignedIn => format!(
                "<div class=\"bar\">{views}\
                 <input name=\"filter\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Find by person or session\" aria-label=\"Find\">\
                 <label class=\"check\"><input type=\"checkbox\" name=\"services\"> Services' sessions</label>{refresh}</div>{notes}\
                 <div class=\"body\"><div class=\"list sessions\"><div class=\"head\"><span>Person</span><span>Signed in</span><span>Since</span><span class=\"right\">Processes</span></div>{listing}</div>{details}</div>{footer}",
                notes = self.sessions_notes(),
                listing = self.sessions_listing(facts.fields),
                details = self.session_details(),
                footer = self.footer(),
            ),
        }
    }

    fn event(&mut self, name: &str, value: &Value, _fields: &mut Fields) {
        let by = value["by"].as_str().unwrap_or("");
        match name {
            "view" => {
                self.view = match by {
                    "Signed in" => View::SignedIn,
                    "Jobs" => View::Jobs,
                    _ => View::Processes,
                };
                self.doing = Doing::Looking;
                self.said = None;
            }
            "pick-job" => {
                if let Some(id) = value["id"].as_str() {
                    if self.job_picked.as_deref() != Some(id) {
                        self.doing = Doing::Looking;
                        self.said = None;
                    }
                    self.job_picked = Some(id.to_string());
                }
            }
            "pick-session" => {
                if let Some(id) = value["id"].as_str().and_then(|id| id.parse().ok()) {
                    self.session = Some(id);
                }
            }
            "show-process" => {
                if let Some(pid) = value["pid"].as_str().and_then(|pid| pid.parse().ok()) {
                    self.view = View::Processes;
                    self.pick(pid);
                }
            }
            "group" => {
                self.grouping = match by {
                    "Person" => Grouping::Person,
                    "None" => Grouping::None,
                    _ => Grouping::Service,
                }
            }
            "sort" => {
                self.sort = match by {
                    "pid" => Sort::Pid,
                    "cpu" => Sort::Cpu,
                    "memory" => Sort::Memory,
                    _ => Sort::Name,
                }
            }
            "pick" => {
                if let Some(pid) = value["pid"].as_str().and_then(|pid| pid.parse().ok()) {
                    self.pick(pid);
                }
            }
            // What is read in the background, read now.
            "refresh" => {
                if let Some(window) = self.window.upgrade() {
                    std::thread::spawn(move || crate::look_now(&window));
                }
            }
            _ => self.act(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procs::{Owner, Stat};
    use peinit::client::ServicePart;
    use peios::token::SessionId;
    use std::time::Duration;

    fn stat(name: &str, ticks: u64) -> Stat {
        Stat { name: name.into(), state: 'S', ppid: 1, kernel: false, ticks, threads: 1, started: 0, resident: 100 }
    }

    fn proc(pid: u32, name: &str, service: Option<&str>, user: Option<&str>) -> Proc {
        Proc {
            pid,
            stat: Ok(stat(name, 0)),
            member: service.map(|s| CgroupMember::Service { service: s.into(), part: Some(ServicePart::Main) }),
            owner: match user {
                Some(sid) => Ok(Owner { user: sid.parse().unwrap(), session: SessionId(1000), integrity: None }),
                None => Err(Closed::Refused),
            },
            psb: None,
        }
    }

    fn window(procs: Vec<Proc>) -> Manager {
        Manager::new(Seen { procs, ..Seen::default() })
    }

    #[test]
    fn processes_group_under_their_service_and_the_rest_say_where_they_are() {
        let m = window(vec![
            proc(10, "sshd", Some("sshd"), Some("S-1-5-18")),
            proc(11, "sshd", Some("sshd"), Some("S-1-5-18")),
            proc(12, "bash", None, None),
        ]);
        let fields = Fields::default();
        let listing = m.listing(&fields);
        assert!(listing.contains("sshd <small>2</small>"), "{listing}");
        assert!(listing.contains("Not in a service <small>1</small>"), "{listing}");
        // The person can't see whose 12 is, and is told so.
        assert!(m.notes().contains("You can&#39;t see who runs 1 process") || m.notes().contains("You can't see who runs 1 process"));
    }

    #[test]
    fn by_person_a_process_whose_owner_is_closed_goes_under_someone_you_can_t_see() {
        let mut m = window(vec![proc(10, "sshd", Some("sshd"), Some("S-1-5-18")), proc(12, "bash", None, None)]);
        m.grouping = Grouping::Person;
        let listing = m.listing(&Fields::default());
        assert!(listing.contains("S-1-5-18 <small>1</small>"), "{listing}");
        assert!(listing.contains("Someone you can"), "{listing}");
    }

    #[test]
    fn a_protected_process_peinit_names_is_called_by_its_service() {
        let mut closed = proc(20, "", None, None);
        closed.stat = Err(Closed::Protected);
        closed.owner = Err(Closed::Protected);
        let mut m = window(vec![closed]);
        m.seen.mains.insert(20, "authd".into());
        let listing = m.listing(&Fields::default());
        assert!(listing.contains("authd <small>1</small>"), "{listing}");
        assert!(listing.contains("<span class=\"name\">authd</span>"), "{listing}");
    }

    #[test]
    fn the_filter_finds_by_name_pid_and_service() {
        let m = window(vec![proc(10, "sshd", Some("ssh"), Some("S-1-5-18")), proc(31, "bash", None, Some("S-1-5-18"))]);
        let p10 = m.proc(10).unwrap();
        assert!(m.matches(p10, "SSHD"));
        assert!(m.matches(p10, "ssh"));
        assert!(m.matches(m.proc(31).unwrap(), "31"));
        assert!(!m.matches(p10, "bash"));
    }

    fn session(id: u64, sid: &str, logon_type: u32) -> LogonSessionInfo {
        LogonSessionInfo {
            id: SessionId(id),
            user: sid.parse().unwrap(),
            logon_type,
            auth_package: "lpsd".into(),
            created_at: std::time::UNIX_EPOCH + Duration::from_secs(1_791_120_598),
        }
    }

    #[test]
    fn the_kernel_s_list_gives_each_session_its_processes_and_services_wait_to_be_asked_for() {
        let mut desktop = proc(40, "gexora", None, Some("S-1-5-21-1-2-3-1002"));
        desktop.member = Some(CgroupMember::Job("4f7a".into()));
        if let Ok(owner) = &mut desktop.owner {
            owner.session = SessionId(1007);
        }
        let mut m = window(vec![desktop]);
        m.seen.sessions = Ok(vec![
            session(1007, "S-1-5-21-1-2-3-1002", 10),
            session(1004, "S-1-5-80-1-2-3-4-5", 5),
            session(999, "S-1-5-18", 5),
        ]);
        m.view = View::SignedIn;
        let listing = m.sessions_listing(&Fields::default());
        assert!(listing.contains("On the desktop"), "{listing}");
        assert!(!listing.contains("S-1-5-80"), "a service's session waits to be asked for: {listing}");
        assert!(!listing.contains("S-1-5-18"), "{listing}");
        let signed = m.signed();
        assert_eq!(signed.iter().find(|s| s.id == 1007).unwrap().pids, vec![40]);
    }

    #[test]
    fn without_the_list_the_person_s_own_sessions_are_shown_and_why_is_said() {
        let mut own = proc(50, "sh", None, Some("S-1-5-21-1-2-3-1001"));
        if let Ok(owner) = &mut own.owner {
            owner.session = SessionId(1010);
        }
        let mut m = window(vec![own]);
        m.seen.sessions = Err("Only Administrators may see everyone who is signed in.".into());
        let signed = m.signed();
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].id, 1010);
        assert_eq!(signed[0].logon_type, None);
        assert!(m.sessions_notes().contains("Only Administrators"));
    }

    #[test]
    fn kernel_threads_are_left_out_until_asked_for() {
        let mut k = proc(2, "kthreadd", None, Some("S-1-5-18"));
        if let Ok(stat) = &mut k.stat {
            stat.kernel = true;
        }
        let m = window(vec![k]);
        assert!(m.listing(&Fields::default()).contains("No process matches"));
    }
}
