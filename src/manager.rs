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
use std::time::{Duration, Instant};

use libgxwi::{Facts, Fields, Live, Surface, Value, escape};
use peinit::client::{CgroupMember, SubmittedJob, Summary};
use peios::security::Sid;

use crate::procs::{self, Closed, Proc};
use crate::{ending, words};

pub struct Manager {
    pub window: Weak<Surface<Manager>>,
    seen: Seen,
    grouping: Grouping,
    sort: Sort,
    picked: Option<u32>,
    /// The picked process's command line, read when it was picked.
    command: Option<(u32, Result<String, Closed>)>,
    /// Whether this person may end the picked process, or why not.
    may_end: Option<(u32, Result<(), String>)>,
    doing: Doing,
    /// What came of the last thing done: what was done, or why it wasn't.
    said: Option<Result<String, String>>,
}

/// What is being done to the picked process.
enum Doing {
    Looking,
    /// Asking before it is ended.
    AskingEnd,
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
            uptime: None,
            ticks_per_second: 100,
            page_size: 4096,
        }
    }
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
            grouping: Grouping::Service,
            sort: Sort::Name,
            picked: None,
            command: None,
            may_end: None,
            doing: Doing::Looking,
            said: None,
        }
    }

    pub fn picked(&self) -> Option<u32> {
        self.picked
    }

    pub fn heard(&mut self, seen: Seen) {
        self.seen = seen;
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
                facts.push(("Belongs to".into(), format!("{} — {}", escape(&shown), words::part(*part))));
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
    }

    /// Whether the picked process is a service's main process, which peinit
    /// restarts by its policy when it ends unasked.
    fn main_of_service(&self, p: &Proc) -> Option<String> {
        match &p.member {
            Some(CgroupMember::Service { service, part: Some(peinit::client::ServicePart::Main) }) => Some(service.clone()),
            None => self.seen.mains.get(&p.pid).cloned(),
            _ => None,
        }
    }

    /// What may be done to the picked process, and what is being done.
    fn actions(&self, p: &Proc) -> String {
        let said = match &self.said {
            Some(Ok(done)) => format!("<p class=\"note\" role=\"status\">{}</p>", escape(done)),
            Some(Err(why)) => format!("<p class=\"note bad\" role=\"alert\">{}</p>", escape(why)),
            None => String::new(),
        };
        let service = self.main_of_service(p);
        let body = match &self.doing {
            Doing::AskingEnd => format!(
                "<div class=\"asking\"><p>End {name}? Anything it hasn't saved is lost.{service}</p>\
                 <button type=\"button\" class=\"danger\" fx-click=\"end-confirm\">End process</button>\
                 <button type=\"button\" fx-click=\"cancel\">Cancel</button></div>",
                name = escape(&self.name(p)),
                service = match &service {
                    Some(_) => " It is a service's main process: peinit will take it as having crashed, and may start it again.",
                    None => "",
                },
            ),
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
            _ => match self.may_end.as_ref().filter(|(pid, _)| *pid == p.pid) {
                Some((_, Ok(()))) => {
                    "<div class=\"actions\"><button type=\"button\" fx-click=\"end\">End process</button></div>".into()
                }
                Some((_, Err(why))) => format!("<p class=\"may\">{}</p>", escape(why)),
                None => String::new(),
            },
        };
        format!("{said}{body}")
    }

    fn act(&mut self, name: &str) {
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
            "cancel" => self.doing = Doing::Looking,
            _ => {}
        }
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
        format!(
            "<div class=\"bar\"><span class=\"label\">Group by</span><div class=\"tabs\" role=\"group\" aria-label=\"Group by\">{service}{person}{none}</div>\
             <input name=\"filter\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Find by name, PID, person or service\" aria-label=\"Find\">\
             <label class=\"check\"><input type=\"checkbox\" name=\"kernel\"> Kernel threads</label>\
             <button type=\"button\" fx-click=\"refresh\" fx-key=\"F5\" title=\"Read again (F5)\">Refresh</button></div>{notes}\
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
        )
    }

    fn event(&mut self, name: &str, value: &Value, _fields: &mut Fields) {
        let by = value["by"].as_str().unwrap_or("");
        match name {
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
