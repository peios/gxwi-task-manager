//! Task Manager: what is running on this machine now, as far as the person
//! looking may see it — every process, which service or job it belongs to,
//! who it runs as, and how it is protected.
//!
//! It reads `/proc` as whoever is looking, and asks peinit's control socket
//! which services and jobs there are and authd's identity socket who a SID
//! is, with no more authority than they have. What is defined, rather than
//! what is running, is Services Manager's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use gxwi_sd_editor::names::Names;
use libgxwi::{App, Surface};
use peinit::client::{ControlClient, State};

mod manager;
mod procs;
mod words;

use manager::{Manager, Seen};

// What this program looks like, to whatever lists it. The icon itself is
// `gxwi-task-manager.svg` at the repo root, installed as the base theme's.
libgxwi::icon!(b"dev.peios.gxwi-task-manager");

/// How often the machine is looked at again. Nothing tells a program when a
/// process starts or ends, or how much CPU it used, so the window looks.
const LOOK_AGAIN: Duration = Duration::from_secs(2);

/// What a look keeps for the next one: each process's CPU ticks and the
/// machine's, to work out the share of each in between, and the names learnt
/// from authd so far.
struct Looker {
    ticks: HashMap<u32, u64>,
    machine: Option<(u64, u64)>,
    names: Names,
    /// Which service peinit said a process was the main process of, for the
    /// processes whose own cgroup is closed to the person. Asked once each.
    mains: HashMap<u32, Option<String>>,
}

static LOOKER: Mutex<Option<Looker>> = Mutex::new(None);

/// One look at the machine.
fn look() -> Seen {
    let mut guard = LOOKER.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let looker = guard.get_or_insert_with(|| Looker {
        ticks: HashMap::new(),
        machine: None,
        names: Names::new(),
        mains: HashMap::new(),
    });
    let procs = procs::read_all();
    let machine = procs::machine_ticks();
    let (shares, cpu) = match (looker.machine, machine) {
        (Some((was_total, was_idle)), Some((total, idle))) if total > was_total => {
            let spent = total - was_total;
            let busy = spent.saturating_sub(idle.saturating_sub(was_idle));
            (procs::shares(&looker.ticks, &procs, spent), Some(busy as f64 * 100.0 / spent as f64))
        }
        _ => (HashMap::new(), None),
    };
    looker.machine = machine;
    looker.ticks = procs
        .iter()
        .filter_map(|p| Some((p.pid, p.stat.as_ref().ok()?.ticks)))
        .collect();

    // Each connection is one batch: peinit closes one left idle.
    let mut control = ControlClient::connect_default().map_err(|e| e.to_string());
    let services = control
        .as_mut()
        .map_err(|e| e.clone())
        .and_then(|client| client.services().map_err(|e| e.to_string()));
    let jobs = control
        .as_mut()
        .map_err(|e| e.clone())
        .and_then(|client| client.jobs().map_err(|e| e.to_string()));

    // A process whose cgroup the person can't read, such as a protected
    // one, may still be a service's main process, which peinit will say.
    looker.mains.retain(|pid, _| procs.iter().any(|p| p.pid == *pid));
    let unknown: Vec<u32> = procs
        .iter()
        .filter(|p| p.member.is_none() && p.stat.is_err() && !looker.mains.contains_key(&p.pid))
        .map(|p| p.pid)
        .collect();
    if !unknown.is_empty()
        && let (Ok(client), Ok(services)) = (control.as_mut(), &services)
    {
        for summary in services.iter().filter(|s| s.state == State::Active || s.state == State::Reloading) {
            if let Ok(status) = client.status_of(&summary.service)
                && let Some(pid) = status.job.and_then(|job| job.pid)
                && unknown.contains(&pid)
            {
                looker.mains.insert(pid, Some(summary.service.clone()));
            }
        }
        for pid in unknown {
            looker.mains.entry(pid).or_insert(None);
        }
    }

    let mut names = HashMap::new();
    for owner in procs.iter().filter_map(|p| p.owner.as_ref().ok()) {
        names.entry(owner.user).or_insert_with(|| {
            looker.names.learn(&owner.user);
            looker.names.of(&owner.user)
        });
    }
    // A service runs as a SID made from its name, which nobody holds a
    // name for: it is called by the service.
    if let Ok(services) = &services {
        for summary in services {
            if let Some(sid) = libauthd_policy::service_sid::of(&summary.service)
                && names.get(&sid).is_some_and(|name| *name == sid.to_string())
            {
                names.insert(sid, format!("{} service", summary.service));
            }
        }
    }

    Seen {
        procs,
        shares,
        cpu,
        memory: procs::memory(),
        services,
        jobs,
        mains: looker.mains.iter().filter_map(|(pid, s)| Some((*pid, s.clone()?))).collect(),
        names,
        uptime: std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|text| text.split_whitespace().next()?.parse().ok()),
        // SAFETY: sysconf reads a constant.
        ticks_per_second: u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100),
        page_size: u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096),
    }
}

/// Look now, and show what was seen.
pub fn look_now(window: &Arc<Surface<Manager>>) {
    let seen = look();
    window.update(|manager, _| manager.heard(seen));
}

/// Looks again every little while, for as long as the window is there.
fn look_again(window: Weak<Surface<Manager>>) {
    loop {
        std::thread::sleep(LOOK_AGAIN);
        let Some(shown) = window.upgrade() else { return };
        look_now(&shown);
    }
}

fn main() {
    if std::env::args().nth(1).is_some() {
        eprintln!("gxwi-task-manager: usage: gxwi-task-manager");
        std::process::exit(64);
    }
    let mut app = match App::connect() {
        Ok(app) => app,
        Err(e) => {
            eprintln!("gxwi-task-manager: no desktop to open on: {e}");
            std::process::exit(1);
        }
    };
    app.stylesheet("/gxwi-task-manager.css", include_str!("gxwi-task-manager.css"));
    let window = app.live("Task Manager", Manager::new(look()));
    let aside = Arc::downgrade(&window);
    window.update(|manager, _| manager.window = aside.clone());
    std::thread::spawn(move || look_again(aside));
    if let Err(e) = app.run() {
        eprintln!("gxwi-task-manager: {e}");
        std::process::exit(1);
    }
}
