//! The machine as a whole: how busy its processors are, how much of its
//! memory is in use, and how fast each disk and network interface moves
//! data — now, and over the last two minutes.
//!
//! Everything comes from the kernel's own counters, which anyone may read:
//! `/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`, and
//! what `/sys` says of each disk and interface. A speed is the difference
//! between two looks over the time between them. Nothing is kept once the
//! window closes: a record over hours would be eventd's to keep.
//!
//! The graphs are drawn as the desktop's page can show them, as Event
//! Viewer's are: an SVG whose geometry is all in its attributes, stretched
//! over the graph, with colours the stylesheet gives by class.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::time::Instant;

use libgxwi::{Value, escape};

use crate::words;

/// How many looks are kept: two minutes, at a look every two seconds.
pub const KEPT: usize = 60;
/// What the left edge of a graph is, said.
const SPAN: &str = "2 minutes ago";

// ---- what the kernel counts

/// A processor's time, in clock ticks since the machine started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ticks {
    pub total: u64,
    /// Idle, or waiting on a disk with nothing else to run.
    pub idle: u64,
    /// Running the kernel, or answering an interrupt.
    pub kernel: u64,
}

/// What a disk has moved, in bytes, and for how long it has been busy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskCount {
    pub read: u64,
    pub written: u64,
    pub busy_ms: u64,
}

/// What an interface has moved, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetCount {
    pub received: u64,
    pub sent: u64,
}

/// `/proc/stat`'s processor lines: the whole machine's first, then each
/// logical processor's.
pub fn parse_cpus(text: &str) -> Vec<Ticks> {
    text.lines()
        .take_while(|line| line.starts_with("cpu"))
        .filter_map(|line| {
            // user nice system idle iowait irq softirq steal; guest time is
            // already counted in user and nice.
            let t: Vec<u64> = line.split_whitespace().skip(1).take(8).map(|v| v.parse().ok()).collect::<Option<_>>()?;
            (t.len() == 8).then(|| Ticks { total: t.iter().sum(), idle: t[3] + t[4], kernel: t[2] + t[5] + t[6] })
        })
        .collect()
}

/// The machine's memory, in bytes, from `/proc/meminfo`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Memory {
    pub total: u64,
    /// What could be given to programs now without swapping: the free, and
    /// the cache the kernel would give back.
    pub available: u64,
    pub free: u64,
    pub cached: u64,
    pub shared: u64,
    /// What programs have been promised, and how much may be promised.
    pub committed: u64,
    pub commit_limit: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl Memory {
    pub fn in_use(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
}

pub fn parse_meminfo(text: &str) -> Option<Memory> {
    let kib = |key: &str| {
        text.lines()
            .find_map(|line| {
                let (name, rest) = line.split_once(':')?;
                (name == key).then_some(())?;
                rest.trim().strip_suffix("kB")?.trim().parse::<u64>().ok()
            })
            .map(|n| n * 1024)
    };
    let or_none = |key: &str| kib(key).unwrap_or(0);
    Some(Memory {
        total: kib("MemTotal")?,
        available: kib("MemAvailable")?,
        free: or_none("MemFree"),
        cached: or_none("Cached") + or_none("Buffers") + or_none("SReclaimable"),
        shared: or_none("Shmem"),
        committed: or_none("Committed_AS"),
        commit_limit: or_none("CommitLimit"),
        swap_total: or_none("SwapTotal"),
        swap_free: or_none("SwapFree"),
    })
}

/// `/proc/diskstats`: each block device's bytes read and written, and the
/// milliseconds it spent busy. Sectors there are always 512 bytes.
pub fn parse_diskstats(text: &str) -> Vec<(String, DiskCount)> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let n = |i: usize| f.get(i)?.parse::<u64>().ok();
            Some((f.get(2)?.to_string(), DiskCount { read: n(5)? * 512, written: n(9)? * 512, busy_ms: n(12)? }))
        })
        .collect()
}

/// `/proc/net/dev`: each interface's bytes received and sent.
pub fn parse_net_dev(text: &str) -> Vec<(String, NetCount)> {
    text.lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let f: Vec<u64> = rest.split_whitespace().map(|v| v.parse().ok()).collect::<Option<_>>()?;
            Some((name.trim().to_string(), NetCount { received: *f.first()?, sent: *f.get(8)? }))
        })
        .collect()
}

/// `/proc/loadavg`: the load averages, and how many threads there are,
/// the kernel's own among them.
pub fn parse_loadavg(text: &str) -> Option<((f64, f64, f64), u64)> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let load = (f.first()?.parse().ok()?, f.get(1)?.parse().ok()?, f.get(2)?.parse().ok()?);
    let threads = f.get(3)?.split_once('/')?.1.parse().ok()?;
    Some((load, threads))
}

/// `/proc/cpuinfo`: the processor's model, and its speed now, averaged over
/// every logical processor.
pub fn parse_cpuinfo(text: &str) -> (Option<String>, Option<f64>) {
    let value = |line: &str, key: &str| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_string())
    };
    let model = text.lines().find_map(|line| value(line, "model name")).filter(|m| !m.is_empty());
    let speeds: Vec<f64> = text.lines().filter_map(|line| value(line, "cpu MHz")?.parse().ok()).collect();
    let mhz = (!speeds.is_empty()).then(|| speeds.iter().sum::<f64>() / speeds.len() as f64);
    (model, mhz)
}

// ---- what is there

/// A disk, as the machine has it.
#[derive(Debug, Clone, PartialEq)]
pub struct Disk {
    pub name: String,
    pub kind: DiskKind,
    pub capacity: u64,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskKind {
    Disk,
    Removable,
    Optical,
}

/// A network interface, as the machine has it.
#[derive(Debug, Clone, PartialEq)]
pub struct Net {
    pub name: String,
    pub kind: NetKind,
    /// `operstate`, as the kernel says it.
    pub state: Option<String>,
    pub address: Option<String>,
    /// Its link speed, in megabits a second, where it has one.
    pub speed: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    Ethernet,
    WiFi,
    Other,
}

/// Whether a block device is a disk a person would call one: not a loop
/// device, a RAM disk, a device-mapper view of another or a floppy drive.
pub fn is_disk(name: &str) -> bool {
    !["loop", "ram", "zram", "dm-", "fd", "md"].iter().any(|prefix| name.starts_with(prefix))
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|text| text.trim().to_string()).filter(|text| !text.is_empty())
}

fn disks() -> Vec<Disk> {
    let Ok(entries) = fs::read_dir("/sys/block") else { return Vec::new() };
    let mut disks: Vec<Disk> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let at = entry.path();
            let capacity = read_trimmed(&at.join("size"))?.parse::<u64>().ok()? * 512;
            (is_disk(&name) && capacity > 0).then_some(())?;
            let kind = if name.starts_with("sr") {
                DiskKind::Optical
            } else if read_trimmed(&at.join("removable")).as_deref() == Some("1") {
                DiskKind::Removable
            } else {
                DiskKind::Disk
            };
            Some(Disk { name, kind, capacity, model: read_trimmed(&at.join("device/model")) })
        })
        .collect();
    // The machine's own disks first, then what can be taken out.
    disks.sort_by(|a, b| (a.kind as u8, &a.name).cmp(&(b.kind as u8, &b.name)));
    disks
}

fn nets() -> Vec<Net> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else { return Vec::new() };
    let mut nets: Vec<Net> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let at = entry.path();
            // 772 is ARPHRD_LOOPBACK: the machine talking to itself.
            let link = read_trimmed(&at.join("type")).and_then(|t| t.parse::<u32>().ok());
            (link != Some(772)).then_some(())?;
            let kind = if at.join("wireless").exists() || at.join("phy80211").exists() {
                NetKind::WiFi
            } else if link == Some(1) {
                NetKind::Ethernet
            } else {
                NetKind::Other
            };
            Some(Net {
                name,
                kind,
                state: read_trimmed(&at.join("operstate")),
                address: read_trimmed(&at.join("address")).filter(|a| a != "00:00:00:00:00:00"),
                speed: read_trimmed(&at.join("speed")).and_then(|s| s.parse::<i64>().ok()).and_then(|s| u64::try_from(s).ok()).filter(|s| *s > 0),
            })
        })
        .collect();
    nets.sort_by(|a, b| a.name.cmp(&b.name));
    nets
}

// ---- one look

/// How busy a processor was between two looks, in percent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Busy {
    pub used: f64,
    /// The kernel's part of `used`.
    pub kernel: f64,
}

fn busy(before: Ticks, now: Ticks) -> Option<Busy> {
    let spent = now.total.checked_sub(before.total).filter(|spent| *spent > 0)?;
    let idle = now.idle.saturating_sub(before.idle).min(spent);
    let used = (spent - idle) as f64 * 100.0 / spent as f64;
    let kernel = now.kernel.saturating_sub(before.kernel) as f64 * 100.0 / spent as f64;
    Some(Busy { used, kernel: kernel.min(used) })
}

/// A disk's speeds between two looks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskRate {
    /// How much of the time it was busy, in percent.
    pub active: f64,
    /// Bytes a second.
    pub read: f64,
    pub write: f64,
}

/// An interface's speeds between two looks, in bytes a second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NetRate {
    pub received: f64,
    pub sent: f64,
}

/// What one look saw: how busy each thing was since the look before, and
/// the memory now.
#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub cpu: Option<Busy>,
    pub cpus: Vec<Option<f64>>,
    pub memory: Option<Memory>,
    pub disks: Vec<(String, DiskRate)>,
    pub nets: Vec<(String, NetRate)>,
}

/// Counters as read at one moment, for the next look to take the
/// difference from.
#[derive(Debug, Clone)]
struct Counters {
    at: Instant,
    cpus: Vec<Ticks>,
    disks: Vec<(String, DiskCount)>,
    nets: Vec<(String, NetCount)>,
}

fn between(before: &Counters, now: &Counters) -> Sample {
    let seconds = now.at.duration_since(before.at).as_secs_f64();
    let mut sample = Sample::default();
    if let (Some(was), Some(is)) = (before.cpus.first(), now.cpus.first()) {
        sample.cpu = busy(*was, *is);
    }
    sample.cpus = now
        .cpus
        .iter()
        .skip(1)
        .enumerate()
        .map(|(i, is)| busy(*before.cpus.get(i + 1)?, *is).map(|b| b.used))
        .collect();
    if seconds > 0.0 {
        let per_second = |was: u64, is: u64| is.saturating_sub(was) as f64 / seconds;
        sample.disks = now
            .disks
            .iter()
            .filter_map(|(name, is)| {
                let (_, was) = before.disks.iter().find(|(n, _)| n == name)?;
                let active = (is.busy_ms.saturating_sub(was.busy_ms) as f64 / (seconds * 10.0)).min(100.0);
                Some((name.clone(), DiskRate { active, read: per_second(was.read, is.read), write: per_second(was.written, is.written) }))
            })
            .collect();
        sample.nets = now
            .nets
            .iter()
            .filter_map(|(name, is)| {
                let (_, was) = before.nets.iter().find(|(n, _)| n == name)?;
                Some((name.clone(), NetRate { received: per_second(was.received, is.received), sent: per_second(was.sent, is.sent) }))
            })
            .collect();
    }
    sample
}

/// What is said of the machine but not graphed.
#[derive(Debug, Clone, Default)]
pub struct About {
    pub model: Option<String>,
    pub mhz: Option<f64>,
    pub logical: usize,
    pub load: Option<(f64, f64, f64)>,
    pub threads: Option<u64>,
    pub disks: Vec<Disk>,
    pub nets: Vec<Net>,
    /// What each disk has moved, and each interface, since the machine
    /// started.
    pub disk_totals: Vec<(String, DiskCount)>,
    pub net_totals: Vec<(String, NetCount)>,
}

/// One look at the machine as a whole.
#[derive(Debug, Clone, Default)]
pub struct Look {
    pub sample: Sample,
    pub about: About,
    /// What couldn't be read, and why.
    pub unread: Vec<String>,
}

/// Looks at the machine, keeping each look's counters for the next.
#[derive(Default)]
pub struct Reader {
    last: Option<Counters>,
}

impl Reader {
    pub fn look(&mut self) -> Look {
        let mut unread = Vec::new();
        let mut read = |path: &str| match fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(e) => {
                unread.push(format!("{path}: {}", words::io_error(&e)));
                None
            }
        };
        let stat = read("/proc/stat");
        let meminfo = read("/proc/meminfo");
        let diskstats = read("/proc/diskstats");
        let net_dev = read("/proc/net/dev");
        let loadavg = read("/proc/loadavg");
        let cpuinfo = read("/proc/cpuinfo");

        let disks = disks();
        let nets = nets();
        let now = Counters {
            at: Instant::now(),
            cpus: stat.as_deref().map(parse_cpus).unwrap_or_default(),
            disks: diskstats
                .as_deref()
                .map(parse_diskstats)
                .unwrap_or_default()
                .into_iter()
                .filter(|(name, _)| disks.iter().any(|d| &d.name == name))
                .collect(),
            nets: net_dev
                .as_deref()
                .map(parse_net_dev)
                .unwrap_or_default()
                .into_iter()
                .filter(|(name, _)| nets.iter().any(|n| &n.name == name))
                .collect(),
        };
        let mut sample = self.last.as_ref().map(|before| between(before, &now)).unwrap_or_default();
        sample.memory = meminfo.as_deref().and_then(parse_meminfo);
        let (model, mhz) = cpuinfo.as_deref().map(parse_cpuinfo).unwrap_or_default();
        let (load, threads) = match loadavg.as_deref().and_then(parse_loadavg) {
            Some((load, threads)) => (Some(load), Some(threads)),
            None => (None, None),
        };
        let about = About {
            model,
            mhz,
            logical: now.cpus.len().saturating_sub(1),
            load,
            threads,
            disks,
            nets,
            disk_totals: now.disks.clone(),
            net_totals: now.nets.clone(),
        };
        self.last = Some(now);
        Look { sample, about, unread }
    }
}

// ---- the view

/// Which resource is shown in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    Cpu,
    Memory,
    Disk(String),
    Net(String),
}

impl Resource {
    fn id(&self) -> String {
        match self {
            Resource::Cpu => "cpu".into(),
            Resource::Memory => "memory".into(),
            Resource::Disk(name) => format!("disk:{name}"),
            Resource::Net(name) => format!("net:{name}"),
        }
    }

    fn from_id(id: &str) -> Option<Resource> {
        match id.split_once(':') {
            None if id == "cpu" => Some(Resource::Cpu),
            None if id == "memory" => Some(Resource::Memory),
            Some(("disk", name)) => Some(Resource::Disk(name.into())),
            Some(("net", name)) => Some(Resource::Net(name.into())),
            _ => None,
        }
    }
}

/// The Performance view: the looks kept, what was last said of the
/// machine, and what is shown.
pub struct Perf {
    history: VecDeque<Sample>,
    last: Look,
    picked: Resource,
    /// The CPU graph drawn once for each logical processor, not once for
    /// the whole machine.
    each_cpu: bool,
}

impl Default for Perf {
    fn default() -> Perf {
        Perf { history: VecDeque::new(), last: Look::default(), picked: Resource::Cpu, each_cpu: false }
    }
}

/// One line on a graph: its class, which gives its colour, and a value for
/// each look kept, oldest first.
struct Line {
    class: &'static str,
    values: Vec<Option<f64>>,
}

/// The plotting area's height in the SVG's own units; its width is one unit
/// between each two looks.
const HEIGHT: f64 = 100.0;

/// The lines, drawn against `top` at the top edge, the newest look at the
/// right. The first line is filled beneath, as the main measure.
fn plot(lines: &[Line], top: f64) -> String {
    let width = (KEPT - 1) as f64;
    let y = |value: f64| HEIGHT - (value / top).clamp(0.0, 1.0) * HEIGHT;
    let mut drawn = String::new();
    for (index, line) in lines.iter().enumerate() {
        // Only the newest are drawn; fewer than are kept start further
        // right, so the graph fills from the right as time passes.
        let values = &line.values[line.values.len().saturating_sub(KEPT)..];
        let offset = KEPT - values.len();
        let mut runs: Vec<Vec<(f64, f64)>> = vec![Vec::new()];
        for (at, value) in values.iter().enumerate() {
            match value {
                Some(value) if value.is_finite() => {
                    runs.last_mut().expect("a run").push(((offset + at) as f64, y(*value)));
                }
                _ => runs.push(Vec::new()),
            }
        }
        for run in runs.iter().filter(|run| !run.is_empty()) {
            let points: Vec<String> = run.iter().map(|(x, y)| format!("{x:.2},{y:.2}")).collect();
            if index == 0 && run.len() > 1 {
                let (first, last) = (run[0].0, run[run.len() - 1].0);
                drawn += &format!(
                    "<polygon class=\"fill {}\" points=\"{first:.2},{HEIGHT:.2} {} {last:.2},{HEIGHT:.2}\"/>",
                    line.class,
                    points.join(" ")
                );
            }
            // A look alone between gaps is drawn as a dot: a line from the
            // point to itself, whose round ends are one.
            let points = if run.len() == 1 { format!("{0} {0}", points[0]) } else { points.join(" ") };
            drawn += &format!("<polyline class=\"{}\" points=\"{points}\"/>", line.class);
        }
    }
    // A square every twenty seconds and every quarter of the height.
    let across: String = [25.0, 50.0, 75.0]
        .iter()
        .map(|at| format!("<line class=\"grid\" x1=\"0\" y1=\"{at}\" x2=\"{width}\" y2=\"{at}\"/>"))
        .collect();
    let down: String = (1..6)
        .map(|n| {
            let x = width - (n * 10) as f64;
            format!("<line class=\"grid\" x1=\"{x}\" y1=\"0\" x2=\"{x}\" y2=\"{HEIGHT}\"/>")
        })
        .collect();
    format!(
        "<svg viewBox=\"0 0 {width} {HEIGHT}\" preserveAspectRatio=\"none\" aria-hidden=\"true\">{across}{down}{drawn}</svg>"
    )
}

/// A graph with what it measures, its scale and its two ends said.
fn graph(title: &str, top_said: &str, lines: &[Line], top: f64, class: &str) -> String {
    format!(
        "<figure class=\"graph {class}\"><figcaption><span>{}</span><span>{}</span></figcaption>\
         <div class=\"plot\">{}</div><div class=\"ends\"><span>{SPAN}</span><span>Now</span></div></figure>",
        escape(title),
        escape(top_said),
        plot(lines, top)
    )
}

/// The smallest round speed at or above `most`: 1, 2 or 5 times a power of
/// ten in one of `units`, each `base` times the one before. Returns it, and
/// it said.
fn round_top(most: f64, base: f64, units: &[&str]) -> (f64, String) {
    let most = most.max(base);
    for (power, unit) in units.iter().enumerate() {
        for step in [1u32, 2, 5, 10, 20, 50, 100, 200, 500] {
            let top = f64::from(step) * base.powi(power as i32);
            if top >= most {
                return (top, format!("{step} {unit}"));
            }
        }
    }
    (most, words::bytes(most as u64))
}

const BYTE_UNITS: [&str; 5] = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
const BIT_UNITS: [&str; 5] = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];

fn dl(rows: &[(&str, String)]) -> String {
    let rows: String = rows
        .iter()
        .map(|(what, said)| format!("<dt>{}</dt><dd>{}</dd>", escape(what), escape(said)))
        .collect();
    format!("<dl class=\"facts\">{rows}</dl>")
}

fn legend(items: &[(&str, &str)]) -> String {
    let items: String = items.iter().map(|(class, what)| format!("<li class=\"{class}\">{}</li>", escape(what))).collect();
    format!("<ul class=\"legend\">{items}</ul>")
}

const MEASURING: &str = "Measuring…";

impl Perf {
    pub fn heard(&mut self, look: Look) {
        self.history.push_back(look.sample.clone());
        while self.history.len() > KEPT {
            self.history.pop_front();
        }
        self.last = look;
        // A disk taken out, or an interface gone, is no longer shown.
        let there = match &self.picked {
            Resource::Disk(name) => self.last.about.disks.iter().any(|d| &d.name == name),
            Resource::Net(name) => self.last.about.nets.iter().any(|n| &n.name == name),
            _ => true,
        };
        if !there {
            self.picked = Resource::Cpu;
        }
    }

    /// Takes the events that are the Performance view's; says whether it did.
    pub fn event(&mut self, name: &str, value: &Value) -> bool {
        match name {
            "pick-resource" => {
                if let Some(picked) = value["id"].as_str().and_then(Resource::from_id) {
                    self.picked = picked;
                }
                true
            }
            "cpu-graph" => {
                self.each_cpu = value["by"].as_str() == Some("each");
                true
            }
            _ => false,
        }
    }

    fn latest(&self) -> Option<&Sample> {
        self.history.back()
    }

    fn series(&self, of: impl Fn(&Sample) -> Option<f64>) -> Vec<Option<f64>> {
        self.history.iter().map(of).collect()
    }

    fn disk_rate(sample: &Sample, name: &str) -> Option<DiskRate> {
        sample.disks.iter().find(|(n, _)| n == name).map(|(_, rate)| *rate)
    }

    fn net_rate(sample: &Sample, name: &str) -> Option<NetRate> {
        sample.nets.iter().find(|(n, _)| n == name).map(|(_, rate)| *rate)
    }

    fn disk_title(disk: &Disk) -> String {
        let kind = match disk.kind {
            DiskKind::Disk => "Disk",
            DiskKind::Removable => "Removable disk",
            DiskKind::Optical => "Optical drive",
        };
        format!("{kind} ({})", disk.name)
    }

    fn net_title(net: &Net) -> String {
        let kind = match net.kind {
            NetKind::Ethernet => "Ethernet",
            NetKind::WiFi => "Wi-Fi",
            NetKind::Other => "Network",
        };
        format!("{kind} ({})", net.name)
    }

    /// The whole view: every resource down the side, the one picked in full.
    /// `processes` and `uptime` are what the rest of the window has read.
    pub fn render(&self, processes: usize, uptime: Option<f64>) -> String {
        let unread = if self.last.unread.is_empty() {
            String::new()
        } else {
            format!(
                "<p class=\"said\">Not everything could be read: {}.</p>",
                escape(&self.last.unread.join("; "))
            )
        };
        let pane = match &self.picked {
            Resource::Cpu => self.cpu_pane(processes, uptime),
            Resource::Memory => self.memory_pane(),
            Resource::Disk(name) => self.disk_pane(name),
            Resource::Net(name) => self.net_pane(name),
        };
        format!(
            "<nav class=\"resources\" aria-label=\"Resources\">{}</nav><section class=\"resource\">{unread}{pane}</section>",
            self.resources()
        )
    }

    fn item(&self, resource: Resource, class: &str, name: &str, said: &str, lines: &[Line], top: f64) -> String {
        format!(
            "<button type=\"button\" class=\"item {class}\" fx-click=\"pick-resource\" fx-value-id=\"{}\" aria-pressed=\"{}\">\
             <div class=\"spark\">{}</div><span class=\"what\"><b>{}</b><small>{}</small></span></button>",
            escape(&resource.id()),
            self.picked == resource,
            plot(lines, top),
            escape(name),
            escape(said)
        )
    }

    fn resources(&self) -> String {
        let latest = self.latest();
        let mut items = String::new();

        let cpu = latest.and_then(|s| s.cpu).map(|b| words::share(b.used));
        let speed = self.last.about.mhz.map(words::ghz);
        let said = [cpu, speed].into_iter().flatten().collect::<Vec<_>>().join(" · ");
        let said = if said.is_empty() { MEASURING.into() } else { said };
        items += &self.item(Resource::Cpu, "k-cpu", "CPU", &said, &[Line { class: "k-cpu", values: self.series(|s| s.cpu.map(|b| b.used)) }], 100.0);

        let memory = latest.and_then(|s| s.memory);
        let said = memory
            .map(|m| format!("{} of {} ({})", words::bytes(m.in_use()), words::bytes(m.total), words::share(m.in_use() as f64 * 100.0 / m.total.max(1) as f64)))
            .unwrap_or_else(|| "Couldn't be read".into());
        let top = memory.map_or(1.0, |m| m.total as f64);
        items += &self.item(Resource::Memory, "k-memory", "Memory", &said, &[Line { class: "k-memory", values: self.series(|s| s.memory.map(|m| m.in_use() as f64)) }], top);

        for disk in &self.last.about.disks {
            let said = latest.and_then(|s| Self::disk_rate(s, &disk.name)).map_or_else(|| MEASURING.into(), |r| format!("{} active", words::share(r.active)));
            let line = Line { class: "k-disk", values: self.series(|s| Self::disk_rate(s, &disk.name).map(|r| r.active)) };
            items += &self.item(Resource::Disk(disk.name.clone()), "k-disk", &Self::disk_title(disk), &said, &[line], 100.0);
        }
        for net in &self.last.about.nets {
            let said = latest
                .and_then(|s| Self::net_rate(s, &net.name))
                .map_or_else(|| MEASURING.into(), |r| format!("Send {} · Receive {}", words::bits_per_second(r.sent), words::bits_per_second(r.received)));
            let received = self.series(|s| Self::net_rate(s, &net.name).map(|r| r.received * 8.0));
            let sent = self.series(|s| Self::net_rate(s, &net.name).map(|r| r.sent * 8.0));
            let most = received.iter().chain(sent.iter()).flatten().copied().fold(0.0, f64::max);
            let (top, _) = round_top(most, 1000.0, &BIT_UNITS);
            items += &self.item(
                Resource::Net(net.name.clone()),
                "k-net",
                &Self::net_title(net),
                &said,
                &[Line { class: "k-net", values: received }, Line { class: "k-net-2", values: sent }],
                top,
            );
        }
        items
    }

    fn cpu_pane(&self, processes: usize, uptime: Option<f64>) -> String {
        let about = &self.last.about;
        let latest = self.latest().and_then(|s| s.cpu);
        let tab = |by: &str, label: &str, pressed: bool| {
            format!("<button type=\"button\" class=\"tab\" fx-click=\"cpu-graph\" fx-value-by=\"{by}\" aria-pressed=\"{pressed}\">{label}</button>")
        };
        let choice = format!(
            "<div class=\"tabs\" role=\"group\" aria-label=\"Graph\">{}{}</div>",
            tab("all", "Overall", !self.each_cpu),
            tab("each", "Each processor", self.each_cpu)
        );
        let graphs = if self.each_cpu && about.logical > 0 {
            let each: String = (0..about.logical)
                .map(|i| {
                    let values = self.series(|s| s.cpus.get(i).copied().flatten());
                    let now = values.last().copied().flatten().map_or_else(|| MEASURING.into(), words::share);
                    format!(
                        "<figure class=\"small k-cpu\"><figcaption><span>CPU {i}</span><span>{}</span></figcaption><div class=\"plot\">{}</div></figure>",
                        escape(&now),
                        plot(&[Line { class: "k-cpu", values }], 100.0)
                    )
                })
                .collect();
            format!("<div class=\"each\">{each}</div>")
        } else {
            graph(
                "Utilisation",
                "100%",
                &[
                    Line { class: "k-cpu", values: self.series(|s| s.cpu.map(|b| b.used)) },
                    Line { class: "k-kernel", values: self.series(|s| s.cpu.map(|b| b.kernel)) },
                ],
                100.0,
                "k-cpu",
            ) + &legend(&[("k-cpu", "In use"), ("k-kernel", "Of which the kernel")])
        };
        let mut rows = vec![
            ("Utilisation", latest.map_or_else(|| MEASURING.into(), |b| format!("{}, the kernel {}", words::share(b.used), words::share(b.kernel)))),
        ];
        if let Some(mhz) = about.mhz {
            rows.push(("Speed", words::ghz(mhz)));
        }
        rows.push(("Processes", processes.to_string()));
        if let Some(threads) = about.threads {
            rows.push(("Threads", threads.to_string()));
        }
        if let Some(uptime) = uptime {
            rows.push(("Up for", words::running_for(uptime as u64)));
        }
        if let Some((one, five, fifteen)) = about.load {
            rows.push(("Load average", format!("{one:.2}, {five:.2}, {fifteen:.2}")));
        }
        rows.push(("Logical processors", about.logical.to_string()));
        format!(
            "<header><h2>CPU</h2><span class=\"model\">{}</span></header>{choice}{graphs}{}\
             <p class=\"note\">Threads count the kernel's own. The load average is how many threads were running or \
             waiting to, on average over the last 1, 5 and 15 minutes.</p>",
            escape(about.model.as_deref().unwrap_or("")),
            dl(&rows)
        )
    }

    fn memory_pane(&self) -> String {
        let Some(memory) = self.latest().and_then(|s| s.memory) else {
            return "<header><h2>Memory</h2></header><p class=\"note\">The machine's memory couldn't be read.</p>".into();
        };
        let total = memory.total.max(1) as f64;
        let in_use = memory.in_use();
        // In use, then the cache the kernel would give back, then the free:
        // together, all of it.
        let given_back = memory.available.saturating_sub(memory.free);
        let parts = [("k-memory", in_use), ("k-cached", given_back), ("k-free", memory.free.min(memory.available))];
        let mut at = 0.0;
        let bars: String = parts
            .iter()
            .map(|(class, bytes)| {
                let width = *bytes as f64 / total * 1000.0;
                let bar = format!("<rect class=\"{class}\" x=\"{at:.2}\" y=\"0\" width=\"{width:.2}\" height=\"10\"/>");
                at += width;
                bar
            })
            .collect();
        let composition = format!(
            "<figure class=\"composition\"><figcaption><span>Composition</span></figcaption>\
             <svg viewBox=\"0 0 1000 10\" preserveAspectRatio=\"none\" aria-hidden=\"true\">{bars}</svg></figure>{}",
            legend(&[("k-memory", "In use"), ("k-cached", "Cached, given back when needed"), ("k-free", "Free")])
        );
        let swap = if memory.swap_total == 0 {
            "None".to_string()
        } else {
            format!("{} of {} in use", words::bytes(memory.swap_total.saturating_sub(memory.swap_free)), words::bytes(memory.swap_total))
        };
        let rows = [
            ("In use", words::bytes(in_use)),
            ("Available", words::bytes(memory.available)),
            ("Cached", words::bytes(memory.cached)),
            ("Free", words::bytes(memory.free)),
            ("Committed", format!("{} of {}", words::bytes(memory.committed), words::bytes(memory.commit_limit))),
            ("Shared", words::bytes(memory.shared)),
            ("Swap", swap),
        ];
        format!(
            "<header><h2>Memory</h2><span class=\"model\">{}</span></header>{}{composition}{}\
             <p class=\"note\">Available is what programs could be given now: the free memory, and the cache the \
             kernel gives back when it is needed. Committed is what programs have been promised, against how much \
             may be.</p>",
            escape(&words::bytes(memory.total)),
            graph("In use", &words::bytes(memory.total), &[Line { class: "k-memory", values: self.series(|s| s.memory.map(|m| m.in_use() as f64)) }], total, "k-memory"),
            dl(&rows)
        )
    }

    fn disk_pane(&self, name: &str) -> String {
        let Some(disk) = self.last.about.disks.iter().find(|d| d.name == name) else {
            return String::new();
        };
        let latest = self.latest().and_then(|s| Self::disk_rate(s, name));
        let read = self.series(|s| Self::disk_rate(s, name).map(|r| r.read));
        let write = self.series(|s| Self::disk_rate(s, name).map(|r| r.write));
        let most = read.iter().chain(write.iter()).flatten().copied().fold(0.0, f64::max);
        let (top, top_said) = round_top(most, 1024.0, &BYTE_UNITS);
        let totals = self.last.about.disk_totals.iter().find(|(n, _)| n == name).map(|(_, c)| *c);
        let mut rows = vec![
            ("Active time", latest.map_or_else(|| MEASURING.into(), |r| words::share(r.active))),
            ("Read speed", latest.map_or_else(|| MEASURING.into(), |r| words::bytes_per_second(r.read))),
            ("Write speed", latest.map_or_else(|| MEASURING.into(), |r| words::bytes_per_second(r.write))),
            ("Capacity", words::bytes(disk.capacity)),
        ];
        if let Some(totals) = totals {
            rows.push(("Read since start", words::bytes(totals.read)));
            rows.push(("Written since start", words::bytes(totals.written)));
        }
        format!(
            "<header><h2>{}</h2><span class=\"model\">{}</span></header>{}{}{}{}",
            escape(&Self::disk_title(disk)),
            escape(disk.model.as_deref().unwrap_or("")),
            graph("Active time", "100%", &[Line { class: "k-disk", values: self.series(|s| Self::disk_rate(s, name).map(|r| r.active)) }], 100.0, "k-disk"),
            graph("Transfer rate", &top_said, &[Line { class: "k-disk", values: read }, Line { class: "k-disk-2", values: write }], top, "k-disk"),
            legend(&[("k-disk", "Read"), ("k-disk-2", "Write")]),
            dl(&rows)
        )
    }

    fn net_pane(&self, name: &str) -> String {
        let Some(net) = self.last.about.nets.iter().find(|n| n.name == name) else {
            return String::new();
        };
        let latest = self.latest().and_then(|s| Self::net_rate(s, name));
        let received = self.series(|s| Self::net_rate(s, name).map(|r| r.received * 8.0));
        let sent = self.series(|s| Self::net_rate(s, name).map(|r| r.sent * 8.0));
        let most = received.iter().chain(sent.iter()).flatten().copied().fold(0.0, f64::max);
        let (top, top_said) = round_top(most, 1000.0, &BIT_UNITS);
        let state = match net.state.as_deref() {
            Some("up") => "Connected".to_string(),
            Some("down") | Some("lowerlayerdown") => "Not connected".into(),
            Some("dormant") => "Waiting to connect".into(),
            Some(other) => other.to_string(),
            None => "Unknown".into(),
        };
        let mut rows = vec![
            ("Send", latest.map_or_else(|| MEASURING.into(), |r| words::bits_per_second(r.sent))),
            ("Receive", latest.map_or_else(|| MEASURING.into(), |r| words::bits_per_second(r.received))),
            ("State", state),
        ];
        if let Some(speed) = net.speed {
            rows.push(("Link speed", words::bits_per_second(speed as f64 * 1_000_000.0 / 8.0)));
        }
        if let Some(address) = &net.address {
            rows.push(("Hardware address", address.clone()));
        }
        if let Some((_, totals)) = self.last.about.net_totals.iter().find(|(n, _)| n == name) {
            rows.push(("Sent since start", words::bytes(totals.sent)));
            rows.push(("Received since start", words::bytes(totals.received)));
        }
        format!(
            "<header><h2>{}</h2></header>{}{}{}<p class=\"note\">Its addresses and settings are Network Manager's.</p>",
            escape(&Self::net_title(net)),
            graph("Throughput", &top_said, &[Line { class: "k-net", values: received }, Line { class: "k-net-2", values: sent }], top, "k-net"),
            legend(&[("k-net", "Receive"), ("k-net-2", "Send")]),
            dl(&rows)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const STAT: &str = "cpu  100 0 50 800 50 10 10 0 0 0\ncpu0 60 0 30 400 10 5 5 0 0 0\ncpu1 40 0 20 400 40 5 5 0 0 0\nintr 1 2 3\n";

    #[test]
    fn the_cpu_lines_are_read_the_machine_first() {
        let cpus = parse_cpus(STAT);
        assert_eq!(cpus.len(), 3);
        assert_eq!(cpus[0], Ticks { total: 1020, idle: 850, kernel: 70 });
        assert_eq!(cpus[2], Ticks { total: 510, idle: 440, kernel: 30 });
    }

    #[test]
    fn busy_is_the_share_not_idle_and_the_kernel_part_of_it() {
        let was = Ticks { total: 1000, idle: 800, kernel: 50 };
        let is = Ticks { total: 1100, idle: 850, kernel: 60 };
        assert_eq!(busy(was, is), Some(Busy { used: 50.0, kernel: 10.0 }));
        // No time passed: nothing to say.
        assert_eq!(busy(is, is), None);
    }

    #[test]
    fn memory_in_use_is_what_is_not_available() {
        let text = "MemTotal:  2000 kB\nMemFree:  500 kB\nMemAvailable:  1500 kB\nBuffers: 10 kB\nCached: 900 kB\nSReclaimable: 90 kB\nShmem: 100 kB\nCommitted_AS: 700 kB\nCommitLimit: 1000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n";
        let memory = parse_meminfo(text).unwrap();
        assert_eq!(memory.in_use(), 500 * 1024);
        assert_eq!(memory.cached, 1000 * 1024);
        assert_eq!(memory.committed, 700 * 1024);
        assert!(parse_meminfo("MemFree: 1 kB\n").is_none());
    }

    #[test]
    fn disks_and_interfaces_are_read_from_their_counters() {
        let disks = parse_diskstats(" 254       0 vda 421 5 200 28 7 0 100 3 0 20 28 0 0 0 0 0 0\n");
        assert_eq!(disks, vec![("vda".to_string(), DiskCount { read: 200 * 512, written: 100 * 512, busy_ms: 20 })]);
        let nets = parse_net_dev(
            "Inter-|   Receive                            |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes\n  eth0: 1820 15 0 0 0 0 0 0 18902 15 0 0 0 0 0 0\n",
        );
        assert_eq!(nets, vec![("eth0".to_string(), NetCount { received: 1820, sent: 18902 })]);
        assert_eq!(parse_loadavg("0.13 0.09 0.10 1/124 15626\n"), Some(((0.13, 0.09, 0.10), 124)));
        let (model, mhz) = parse_cpuinfo("model name\t: AMD Ryzen\ncpu MHz\t\t: 4000.0\nmodel name\t: AMD Ryzen\ncpu MHz\t\t: 5000.0\n");
        assert_eq!(model.as_deref(), Some("AMD Ryzen"));
        assert_eq!(mhz, Some(4500.0));
    }

    #[test]
    fn only_disks_a_person_would_call_one_are_shown() {
        assert!(is_disk("vda") && is_disk("sda") && is_disk("nvme0n1") && is_disk("sr0"));
        assert!(!is_disk("loop0") && !is_disk("dm-1") && !is_disk("fd0") && !is_disk("zram0"));
    }

    #[test]
    fn speeds_are_the_difference_over_the_time_between_looks() {
        let at = Instant::now();
        let before = Counters {
            at,
            cpus: parse_cpus(STAT),
            disks: vec![("vda".into(), DiskCount { read: 0, written: 0, busy_ms: 0 })],
            nets: vec![("eth0".into(), NetCount { received: 0, sent: 0 })],
        };
        let after = Counters {
            at: at + Duration::from_secs(2),
            cpus: parse_cpus(STAT),
            disks: vec![("vda".into(), DiskCount { read: 4096, written: 2048, busy_ms: 500 })],
            nets: vec![("eth0".into(), NetCount { received: 1000, sent: 250 })],
        };
        let sample = between(&before, &after);
        assert_eq!(sample.disks, vec![("vda".to_string(), DiskRate { active: 25.0, read: 2048.0, write: 1024.0 })]);
        assert_eq!(sample.nets, vec![("eth0".to_string(), NetRate { received: 500.0, sent: 125.0 })]);
        // The same ticks twice: no time passed on the processors.
        assert_eq!(sample.cpu, None);
        assert_eq!(sample.cpus, vec![None, None]);
    }

    #[test]
    fn a_graph_fills_from_the_right_and_leaves_gaps_where_nothing_was_read() {
        let svg = plot(&[Line { class: "k-cpu", values: vec![Some(50.0), None, Some(100.0)] }], 100.0);
        // Three looks of sixty: the newest at the right edge.
        assert!(svg.contains("<polyline class=\"k-cpu\" points=\"57.00,50.00 57.00,50.00\"/>"), "{svg}");
        assert!(svg.contains("<polyline class=\"k-cpu\" points=\"59.00,0.00 59.00,0.00\"/>"), "{svg}");
        // A run of two is filled beneath.
        let svg = plot(&[Line { class: "k-cpu", values: vec![Some(0.0), Some(100.0)] }], 100.0);
        assert!(svg.contains("<polygon class=\"fill k-cpu\" points=\"58.00,100.00 58.00,100.00 59.00,0.00 59.00,100.00\"/>"), "{svg}");
        // More than are kept: only the newest are drawn.
        let svg = plot(&[Line { class: "k-cpu", values: vec![Some(1.0); KEPT + 5] }], 100.0);
        assert!(svg.contains("<polyline class=\"k-cpu\" points=\"0.00,99.00 "), "{svg}");
        assert!(!svg.contains(",-") && !svg.contains("\"-") && !svg.contains(" -"), "{svg}");
    }

    #[test]
    fn a_speed_graph_tops_out_at_a_round_figure() {
        assert_eq!(round_top(0.0, 1024.0, &BYTE_UNITS), (1024.0, "1 KB/s".into()));
        assert_eq!(round_top(3000.0, 1024.0, &BYTE_UNITS), (5120.0, "5 KB/s".into()));
        assert_eq!(round_top(1.5e6, 1000.0, &BIT_UNITS), (2e6, "2 Mbps".into()));
    }

    fn look(cpu: f64) -> Look {
        Look {
            sample: Sample {
                cpu: Some(Busy { used: cpu, kernel: 1.0 }),
                cpus: vec![Some(cpu), Some(cpu)],
                memory: Some(Memory { total: 2 << 30, available: 1 << 30, free: 1 << 29, ..Memory::default() }),
                disks: vec![("vda".into(), DiskRate { active: 3.0, read: 2048.0, write: 0.0 })],
                nets: vec![("eth0".into(), NetRate { received: 1000.0, sent: 125.0 })],
            },
            about: About {
                model: Some("AMD Ryzen".into()),
                mhz: Some(4700.0),
                logical: 2,
                disks: vec![Disk { name: "vda".into(), kind: DiskKind::Disk, capacity: 1 << 30, model: None }],
                nets: vec![Net { name: "eth0".into(), kind: NetKind::Ethernet, state: Some("up".into()), address: Some("52:54:00:12:34:56".into()), speed: None }],
                ..About::default()
            },
            unread: Vec::new(),
        }
    }

    #[test]
    fn every_resource_is_listed_and_the_cpu_shown_first() {
        let mut perf = Perf::default();
        perf.heard(look(12.0));
        let html = perf.render(30, Some(4000.0));
        assert!(html.contains("<b>CPU</b><small>12% · 4.70 GHz</small>"), "{html}");
        assert!(html.contains("<b>Memory</b><small>1.0 GB of 2.0 GB (50%)</small>"), "{html}");
        assert!(html.contains("<b>Disk (vda)</b><small>3.0% active</small>"), "{html}");
        assert!(html.contains("<b>Ethernet (eth0)</b><small>Send 1.0 Kbps · Receive 8.0 Kbps</small>"), "{html}");
        assert!(html.contains("fx-value-id=\"cpu\" aria-pressed=\"true\""), "{html}");
        assert!(html.contains("<dt>Utilisation</dt><dd>12%, the kernel 1.0%</dd>"), "{html}");
        assert!(html.contains("<dt>Processes</dt><dd>30</dd>"), "{html}");
        assert!(html.contains("<dt>Up for</dt><dd>1 hour, 6 minutes</dd>"), "{html}");
    }

    #[test]
    fn a_resource_picked_is_shown_in_full_until_it_goes() {
        let mut perf = Perf::default();
        perf.heard(look(12.0));
        assert!(perf.event("pick-resource", &serde_json::json!({ "id": "net:eth0" })));
        let html = perf.render(30, None);
        assert!(html.contains("<h2>Ethernet (eth0)</h2>"), "{html}");
        assert!(html.contains("<dt>State</dt><dd>Connected</dd>"), "{html}");
        assert!(html.contains("<dt>Hardware address</dt><dd>52:54:00:12:34:56</dd>"), "{html}");
        // The interface gone, the CPU is shown again.
        let mut gone = look(12.0);
        gone.about.nets.clear();
        perf.heard(gone);
        assert!(perf.render(30, None).contains("<h2>CPU</h2>"));
        // Each processor, a graph of its own.
        perf.event("cpu-graph", &serde_json::json!({ "by": "each" }));
        let html = perf.render(30, None);
        assert!(html.contains("<span>CPU 1</span>"), "{html}");
    }

    #[test]
    fn only_the_last_two_minutes_are_kept() {
        let mut perf = Perf::default();
        for n in 0..KEPT + 10 {
            perf.heard(look(n as f64));
        }
        assert_eq!(perf.history.len(), KEPT);
        assert_eq!(perf.history.front().and_then(|s| s.cpu).map(|b| b.used), Some(10.0));
    }
}
