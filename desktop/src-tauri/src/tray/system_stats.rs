//! The CPU, memory, disk and network figures in the tray menu and the window's
//! Dashboard tab. The app reads them itself, since none of them needs the helper
//! or any privilege, and they keep showing while the helper is away.
//!
//! Reading is separate from spelling, so the rules for both are tested without
//! a menu. The menu rows are refreshed in place rather than through the tray
//! model: these figures change on nearly every sample, and rebuilding the whole
//! native menu each time would replace it under a user who has it open.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{Disks, Networks, System};
use tauri::State;

/// How many menu rows the figures take.
pub const ROW_COUNT: usize = 4;
/// Pause between samples.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(2);
/// A disk fills slowly and asking about it costs more than the other figures,
/// so it is read once every this many samples.
const DISK_EVERY_SAMPLES: u32 = 15;

/// How many samples the Dashboard can show: five minutes. They are kept here
/// rather than in the window, so the tab has its history the moment it opens.
const HISTORY_LEN: usize = 150;

/// Shown for a figure that cannot be read yet.
const UNKNOWN: &str = "\u{2014}";

/// Traffic over the last sample, in bytes per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rates {
    pub up: u64,
    pub down: u64,
}

/// One sample. A figure is `None` until it can be read: CPU load and network
/// rates are differences between two samples, so the first sample has neither.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reading {
    /// When it was read, in milliseconds since the Unix epoch.
    pub time_ms: u64,
    pub cpu_percent: Option<u8>,
    pub memory_percent: Option<u8>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub disk_percent: Option<u8>,
    pub disk_used_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub network: Option<Rates>,
}

/// The latest samples, oldest first.
#[derive(Default)]
pub struct SystemStatsHistory(Mutex<VecDeque<Reading>>);

impl SystemStatsHistory {
    pub fn push(&self, reading: Reading) {
        let mut samples = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if samples.len() == HISTORY_LEN {
            samples.pop_front();
        }
        samples.push_back(reading);
    }

    fn snapshot(&self) -> Vec<Reading> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).iter().copied().collect()
    }
}

/// The samples the Dashboard tab draws.
#[tauri::command]
pub fn system_stats_history(history: State<'_, SystemStatsHistory>) -> Vec<Reading> {
    history.snapshot()
}

/// The menu rows for a reading, top to bottom.
pub fn rows(reading: &Reading) -> [String; ROW_COUNT] {
    let percent = |value: Option<u8>| value.map_or_else(|| UNKNOWN.to_string(), |p| format!("{p}%"));
    let network = reading.network.map_or_else(
        || UNKNOWN.to_string(),
        |rates| format!("\u{2191} {}  \u{2193} {}", rate(rates.up), rate(rates.down)),
    );
    [
        format!("CPU  {}", percent(reading.cpu_percent)),
        format!("Memory  {}", percent(reading.memory_percent)),
        format!("Disk  {}", percent(reading.disk_percent)),
        format!("Network  {network}"),
    ]
}

/// Spells a rate the way macOS spells sizes: in powers of 1000.
fn rate(bytes_per_second: u64) -> String {
    let value = bytes_per_second as f64;
    match bytes_per_second {
        0..=999 => format!("{bytes_per_second} B/s"),
        1_000..=999_999 => format!("{:.0} KB/s", value / 1e3),
        1_000_000..=999_999_999 => format!("{:.1} MB/s", value / 1e6),
        _ => format!("{:.1} GB/s", value / 1e9),
    }
}

/// `used` as a whole percentage of `total`, or `None` without a total to compare to.
fn percent_of(used: u64, total: u64) -> Option<u8> {
    if total == 0 {
        return None;
    }
    let percent = (used as f64 / total as f64 * 100.0).round().clamp(0.0, 100.0);
    Some(percent as u8)
}

/// Whether `name` is `stem` alone or `stem` and a unit number, as in `lo0`.
fn is_unit_of(name: &str, stem: &str) -> bool {
    name.strip_prefix(stem).is_some_and(|unit| unit.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether an interface's traffic counts as the machine's. Loopback never
/// leaves it. A tunnel's traffic also crosses the physical interface it runs
/// over, and a bridge's crosses the one it forwards to, so counting those as
/// well would report the same bytes twice.
fn counts_as_traffic(interface: &str) -> bool {
    const UNITS: [&str; 7] = ["lo", "gif", "stf", "ap", "awdl", "llw", "anpi"];
    const PREFIXES: [&str; 13] = [
        "utun", "tun", "tap", "wg", "ppp", "ipsec", "bridge", "vmenet", "vnic", "br-", "docker", "veth", "virbr",
    ];
    const WINDOWS_NAMES: [&str; 5] = ["loopback", "vethernet", "wintun", "wireguard", "virtual"];
    let name = interface.to_ascii_lowercase();
    !(UNITS.iter().any(|stem| is_unit_of(&name, stem))
        || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || WINDOWS_NAMES.iter().any(|part| name.contains(part)))
}

/// Where the operating system lives: the volume whose fullness matters.
fn system_mount_point() -> String {
    if cfg!(windows) {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        format!("{drive}\\")
    } else {
        "/".to_string()
    }
}

/// Keeps what a reading is measured against: CPU counters and interface totals
/// from the previous sample.
pub struct Sampler {
    system: System,
    networks: Networks,
    last_network: Instant,
    samples: u32,
    disk: Option<DiskUse>,
}

/// How full the system volume is.
#[derive(Debug, Clone, Copy)]
struct DiskUse {
    used: u64,
    total: u64,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            networks: Networks::new_with_refreshed_list(),
            last_network: Instant::now(),
            samples: 0,
            disk: None,
        }
    }

    pub fn sample(&mut self) -> Reading {
        let first = self.samples == 0;
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        if self.samples.is_multiple_of(DISK_EVERY_SAMPLES) {
            self.disk = read_disk_use();
        }
        self.samples = self.samples.wrapping_add(1);
        let network = self.read_network();
        let (memory_used, memory_total) = (self.system.used_memory(), self.system.total_memory());
        let memory_percent = percent_of(memory_used, memory_total);
        Reading {
            time_ms: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_millis() as u64),
            cpu_percent: (!first).then(|| self.system.global_cpu_usage().round().clamp(0.0, 100.0) as u8),
            memory_percent,
            memory_used_bytes: memory_percent.map(|_| memory_used),
            memory_total_bytes: memory_percent.map(|_| memory_total),
            disk_percent: self.disk.and_then(|d| percent_of(d.used, d.total)),
            disk_used_bytes: self.disk.map(|d| d.used),
            disk_total_bytes: self.disk.map(|d| d.total),
            network: (!first).then_some(network),
        }
    }

    fn read_network(&mut self) -> Rates {
        self.networks.refresh(true);
        let elapsed = self.last_network.elapsed().as_secs_f64().max(0.001);
        self.last_network = Instant::now();
        let (mut up, mut down) = (0, 0);
        for (name, data) in &self.networks {
            if counts_as_traffic(name) {
                up += data.transmitted();
                down += data.received();
            }
        }
        Rates { up: (up as f64 / elapsed) as u64, down: (down as f64 / elapsed) as u64 }
    }
}

fn read_disk_use() -> Option<DiskUse> {
    let disks = Disks::new_with_refreshed_list();
    let mount_point = system_mount_point();
    let disk = disks.list().iter().find(|d| d.mount_point().to_str() == Some(mount_point.as_str()))?;
    let total = disk.total_space();
    (total > 0).then(|| DiskUse { used: total.saturating_sub(disk.available_space()), total })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spells_every_row() {
        let reading = Reading {
            cpu_percent: Some(61),
            memory_percent: Some(76),
            disk_percent: Some(90),
            network: Some(Rates { up: 1_000, down: 2_400 }),
            ..Reading::default()
        };
        assert_eq!(rows(&reading), ["CPU  61%", "Memory  76%", "Disk  90%", "Network  \u{2191} 1 KB/s  \u{2193} 2 KB/s"]);
    }

    #[test]
    fn a_figure_not_read_yet_reads_as_unknown() {
        assert_eq!(
            rows(&Reading::default()),
            ["CPU  \u{2014}", "Memory  \u{2014}", "Disk  \u{2014}", "Network  \u{2014}"]
        );
    }

    #[test]
    fn rates_change_unit_at_each_power_of_1000() {
        assert_eq!(rate(0), "0 B/s");
        assert_eq!(rate(999), "999 B/s");
        assert_eq!(rate(1_000), "1 KB/s");
        assert_eq!(rate(999_999), "1000 KB/s");
        assert_eq!(rate(1_500_000), "1.5 MB/s");
        assert_eq!(rate(2_500_000_000), "2.5 GB/s");
    }

    #[test]
    fn percentages_round_and_stay_in_range() {
        assert_eq!(percent_of(1, 3), Some(33));
        assert_eq!(percent_of(2, 3), Some(67));
        assert_eq!(percent_of(5, 4), Some(100));
        assert_eq!(percent_of(1, 0), None);
    }

    #[test]
    fn only_physical_interfaces_count_as_traffic() {
        for physical in ["en0", "en5", "eth0", "wlan0", "wlp3s0", "enp0s31f6", "Ethernet", "Wi-Fi", "Local Area Connection"] {
            assert!(counts_as_traffic(physical), "{physical}");
        }
        for virtual_one in [
            "lo", "lo0", "utun6", "tun0", "wg0", "bridge100", "vmenet0", "awdl0", "llw0", "ap1", "gif0", "stf0", "docker0",
            "veth12ab", "virbr0", "br-1a2b", "Loopback Pseudo-Interface 1", "vEthernet (WSL)", "RouteWise wintun",
        ] {
            assert!(!counts_as_traffic(virtual_one), "{virtual_one}");
        }
    }

    #[test]
    fn history_keeps_the_latest_samples_oldest_first() {
        let history = SystemStatsHistory::default();
        for i in 0..(HISTORY_LEN as u64 + 3) {
            history.push(Reading { time_ms: i, ..Reading::default() });
        }
        let samples = history.snapshot();
        assert_eq!(samples.len(), HISTORY_LEN);
        assert_eq!(samples[0].time_ms, 3);
        assert_eq!(samples[HISTORY_LEN - 1].time_ms, HISTORY_LEN as u64 + 2);
    }

    #[test]
    fn a_reading_reaches_the_window_in_camel_case() {
        let reading = Reading {
            cpu_percent: Some(5),
            network: Some(Rates { up: 1, down: 2 }),
            ..Reading::default()
        };
        let json = serde_json::to_value(reading).expect("a reading serializes");
        assert_eq!(json["cpuPercent"], 5);
        assert_eq!(json["memoryUsedBytes"], serde_json::Value::Null);
        assert_eq!(json["network"]["down"], 2);
    }

    #[test]
    fn samples_this_machine() {
        let mut sampler = Sampler::new();
        let first = sampler.sample();
        assert_eq!(first.cpu_percent, None, "load is a difference between two samples");
        assert_eq!(first.network, None, "rates are a difference between two samples");
        assert!(first.memory_percent.is_some_and(|p| p > 0));
        assert!(first.disk_percent.is_some_and(|p| p > 0), "the system volume must be found");
        assert!(first.time_ms > 0);
        assert!(first.memory_used_bytes.is_some_and(|used| used <= first.memory_total_bytes.unwrap_or(0)));
        assert!(first.disk_used_bytes.is_some_and(|used| used <= first.disk_total_bytes.unwrap_or(0)));

        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        let second = sampler.sample();
        assert!(second.cpu_percent.is_some());
        assert!(second.network.is_some());
    }
}
