//! System metrics collector.
//!
//! Periodically executes commands over SSH to collect CPU, memory, disk, and
//! load average metrics from the remote host. Supports both Linux and macOS.
//! Internal to the service module.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use super::session::SshInput;
use super::types::*;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const EXEC_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawns a background metrics collector that periodically runs commands over SSH.
///
/// Returns a cancel flag that can be set to stop the collector.
pub(super) fn spawn(
    input_tx: mpsc::UnboundedSender<SshInput>,
    mut cmd_rx: mpsc::UnboundedReceiver<MetricsCommand>,
    event_tx: mpsc::UnboundedSender<MetricsEvent>,
) -> Arc<AtomicBool> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        // Detect OS first
        let os_type = detect_os(&input_tx).await;

        // Previous CPU sample for delta calculation (Linux only)
        let mut prev_cpu: Option<CpuSample> = None;

        loop {
            if cancel_clone.load(Ordering::Relaxed) {
                break;
            }

            // Collect metrics
            match collect_metrics(&input_tx, &os_type, &mut prev_cpu).await {
                Ok(metrics) => {
                    if event_tx.send(MetricsEvent::Updated(metrics)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if event_tx.send(MetricsEvent::Error(e)).is_err() {
                        break;
                    }
                }
            }

            // Wait for next poll or a manual refresh command
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(MetricsCommand::Refresh) => {
                            // Immediate refresh -- skip sleep, loop back
                        }
                        Some(MetricsCommand::Stop) | None => break,
                    }
                }
            }
        }
    });

    cancel
}

/// Raw CPU time counters from /proc/stat
#[derive(Debug, Clone)]
struct CpuSample {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuSample {
    fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }
}

/// Execute a command over SSH and return stdout
async fn ssh_exec(
    input_tx: &mpsc::UnboundedSender<SshInput>,
    command: &str,
) -> Result<String, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    input_tx
        .send(SshInput::Exec {
            command: command.to_string(),
            reply: reply_tx,
        })
        .map_err(|_| "SSH session disconnected".to_string())?;

    match tokio::time::timeout(EXEC_TIMEOUT, reply_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("SSH session closed".to_string()),
        Err(_) => Err("Command timed out".to_string()),
    }
}

/// Detect the remote OS type
async fn detect_os(input_tx: &mpsc::UnboundedSender<SshInput>) -> OsType {
    match ssh_exec(input_tx, "uname -s").await {
        Ok(output) => {
            let name = output.trim();
            if name.eq_ignore_ascii_case("linux") {
                OsType::Linux
            } else if name.eq_ignore_ascii_case("darwin") {
                OsType::MacOS
            } else {
                OsType::Unknown(name.to_string())
            }
        }
        Err(_) => OsType::Unknown("detection failed".to_string()),
    }
}

/// Collect all system metrics in a single pass
async fn collect_metrics(
    input_tx: &mpsc::UnboundedSender<SshInput>,
    os_type: &OsType,
    prev_cpu: &mut Option<CpuSample>,
) -> Result<SystemMetrics, String> {
    match os_type {
        OsType::Linux => collect_linux(input_tx, prev_cpu).await,
        OsType::MacOS => collect_macos(input_tx).await,
        OsType::Unknown(name) => Err(format!("Unsupported OS: {}", name)),
    }
}

// ---------------------------------------------------------------------------
// Linux metrics collection
// ---------------------------------------------------------------------------

async fn collect_linux(
    input_tx: &mpsc::UnboundedSender<SshInput>,
    prev_cpu: &mut Option<CpuSample>,
) -> Result<SystemMetrics, String> {
    // Single combined command to minimize SSH round-trips
    let output = ssh_exec(
        input_tx,
        "cat /proc/stat | head -1 && echo '---SECTION---' && \
         cat /proc/meminfo && echo '---SECTION---' && \
         cat /proc/loadavg && echo '---SECTION---' && \
         cat /proc/uptime && echo '---SECTION---' && \
         df -P && echo '---SECTION---' && \
         hostname",
    )
    .await?;

    let sections: Vec<&str> = output.split("---SECTION---").collect();
    if sections.len() < 6 {
        return Err("Unexpected output format from Linux metrics command".to_string());
    }

    // CPU
    let cpu_sample = parse_linux_cpu(sections[0].trim())?;
    let cpu_usage = if let Some(prev) = prev_cpu {
        let total_delta = cpu_sample.total().saturating_sub(prev.total());
        let busy_delta = cpu_sample.busy().saturating_sub(prev.busy());
        if total_delta > 0 {
            (busy_delta as f64 / total_delta as f64) * 100.0
        } else {
            0.0
        }
    } else {
        // First sample -- show instantaneous usage
        let total = cpu_sample.total();
        if total > 0 {
            (cpu_sample.busy() as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    };
    *prev_cpu = Some(cpu_sample);

    // Memory
    let memory = parse_linux_meminfo(sections[1].trim())?;

    // Load average
    let load_average = parse_linux_loadavg(sections[2].trim())?;

    // Uptime
    let uptime_secs = parse_linux_uptime(sections[3].trim())?;

    // Disks
    let disks = parse_df_output(sections[4].trim());

    // Hostname
    let hostname = sections[5].trim().to_string();

    Ok(SystemMetrics {
        cpu_usage,
        memory,
        disks,
        load_average,
        uptime_secs,
        os_type: OsType::Linux,
        hostname,
        timestamp: Instant::now(),
    })
}

fn parse_linux_cpu(line: &str) -> Result<CpuSample, String> {
    // "cpu  USER NICE SYSTEM IDLE IOWAIT IRQ SOFTIRQ STEAL ..."
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 || parts[0] != "cpu" {
        return Err("Failed to parse /proc/stat".to_string());
    }
    let p = |i: usize| -> u64 { parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0) };
    Ok(CpuSample {
        user: p(1),
        nice: p(2),
        system: p(3),
        idle: p(4),
        iowait: p(5),
        irq: p(6),
        softirq: p(7),
        steal: p(8),
    })
}

fn parse_linux_meminfo(text: &str) -> Result<MemoryInfo, String> {
    let mut total = 0u64;
    let mut available = 0u64;
    let mut free = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let val: u64 = parts[1].parse().unwrap_or(0) * 1024; // kB -> bytes
        match parts[0] {
            "MemTotal:" => total = val,
            "MemAvailable:" => available = val,
            "MemFree:" => free = val,
            "Buffers:" => buffers = val,
            "Cached:" => cached = val,
            _ => {}
        }
    }

    // If MemAvailable is not present (very old kernels), estimate it
    if available == 0 {
        available = free + buffers + cached;
    }

    Ok(MemoryInfo {
        total,
        used: total.saturating_sub(available),
        available,
    })
}

fn parse_linux_loadavg(text: &str) -> Result<[f64; 3], String> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Failed to parse /proc/loadavg".to_string());
    }
    let p = |i: usize| -> f64 { parts[i].parse().unwrap_or(0.0) };
    Ok([p(0), p(1), p(2)])
}

fn parse_linux_uptime(text: &str) -> Result<u64, String> {
    // "12345.67 98765.43"
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Failed to parse /proc/uptime".to_string());
    }
    Ok(parts[0].parse::<f64>().unwrap_or(0.0) as u64)
}

// ---------------------------------------------------------------------------
// macOS metrics collection
// ---------------------------------------------------------------------------

async fn collect_macos(
    input_tx: &mpsc::UnboundedSender<SshInput>,
) -> Result<SystemMetrics, String> {
    let output = ssh_exec(
        input_tx,
        "vm_stat && echo '---SECTION---' && \
         sysctl hw.memsize && echo '---SECTION---' && \
         sysctl -n vm.loadavg && echo '---SECTION---' && \
         sysctl kern.boottime && echo '---SECTION---' && \
         top -l 1 -n 0 | head -4 && echo '---SECTION---' && \
         df -P && echo '---SECTION---' && \
         hostname",
    )
    .await?;

    let sections: Vec<&str> = output.split("---SECTION---").collect();
    if sections.len() < 7 {
        return Err("Unexpected output format from macOS metrics command".to_string());
    }

    // Memory
    let (memory, _page_size) = parse_macos_vmstat(sections[0].trim(), sections[1].trim())?;

    // Load average
    let load_average = parse_macos_loadavg(sections[2].trim())?;

    // Uptime (from boot time)
    let uptime_secs = parse_macos_boottime(sections[3].trim())?;

    // CPU (from top output)
    let cpu_usage = parse_macos_cpu(sections[4].trim());

    // Disks
    let disks = parse_df_output(sections[5].trim());

    // Hostname
    let hostname = sections[6].trim().to_string();

    Ok(SystemMetrics {
        cpu_usage,
        memory,
        disks,
        load_average,
        uptime_secs,
        os_type: OsType::MacOS,
        hostname,
        timestamp: Instant::now(),
    })
}

fn parse_macos_vmstat(vmstat: &str, memsize: &str) -> Result<(MemoryInfo, u64), String> {
    // Parse page size from vm_stat header
    let page_size: u64 = vmstat
        .lines()
        .next()
        .and_then(|l| {
            // "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
            l.rsplit("page size of ")
                .next()
                .and_then(|s| s.trim_end_matches(|c: char| !c.is_ascii_digit()).parse().ok())
        })
        .unwrap_or(4096);

    let mut free_pages = 0u64;
    let mut active_pages = 0u64;
    let mut inactive_pages = 0u64;
    let mut speculative_pages = 0u64;
    let mut wired_pages = 0u64;
    let mut purgeable_pages = 0u64;

    for line in vmstat.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() < 2 {
            continue;
        }
        let val: u64 = parts[1].trim().trim_end_matches('.').parse().unwrap_or(0);
        match parts[0].trim() {
            "Pages free" => free_pages = val,
            "Pages active" => active_pages = val,
            "Pages inactive" => inactive_pages = val,
            "Pages speculative" => speculative_pages = val,
            "Pages wired down" => wired_pages = val,
            "Pages purgeable" => purgeable_pages = val,
            _ => {}
        }
    }

    // Total memory from sysctl hw.memsize
    let total: u64 = memsize
        .split(':')
        .next_back()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    let used = (active_pages + wired_pages) * page_size;
    let available =
        (free_pages + inactive_pages + speculative_pages + purgeable_pages) * page_size;

    Ok((
        MemoryInfo {
            total,
            used,
            available: total
                .saturating_sub(used)
                .min(available.max(total.saturating_sub(used))),
        },
        page_size,
    ))
}

fn parse_macos_loadavg(text: &str) -> Result<[f64; 3], String> {
    // "{ 0.52 1.03 0.87 }" or just "0.52 1.03 0.87"
    let cleaned = text
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Failed to parse macOS load average".to_string());
    }
    let p = |i: usize| -> f64 { parts[i].parse().unwrap_or(0.0) };
    Ok([p(0), p(1), p(2)])
}

fn parse_macos_boottime(text: &str) -> Result<u64, String> {
    // "kern.boottime: { sec = 1712345678, usec = 0 }"
    if let Some(sec_str) = text.split("sec = ").nth(1)
        && let Some(sec_val) = sec_str.split(',').next()
    {
        let boot_time: u64 = sec_val.trim().parse().unwrap_or(0);
        if boot_time > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            return Ok(now.saturating_sub(boot_time));
        }
    }
    Ok(0)
}

fn parse_macos_cpu(top_output: &str) -> f64 {
    // Look for "CPU usage: X% user, Y% sys, Z% idle"
    for line in top_output.lines() {
        if line.contains("CPU usage") {
            // Extract idle percentage and compute usage
            if let Some(idle_part) = line.split("idle").next() {
                let parts: Vec<&str> = idle_part.split(',').collect();
                if let Some(last) = parts.last() {
                    let idle: f64 = last
                        .trim()
                        .trim_end_matches('%')
                        .trim()
                        .parse()
                        .unwrap_or(0.0);
                    return 100.0 - idle;
                }
            }
        }
    }
    0.0
}

// ---------------------------------------------------------------------------
// Shared parsers
// ---------------------------------------------------------------------------

/// Parse `df -P` output (POSIX format, works on both Linux and macOS)
fn parse_df_output(text: &str) -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    for line in text.lines().skip(1) {
        // skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let mountpoint = parts[5];
        // Skip pseudo-filesystems
        if mountpoint.starts_with("/dev")
            || mountpoint.starts_with("/sys")
            || mountpoint.starts_with("/proc")
            || mountpoint.starts_with("/run")
        {
            continue;
        }
        // df -P reports 1024-byte blocks
        let total: u64 = parts[1].parse().unwrap_or(0) * 1024;
        let used: u64 = parts[2].parse().unwrap_or(0) * 1024;
        let available: u64 = parts[3].parse().unwrap_or(0) * 1024;

        // Skip tiny filesystems (< 100MB)
        if total < 100 * 1024 * 1024 {
            continue;
        }

        disks.push(DiskInfo {
            filesystem: parts[0].to_string(),
            mountpoint: mountpoint.to_string(),
            total,
            used,
            available,
        });
    }
    disks
}
