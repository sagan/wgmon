mod bpf;
mod render;
mod stats;
mod wg;

use clap::{Parser, ValueEnum};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use render::{Config as RenderConfig, Format, Row};
use stats::{Config as LossConfig, Tracker};

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
enum Hook {
    Auto,
    Kprobe,
    Tc,
    Socket,
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
enum OutFormat {
    Table,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum KprobeSymbol {
    Auto,
    ConsumeData,
    Receive,
}

/// Passively measure WireGuard ingress link quality (packet loss) with eBPF.
///
/// For every Type-4 WireGuard packet the receiver sees the sender's
/// monotonic counter in plaintext. The eBPF program records the highest
/// counter and the number of packets per session; the userspace daemon
/// derives loss from the counter deltas each window, so packet reordering
/// inside a window is not mistaken for loss and no traffic is ever sent.
#[derive(Parser, Debug)]
#[command(name = "wgmon", version, about)]
struct Args {
    /// WireGuard interface(s) to monitor (repeatable).
    /// Default: all interfaces reported by `wg show interfaces`.
    #[arg(short, long)]
    interface: Vec<String>,

    /// Observation window in seconds.
    #[arg(long, default_value_t = 5)]
    interval: u64,

    /// Print one report and exit.
    #[arg(long, default_value_t = false)]
    once: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,

    /// Disable ANSI colors.
    #[arg(long, default_value_t = false)]
    no_color: bool,

    /// eBPF backend. `auto` prefers the kprobe on the WireGuard receive
    /// path, falls back to tc ingress, and then to an AF_PACKET socket
    /// filter when tc clsact is unavailable (e.g. OpenWrt without extra modules).
    #[arg(long, value_enum, default_value_t = Hook::Auto)]
    hook: Hook,

    /// WireGuard symbol for the kprobe backend (for troubleshooting only).
    #[arg(long, value_enum, default_value_t = KprobeSymbol::Auto, hide = true)]
    kprobe_symbol: KprobeSymbol,

    /// Physical interface(s) for the tc and socket filter backends (repeatable).
    /// Default for `auto`: inferred from each peer's endpoint route.
    #[arg(long)]
    dev: Vec<String>,

    /// Only windows with at least this many expected packets are trusted.
    #[arg(long, default_value_t = 100)]
    min_packets: u64,

    /// Loss ratio above which a window counts as bad (e.g. 0.05 = 5%).
    #[arg(long, default_value_t = 0.05)]
    loss_threshold: f64,

    /// Consecutive bad windows before going DEGRADED.
    #[arg(long, default_value_t = 2)]
    degrade_after: u32,

    /// Consecutive good windows before leaving DEGRADED.
    #[arg(long, default_value_t = 3)]
    recover_after: u32,

    /// Delete map entries idle for longer than this many seconds.
    #[arg(long, default_value_t = 600)]
    gc_secs: u64,

    /// Enable verbose diagnostics.
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

impl From<OutFormat> for Format {
    fn from(f: OutFormat) -> Self {
        match f {
            OutFormat::Table => Format::Table,
            OutFormat::Json => Format::Json,
        }
    }
}

impl From<Hook> for bpf::Hook {
    fn from(h: Hook) -> Self {
        match h {
            Hook::Auto => bpf::Hook::Auto,
            Hook::Kprobe => bpf::Hook::Kprobe,
            Hook::Tc => bpf::Hook::Tc,
            Hook::Socket => bpf::Hook::Socket,
        }
    }
}

impl From<KprobeSymbol> for bpf::KprobeSymbol {
    fn from(s: KprobeSymbol) -> Self {
        match s {
            KprobeSymbol::Auto => bpf::KprobeSymbol::Auto,
            KprobeSymbol::ConsumeData => bpf::KprobeSymbol::ConsumeData,
            KprobeSymbol::Receive => bpf::KprobeSymbol::Receive,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        eprintln!("wgmon: args={args:?}");
    }

    // ---- Discover WireGuard interfaces ---------------------------------
    let mut ifaces = wg::discover().context("failed to discover WireGuard interfaces")?;
    if !args.interface.is_empty() {
        let want: std::collections::HashSet<&str> =
            args.interface.iter().map(String::as_str).collect();
        ifaces.retain(|i| want.contains(i.name.as_str()));
        if ifaces.is_empty() {
            anyhow::bail!(
                "none of the requested interfaces were found: {:?}",
                args.interface
            );
        }
    }
    let ports: Vec<u16> = ifaces.iter().map(|i| i.port).collect();
    if args.verbose {
        eprintln!(
            "wgmon: monitoring {:?}",
            ifaces.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
    }

    // ---- Physical devices for tc / socket filter -----------------------
    let dev_ifindexes: Vec<i32> = match args.hook {
        Hook::Tc | Hook::Socket | Hook::Auto => {
            let devs = match wg::tc_devices(&ifaces, &args.dev) {
                Ok(d) => d,
                Err(e) => {
                    if args.hook == Hook::Tc {
                        eprintln!("wgmon: {e}");
                    }
                    Vec::new()
                }
            };
            let mut idxs = Vec::new();
            for d in &devs {
                match wg::interface_index(d) {
                    Ok(i) => idxs.push(i),
                    Err(e) => eprintln!("wgmon: cannot resolve device {d}: {e}"),
                }
            }
            idxs
        }
        Hook::Kprobe => Vec::new(),
    };

    // ---- Load the eBPF backend ------------------------------------------
    let mut open_object = MaybeUninit::uninit();
    let mut open_object_tc = MaybeUninit::uninit();
    let mut open_object_sock = MaybeUninit::uninit();
    let hook: bpf::Hook = args.hook.into();
    let symbol: bpf::KprobeSymbol = args.kprobe_symbol.into();
    let backend = bpf::load(
        &mut open_object,
        &mut open_object_tc,
        &mut open_object_sock,
        &hook,
        &dev_ifindexes,
        &ports,
        &symbol,
    )
    .context("failed to load eBPF backend")?;
    if args.verbose {
        eprintln!("wgmon: backend={}", backend.description());
    }

    // ---- Reporting loop --------------------------------------------------
    let stopped = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&stopped);
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::Relaxed);
        })?;
    }

    let cfg = LossConfig {
        min_packets: args.min_packets,
        loss_threshold: args.loss_threshold,
        degrade_after: args.degrade_after,
        recover_after: args.recover_after,
    };

    let mut trackers: HashMap<String, Tracker> = HashMap::new();
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let render_cfg = RenderConfig {
        format: args.format.into(),
        color: !args.no_color && std::io::stdout().is_terminal(),
        window_secs: args.interval,
    };
    render::print_header(&render_cfg, &backend.description(), started_unix);

    let interval = Duration::from_secs(args.interval.max(1));
    loop {
        if stopped.load(Ordering::Relaxed) {
            break;
        }
        let snap = stats::snapshot(backend.stats_map())?;
        let now_ns = stats::monotonic_ns();

        let mut rows: Vec<Row> = Vec::new();
        for iface in &ifaces {
            let entry = trackers
                .entry(iface.name.clone())
                .or_insert_with(|| Tracker::new(now_ns));
            let report = entry.step(now_ns, &snap, iface.port, &cfg);
            rows.push(Row {
                iface: iface.name.clone(),
                port: iface.port,
                report,
            });
        }

        if args.once {
            render::report_once(&rows, &render_cfg)?;
            break;
        }
        render::report(&rows, &render_cfg)?;

        if let Err(e) = stats::gc_stale(backend.stats_map(), args.gc_secs) {
            if args.verbose {
                eprintln!("wgmon: gc failed: {e}");
            }
        }

        let started = std::time::Instant::now();
        while !stopped.load(Ordering::Relaxed) && started.elapsed() < interval {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    if args.format == OutFormat::Table {
        println!("wgmon: stopped");
    } else {
        eprintln!("wgmon: stopped");
    }
    Ok(())
}
