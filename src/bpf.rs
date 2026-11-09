//! eBPF backends: a kprobe on the WireGuard receive path (preferred) and a
//! tc-ingress fallback that needs no kernel BTF.

use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, Map, MapCore, MapFlags, TcHook, TC_INGRESS};

mod kprobe_skel {
    include!(concat!(env!("OUT_DIR"), "/kprobe.skel.rs"));
}

mod tc_skel {
    include!(concat!(env!("OUT_DIR"), "/tc.skel.rs"));
}

use kprobe_skel::KprobeSkelBuilder;
use tc_skel::TcSkelBuilder;

/// A loaded backend. Owns everything needed to keep the BPF program and the
/// stats map alive; dropping it detaches the hooks.
pub enum Backend<'obj> {
    Kprobe {
        skel: kprobe_skel::KprobeSkel<'obj>,
        // Kept alive for the whole session; dropping detaches the probe.
        #[allow(dead_code)]
        link: Link,
        symbol: &'static str,
    },
    Tc {
        skel: tc_skel::TcSkel<'obj>,
        hooks: Vec<TcHook>,
    },
}

impl<'obj> Backend<'obj> {
    pub fn stats_map(&self) -> &Map<'obj> {
        match self {
            Backend::Kprobe { skel, .. } => &skel.maps.stats,
            Backend::Tc { skel, .. } => &skel.maps.stats,
        }
    }

    pub fn description(&self) -> String {
        match self {
            Backend::Kprobe { symbol, .. } => format!("kprobe on {symbol}"),
            Backend::Tc { hooks, .. } => {
                format!("tc ingress on {} device(s)", hooks.len())
            }
        }
    }
}

impl<'obj> Drop for Backend<'obj> {
    /// Remove the tc hooks so that a stopped wgmon leaves no filters behind.
    /// (libbpf-rs does not do this on its own.)
    fn drop(&mut self) {
        if let Backend::Tc { hooks, .. } = self {
            for hook in hooks.iter_mut() {
                let _ = hook.destroy();
            }
        }
    }
}

/// Does the given symbol exist in the kernel (module or vmlinux)?
fn has_symbol(name: &str) -> bool {
    let Ok(kallsyms) = fs::read_to_string("/proc/kallsyms") else {
        return false;
    };
    kallsyms.lines().any(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        parts.len() >= 3 && parts[2] == name
    })
}

fn load_kprobe<'obj>(
    open_object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    enabled_ports: &[u16],
    symbol: &KprobeSymbol,
) -> Result<Backend<'obj>> {
    let builder = KprobeSkelBuilder::default();
    let open_skel = builder
        .open(open_object)
        .context("failed to open kprobe skeleton (needs kernel BTF for sk_buff)")?;
    let skel = open_skel.load().context("failed to load kprobe program")?;

    for port in enabled_ports {
        let mut key = [0u8; 4];
        key[0..2].copy_from_slice(&port.to_le_bytes());
        skel.maps.ports.update(&key, &[1u8], MapFlags::ANY)?;
    }

    // Prefer the post-validation probe (data already points at the
    // WireGuard header); fall back to the entry-point probe.
    let chosen = match symbol {
        KprobeSymbol::ConsumeData => "wg_packet_consume_data",
        KprobeSymbol::Receive => "wg_packet_receive",
        KprobeSymbol::Auto => {
            if has_symbol("wg_packet_consume_data") {
                "wg_packet_consume_data"
            } else {
                "wg_packet_receive"
            }
        }
    };

    let link = match chosen {
        "wg_packet_consume_data" => skel.progs.wgmon_consume_data.attach(),
        _ => skel.progs.wgmon_receive.attach(),
    }
    .with_context(|| format!("failed to attach kprobe to {chosen}"))?;

    // The other program stays loaded but unattached: libbpf only
    // auto-attaches when `Skel::attach()` is called, which we do not do.
    let symbol: &'static str = if chosen == "wg_packet_consume_data" {
        "wg_packet_consume_data"
    } else {
        "wg_packet_receive"
    };
    Ok(Backend::Kprobe { skel, link, symbol })
}

fn load_tc<'obj>(
    open_object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ifindexes: &[i32],
    enabled_ports: &[u16],
) -> Result<Backend<'obj>> {
    let builder = TcSkelBuilder::default();
    let open_skel = builder
        .open(open_object)
        .context("failed to open tc skeleton")?;
    let skel = open_skel.load().context("failed to load tc program")?;

    for port in enabled_ports {
        let mut key = [0u8; 4];
        key[0..2].copy_from_slice(&port.to_le_bytes());
        skel.maps.ports.update(&key, &[1u8], MapFlags::ANY)?;
    }

    let mut hooks = Vec::new();
    for &ifindex in ifindexes {
        let mut hook = TcHook::new(skel.progs.wgmon_tc.as_fd());
        hook.ifindex(ifindex)
            .attach_point(TC_INGRESS)
            .priority(1)
            .create()?;
        hook.replace(true).attach()?;
        hooks.push(hook);
    }

    Ok(Backend::Tc { skel, hooks })
}

pub enum Hook {
    Auto,
    Kprobe,
    Tc,
}

pub enum KprobeSymbol {
    Auto,
    ConsumeData,
    Receive,
}

/// Load the requested backend. Two object storages are provided because the
/// skeleton borrows its storage for its whole lifetime: `open_object` for
/// the kprobe skeleton and `open_object_tc` for the tc skeleton. Only one
/// of them is actually used.
pub fn load<'obj>(
    open_object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    open_object_tc: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    hook: &Hook,
    tc_ifindexes: &[i32],
    ports: &[u16],
    symbol: &KprobeSymbol,
) -> Result<Backend<'obj>> {
    match hook {
        Hook::Kprobe => load_kprobe(open_object, ports, symbol),
        Hook::Tc => {
            if tc_ifindexes.is_empty() {
                bail!("tc backend needs at least one physical device (--dev)");
            }
            load_tc(open_object_tc, tc_ifindexes, ports)
        }
        Hook::Auto => match load_kprobe(open_object, ports, symbol) {
            Ok(b) => Ok(b),
            Err(e) => {
                if tc_ifindexes.is_empty() {
                    bail!(
                        "kprobe backend unavailable ({e}); pass --dev <iface> to use the tc fallback"
                    );
                }
                eprintln!("kprobe backend unavailable ({e}); falling back to tc");
                load_tc(open_object_tc, tc_ifindexes, ports)
            }
        },
    }
}
