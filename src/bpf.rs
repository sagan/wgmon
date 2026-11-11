//! eBPF backends: a kprobe on the WireGuard receive path (preferred), a
//! tc-ingress fallback that needs no kernel BTF, and an AF_PACKET socket_filter
//! fallback that requires neither kernel BTF nor tc clsact qdisc support.

use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, Map, MapCore, MapFlags, TcHook, TC_INGRESS};

mod kprobe_skel {
    include!(concat!(env!("OUT_DIR"), "/kprobe.skel.rs"));
}

mod tc_skel {
    include!(concat!(env!("OUT_DIR"), "/tc.skel.rs"));
}

mod sock_skel {
    include!(concat!(env!("OUT_DIR"), "/sock.skel.rs"));
}

use kprobe_skel::KprobeSkelBuilder;
use sock_skel::SockSkelBuilder;
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
    Socket {
        skel: sock_skel::SockSkel<'obj>,
        #[allow(dead_code)]
        sockets: Vec<OwnedFd>,
        dev_count: usize,
    },
}

impl<'obj> Backend<'obj> {
    pub fn stats_map(&self) -> &Map<'obj> {
        match self {
            Backend::Kprobe { skel, .. } => &skel.maps.stats,
            Backend::Tc { skel, .. } => &skel.maps.stats,
            Backend::Socket { skel, .. } => &skel.maps.stats,
        }
    }

    pub fn description(&self) -> String {
        match self {
            Backend::Kprobe { symbol, .. } => format!("kprobe on {symbol}"),
            Backend::Tc { hooks, .. } => {
                format!("tc ingress on {} device(s)", hooks.len())
            }
            Backend::Socket { dev_count, .. } => {
                if *dev_count == 0 {
                    "socket filter on all devices".to_string()
                } else {
                    format!("socket filter on {dev_count} device(s)")
                }
            }
        }
    }
}

impl<'obj> Drop for Backend<'obj> {
    /// Remove the tc hooks so that a stopped wgmon leaves no filters behind.
    /// (libbpf-rs does not do this on its own.)
    /// Sockets in Backend::Socket are automatically closed on drop, which detaches
    /// the socket filters in the kernel.
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

fn load_socket<'obj>(
    open_object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ifindexes: &[i32],
    enabled_ports: &[u16],
) -> Result<Backend<'obj>> {
    let builder = SockSkelBuilder::default();
    let open_skel = builder
        .open(open_object)
        .context("failed to open socket filter skeleton")?;
    let skel = open_skel
        .load()
        .context("failed to load socket filter program")?;

    for port in enabled_ports {
        let mut key = [0u8; 4];
        key[0..2].copy_from_slice(&port.to_le_bytes());
        skel.maps.ports.update(&key, &[1u8], MapFlags::ANY)?;
    }

    let prog_fd = skel.progs.wgmon_sock.as_fd().as_raw_fd();
    let mut sockets = Vec::new();

    let targets: Vec<i32> = if ifindexes.is_empty() {
        vec![0]
    } else {
        ifindexes.to_vec()
    };

    for &ifindex in &targets {
        let sock = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if sock < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET socket");
        }
        let sock_fd = unsafe { OwnedFd::from_raw_fd(sock) };

        // Best effort: instruct kernel to ignore outgoing packets on this socket
        #[cfg(target_os = "linux")]
        {
            const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
            let val: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    sock_fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    PACKET_IGNORE_OUTGOING,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        if ifindex > 0 {
            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            sll.sll_ifindex = ifindex;
            let ret = unsafe {
                libc::bind(
                    sock_fd.as_raw_fd(),
                    &sll as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to bind AF_PACKET socket to ifindex {ifindex}"));
            }
        }

        let ret = unsafe {
            libc::setsockopt(
                sock_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_BPF,
                &prog_fd as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to attach BPF socket filter (SO_ATTACH_BPF)");
        }

        sockets.push(sock_fd);
    }

    Ok(Backend::Socket {
        skel,
        sockets,
        dev_count: if ifindexes.is_empty() { 0 } else { ifindexes.len() },
    })
}

pub enum Hook {
    Auto,
    Kprobe,
    Tc,
    Socket,
}

pub enum KprobeSymbol {
    Auto,
    ConsumeData,
    Receive,
}

/// Load the requested backend.
pub fn load<'obj>(
    open_object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    open_object_tc: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    open_object_sock: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    hook: &Hook,
    dev_ifindexes: &[i32],
    ports: &[u16],
    symbol: &KprobeSymbol,
) -> Result<Backend<'obj>> {
    match hook {
        Hook::Kprobe => load_kprobe(open_object, ports, symbol),
        Hook::Tc => {
            if dev_ifindexes.is_empty() {
                bail!("tc backend needs at least one physical device (--dev)");
            }
            load_tc(open_object_tc, dev_ifindexes, ports)
        }
        Hook::Socket => load_socket(open_object_sock, dev_ifindexes, ports),
        Hook::Auto => match load_kprobe(open_object, ports, symbol) {
            Ok(b) => Ok(b),
            Err(e_kprobe) => {
                eprintln!("kprobe backend unavailable ({e_kprobe}); falling back to tc");
                if !dev_ifindexes.is_empty() {
                    match load_tc(open_object_tc, dev_ifindexes, ports) {
                        Ok(b) => return Ok(b),
                        Err(e_tc) => {
                            eprintln!("tc backend unavailable ({e_tc}); falling back to socket filter");
                        }
                    }
                } else {
                    eprintln!("tc backend skipped (no physical devices); falling back to socket filter");
                }
                load_socket(open_object_sock, dev_ifindexes, ports)
            }
        },
    }
}
