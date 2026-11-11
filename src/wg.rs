//! WireGuard interface discovery via the `wg` utility.

use std::collections::HashSet;
use std::process::Command;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone)]
pub struct WgIface {
    pub name: String,
    pub port: u16,
    pub fwmark: u32,
    /// Peer endpoint IPs seen on this interface (for tc auto-detection).
    pub endpoints: Vec<String>,
    pub has_peers: bool,
}

fn run_wg(args: &[&str]) -> Result<String> {
    let out = Command::new("wg").args(args).output()?;
    if !out.status.success() {
        bail!(
            "`wg {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// All wg interfaces on this host, with their listen ports and peer
/// endpoints, parsed from `wg show all dump`.
pub fn discover() -> Result<Vec<WgIface>> {
    let dump = match run_wg(&["show", "all", "dump"]) {
        Ok(d) => d,
        Err(e) => bail!(
            "cannot run `wg show all dump` ({e}). Is WireGuard installed and the module loaded?"
        ),
    };
    let mut ifaces: Vec<WgIface> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for line in dump.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.len() {
            // interface header: name, privkey, pubkey, listenport, fwmark
            5 => {
                let port: u16 = f[3].parse().unwrap_or(0);
                let fwmark_str = f[4].trim();
                let fwmark: u32 = if let Some(hex) = fwmark_str.strip_prefix("0x").or_else(|| fwmark_str.strip_prefix("0X")) {
                    u32::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    fwmark_str.parse().unwrap_or(0)
                };
                index.insert(f[0].to_string(), ifaces.len());
                ifaces.push(WgIface {
                    name: f[0].to_string(),
                    port,
                    fwmark,
                    endpoints: Vec::new(),
                    has_peers: false,
                });
            }
            // peer line: name, pubkey, psk, endpoint, allowedips, handshake, rx, tx, keepalive
            9 => {
                if let Some(&i) = index.get(f[0]) {
                    ifaces[i].has_peers = true;
                    let endpoint = f[3];
                    if endpoint != "(none)" && !endpoint.is_empty() {
                        if let Some(ip) = endpoint_ip(endpoint) {
                            if !ifaces[i].endpoints.iter().any(|e| e == &ip) {
                                ifaces[i].endpoints.push(ip);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if ifaces.is_empty() {
        bail!("no WireGuard interfaces found (`wg show interfaces` is empty)");
    }
    for iface in &ifaces {
        if iface.port == 0 {
            eprintln!(
                "warning: {} has no explicit listen port; its traffic cannot be attributed",
                iface.name
            );
        }
    }
    ifaces.retain(|i| i.port != 0);
    if ifaces.is_empty() {
        bail!("no WireGuard interfaces with a usable listen port");
    }
    Ok(ifaces)
}

/// Host part of an `ip:port` or `[ipv6]:port` endpoint string.
pub fn endpoint_ip(endpoint: &str) -> Option<String> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let end = rest.find(']')?;
        Some(rest[..end].to_string())
    } else {
        let colon = endpoint.rfind(':')?;
        Some(endpoint[..colon].to_string())
    }
}

/// Outgoing physical device for `dst_ip`, via the routing table.
/// When `fwmark` is non-zero, uses policy routing matching WireGuard's socket mark.
pub fn route_device(dst_ip: &str, fwmark: u32) -> Result<String> {
    let mut cmd = Command::new("ip");
    cmd.args(["-o", "route", "get", dst_ip]);
    if fwmark != 0 {
        cmd.args(["mark", &format!("{fwmark:#x}")]);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "`ip route get {dst_ip}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // format: "<dst> dev <name> src <ip> ..."
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "dev" {
            if let Some(dev) = tokens.next() {
                let dev = dev.trim_end_matches('\\').to_string();
                if !dev.is_empty() {
                    return Ok(dev);
                }
            }
        }
    }
    bail!("could not determine outgoing device for {dst_ip}")
}

/// Physical devices to attach the tc / socket filter fallback to.
pub fn tc_devices(ifaces: &[WgIface], forced: &[String]) -> Result<Vec<String>> {
    let mut devices: Vec<String> = Vec::new();
    if !forced.is_empty() {
        let mut seen = HashSet::new();
        for d in forced {
            if seen.insert(d.clone()) {
                devices.push(d.clone());
            }
        }
        return Ok(devices);
    }
    let wg_names: HashSet<&str> = ifaces.iter().map(|i| i.name.as_str()).collect();
    for iface in ifaces {
        if iface.endpoints.is_empty() {
            continue;
        }
        for endpoint in &iface.endpoints {
            match route_device(endpoint, iface.fwmark) {
                Ok(dev) => {
                    // Do not bind to a WireGuard tunnel interface itself (it only carries
                    // decrypted inner packets, not outer WireGuard UDP packets).
                    if !dev.is_empty() && !wg_names.contains(dev.as_str()) && !devices.contains(&dev) {
                        devices.push(dev);
                    }
                }
                Err(e) => eprintln!("warning: cannot route {endpoint} ({e})"),
            }
        }
    }
    if devices.is_empty() {
        bail!("no physical device detected for the tc fallback; pass --dev <iface>");
    }
    devices.sort();
    devices.dedup();
    Ok(devices)
}

pub fn interface_index(name: &str) -> Result<i32> {
    // Prefer `ip link show <name>`; fall back to if_nametoindex.
    let out = Command::new("ip")
        .args(["-o", "link", "show", name])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(colon) = text.find(':') {
                if let Ok(idx) = text[..colon].trim().parse::<i32>() {
                    return Ok(idx);
                }
            }
        }
    }
    let cname = std::ffi::CString::new(name).context("interface name contains NUL")?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        bail!("interface {name} not found");
    }
    Ok(idx as i32)
}
