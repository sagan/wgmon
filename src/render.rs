//! Output formatting: a live table on TTY, plain text otherwise, or NDJSON.

use std::io::{IsTerminal, Write};

use serde::Serialize;

use crate::stats::{Report, State};

pub struct Row {
    pub iface: String,
    pub port: u16,
    pub report: Report,
}

#[derive(Serialize)]
pub struct JsonRow {
    pub iface: String,
    pub port: u16,
    pub state: String,
    pub expected: u64,
    pub received: u64,
    pub lost: u64,
    pub loss_pct: f64,
    pub rolling_loss_pct: f64,
    pub rate_pps: f64,
    pub sessions: usize,
    pub loss_valid: bool,
    pub new_session: bool,
}

impl From<&Row> for JsonRow {
    fn from(row: &Row) -> Self {
        let r = &row.report;
        Self {
            iface: row.iface.clone(),
            port: row.port,
            state: r.state.as_str().to_string(),
            expected: r.expected,
            received: r.received,
            lost: r.lost,
            loss_pct: r.loss * 100.0,
            rolling_loss_pct: r.roll_loss * 100.0,
            rate_pps: r.rate,
            sessions: r.sessions,
            loss_valid: r.loss_valid,
            new_session: r.new_session,
        }
    }
}

pub struct Config {
    pub format: Format,
    pub color: bool,
    pub window_secs: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

fn colorize(s: &str, code: &str, enabled: bool) -> String {
    if !enabled {
        return s.to_string();
    }
    format!("\x1b[{code}m{s}\x1b[0m")
}

fn state_str(state: State, color: bool) -> String {
    match state {
        State::Ok => colorize("OK", "32", color),
        State::Degraded => colorize("DEGRADED", "31", color),
        State::Idle => colorize("IDLE", "90", color),
        State::Rekey => colorize("REKEY", "33", color),
        State::Insufficient => colorize("LOW", "33", color),
    }
}

pub fn print_header(cfg: &Config, backend_desc: &str, started_unix: u64) {
    if cfg.format != Format::Table {
        return; // keep stdout clean for machine-readable output
    }
    println!(
        "wgmon: WireGuard ingress link quality  backend={backend_desc}  window={}s",
        cfg.window_secs
    );
    println!("started={started_unix}  (Ctrl-C to stop)");
    println!();
}

pub fn report(rows: &[Row], cfg: &Config) -> std::io::Result<()> {
    match cfg.format {
        Format::Json => {
            for row in rows {
                let json = serde_json::to_string(&JsonRow::from(row))?;
                println!("{json}");
            }
        }
        Format::Table => {
            let tty = std::io::stdout().is_terminal();
            if tty && cfg.color {
                print!("\x1b[2J\x1b[H");
            }
            let header = format!(
                "{:<14} {:<6} {:<9} {:>8} {:>9} {:>7} {:>8} {:>9} {:>9}",
                "INTERFACE",
                "PORT",
                "STATE",
                "RX",
                "EXPECTED",
                "LOST",
                "LOSS",
                "ROLL. LOSS",
                "RATE"
            );
            if !tty && cfg.color {
                // plain-text header still fine
            }
            println!("{header}");
            println!("{}", "-".repeat(88));
            for row in rows {
                let r = &row.report;
                let loss = r.loss * 100.0;
                let roll = r.roll_loss * 100.0;
                let loss_str = if r.loss_valid {
                    format!("{loss:>7.2}%")
                } else {
                    "      -".to_string()
                };
                let roll_str = if r.roll_expected > 0 {
                    format!("{roll:>8.2}%")
                } else {
                    "       -".to_string()
                };
                let state = state_str(r.state, cfg.color);
                println!(
                    "{:<14} {:<6} {:<9} {:>8} {:>9} {:>7} {} {} {:>8.0}pps",
                    row.iface,
                    row.port,
                    state,
                    r.received,
                    r.expected,
                    r.lost,
                    loss_str,
                    roll_str,
                    r.rate
                );
            }
        }
    }
    std::io::stdout().flush()
}

/// One-shot table for --once (no screen clearing).
pub fn report_once(rows: &[Row], cfg: &Config) -> std::io::Result<()> {
    let plain = Config {
        format: cfg.format,
        color: false,
        window_secs: cfg.window_secs,
    };
    report(rows, &plain)
}
