# wgmon

Passively measure the **ingress** packet-loss of a point-to-point
WireGuard link with eBPF — no traffic is ever sent by wgmon itself, and
the two peers never need to cooperate.

## How it works

Every WireGuard DATA packet carries a plaintext 64-bit monotonic counter
at byte offset 8 of the outer UDP payload (`[4B type=4][4B receiver_index]
[8B counter][encrypted payload]`). The receiving node alone can therefore
derive the exact number of packets the sender transmitted, by watching
which counters arrive.

* A small eBPF program records, per `(ListenPort, receiver_index)`
  session: the number of Type-4 packets received and the highest counter
  observed. State is kept in a per-CPU hash map, so the hot path needs no
  locks.
* Userspace diffs the cumulative counters every N seconds:
  `expected = max_seq_now − max_seq_then`, `received = rx_now − rx_then`,
  `loss = 1 − received/expected`.

### Hook points

| backend | hook | needs |
|---|---|---|
| `kprobe` (preferred) | `wg_packet_consume_data()` (after header validation; fallback `wg_packet_receive()`) | kernel BTF for `struct sk_buff` (CO-RE); the WireGuard module loaded |
| `tc` | clsact ingress on a physical interface, matching the UDP destination port | nothing (parses packets with `bpf_skb_load_bytes`) |

The listen port is used instead of `struct wg_device` to discover which
interface a packet belongs to, so no kernel-internal WireGuard structs are
required. Interface ↔ port translation comes from `wg show all dump`.

## Edge cases, and how they are handled

* **Reordering vs. loss.** Using counter endpoints over a whole window
  absorbs any reordering *inside* the window; a packet that arrives late
  into the next window can make one window's ratio exceed 1 (clamped to
  0% loss), and the rolling figure across the last 12 windows smooths it
  out.
* **Rekeying (~every 120 s).** `receiver_index` changes and the counter
  restarts at 0. Each session is keyed separately; a fresh session is
  baselined on its first sighting and its first window is reported as
  `REKEY` instead of a bogus loss figure. Old sessions are garbage
  collected after ~10 minutes of silence.
* **Recovery deadlock.** A window with fewer than `--min-packets`
  expected packets (e.g. only BGP/WireGuard keepalives, which never show
  loss) never *clears* a `DEGRADED` state, and degradation requires
  consecutive bad windows. To be able to recover at all, some component
  must send full-MTU probe bursts while degraded (see below).

## Usage

```sh
# live table for all wg interfaces (--interval defaults to 5 s)
wgmon

# just the state of one interface, one shot, machine-readable
wgmon --interface wg_tokyo --once --format json

# tc fallback on the physical NIC (no BTF needed)
wgmon --hook tc --dev eth0
```

Requires root (`CAP_BPF`/`CAP_NET_ADMIN`) or an equivalent privilege
setup, and `clang` + `libelf-dev` at build time.

## Tuning

* `--min-packets` (default 100): minimum window size for a trusted
  estimate.
* `--loss-threshold` (default 0.05): loss ratio counted as a bad window.
* `--degrade-after` (default 2) / `--recover-after` (default 3):
  consecutive windows required to enter/leave `DEGRADED`.
* `--gc-secs` (default 600): drop map entries idle for longer.

## Design notes

* Two small BPF programs (`src/bpf/kprobe.bpf.c`, `src/bpf/tc.bpf.c`)
  share one accounting routine (`common.h`) and one stats map. Per-CPU
  maps + atomics keep the hot path lock-free (`bpf_spin_lock` is not
  permitted in tracing programs anyway).
* If both kprobe symbols exist, `wg_packet_consume_data` is used
  (skb->data is already the WireGuard header). Otherwise
  `wg_packet_receive` is used with an 8-byte offset.
* A hidden `--kprobe-symbol` flag exists for troubleshooting symbol
  selection.

## Wiring it up

`--format json` emits one NDJSON object per interface per window; the
`state` field (`OK`/`DEGRADED`/`IDLE`/`LOW`/`REKEY`) is the signal a
BGP or routing agent would key on. For instance, `--once --format json`
can be run periodically from systemd or a supervisor and inspected for
`state == "DEGRADED"`. Recovery probes (full-MTU UDP bursts every 30–60 s
while degraded) are deliberately *not* part of wgmon: it only measures.
