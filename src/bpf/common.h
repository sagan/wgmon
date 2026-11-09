/* Shared BPF map definitions and the packet accounting helper.
 * Included by both the kprobe and tc programs so that both backends feed
 * the exact same stats map. Must be included after <bpf/bpf_helpers.h>.
 */
#ifndef WGMON_COMMON_H
#define WGMON_COMMON_H

#include "types.h"

struct {
	__uint(type, WGMON_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct stat_key);
	__type(value, struct stat_val);
} stats SEC(".maps");

/* Allow-list of listen ports to observe, populated by userspace (one
 * entry per WireGuard interface). Keyed by host-order port, value 1.
 */
struct {
	__uint(type, 1); /* BPF_MAP_TYPE_HASH */
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} ports SEC(".maps");

static __always_inline int record_packet(__u16 port, __u32 receiver_index,
					 __u64 counter, __u64 bytes)
{
	__u32 port_key;

	if (unlikely(!port || !receiver_index))
		return 0;

	port_key = port;
	if (unlikely(!bpf_map_lookup_elem(&ports, &port_key)))
		return 0;

	{
		struct stat_key key = {};
		struct stat_val *v;
		__u64 now;
		__u64 old;

		key.port = port;
		key.receiver_index = receiver_index;

		v = bpf_map_lookup_elem(&stats, &key);
		if (unlikely(!v)) {
			struct stat_val zero = {};

			/* Multiple CPUs may race here; BPF_NOEXIST lets
			 * exactly one win, the others re-look-up below.
			 * For per-CPU maps a BPF-side update initializes
			 * only the current CPU's slot and zero-fills the
			 * rest, which is exactly what we want.
			 */
			bpf_map_update_elem(&stats, &key, &zero,
					    WGMON_BPF_NOEXIST);
			v = bpf_map_lookup_elem(&stats, &key);
			if (unlikely(!v))
				return 0;
		}

		now = bpf_ktime_get_ns();
		__sync_fetch_and_add(&v->rx_packets, 1);
		__sync_fetch_and_add(&v->rx_bytes, bytes);
		if (!v->first_seen_ns)
			v->first_seen_ns = now;
		v->last_seen_ns = now;

		/* Per-CPU slots are only ever touched by their own CPU, so a
		 * plain store is race-free here. (A CAS retry loop makes the
		 * verifier give up with "infinite loop detected"; it also
		 * buys nothing because no other CPU shares this slot.)
		 */
		old = v->max_counter;
		if (counter > old)
			v->max_counter = counter;

		/* min_counter is diagnostic only. */
		old = v->min_counter;
		if (!old || counter < old)
			v->min_counter = counter;
	}
	return 0;
}

#endif /* WGMON_COMMON_H */
