/* socket_filter fallback (requires no BTF and no tc clsact qdisc).
 *
 * Attached to an AF_PACKET socket via SO_ATTACH_BPF. Matches inbound
 * WireGuard DATA packets by their UDP destination port (== the wireguard
 * interface's ListenPort).
 *
 * Returns 0 to prevent the kernel from delivering any packet payload to the
 * userspace socket queue (zero userspace buffer / memory overhead).
 */
#include "packet.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("socket")
int wgmon_sock(struct __sk_buff *skb)
{
	if (skb->pkt_type == 4) /* PACKET_OUTGOING */
		return 0;

	filter_packet(skb);
	return 0;
}
