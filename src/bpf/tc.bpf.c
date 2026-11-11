/* tc ingress fallback (requires no BTF).
 *
 * Attach to a physical interface and match inbound WireGuard DATA packets
 * by their UDP destination port (== the wireguard interface's ListenPort).
 * No kernel struct access is needed: the packet is parsed byte by byte
 * with bpf_skb_load_bytes().
 */
#include "packet.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("tc")
int wgmon_tc(struct __sk_buff *skb)
{
	return filter_packet(skb);
}
