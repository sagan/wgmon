/* Shared packet parsing for tc and socket_filter backends (no BTF required).
 *
 * Matches inbound WireGuard DATA packets by their UDP destination port
 * (== the wireguard interface's ListenPort). Parses the packet byte by
 * byte with bpf_skb_load_bytes().
 */
#ifndef WGMON_PACKET_H
#define WGMON_PACKET_H

#include "types.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__u64 flow_keys;
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
};

static __always_inline int load_bytes(struct __sk_buff *skb, __u32 off,
				      void *buf, __u32 len)
{
	return bpf_skb_load_bytes(skb, off, buf, len);
}

static __always_inline int filter_packet(struct __sk_buff *skb)
{
	__u8 first;
	__u32 l3_off = 0;
	__u32 l4_off;
	__u16 ethertype;
	__u8 l3[40];
	__u8 l4[8];
	struct wg_msg_hdr hdr;
	__u32 i;

	if (load_bytes(skb, 0, &first, 1))
		return 0;

	/* Decide whether the packet carries an Ethernet header. Plain
	 * "version nibble == 4/6" is unusable here (a destination MAC may
	 * start with 0x4x/0x6x), so prefer the EtherType: a real Ethernet
	 * frame carrying IP has 0x0800/0x86dd (or a VLAN tag) at offset
	 * 12; anything else with an IP version nibble is treated as a
	 * raw L3 packet on a device without L2 headers (tun/ppp).
	 */
	if (load_bytes(skb, 12, &ethertype, 2)) {
		if ((first >> 4) != 4 && (first >> 4) != 6)
			return 0;
		l3_off = 0;
	} else {
		ethertype = WGMON_BE16(ethertype);
		if (ethertype == 0x0800 || ethertype == 0x86dd) {
			l3_off = 14;
		} else if (ethertype == 0x8100 || ethertype == 0x88a8) {
			/* At most 4 stacked VLAN tags. The loop must use a
			 * constant trip count so the verifier can reason
			 * about termination.
			 */
			l3_off = 14;
			for (i = 0; i < 4; i++) {
				if (ethertype != 0x8100 &&
				    ethertype != 0x88a8)
					break;
				if (load_bytes(skb, l3_off + 2, &ethertype, 2))
					return 0;
				ethertype = WGMON_BE16(ethertype);
				l3_off += 4;
			}
			if (ethertype != 0x0800 && ethertype != 0x86dd)
				return 0;
		} else if ((first >> 4) == 4 || (first >> 4) == 6) {
			l3_off = 0; /* raw L3 */
		} else {
			return 0; /* ARP and anything else */
		}
	}

	if (load_bytes(skb, l3_off, l3, 2))
		return 0;
	if ((l3[0] >> 4) == 4) {
		__u32 ihl;

		if (load_bytes(skb, l3_off, l3, 20))
			return 0;
		if (l3[9] != 17) /* not UDP */
			return 0;
		ihl = (l3[0] & 0x0f) * 4;
		if (ihl < 20)
			return 0;
		l4_off = l3_off + ihl;
	} else if ((l3[0] >> 4) == 6) {
		if (load_bytes(skb, l3_off, l3, 40))
			return 0;
		if (l3[6] != 17) /* not UDP (no ext headers supported) */
			return 0;
		l4_off = l3_off + 40;
	} else {
		return 0;
	}

	if (load_bytes(skb, l4_off, l4, 8))
		return 0;
	/* l4[2..3] is the destination port, network byte order. */

	if (load_bytes(skb, l4_off + 8, &hdr, sizeof(hdr)))
		return 0;
	if (WGMON_LE32(hdr.type) != 4)
		return 0;

	__u32 segs = skb->gso_segs;
	if (segs == 0)
		segs = 1;

	return record_packet((__u16)((l4[2] << 8) | l4[3]),
			     WGMON_LE32(hdr.receiver_index),
			     WGMON_LE64(hdr.counter),
			     (__u64)skb->len,
			     segs);
}

#endif /* WGMON_PACKET_H */
