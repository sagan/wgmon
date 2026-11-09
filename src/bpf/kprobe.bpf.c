/* kprobe backend.
 *
 * At wg_packet_consume_data() entry, prepare_skb_header() has already run,
 * so skb->data points at the WireGuard message_data header and the outer
 * UDP header ends exactly 8 bytes before it. We read the UDP destination
 * port (the receiver's ListenPort) from there; userspace maps that port
 * back to a wg interface name. This avoids any dependency on the
 * (module-private) struct wg_device definition.
 *
 * The fallback probe on wg_packet_receive() runs before
 * prepare_skb_header(), where skb->data still points at the UDP header,
 * so the WireGuard header sits 8 bytes in. Both probes feed the same map;
 * only one is attached at a time.
 */
#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Only the fields we need, for CO-RE. The real offsets are resolved at
 * load time against the running kernel's BTF.
 */
struct sk_buff {
	unsigned char *data;
	unsigned int len;
} __attribute__((preserve_access_index));

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8,
		rax, rcx, rdx, rsi, rdi, orig_ax, rip, cs, flags, sp, ss;
};
#elif defined(__TARGET_ARCH_arm64)
/* bpf_tracing.h casts the ctx to struct user_pt_regs on arm64. */
struct user_pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};
struct pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};
#elif defined(__TARGET_ARCH_mips)
/* mips32 (CONFIG_32BIT layout). Registers and fields are 32-bit here, so
 * __u32 is used even though BPF is a 64-bit VM. PT_REGS_PARM1/2 become
 * regs[4]/regs[5] on mips (a0/a1).
 */
struct pt_regs {
	__u32 pad0[8];
	__u32 regs[32];
	__u32 cp0_status;
	__u32 hi;
	__u32 lo;
	__u32 cp0_badvaddr;
	__u32 cp0_cause;
	__u32 cp0_epc;
};
#else
#error "unsupported target architecture"
#endif

/* hdr_off is the offset of the WireGuard header relative to skb->data
 * (0 after prepare_skb_header, 8 at wg_packet_receive entry). The UDP
 * header directly precedes it, so the dest port is at hdr_off - 6.
 */
static __always_inline int parse_and_record(void *skb_ptr, int hdr_off)
{
	struct sk_buff *skb = skb_ptr;
	unsigned char *data;
	struct wg_msg_hdr hdr;
	__u16 dport_be;
	__u32 bytes = 0;

	if (bpf_core_read(&data, sizeof(data), &skb->data))
		return 0;
	if (!data)
		return 0;
	(void)bpf_core_read(&bytes, sizeof(bytes), &skb->len);

	if (bpf_probe_read_kernel(&hdr, sizeof(hdr), data + hdr_off))
		return 0;
	if (WGMON_LE32(hdr.type) != 4) /* MESSAGE_DATA */
		return 0;

	if (bpf_probe_read_kernel(&dport_be, sizeof(dport_be),
				  data + hdr_off - 6))
		return 0;

	return record_packet(WGMON_BE16(dport_be),
			     WGMON_LE32(hdr.receiver_index),
			     WGMON_LE64(hdr.counter), bytes);
}

SEC("kprobe/wg_packet_consume_data")
int wgmon_consume_data(struct pt_regs *ctx)
{
	return parse_and_record((void *)PT_REGS_PARM2(ctx), 0);
}

SEC("kprobe/wg_packet_receive")
int wgmon_receive(struct pt_regs *ctx)
{
	return parse_and_record((void *)PT_REGS_PARM2(ctx), 8);
}
