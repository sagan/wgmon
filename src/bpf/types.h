/* Minimal kernel types for building with libbpf-cargo without a generated
 * vmlinux.h. Only the types actually referenced by the BPF programs are
 * defined here; CO-RE relocations resolve the real struct layouts at load
 * time against the running kernel's BTF.
 */
#ifndef WGMON_TYPES_H
#define WGMON_TYPES_H

typedef __UINT8_TYPE__ __u8;
typedef __UINT16_TYPE__ __u16;
typedef __UINT32_TYPE__ __u32;
typedef __UINT64_TYPE__ __u64;
typedef __INT32_TYPE__ __s32;
typedef __INT64_TYPE__ __s64;
typedef __UINT16_TYPE__ __be16;
typedef __UINT16_TYPE__ __le16;
typedef __UINT32_TYPE__ __be32;
typedef __UINT32_TYPE__ __le32;
typedef __UINT16_TYPE__ __wsum;

/* WireGuard message_data header (drivers/net/wireguard/messages.h):
 *   struct message_data {
 *       struct message_header header;  // __le32 type, __le32 key_idx
 *       __le64 counter;
 *       u8 encrypted[];
 *   };
 * Type 4 = MESSAGE_DATA. Fields are little-endian on the wire.
 */
struct wg_msg_hdr {
	__u32 type;
	__u32 receiver_index;
	__u64 counter;
} __attribute__((packed));

/* Map key: the receiver's UDP listen port uniquely identifies a wg
 * interface on this host; receiver_index identifies the keypair session
 * (it changes on every rekey, which resets the counter to 0).
 */
struct stat_key {
	__u16 port; /* host byte order */
	__u16 pad;
	__u32 receiver_index;
};

/* Per-CPU counters: no locks are used (bpf_spin_lock is not permitted in
 * tracing programs such as kprobes). rx_count/rx_bytes use XADD atomics,
 * max_counter uses CAS; everything else is scratch space.
 */
struct stat_val {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 max_counter;
	__u64 min_counter;
	__u64 first_seen_ns;
	__u64 last_seen_ns;
};

/* Endianness helpers. WireGuard stores its header in little-endian;
 * UDP/IPv4 fields are network byte order.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define WGMON_LE32(x) (x)
#define WGMON_LE64(x) (x)
#define WGMON_BE16(x) __builtin_bswap16(x)
#else
#define WGMON_LE32(x) __builtin_bswap32(x)
#define WGMON_LE64(x) __builtin_bswap64(x)
#define WGMON_BE16(x) (x)
#endif

#define WGMON_MAP_TYPE_PERCPU_HASH 5
#define WGMON_BPF_ANY 0
#define WGMON_BPF_NOEXIST 1

#endif /* WGMON_TYPES_H */
