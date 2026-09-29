// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
// Definitions shared by pgtrace.bpf.c (socket capture) and tls.bpf.c (TLS
// plaintext capture). Both objects declare these maps; the agent loads the
// TLS object with the socket object's maps, so they are the same maps.
#ifndef PGTRACE_H
#define PGTRACE_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Compile-time ceiling on bytes copied per syscall; the runtime value is
// capture_bytes (set by the agent before load). The per-CPU scratch event must
// stay below the 32 KiB per-CPU allocation limit.
#define MAX_PAYLOAD 16384
#define EINPROGRESS 115
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
// Wake the consumer only once this much data is pending; otherwise it drains
// the ring on its own poll interval. Avoids one wakeup per event.
#define WAKEUP_BYTES (1 << 20)

#define CLASS_IGNORE 2

const volatile __u32 capture_bytes = 4096;

enum kind { K_DATA = 0, K_CONNECT = 1, K_CLOSE = 2, K_ACCEPT = 3, K_TLS_FD = 4, K_TLS_INFO = 5 };
enum dir { D_SEND = 0, D_RECV = 1 };

// Must match internal/capture/decode.go.
struct event {
	__u64 ts;
	__u32 tgid;
	__s32 fd;
	__u32 total_len;
	__u32 cap_len;
	__u8 kind;
	__u8 dir;
	__u16 family;
	__u8 port[2]; // network order
	__u8 pad[2];
	__u8 addr[16]; // peer address; for TLS events with fd == -1 and K_TLS_*: the session pointer in addr[0:8]
	__u32 seq;   // TCP stream offset of the first payload byte (flags & 1)
	__u32 flags;
	__u8 payload[MAX_PAYLOAD];
};

#define F_SEQ 1
#define F_TLS 2 // plaintext from the TLS library, no stream offset

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

struct fd_key {
	__u32 tgid;
	__s32 fd;
};

// fds that userspace has classified; CLASS_IGNORE means not a postgres
// server connection, so its payload is not captured. Cleared on close.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct fd_key);
	__type(value, __u8);
} fd_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline int traced(__u64 pid_tgid)
{
	__u32 tgid = pid_tgid >> 32;
	return bpf_map_lookup_elem(&target_pids, &tgid) != NULL;
}

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &zero);
	if (d)
		__sync_fetch_and_add(d, 1);
}

static __always_inline __u64 rb_flags(void)
{
	return bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= WAKEUP_BYTES ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline int ignored(__u64 pid_tgid, __s32 fd)
{
	struct fd_key k = { .tgid = pid_tgid >> 32, .fd = fd };
	__u8 *c = bpf_map_lookup_elem(&fd_class, &k);
	return c && *c == CLASS_IGNORE;
}

static __always_inline struct event *new_event(__u64 pid_tgid, __s32 fd, __u8 kind)
{
	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return NULL;
	e->ts = bpf_ktime_get_ns();
	e->tgid = pid_tgid >> 32;
	e->fd = fd;
	e->kind = kind;
	e->dir = 0;
	e->family = 0;
	e->total_len = 0;
	e->cap_len = 0;
	e->seq = 0;
	e->flags = 0;
	return e;
}

#endif
