// SPDX-License-Identifier: GPL-2.0
// Captures socket payloads of traced processes (pgbouncer) with fexit probes on
// the kernel's sendto/recvfrom/connect implementations. fentry/fexit only cost
// the probed functions; syscall tracepoints would push every syscall on the
// host through the slow path.
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

enum kind { K_DATA = 0, K_CONNECT = 1, K_CLOSE = 2, K_ACCEPT = 3 };
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
	__u8 addr[16];
	__u8 payload[MAX_PAYLOAD];
};

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
	return e;
}

static __always_inline void emit_data(__s32 fd, void *buf, int ret, __u8 dir)
{
	if (ret <= 0)
		return;
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id) || ignored(id, fd))
		return;
	struct event *e = new_event(id, fd, K_DATA);
	if (!e)
		return;
	__u32 n = (__u32)ret;
	if (n > capture_bytes)
		n = capture_bytes;
	if (n > MAX_PAYLOAD)
		n = MAX_PAYLOAD;
	e->dir = dir;
	e->total_len = ret;
	if (bpf_probe_read_user(e->payload, n, buf) != 0)
		n = 0;
	e->cap_len = n;
	__u64 size = offsetof(struct event, payload) + n;
	if (size > sizeof(*e))
		size = sizeof(*e);
	if (bpf_ringbuf_output(&events, e, size, rb_flags()) != 0)
		count_drop();
}

SEC("fexit/__sys_sendto")
int BPF_PROG(exit_sendto, int fd, void *buff, __u64 len, unsigned int flags, void *addr, int addr_len, int ret)
{
	emit_data(fd, buff, ret, D_SEND);
	return 0;
}

SEC("fexit/__sys_recvfrom")
int BPF_PROG(exit_recvfrom, int fd, void *ubuf, __u64 size, unsigned int flags, void *addr, int *addr_len, int ret)
{
	emit_data(fd, ubuf, ret, D_RECV);
	return 0;
}

SEC("fexit/__sys_connect")
int BPF_PROG(exit_connect, int fd, void *uservaddr, int addrlen, int ret)
{
	if (ret != 0 && ret != -EINPROGRESS)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	__u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), uservaddr);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	struct event *e = new_event(id, fd, K_CONNECT);
	if (!e)
		return 0;
	e->family = family;
	bpf_probe_read_user(e->port, 2, uservaddr + 2);
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	if (family == AF_INET)
		bpf_probe_read_user(e->addr, 4, uservaddr + 4);
	else
		bpf_probe_read_user(e->addr, 16, uservaddr + 8);
	if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload), rb_flags()) != 0)
		count_drop();
	return 0;
}

// Accepted client connections, with the peer address pgbouncer asked for.
SEC("fexit/__sys_accept4")
int BPF_PROG(exit_accept4, int fd, void *upeer, int *upeer_len, int flags, int ret)
{
	if (ret < 0)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct event *e = new_event(id, ret, K_ACCEPT);
	if (!e)
		return 0;
	__u16 family = 0;
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	__builtin_memset(e->port, 0, sizeof(e->port));
	if (upeer) {
		bpf_probe_read_user(&family, sizeof(family), upeer);
		if (family == AF_INET) {
			bpf_probe_read_user(e->port, 2, upeer + 2);
			bpf_probe_read_user(e->addr, 4, upeer + 4);
		} else if (family == AF_INET6) {
			bpf_probe_read_user(e->port, 2, upeer + 2);
			bpf_probe_read_user(e->addr, 16, upeer + 8);
		}
	}
	e->family = family;
	if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload), rb_flags()) != 0)
		count_drop();
	return 0;
}

// Offset of di (first syscall argument) in x86-64 struct pt_regs.
#define PT_REGS_DI_OFFSET 112

SEC("fentry/__x64_sys_close")
int BPF_PROG(enter_close, void *regs)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	__u64 di = 0;
	bpf_probe_read_kernel(&di, sizeof(di), regs + PT_REGS_DI_OFFSET);
	struct fd_key k = { .tgid = id >> 32, .fd = (__s32)di };
	bpf_map_delete_elem(&fd_class, &k);
	struct event *e = new_event(id, k.fd, K_CLOSE);
	if (e && bpf_ringbuf_output(&events, e, offsetof(struct event, payload), rb_flags()) != 0)
		count_drop();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
