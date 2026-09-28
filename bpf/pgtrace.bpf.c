// SPDX-License-Identifier: GPL-2.0
// Captures socket payloads of traced processes (pgbouncer) at syscall level.
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define MAX_PAYLOAD 4096
#define EINPROGRESS 115
#define AF_INET 2
#define AF_INET6 10

enum kind { K_DATA = 0, K_CONNECT = 1, K_CLOSE = 2 };
enum dir { D_SEND = 0, D_RECV = 1 };

// Layout of syscalls:sys_enter_* / sys_exit_* tracepoint records.
struct sys_enter_ctx {
	__u64 common;
	__s32 nr;
	__u32 pad;
	__u64 args[6];
};

struct sys_exit_ctx {
	__u64 common;
	__s32 nr;
	__u32 pad;
	__s64 ret;
};

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

struct args {
	__u64 buf;
	__s32 fd;
	__u8 dir;
	__u8 is_connect;
	__u16 family;
	__u8 port[2];
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct args);
} active SEC(".maps");

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

static __always_inline int enter_io(struct sys_enter_ctx *ctx, __u8 dir)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct args a = {};
	a.fd = (__s32)ctx->args[0];
	a.buf = ctx->args[1];
	a.dir = dir;
	bpf_map_update_elem(&active, &id, &a, BPF_ANY);
	return 0;
}

static __always_inline int exit_io(struct sys_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct args *a = bpf_map_lookup_elem(&active, &id);
	if (!a)
		return 0;
	__s64 ret = ctx->ret;
	if (ret > 0) {
		struct event *e = new_event(id, a->fd, K_DATA);
		if (e) {
			__u32 n = ret > MAX_PAYLOAD ? MAX_PAYLOAD : (__u32)ret;
			e->dir = a->dir;
			e->total_len = ret > 0xffffffff ? 0xffffffff : (__u32)ret;
			if (bpf_probe_read_user(e->payload, n, (void *)a->buf) != 0)
				n = 0;
			e->cap_len = n;
			__u64 size = offsetof(struct event, payload) + n;
			if (size > sizeof(*e))
				size = sizeof(*e);
			if (bpf_ringbuf_output(&events, e, size, 0) != 0)
				count_drop();
		}
	}
	bpf_map_delete_elem(&active, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int enter_sendto(struct sys_enter_ctx *ctx) { return enter_io(ctx, D_SEND); }
SEC("tracepoint/syscalls/sys_exit_sendto")
int exit_sendto(struct sys_exit_ctx *ctx) { return exit_io(ctx); }
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int enter_recvfrom(struct sys_enter_ctx *ctx) { return enter_io(ctx, D_RECV); }
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int exit_recvfrom(struct sys_exit_ctx *ctx) { return exit_io(ctx); }
SEC("tracepoint/syscalls/sys_enter_write")
int enter_write(struct sys_enter_ctx *ctx) { return enter_io(ctx, D_SEND); }
SEC("tracepoint/syscalls/sys_exit_write")
int exit_write(struct sys_exit_ctx *ctx) { return exit_io(ctx); }
SEC("tracepoint/syscalls/sys_enter_read")
int enter_read(struct sys_enter_ctx *ctx) { return enter_io(ctx, D_RECV); }
SEC("tracepoint/syscalls/sys_exit_read")
int exit_read(struct sys_exit_ctx *ctx) { return exit_io(ctx); }

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct sys_enter_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct args a = {};
	a.fd = (__s32)ctx->args[0];
	a.is_connect = 1;
	void *sa = (void *)ctx->args[1];
	bpf_probe_read_user(&a.family, sizeof(a.family), sa);
	if (a.family == AF_INET) {
		bpf_probe_read_user(a.port, 2, sa + 2);
		bpf_probe_read_user(a.addr, 4, sa + 4);
	} else if (a.family == AF_INET6) {
		bpf_probe_read_user(a.port, 2, sa + 2);
		bpf_probe_read_user(a.addr, 16, sa + 8);
	} else {
		return 0;
	}
	bpf_map_update_elem(&active, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int exit_connect(struct sys_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct args *a = bpf_map_lookup_elem(&active, &id);
	if (!a)
		return 0;
	if (a->is_connect && (ctx->ret == 0 || ctx->ret == -EINPROGRESS)) {
		struct event *e = new_event(id, a->fd, K_CONNECT);
		if (e) {
			e->family = a->family;
			__builtin_memcpy(e->port, a->port, 2);
			__builtin_memcpy(e->addr, a->addr, 16);
			if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload), 0) != 0)
				count_drop();
		}
	}
	bpf_map_delete_elem(&active, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int enter_close(struct sys_enter_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct event *e = new_event(id, (__s32)ctx->args[0], K_CLOSE);
	if (e && bpf_ringbuf_output(&events, e, offsetof(struct event, payload), 0) != 0)
		count_drop();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
