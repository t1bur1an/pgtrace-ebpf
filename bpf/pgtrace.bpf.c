// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
// Dual-licensed: the kernel only allows GPL-compatible programs to use
// bpf_probe_read_user and fentry/fexit, and accepts "Dual MIT/GPL" as such.
// Captures socket payloads of traced processes (pgbouncer) with fexit probes on
// the kernel's sendto/recvfrom/connect implementations. fentry/fexit only cost
// the probed functions; syscall tracepoints would push every syscall on the
// host through the slow path.
#include "pgtrace.h"

#define IPPROTO_TCP 6

// Minimal kernel type definitions for CO-RE: only the fields read here; the
// loader relocates them against the running kernel's BTF.
struct fdtable {
	unsigned int max_fds;
	struct file **fd;
} __attribute__((preserve_access_index));
struct files_struct {
	struct fdtable *fdt;
} __attribute__((preserve_access_index));
struct task_struct {
	struct files_struct *files;
} __attribute__((preserve_access_index));
struct file {
	void *private_data;
} __attribute__((preserve_access_index));
struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));
struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));
struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
	__u8 sk_shutdown; // a bitfield on some kernels: read with BPF_CORE_READ_BITFIELD_PROBED
} __attribute__((preserve_access_index));
struct tcp_sock {
	__u32 write_seq;
	__u32 copied_seq;
	__u32 rcv_nxt;
} __attribute__((preserve_access_index));

#define RCV_SHUTDOWN 1

// tcp_seq reads the stream offset of the first byte just sent (write_seq -
// ret) or received (copied_seq - ret) on fd. Returns 0 for non-TCP sockets.
static __always_inline int tcp_seq(__s32 fd, int ret, __u8 dir, __u32 *out)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd < 0 || (unsigned int)fd >= BPF_CORE_READ(fdt, max_fds))
		return 0;
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) != 0 || !f)
		return 0;
	struct socket *so = BPF_CORE_READ(f, private_data);
	if (!so)
		return 0;
	struct sock *sk = BPF_CORE_READ(so, sk);
	if (!sk)
		return 0;
	unsigned short family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if ((family != AF_INET && family != AF_INET6) || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	__u32 end;
	if (dir == D_SEND) {
		end = BPF_CORE_READ(tp, write_seq);
	} else {
		end = BPF_CORE_READ(tp, copied_seq);
		// A read that also consumed the peer's FIN advanced copied_seq by
		// one more than the data returned.
		__u8 shut = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_shutdown);
		if ((shut & RCV_SHUTDOWN) && end == BPF_CORE_READ(tp, rcv_nxt))
			end -= 1;
	}
	*out = end - (__u32)ret;
	return 1;
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
	e->flags = 0;
	if (tcp_seq(fd, ret, dir, &e->seq))
		e->flags = F_SEQ;
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

char LICENSE[] SEC("license") = "Dual MIT/GPL";
