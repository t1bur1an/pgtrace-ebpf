// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
// TLS plaintext capture (-tls-capture): uprobes on the SSL_read/SSL_write of
// pgbouncer's libssl, attached per process. Loaded with the socket capture's
// maps, so events share its ring buffer and target pid set.
#include <asm/ptrace.h>
#include "pgtrace.h"

#define INFO_MAX 32

struct sess_key {
	__u32 tgid;
	__u32 pad;
	__u64 ssl;
};

// TLS session → socket fd; from SSL_set_rfd, or from the fallback.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct sess_key);
	__type(value, __s32);
} tls_sessions SEC(".maps");

struct cur {
	__u64 ssl;
	__u64 buf;
};

// Thread → the SSL_read/SSL_write call it is in. Cleared by the call's
// return probe.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct cur);
} tls_current SEC(".maps");

// Thread → session last passed to SSL_get_version (for the cipher name that
// pgbouncer asks for right after).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} tls_info_ssl SEC(".maps");

static __always_inline __s32 session_fd(__u32 tgid, __u64 ssl)
{
	struct sess_key k = { .tgid = tgid, .ssl = ssl };
	__s32 *fd = bpf_map_lookup_elem(&tls_sessions, &k);
	return fd ? *fd : -1;
}

static __always_inline void put_session(struct event *e, __u64 ssl)
{
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	__builtin_memcpy(e->addr, &ssl, sizeof(ssl));
}

static __always_inline void emit_tls(__u64 id, __u64 ssl, const void *buf, int len, __u8 dir)
{
	if (len <= 0)
		return;
	__s32 fd = session_fd(id >> 32, ssl);
	if (fd >= 0 && ignored(id, fd))
		return;
	struct event *e = new_event(id, fd, K_DATA);
	if (!e)
		return;
	__u32 n = (__u32)len;
	if (n > capture_bytes)
		n = capture_bytes;
	if (n > MAX_PAYLOAD)
		n = MAX_PAYLOAD;
	e->dir = dir;
	e->total_len = len;
	e->flags = F_TLS;
	put_session(e, ssl);
	if (bpf_probe_read_user(e->payload, n, buf) != 0)
		n = 0;
	e->cap_len = n;
	__u64 size = offsetof(struct event, payload) + n;
	if (size > sizeof(*e))
		size = sizeof(*e);
	if (bpf_ringbuf_output(&events, e, size, rb_flags()) != 0)
		count_drop();
}

// SSL_write is captured on return: when the socket is full it returns
// without having written (or writes only part), and pgbouncer calls it again
// with the same bytes. Only what it reports as written is emitted.
SEC("uprobe")
int BPF_UPROBE(ssl_write, void *ssl, const void *buf, int num)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct cur c = { .ssl = (__u64)ssl, .buf = (__u64)buf };
	bpf_map_update_elem(&tls_current, &id, &c, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_write_ret, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct cur *p = bpf_map_lookup_elem(&tls_current, &id);
	if (!p)
		return 0;
	struct cur c = *p;
	bpf_map_delete_elem(&tls_current, &id);
	emit_tls(id, c.ssl, (const void *)c.buf, ret, D_SEND);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_read_enter, void *ssl, void *buf, int num)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct cur c = { .ssl = (__u64)ssl, .buf = (__u64)buf };
	bpf_map_update_elem(&tls_current, &id, &c, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_read_exit, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct cur *p = bpf_map_lookup_elem(&tls_current, &id);
	if (!p)
		return 0;
	struct cur c = *p;
	bpf_map_delete_elem(&tls_current, &id);
	emit_tls(id, c.ssl, (const void *)c.buf, ret, D_RECV);
	return 0;
}

// pgbouncer attaches a session's socket with SSL_set_rfd and SSL_set_wfd
// (same fd); one of them is enough.
SEC("uprobe")
int BPF_UPROBE(ssl_set_rfd, void *ssl, int fd)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct sess_key k = { .tgid = id >> 32, .ssl = (__u64)ssl };
	__s32 v = fd;
	bpf_map_update_elem(&tls_sessions, &k, &v, BPF_ANY);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_free, void *ssl)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct sess_key k = { .tgid = id >> 32, .ssl = (__u64)ssl };
	bpf_map_delete_elem(&tls_sessions, &k);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_ver_enter, void *ssl)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	__u64 s = (__u64)ssl;
	bpf_map_update_elem(&tls_info_ssl, &id, &s, BPF_ANY);
	return 0;
}

// dir 0: version, 1: cipher.
static __always_inline void emit_info(__u64 id, const char *text, __u8 which)
{
	__u64 *ssl = bpf_map_lookup_elem(&tls_info_ssl, &id);
	if (!ssl || !text)
		return;
	__u64 s = *ssl;
	struct event *e = new_event(id, session_fd(id >> 32, s), K_TLS_INFO);
	if (!e)
		return;
	e->dir = which;
	put_session(e, s);
	long n = bpf_probe_read_user_str(e->payload, INFO_MAX, text);
	if (n <= 1)
		return;
	e->cap_len = n - 1;
	if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload) + INFO_MAX, rb_flags()) != 0)
		count_drop();
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_ver_exit, const char *ret)
{
	emit_info(bpf_get_current_pid_tgid(), ret, 0);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_cipher_exit, const char *ret)
{
	emit_info(bpf_get_current_pid_tgid(), ret, 1);
	return 0;
}

// Fallback for sessions opened before the agent: inside SSL_read/SSL_write,
// the ciphertext read/write on the session's socket reveals its fd.
static __always_inline void map_current(unsigned int fd)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return;
	struct cur *c = bpf_map_lookup_elem(&tls_current, &id);
	if (!c)
		return;
	struct sess_key k = { .tgid = id >> 32, .ssl = c->ssl };
	if (bpf_map_lookup_elem(&tls_sessions, &k))
		return;
	__s32 v = fd;
	bpf_map_update_elem(&tls_sessions, &k, &v, BPF_ANY);
	struct event *e = new_event(id, v, K_TLS_FD);
	if (!e)
		return;
	put_session(e, c->ssl);
	if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload), rb_flags()) != 0)
		count_drop();
}

SEC("fentry/ksys_read")
int BPF_PROG(fallback_read, unsigned int fd, char *buf, __u64 count)
{
	map_current(fd);
	return 0;
}

SEC("fentry/ksys_write")
int BPF_PROG(fallback_write, unsigned int fd, const char *buf, __u64 count)
{
	map_current(fd);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
