// +build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* CC: 2020 Cloudflare */

#include <linux/bpf.h>
#include <errno.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Declare BPF maps */

/* List of open echo service ports. Key is the port number. */
struct bpf_map_def SEC("maps") echo_ports = {
		.type = BPF_MAP_TYPE_HASH,
		.max_entries = 1024,
		.key_size = sizeof(__u16),
		.value_size = sizeof(__u8),
};

/* Server socket */
struct bpf_map_def SEC("maps") server_socket = {
		.type = BPF_MAP_TYPE_SOCKMAP,
		.max_entries = 1,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u64),
};

/* Dispatcher program for the proxy service */
SEC("sk_lookup/proxy_dispatch")
int proxy_dispatch(struct bpf_sk_lookup *ctx)
{
	const __u32 zero = 0;
	struct bpf_sock *sk;
	__u16 port;
	__u8 *open;
	long err;

	/* Is echo service enabled on packets destination port? */
	port = ctx->local_port;
	open = bpf_map_lookup_elem(&echo_ports, &port);
	if (!open)
		return SK_PASS;

	/* Get echo server socket */
	sk = bpf_map_lookup_elem(&server_socket, &zero);
	if (!sk)
		return SK_DROP;

	/* Dispatch the packet to echo server socket */
	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);

	// https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
	if (err == -EINVAL)
	{
		bpf_printk("bpf_sk_assign: -EINVAL: specified flags are not supported.", err);
	}
	else if (err == -ENOENT)
	{
		bpf_printk("bpf_sk_assign: -ENOENT: the socket is unavailable for assignment.", err);
	}
	else if (err == -ENETUNREACH)
	{
		bpf_printk("bpf_sk_assign: -ENETUNREACH: the socket is unreachable (wrong netns).", err);
	}
	else if (err == -EOPNOTSUPP)
	{
		bpf_printk("bpf_sk_assign: -EOPNOTSUPP: the operation is not supported, for example a call from outside of TC ingress.", err);
	}
	else if (err == -ESOCKTNOSUPPORT)
	{
		bpf_printk("bpf_sk_assign: -ESOCKTNOSUPPORT if the socket type is not supported (reuseport).", err);
	}

	// add to key

	return err ? SK_DROP : SK_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)
