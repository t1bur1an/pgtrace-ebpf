package capture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 pgtrace ../../bpf/pgtrace.bpf.c -- -O2 -g -Wall -I/usr/include/x86_64-linux-gnu
