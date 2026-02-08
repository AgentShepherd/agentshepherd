//go:build linux

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" deny c/deny.bpf.c -- -I/usr/include -Ic
