// SPDX-License-Identifier: Dual BSD/GPL
//
// deny.bpf.c — eBPF LSM program for Crust Layer 2b deny-list enforcement.
//
// Attaches to the file_open LSM hook (sleepable) and denies access to files
// that match denied filenames or inodes. Only enforces for processes in the
// target_pids map (sandboxed processes).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define MAX_FILENAME 256

// denied_filenames: basename → rule_id
// Matches files by their dentry name (e.g. ".env", ".bashrc", "credentials").
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[MAX_FILENAME]);
	__type(value, __u32);
} denied_filenames SEC(".maps");

// denied_inodes: inode_number → rule_id
// Matches files by pre-resolved inode (e.g. ~/.ssh/id_rsa → inode 12345).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} denied_inodes SEC(".maps");

// allowed_filenames: basename → 1
// Exception list checked before denied_filenames (e.g. ".env.example").
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[MAX_FILENAME]);
	__type(value, __u8);
} allowed_filenames SEC(".maps");

// events: ring buffer for violation reporting to userspace.
struct deny_event {
	__u32 pid;
	__u32 rule_id;
	__u64 ino;
	char filename[MAX_FILENAME];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// target_pids: pid → 1
// Only enforce deny rules for processes in this set.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

// deny_file_open is the LSM hook for file_open.
// Uses sleepable variant (lsm.s/) which is required for bpf_d_path if added later.
SEC("lsm.s/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
	// 1. Fast path: skip if this PID is not in the target set
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&target_pids, &pid))
		return 0;

	// 2. Read basename from dentry->d_name.name
	char filename[MAX_FILENAME] = {};
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	bpf_probe_read_kernel_str(filename, sizeof(filename),
				  BPF_CORE_READ(dentry, d_name.name));

	// 3. Check exception list first (allow overrides deny)
	if (bpf_map_lookup_elem(&allowed_filenames, filename))
		return 0;

	// 4. Check denied filenames (basename match)
	__u32 *rule_id = bpf_map_lookup_elem(&denied_filenames, filename);
	if (rule_id) {
		struct deny_event *evt =
			bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
		if (evt) {
			evt->pid = pid;
			evt->rule_id = *rule_id;
			evt->ino = BPF_CORE_READ(file, f_inode, i_ino);
			__builtin_memcpy(evt->filename, filename,
					 MAX_FILENAME);
			bpf_ringbuf_submit(evt, 0);
		}
		return -EPERM;
	}

	// 5. Check denied inodes (for absolute path rules)
	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	rule_id = bpf_map_lookup_elem(&denied_inodes, &ino);
	if (rule_id) {
		struct deny_event *evt =
			bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
		if (evt) {
			evt->pid = pid;
			evt->rule_id = *rule_id;
			evt->ino = ino;
			__builtin_memcpy(evt->filename, filename,
					 MAX_FILENAME);
			bpf_ringbuf_submit(evt, 0);
		}
		return -EPERM;
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
