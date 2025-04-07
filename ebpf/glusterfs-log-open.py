from bcc import BPF
import sys
import os
import signal

# eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

struct event_data {
    u64 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 event_type;
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_data_storage, struct event_data, 1);

static __inline int startswith(const char *str, const char *prefix) {
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (prefix[i] == 0) return 1;
        if (str[i] != prefix[i]) return 0;
    }
    return 0;
}

static __inline int endswith(const char *str, const char *suffix) {
    int len = 0;
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (str[i] == 0) break;
        len++;
    }
    int suff_len = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (suffix[i] == 0) break;
        suff_len++;
    }
    if (len < suff_len) return 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (suffix[i] == 0) break;
        if (str[len - suff_len + i] != suffix[i]) return 0;
    }
    return 1;
}

static __inline int streq(const char *a, const char *b) {
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (a[i] != b[i]) return 1;
        if (a[i] == 0) return 0;
    }
    return 1;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int zero = 0;
    struct event_data *data = event_data_storage.lookup(&zero);
    if (!data) return 0;

    __builtin_memset(data, 0, sizeof(*data));
    data->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), args->filename);
    data->event_type = 1;

    if ((startswith(data->filename, "/var/log/glusterfs/") ||
         startswith(data->filename, "/var/lib/glusterd/") ||
         startswith(data->filename, "/mnt1/")) &&
         endswith(data->filename, ".log")) {

        if (streq(data->comm, "glusterd") == 0 ||
            streq(data->comm, "glusterfsd") == 0 ||
            streq(data->comm, "gluster") == 0) return 0;

        events.perf_submit(args, data, sizeof(*data));
    }

    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    filename = event.filename.decode('utf-8', errors='replace')
    comm = event.comm.decode('utf-8', errors='replace')
    real_pid = event.pid >> 32  # Extract actual PID from upper 32 bits

    print(f"[ALERT] Unauthorized .log Access:")
    print(f"  Process: {comm}")
    print(f"  PID: {real_pid}")
    print(f"  File: {filename}")
    print("-" * 50)

    try:
        os.kill(real_pid, signal.SIGKILL)
        print(f"  >> Process {real_pid} ({comm}) killed.\n")
    except Exception as e:
        print(f"  !! Failed to kill process {real_pid}: {e}")

def main():
    global b
    b = BPF(text=bpf_program)
    b.attach_tracepoint("syscalls:sys_enter_openat", "syscalls__sys_enter_openat")
    b["events"].open_perf_buffer(print_event)
    print("GlusterFS Log Monitor Started. Press Ctrl+C to stop.")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    main()
