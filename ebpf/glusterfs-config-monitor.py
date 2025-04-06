#!/usr/bin/env python3
from bcc import BPF
from bcc.utils import printb

# eBPF Program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/signal.h>

#define FILENAME_LEN 256

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    char type[8]; // "open" or "exec"
};

BPF_PERF_OUTPUT(events);

// Trace openat syscall
int trace_openat(struct tracepoint__syscalls__sys_enter_openat *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->filename);

    if (data.filename[0] == '/' && data.filename[1] == 'e' && data.filename[2] == 't' &&
        data.filename[3] == 'c' && data.filename[4] == '/' && data.filename[5] == 'g' && data.filename[6] == 'l' &&
        data.filename[7] == 'u' && data.filename[8] == 's' && data.filename[9] == 't' &&
        data.filename[10] == 'e' && data.filename[11] == 'r' && data.filename[12] == 'f' &&
        data.filename[13] == 's' && data.filename[14] == '/') {

        __builtin_memcpy(&data.type, "open", 5);

        // Kill the process immediately
        bpf_send_signal(SIGKILL);

        // Submit event for user-space logging
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Trace execve syscall
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->filename);

    if (data.filename[0] == '/' && data.filename[1] == 'e' && data.filename[2] == 't' &&
        data.filename[3] == 'c' && data.filename[4] == '/' && data.filename[5] == 'g' && data.filename[6] == 'l' &&
        data.filename[7] == 'u' && data.filename[8] == 's' && data.filename[9] == 't' &&
        data.filename[10] == 'e' && data.filename[11] == 'r' && data.filename[12] == 'f' &&
        data.filename[13] == 's' && data.filename[14] == '/') {

        __builtin_memcpy(&data.type, "exec", 5);

        // Kill the process immediately
        bpf_send_signal(SIGKILL);

        // Submit event
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""

# Load BPF
b = BPF(text=bpf_program)

# Attach tracepoints
b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat")
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")

print("%-6s %-16s %-6s %-8s %s" % ("PID", "COMM", "UID", "TYPE", "FILENAME"))

# Event callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"KILLED -> PID: %-6d COMM: %-16s UID: %-6d TYPE: %-8s FILE: %s" % (
        event.pid, event.comm, event.uid, event.type, event.filename))

# Open perf buffer
b["events"].open_perf_buffer(print_event)

# Poll loop
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
