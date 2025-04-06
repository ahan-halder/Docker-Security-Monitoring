from bcc import BPF
from bcc.utils import printb

# eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/signal.h>

#define ARGSIZE  128

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char arg1[ARGSIZE];
    char arg2[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {
    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char **argv = (const char **)(ctx->argv);
    bpf_probe_read_user_str(&data.arg1, sizeof(data.arg1), (void *)argv[0]);
    bpf_probe_read_user_str(&data.arg2, sizeof(data.arg2), (void *)argv[1]);

    // Check for "gluster" and "volume"
    if (data.arg1[0] != '\\0' && data.arg2[0] != '\\0') {
        if (__builtin_memcmp(data.arg1, "gluster", 7) == 0 &&
            __builtin_memcmp(data.arg2, "volume", 6) == 0) {

            // Send SIGKILL to this process
            bpf_send_signal(SIGKILL);

            // Submit event for logging
            events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)

# Attach to execve syscall tracepoint
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")

# Callback function
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"KILLED -> PID: %-6d COMM: %-16s ARG1: %-16s ARG2: %-16s" % (event.pid, event.comm, event.arg1, event.arg2))

print("%-6s %-16s %-16s %-16s" % ("PID", "COMM", "ARG1", "ARG2"))

# Loop
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
