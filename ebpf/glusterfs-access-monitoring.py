from bcc import BPF

# Define the eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct access_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int trace_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct access_event_t event = {};
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Only monitor non-root (UID != 0) access
    if (uid == 0) return 0;
    if (!filename) return 0;  // Null check

    // Read filename safely
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    // Check if file is within /mnt/gluster (basic filtering)
    if (!(event.filename[0] == '/' && event.filename[1] == 'm' &&
          event.filename[2] == 'n' && event.filename[3] == 't' &&
          event.filename[4] == '1' && event.filename[5] == '/'))
        return 0;

    // Capture PID, UID, and process name
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = uid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Send event to user-space
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Load the eBPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="do_sys_openat2", fn_name="trace_open")

# Print output
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"WARNING: Non-root access detected - PID={event.pid}, UID={event.uid}, Process={event.comm}, File={event.filename}")

# Open perf buffer and listen for events
b["events"].open_perf_buffer(print_event)
print("Monitoring non-root GlusterFS access attempts...")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
