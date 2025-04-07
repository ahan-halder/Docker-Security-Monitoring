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
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_data_storage, struct event_data, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    int zero = 0;
    struct event_data *data = event_data_storage.lookup(&zero);
    if (!data) return 0;

    __builtin_memset(data, 0, sizeof(*data));
    data->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), args->pathname);

    events.perf_submit(args, data, sizeof(*data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    filename_raw = event.filename.decode('utf-8', errors='replace')
    comm = event.comm.decode('utf-8', errors='replace')
    real_pid = event.pid >> 32

    try:
        # Resolve full path from /proc/[pid]/cwd
        if os.path.isabs(filename_raw):
            full_path = filename_raw
        else:
            cwd = os.readlink(f"/proc/{real_pid}/cwd")
            full_path = os.path.abspath(os.path.join(cwd, filename_raw))
    except Exception as e:
        print(f"  !! Could not resolve full path for PID {real_pid}: {e}")
        return

    # Filtering: only .log files in specific GlusterFS directories
    monitored_dirs = ["/var/log/glusterfs/", "/var/lib/glusterd/", "/mnt/glusterfs/"]
    if full_path.endswith(".log") and any(full_path.startswith(dir_) for dir_ in monitored_dirs):
        if comm not in ("glusterd", "glusterfsd", "gluster"):
            print(f"[ALERT] Unauthorized attempt to unlink .log file:")
            print(f"  Process: {comm}")
            print(f"  PID: {real_pid}")
            print(f"  File: {full_path}")
            print("-" * 50)

            try:
                os.kill(real_pid, signal.SIGKILL)
                print(f"  >> Process {real_pid} ({comm}) killed.\n")
            except Exception as e:
                print(f"  !! Failed to kill process {real_pid}: {e}")

def main():
    global b
    b = BPF(text=bpf_program)
    b.attach_tracepoint("syscalls:sys_enter_unlinkat", "syscalls__sys_enter_unlinkat")
    b["events"].open_perf_buffer(print_event)
    print("GlusterFS Log Unlink Monitor Started. Press Ctrl+C to stop.")
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
