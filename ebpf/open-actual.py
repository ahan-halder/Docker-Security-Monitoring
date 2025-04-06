from bcc import BPF
import time
import os
import signal
from collections import defaultdict, deque

# === Config ===
THRESHOLD = 200      # Max opens allowed
WINDOW = 30          # Time window (seconds)
MOUNT_PREFIX = "/mnt1/"

# === BPF Program ===
bpf_text = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char fname[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# === State ===
b = BPF(text=bpf_text)
open_log = defaultdict(deque)  # pid -> deque of timestamps

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    path = event.fname.decode(errors="replace")
    pid = event.pid
    now = time.time()

    # Filter: GlusterFS only
    if not path.startswith(MOUNT_PREFIX):
        return

    print(f"[GLUSTER OPEN] {path} (pid={pid})")

    # Track timestamps
    log = open_log[pid]
    log.append(now)

    # Remove timestamps outside the time window
    while log and now - log[0] > WINDOW:
        log.popleft()

    # KILL if too many opens
    if len(log) >= THRESHOLD - 1:
        print(f"MASS OPEN ALERT: PID {pid} attempted {len(log)} opens in {WINDOW}s! Sending SIGKILL...")
        try:
            os.kill(pid, signal.SIGKILL)
            print(f"Killed PID {pid}")
        except ProcessLookupError:
            print(f"PID {pid} already exited")
        open_log[pid].clear()

# === Start Monitor ===
print(f"Monitoring {MOUNT_PREFIX} for mass opens ({THRESHOLD - 1} in {WINDOW}s)...")
b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting monitor.")
