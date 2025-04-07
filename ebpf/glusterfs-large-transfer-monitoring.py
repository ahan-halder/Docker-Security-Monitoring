#!/usr/bin/env python3
from bcc import BPF
import ctypes
import os

THRESHOLD = 10 * 1024 * 1024  # 10MB
TARGET_CWD = "/mnt1"

bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/signal.h>

struct data_t {{
    u32 pid;
    long count;
    char comm[TASK_COMM_LEN];
}};

BPF_PERF_OUTPUT(events);

int trace_write(struct tracepoint__syscalls__sys_enter_write *ctx)
{{
    struct data_t data = {{}};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.count = ctx->count;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (ctx->count >= {THRESHOLD}) {{
        events.perf_submit(ctx, &data, sizeof(data));
    }}
    return 0;
}}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("count", ctypes.c_long),
        ("comm", ctypes.c_char * 16)
    ]

print(f"[+] Monitoring processes writing ≥{THRESHOLD // (1024 * 1024)}MB inside {TARGET_CWD}...")

bpf = BPF(text=bpf_text)
bpf.attach_tracepoint(tp="syscalls:sys_enter_write", fn_name="trace_write")

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    pid = event.pid
    comm = event.comm.decode()
    count = event.count

    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
        if cwd == TARGET_CWD or cwd.startswith(f"{TARGET_CWD}/"):
            print(f"[!] KILLING PID={pid} COMM={comm} BYTES={count} CWD={cwd}")
            os.kill(pid, 9)
        else:
            print(f"[~] IGNORED PID={pid} COMM={comm} BYTES={count} CWD={cwd}")
    except Exception as e:
        print(f"[x] Could not resolve cwd for PID={pid}: {e}")

bpf["events"].open_perf_buffer(print_event)

try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[+] Monitor stopped.")
