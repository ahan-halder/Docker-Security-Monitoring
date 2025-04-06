#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct
import socket
from datetime import datetime
import os
import signal
import subprocess

# ------------------------
# BPF Program (tracepoint)
# ------------------------
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/inet.h>

struct connect_data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

int trace_sys_connect(struct tracepoint__syscalls__sys_enter_connect *args) {
    struct connect_data_t data = {};
    struct sockaddr_in sa = {};

    bpf_probe_read_user(&sa, sizeof(sa), (void *)args->uservaddr);

    if (sa.sin_family != AF_INET)
        return 0;

    data.daddr = sa.sin_addr.s_addr;
    data.dport = ntohs(sa.sin_port);

    if (data.dport != 24007 && data.dport != 49152)
        return 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# ------------------------
# Python side struct match
# ------------------------
class ConnectData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("daddr", ct.c_uint),
        ("dport", ct.c_ushort),
    ]

def ip_to_str(ip):
    return socket.inet_ntoa(ct.c_uint(ip).value.to_bytes(4, byteorder="little"))

# Track total connections per UID
connection_counts = {}

# Load and attach BPF
b = BPF(text=bpf_text)
b.attach_tracepoint(tp="syscalls:sys_enter_connect", fn_name="trace_sys_connect")
print(" Monitoring GlusterFS ports (24007, 49152)...\n")

# ------------------------
# Handle BPF event
# ------------------------
def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ConnectData)).contents
    pid = event.pid
    uid = event.uid
    ip = ip_to_str(event.daddr)
    proc = event.comm.decode("utf-8", "replace")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count connections per user
    count = connection_counts.get(uid, 0) + 1
    connection_counts[uid] = count

    if count > 10:
        try:
            # Kill all 'nc' processes for this UID
            subprocess.run(["pkill", "-KILL", "-u", str(uid), "nc"], check=False)
            print(f"[{ts}]  KILLED all 'nc' processes from UID {uid} after {count} GlusterFS connections.")
        except Exception as e:
            print(f"[{ts}] Kill failed: {e}")
    else:
        print(f"[{ts}]  WARNING: {proc} (PID {pid}, UID {uid}) made {count} GlusterFS connections.")

b["events"].open_perf_buffer(handle_event)

# ------------------------
# Main loop
# ------------------------
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n Exiting monitor.")
