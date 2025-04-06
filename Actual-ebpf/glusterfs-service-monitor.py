#!/usr/bin/env python3
from bcc import BPF
import time
import sys
import os
import ctypes
import datetime

# Log file path
LOG_FILE = "/tmp/glusterfs_service_monitor.log"

# Ensure we're running as root
if os.geteuid() != 0:
    print("This program must be run as root (sudo). Exiting.")
    sys.exit(1)

# Simple BPF program to trace execve syscalls
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get the command name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get the file path (simplified)
    bpf_probe_read_user_str(&data.path, sizeof(data.path), (void *)filename);
    
    data.pid = pid;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Data structure for events
class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("path", ctypes.c_char * 256)
    ]

# Log message function
def log_message(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp}: {msg}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

# Initialize log file
with open(LOG_FILE, "w") as f:
    f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: GlusterFS service monitor started\n")

# Load BPF program
log_message("Compiling and loading BPF program...")
try:
    b = BPF(text=bpf_program)
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")
except Exception as e:
    log_message(f"Failed to load BPF program: {e}")
    sys.exit(1)

# System call callback
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    comm = event.comm.decode('utf-8', 'replace').rstrip('\0')
    path = event.path.decode('utf-8', 'replace').rstrip('\0')
    
    # Check for glusterfs related commands
    if ("systemctl" in comm and "gluster" in path) or \
       ("systemctl" in path and "gluster" in path) or \
       (comm == "systemctl" and "gluster" in os.popen(f"ps -p {event.pid} -o cmd= 2>/dev/null").read()):
        log_message(f"GlusterFS service event detected - PID: {event.pid}, Command: {comm}, Path: {path}")
        
        # Try to get more details about the command
        try:
            cmdline = open(f"/proc/{event.pid}/cmdline", "rb").read().decode('utf-8', 'replace').replace('\0', ' ')
            log_message(f"Command details: {cmdline}")
            
            # Check glusterd status after command execution
            time.sleep(0.5)  # Give a moment for the command to take effect
            status = os.popen("systemctl is-active glusterd 2>/dev/null").read().strip()
            log_message(f"GlusterFS service status: {status}")
        except Exception as e:
            log_message(f"Error getting command details: {e}")

# Set up perf buffer for events
b["events"].open_perf_buffer(handle_event)

# Main monitoring loop
print("="*80)
print("GlusterFS Service Monitor")
print("="*80)
print(f"Monitoring GlusterFS service status changes... Output logged to {LOG_FILE}")
print("Press Ctrl+C to stop monitoring.")
print("="*80)

# Periodically check service status independently
last_status = None

try:
    # Initial status check
    status = os.popen("systemctl is-active glusterd 2>/dev/null").read().strip()
    log_message(f"Initial GlusterFS service status: {status}")
    last_status = status
    
    while True:
        # Process eBPF events
        b.perf_buffer_poll(timeout=100)
        
        # Also check service status periodically
        if time.time() % 5 < 0.1:  # Check roughly every 5 seconds
            status = os.popen("systemctl is-active glusterd 2>/dev/null").read().strip()
            if status != last_status:
                log_message(f"GlusterFS service status changed from {last_status} to {status}")
                last_status = status
                
except KeyboardInterrupt:
    log_message("Monitoring stopped by user")
except Exception as e:
    log_message(f"Error: {e}")
finally:
    log_message("GlusterFS service monitor terminated")
