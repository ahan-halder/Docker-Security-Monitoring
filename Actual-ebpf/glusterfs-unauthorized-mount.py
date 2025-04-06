import os
import subprocess
import pwd
from bcc import BPF

# eBPF program to detect unauthorized mount attempts
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define a perf buffer event structure
struct mount_event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
};

// Create a perf buffer map to send events to userspace
BPF_PERF_OUTPUT(mount_events);

// Tracepoint for mount syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_mount)
{
    // Get current process information
    char parent_comm[TASK_COMM_LEN];
    bpf_get_current_comm(&parent_comm, sizeof(parent_comm));
    
    // Check if the mount is by a non-system process
    if (!(parent_comm[0] == 's' && parent_comm[1] == 'y' && parent_comm[2] == 's')) {
        struct mount_event event = {};
        
        // Populate event details
        event.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        
        // Submit the event to userspace
        mount_events.perf_submit(args, &event, sizeof(event));
    }

    return 0;
}
"""

def print_event(cpu, data, size):
    """
    Callback function to handle and print mount events
    """
    event = b["mount_events"].event(data)

    # Get username from UID
    try:
        username = pwd.getpwuid(event.uid).pw_name
    except KeyError:
        username = f"UID {event.uid}"

    # Construct detailed output message
    output_message = (
        f"Unauthorized Mount Detected:\n"
        f"  PID: {event.pid}\n"
        f"  Process: {event.comm.decode('utf-8', errors='replace')}\n"
        f"  User: {username}\n"
    )

    print(output_message)
    subprocess.run(['logger', '-t', 'unauthorized_mount', output_message])

def main():
    global b
    b = BPF(text=bpf_program)

    b["mount_events"].open_perf_buffer(print_event)

    print("Starting Unauthorized Mount Detection...")
    print("Press Ctrl+C to stop monitoring")

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nStopping mount monitoring...")
            break

if _name_ == "_main_":
    if os.geteuid() != 0:
        print("This script must be run with root privileges.")
        exit(1)

    main()
