from bcc import BPF
from bcc.utils import printb
import os
import ctypes
import pwd

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct mount_event {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char dir[256];
    char fstype[32];
};

BPF_PERF_OUTPUT(mount_events);

TRACEPOINT_PROBE(syscalls, sys_enter_mount)
{
    struct mount_event event = {};
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.uid = uid;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Filter out shell processes
    if (event.comm[0] == 'b' || event.comm[0] == 'z') {
        if ((event.comm[1] == 'a' && event.comm[2] == 's' && event.comm[3] == 'h') ||
            (event.comm[1] == 's' && event.comm[2] == 'h')) {
            return 0;
        }
    }

    const char __user *dir = args->dir_name;
    const char __user *fstype = args->type;
    if (!dir || !fstype) return 0;

    bpf_probe_read_user_str(&event.dir, sizeof(event.dir), dir);
    bpf_probe_read_user_str(&event.fstype, sizeof(event.fstype), fstype);

    // Only allow mounts under /mnt
    if (!(event.dir[0] == '/' &&
          event.dir[1] == 'm' &&
          event.dir[2] == 'n' &&
          event.dir[3] == 't' &&
	  event.dir[4] == '1' 
          (event.dir[5] == 0 || event.dir[5] == '/')))
        return 0;

    mount_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# Struct matching the BPF event
class MountEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("dir", ctypes.c_char * 256),
        ("fstype", ctypes.c_char * 32),
    ]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(MountEvent)).contents
    user = pwd.getpwuid(event.uid).pw_name
    mount_dir = event.dir.decode("utf-8", errors="replace")
    fstype = event.fstype.decode("utf-8", errors="replace")
    comm = event.comm.decode("utf-8", errors="replace")

    print(f"[MOUNT] UID={user} PID={event.pid} COMM={comm} DIR={mount_dir} TYPE={fstype}")

    if fstype != "glusterfs":
        try:
            print(f"[!] Attempting to unmount unauthorized mount: {mount_dir}")
            os.system(f"umount -l '{mount_dir}'")
        except Exception as e:
            print(f"[!] Unmount failed: {e}")

def main():
    b = BPF(text=bpf_program)
    print("[+] Monitoring mount syscalls under /mnt ...\n")
    b["mount_events"].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n[!] Exiting ...")
            break

if __name__ == "__main__":
    main()
