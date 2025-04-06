#!/usr/bin/env python3
from bcc import BPF
import docker
import os
import signal
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define NAME_MAX 255

struct val_t {
    u64 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags;
};

struct data_t {
    u64 pid;
    u64 ts;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags;
    int ret;
    int syscall; // 1=open, 2=unlink, 3=write
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

// open/openat entry
int trace_open_entry(struct pt_regs *ctx, const char __user *filename, int flags) {
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    val.pid = id;
    val.ts = bpf_ktime_get_ns();
    val.fname = filename;
    val.flags = flags;
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    infotmp.update(&id, &val);
    return 0;
}

int trace_open_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = infotmp.lookup(&id);
    if (!valp) return 0;

    struct data_t data = {};
    data.pid = valp->pid;
    data.ts = bpf_ktime_get_ns();
    data.delta = data.ts - valp->ts;
    data.flags = valp->flags;
    data.ret = PT_REGS_RC(ctx);
    data.syscall = 1; // open
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)valp->fname);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}

// unlink syscall
int trace_unlink(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.delta = 0;
    data.flags = 0;
    data.ret = 0;
    data.syscall = 2; // unlink
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// write syscall
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    if (fd <= 2) return 0; // skip stdout/stderr/stdin

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.delta = 0;
    data.flags = fd;
    data.ret = PT_REGS_RC(ctx);  // <-- actual syscall return
    data.syscall = 3; // write
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_strncpy(data.fname, "FD_WRITE", 9);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

container_mntns = {}

def get_container_mntns(prefix=""):
    client = docker.from_env()
    containers = client.containers.list()
    mntns_map = {}
    for container in containers:
        if container.name.startswith(prefix):
            pid = container.attrs["State"]["Pid"]
            try:
                nslink = os.readlink(f"/proc/{pid}/ns/mnt")
                nsid = int(nslink.strip().split("[")[1].strip("]"))
                mntns_map[nsid] = container.name
            except Exception:
                continue
    return mntns_map

def get_proc_mntns(pid):
    try:
        nslink = os.readlink(f"/proc/{pid}/ns/mnt")
        return int(nslink.strip().split("[")[1].strip("]"))
    except Exception:
        return None

def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

def main():
    global container_mntns
    container_mntns = get_container_mntns("")  # track all containers

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Loading BPF program...")
    b = BPF(text=bpf_text)

    for syscall in ["__x64_sys_openat", "__x64_sys_open"]:
        b.attach_kprobe(event=syscall, fn_name="trace_open_entry")
        b.attach_kretprobe(event=syscall, fn_name="trace_open_return")

    b.attach_kprobe(event="__x64_sys_unlink", fn_name="trace_unlink")
    b.attach_kretprobe(event="__x64_sys_write", fn_name="trace_write")

    print("Monitoring syscalls in Docker containers:")
    print("%-6s %-16s %-12s " %
          ("PID", "COMM", "CONTAINER" ))

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        pid = event.pid >> 32
        nsid = get_proc_mntns(pid)
        container = container_mntns.get(nsid)
        if not container:
            return  # skip if not in Docker

        if b'runc' in event.comm:
            return

        syscall_map = {1: "open", 2: "unlink", 3: "write"}
        syscall = syscall_map.get(event.syscall, "unknown")

        # Decode flags or ret
        info = str(event.flags)
        #if syscall == "open":
        #    flag_str = ""
        #    if event.flags & os.O_RDONLY: flag_str += "O_RDONLY "
        #    if event.flags & os.O_WRONLY: flag_str += "O_WRONLY "
        #    if event.flags & os.O_RDWR:   flag_str += "O_RDWR "
        #    if event.flags & os.O_CREAT:  flag_str += "O_CREAT "
        #    if event.flags & os.O_TRUNC:  flag_str += "O_TRUNC "
        #    if event.flags & os.O_APPEND: flag_str += "O_APPEND "
        #    info = flag_str.strip()
        if syscall == "write":
            errno_map = {
                -30: "EROFS (Read-only FS)",
                -13: "EACCES (Permission Denied)",
                -1: "EPERM",
            }
            if event.ret < 0:
                info = errno_map.get(event.ret, f"ERR({event.ret})")
            else:
                info = f"FD_{event.flags} OK"

        print("%-6d %-16s %-12s %-8s %-20s %-30s" %
              (pid, event.comm.decode(errors='ignore'),
               container, syscall, info,
               event.fname.decode(errors='ignore')))

    def lost_event(cpu, count):
        print(f"[!] Lost {count} events on CPU {cpu}")

    b["events"].open_perf_buffer(print_event, lost_cb=lost_event, page_cnt=512)

    while True:
        b.perf_buffer_poll(timeout=100)

if __name__ == "__main__":
    main()
