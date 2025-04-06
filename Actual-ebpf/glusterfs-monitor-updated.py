#!/usr/bin/env python3
from bcc import BPF
import pwd
import argparse
from datetime import datetime

bpf_text = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char type[16];
};

BPF_PERF_OUTPUT(events);

// Trace openat
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);

    if (data.fname[0] == '/' && data.fname[1] == 'm' && data.fname[2] == 'n' &&
        data.fname[3] == 't' && data.fname[4] == '/') {
        __builtin_memcpy(data.type, "open", 5);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// Trace execve
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);

    if (data.fname[0] == '/' && data.fname[1] == 'm' && data.fname[2] == 'n' &&
        data.fname[3] == 't' && data.fname[4] == '/') {
        __builtin_memcpy(data.type, "execve", 7);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

class GlusterFsMonitor:
    def __init__(self, log_file=None):
        self.log_file = log_file
        self.bpf = BPF(text=bpf_text)

        # Log file
        self.log_fd = None
        if self.log_file:
            self.log_fd = open(self.log_file, 'w')

        self.bpf["events"].open_perf_buffer(self.process_event)

        print("============================================================")
        print("GlusterFS Monitor (Tracepoints-based)")
        print("Monitoring /mnt/glusterfs accesses...")
        print("============================================================")

    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        try:
            username = pwd.getpwuid(event.uid).pw_name
        except:
            username = str(event.uid)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        message = f"{timestamp} | GlusterFS accessed (user={username}, pid={event.pid}, cmd={event.comm.decode()}, file={event.fname.decode()}, type={event.type.decode()})"

        print(message)

        if self.log_fd:
            self.log_fd.write(message + '\n')
            self.log_fd.flush()

        with open("/tmp/glusterfs_monitor.log", "a") as f:
            f.write(message + '\n')

    def run(self):
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Stopping monitor...")
        finally:
            if self.log_fd:
                self.log_fd.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor GlusterFS mount point modifications')
    parser.add_argument('-l', '--log', help='Log file to write events to')
    args = parser.parse_args()

    monitor = GlusterFsMonitor(log_file=args.log)
    monitor.run()

