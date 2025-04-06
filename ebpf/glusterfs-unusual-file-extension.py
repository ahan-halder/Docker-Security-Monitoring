#!/usr/bin/env python3
from bcc import BPF
import pwd
import argparse
import time
import os
import signal
import socket
from datetime import datetime

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char type[16];
};

BPF_PERF_OUTPUT(events);

static inline bool has_suspicious_extension(const char *filename) {
    int len = 0;
    for (len = 0; len < 255; len++) {
        if (filename[len] == '\\0') break;
    }

    const char *exts[] = {".exe", ".bat", ".ps1", ".vbs", ".js", ".sh", ".jar"};
    #pragma unroll
    for (int i = 0; i < 7; i++) {
        const char *ext = exts[i];
        int ext_len = 0;
        for (ext_len = 0; ext[ext_len] != '\\0'; ext_len++);
        if (len >= ext_len) {
            int match = 1;
            for (int j = 0; j < ext_len; j++) {
                if (filename[len - ext_len + j] != ext[j]) {
                    match = 0;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

static inline bool is_glusterfs_path(const char *path) {
    return (path[0] == '/' && path[1] == 'm' && path[2] == 'n' && path[3] == 't' && path[4] == '/');
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    if (is_glusterfs_path(data.fname) && has_suspicious_extension(data.fname)) {
        __builtin_memcpy(data.type, "open", 5);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->pathname);

    if (is_glusterfs_path(data.fname) && has_suspicious_extension(data.fname)) {
        __builtin_memcpy(data.type, "creat", 6);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    if (is_glusterfs_path(data.fname) && has_suspicious_extension(data.fname)) {
        __builtin_memcpy(data.type, "execve", 7);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

class GlusterFsExtensionMonitor:
    def __init__(self, socket_path="/tmp/glusterfs_monitor.sock", log_file=None):
        self.socket_path = socket_path
        self.log_file = log_file
        print("Loading BPF program...")
        self.bpf = BPF(text=bpf_text)
        self.setup_socket()
        self.log_fd = open(self.log_file, 'w') if self.log_file else None
        self.bpf["events"].open_perf_buffer(self.process_event)
        print("============================================================")
        print("GlusterFS Unusual File Extension Monitor")
        print("Monitoring /mnt/glusterfs for suspicious file extensions")
        print("KILLING + DELETING + BLOCKING")
        print("============================================================")
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)

    def setup_socket(self):
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.bind(self.socket_path)
        os.chmod(self.socket_path, 0o666)

    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        try:
            username = pwd.getpwuid(event.uid).pw_name
        except Exception:
            username = str(event.uid)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        pid = event.pid
        filename = event.fname.decode()
        command = event.comm.decode()
        event_type = event.type.decode()

        message = f"{timestamp} | WARNING | Suspicious file detected (file={filename} user={username} pid={pid} cmd={command} type={event_type})"
        print(message)

        if self.log_fd:
            self.log_fd.write(message + "\n")
            self.log_fd.flush()

        try:
            self.socket.sendto(message.encode(), self.socket_path)
        except Exception as e:
            print(f"Error sending to socket: {e}")

        try:
            print(f"\u26a0\ufe0f  Killing suspicious process: PID {pid} ({command})")
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            print(f"\u26a0\ufe0f  Process {pid} already exited.")
        except PermissionError:
            print(f"\u274c  Not enough permissions to kill process {pid}. Run as root.")
        except Exception as e:
            print(f"\u274c  Error killing process {pid}: {e}")

        try:
            if os.path.exists(filename):
                os.remove(filename)
                print(f"\U0001f9f9 Deleted suspicious file: {filename}")
        except Exception as e:
            print(f"\u274c Error deleting file {filename}: {e}")

        try:
            blocklist_path = "/etc/glusterfs_blocked_users"
            with open(blocklist_path, 'a') as f:
                f.write(f"{username} ({event.uid}) - {timestamp}\n")
            print(f"\u26d4 Blocklisted user: {username} (UID: {event.uid})")
        except PermissionError:
            print("\u274c Cannot write to /etc/glusterfs_blocked_users (try running as root).")
        except Exception as e:
            print(f"\u274c Error blocklisting user {username}: {e}")

    def cleanup(self, signum, frame):
        print("\nCleaning up...")
        if self.log_fd:
            self.log_fd.close()
        self.socket.close()
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        exit(0)

    def run(self):
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            self.cleanup(None, None)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor GlusterFS mount point for suspicious file extensions')
    parser.add_argument('-l', '--log', help='Log file to write events to')
    parser.add_argument('-s', '--socket', default='/tmp/glusterfs_monitor.sock', help='Socket path')
    args = parser.parse_args()
    monitor = GlusterFsExtensionMonitor(socket_path=args.socket, log_file=args.log)
    monitor.run()
