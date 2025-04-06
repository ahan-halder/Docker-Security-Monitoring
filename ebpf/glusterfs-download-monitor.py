#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct
from datetime import datetime
import os
import pwd

# Constants
MAX_ARGS = 4
ARG_LEN = 100
LOG_FILE = "/var/log/trial_guard.log"
FALLBACK_LOG = "./trial_guard.log"

# BPF program: captures up to MAX_ARGS arguments
bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGS {MAX_ARGS}
#define ARG_LEN {ARG_LEN}

struct data_t {{
    u32 pid;
    char args[MAX_ARGS][ARG_LEN];
}};

BPF_PERF_OUTPUT(events);

int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {{
    struct data_t data = {{}};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    const char * const *argv = ctx->argv;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {{
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (argp) {{
            bpf_probe_read_user_str(&data.args[i], sizeof(data.args[i]), argp);
        }}
    }}

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}
"""

# Python representation of struct
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("args", (ct.c_char * ARG_LEN) * MAX_ARGS),
    ]

# Utility: get username from PID
def get_username(pid):
    try:
        uid = os.stat(f"/proc/{pid}").st_uid
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return "unknown"

# Utility: log to file
def log_event(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
    except PermissionError:
        with open(FALLBACK_LOG, "a") as f:
            f.write(msg + "\n")

# Helper: is path within /trial
def is_target_arg_path(arg):
    return arg == "/trial" or arg.startswith("/trial/")

# Helper: is process running from /trial
def is_in_trial_cwd(pid):
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
        return cwd == "/trial" or cwd.startswith("/trial/")
    except Exception:
        return False

# Callback to handle events
def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    args = [bytes(event.args[i]).split(b'\0', 1)[0].decode("utf-8", "replace") for i in range(MAX_ARGS)]
    binary = os.path.basename(args[0])
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = get_username(event.pid)

    trial_in_args = any(is_target_arg_path(arg) for arg in args[1:])
    trial_cwd = is_in_trial_cwd(event.pid)

    # Allow wget/curl in /trial if destination is clearly outside
    # So kill only if:
    # 1. args hit /trial
    # 2. OR cwd is /trial AND args don't clearly write elsewhere
    should_kill = False

    if binary in ("wget", "curl"):
        if trial_in_args:
            should_kill = True
        elif trial_cwd:
            # If ALL args are either not paths or also in /trial — then kill
            external_path_found = any(
                arg.startswith("/") and not is_target_arg_path(arg)
                for arg in args[1:]
            )
            if not external_path_found:
                should_kill = True

    if should_kill:
        msg = (f"[{ts}] 🚨 {binary} run by {username} (PID {event.pid}) "
               f"in/targeting /trial — args: {args}")
        print(msg)
        log_event(msg)

        try:
            os.kill(event.pid, 9)
            print(f"[{ts}] 💀 Killed PID {event.pid} ({binary})")
            log_event(f"[{ts}] 💀 Killed PID {event.pid} ({binary})")
        except ProcessLookupError:
            print(f"[{ts}] ⚠️ PID {event.pid} already exited.")
        except Exception as e:
            print(f"[{ts}] ❌ Kill error: {e}")

# Main function
if __name__ == "__main__":
    print("🛡️  Watching for wget/curl commands accessing /trial (auto-kill active)...")
    b = BPF(text=bpf_text)
    b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")
    b["events"].open_perf_buffer(handle_event)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n👋 Exiting.")


