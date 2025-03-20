// Detect Privilege Escalation Attempts in Containers

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int detect_setuid(struct pt_regs *ctx, uid_t uid) {
    u32 pid = bpf_get_current_pid_tgid();
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(&comm, sizeof(comm));

    if (uid == 0) {  // Root privileges
        bpf_trace_printk("WARNING: Process %s (PID %d) attempted privilege escalation\n", comm, pid);
    }

    return 0;
}
