//Detect Process Execution inside Docker Containers

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int monitor_exec(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(&comm, sizeof(comm));

    if (bpf_strncmp(comm, "dockerd", 7) != 0) {  // Ignore Docker daemon
        bpf_trace_printk("Container process started: %s (PID %d)\n", comm, pid);
    }

    return 0;
}
