// Monitor File Access 

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(file_access_count, u32, u64);

int monitor_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    u32 pid = bpf_get_current_pid_tgid();
    char fname[256];

    bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (bpf_strncmp(fname, "/mnt/gluster", 12) == 0) {  // Monitor only GlusterFS files
        u64 count = 0;
        u64 *stored_count = file_access_count.lookup(&pid);
        if (stored_count) {
            count = *stored_count;
        }
        count++;
        file_access_count.update(&pid, &count);

        bpf_trace_printk("GlusterFS file accessed: %s by PID %d\n", fname, pid);
    }
    return 0;
}
