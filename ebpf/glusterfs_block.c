//Block Unauthorized Write/Delete Operations

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int block_unauthorized_write(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    char fname[256];

    bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (bpf_strncmp(fname, "/mnt/gluster/secure", 19) == 0) {
        bpf_trace_printk("SECURITY ALERT: Unauthorized write attempt on %s\n", fname);
        return -1;  // Block operation
    }

    return 0;
}

int block_unauthorized_delete(struct pt_regs *ctx, int dfd, const char __user *filename) {
    char fname[256];

    bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (bpf_strncmp(fname, "/mnt/gluster/secure", 19) == 0) {
        bpf_trace_printk("SECURITY ALERT: Unauthorized delete attempt on %s\n", fname);
        return -1;  // Block operation
    }

    return 0;
}
