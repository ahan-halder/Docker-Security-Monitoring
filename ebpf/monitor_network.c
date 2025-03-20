// Detect Suspicious Network Connections from Containers

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>

BPF_HASH(connection_count, u32, u64);

int detect_network_activity(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, int addrlen) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 count = 0;
    
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    
    if (addr_in->sin_family == AF_INET) {  // Check if it's an IPv4 connection
        u64 *stored_count = connection_count.lookup(&pid);
        if (stored_count) {
            count = *stored_count;
        }
        count++;
        connection_count.update(&pid, &count);

        bpf_trace_printk("Container PID %d made an outbound connection\n", pid);
    }

    return 0;
}
