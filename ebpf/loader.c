#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main() {
    struct bpf_object *obj;
    int prog_fd;

    obj = bpf_object__open_file("glusterfs_monitor.o", NULL);
    if (!obj) {
        printf("Failed to load eBPF object\n");
        return 1;
    }

    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "monitor_open"));
    if (prog_fd < 0) {
        printf("Failed to get program FD\n");
        return 1;
    }

    printf("eBPF program loaded successfully!\n");

    while (1) {
        sleep(1);
    }

    return 0;
}
