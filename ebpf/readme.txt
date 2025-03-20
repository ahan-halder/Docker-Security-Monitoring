- Compile and Load eBPF Programs
1. Install Required Tools
    sudo apt update
    sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
2. Compile eBPF Programs
    clang -O2 -target bpf -c glusterfs_monitor.c -o glusterfs_monitor.o
    clang -O2 -target bpf -c glusterfs_block.c -o glusterfs_block.o
    clang -O2 -target bpf -c monitor_network.c -o monitor_network.o
    clang -O2 -target bpf -c monitor_exec.c -o monitor_exec.o
    clang -O2 -target bpf -c detect_privilege_escalation.c -o detect_privilege_escalation.o
3. Load eBPF Programs
    Create a C loader to load the eBPF programs.
4. Compile and Run the Loader
    gcc -o loader loader.c -lbpf
    sudo ./loader

eBPF Program	Function
 Monitor File Access	       -  Logs every file operation inside GlusterFS
 Block Unauthorized Writes	   -  Prevents modification of critical files
 Detect Network Activity	   -  Tracks outbound connections from containers
 Monitor Process Execution	   -  Logs every new process in Docker containers
 Detect Privilege Escalation   -  Alerts when a container tries to gain root
