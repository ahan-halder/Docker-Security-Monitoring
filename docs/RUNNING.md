# Running the Monitors

This guide explains how to deploy Falco rules, start eBPF monitors, and run manual tests.

## Prerequisites

1. Complete the [installation steps](../README.md) for Docker, GlusterFS, and Falco.
2. Install BCC and Python dependencies:

```sh
sudo apt install -y bpfcc-tools python3-bpfcc
pip install -r requirements.txt
```

3. Ensure GlusterFS is mounted at `/mnt1`:

```sh
sudo mkdir -p /mnt1
# Mount your GlusterFS volume (see README for cluster setup)
sudo mount -t glusterfs <node>:/myvol /mnt1
```

## Deploying Falco Rules

Copy the custom rules into Falco's rules directory and restart the service:

```sh
sudo cp falco_rules/rules.d/*.yaml /etc/falco/rules.d/
sudo systemctl restart falco
```

View Falco alerts:

```sh
sudo journalctl -u falco -f
```

## Running eBPF Monitors

All eBPF scripts require root privileges. Run each monitor in its own terminal:

```sh
# General Docker container syscall monitoring
sudo python3 ebpf/docker_monitoring.py

# GlusterFS config protection (kills processes accessing /etc/glusterfs)
sudo python3 ebpf/glusterfs-config-monitor.py

# Suspicious file extension detection (kills + deletes + blocklists)
sudo python3 ebpf/glusterfs-unusual-file-extension.py -l /tmp/monitor.log

# Volume operation blocking
sudo python3 ebpf/glusterfs-volume-monitor.py

# Network spike detection
sudo python3 ebpf/glusterfs-network-monitor.py
```

See the [architecture mapping](ARCHITECTURE.md#3-security-scenarios-covered) for the full list of monitors and their corresponding Falco rules.

## Running Manual Tests

Each monitor has a companion shell script that simulates the attack or policy violation it detects.

### eBPF Tests

In one terminal, start the monitor. In another, run the trigger script:

```sh
# Terminal 1
sudo python3 ebpf/glusterfs-config-monitor.py

# Terminal 2
bash ebpf_shell_scripts/glusterfs-config-monitor.sh
```

### Falco Tests

With Falco running, execute the corresponding trigger script:

```sh
bash "falco_rules_shell _scripts/0_glusterfs_mount_point_modification.sh"
```

Then check Falco logs for the alert.

## Test Containers

Use Docker Compose to create test containers including a read-only container:

```sh
cd docker
docker compose up -d
```

This starts:
- `readonly_container1` — read-only root filesystem for testing write-denial rules
- `test_container1` — standard container with `/mnt1` mounted

## Validation

Run the validation script to check syntax and structure without requiring root or live infrastructure:

```sh
bash scripts/validate.sh
```

This validates:
- Python syntax for all eBPF scripts
- Shell script syntax for all test triggers
- YAML syntax for all Falco rules
- Required files and directory structure

## Stopping Monitors

Press `Ctrl+C` in the terminal running the eBPF monitor. Falco runs as a system service:

```sh
sudo systemctl stop falco
```
