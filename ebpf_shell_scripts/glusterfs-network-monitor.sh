#!/bin/bash

# File: trigger_glusterfs_connect.sh

# Exit on error
set -e

# Target IP (you can adjust this to the GlusterFS node IP)
TARGET_IP="127.0.0.1"

# Ports to trigger (GlusterFS)
PORTS=(24007 49152)

# Number of simulated connections per port
REPEAT=5

echo " Triggering GlusterFS-style connections to $TARGET_IP..."

for port in "${PORTS[@]}"; do
  for i in $(seq 1 $REPEAT); do
    echo "→ Connecting to $TARGET_IP:$port (attempt $i)"
    # Trigger connect syscall using netcat (will timeout quickly)
    nc -z -w1 "$TARGET_IP" "$port" || echo "Connection to $port failed (expected if no server listening)"
  done
done

echo " Finished triggering GlusterFS connect() syscalls."
