#!/bin/bash

# GlusterFS server IP (replace with actual remote Gluster node IP)
GLUSTER_SERVER_IP="192.168.1.100"

# GlusterFS ports to target
PORT=24007

# Number of connections to trigger the rule
COUNT=12

echo "Triggering $COUNT connections to GlusterFS port $PORT on $GLUSTER_SERVER_IP..."

for i in $(seq 1 $COUNT); do
    # Using nc (netcat) to open a short-lived TCP connection
    nc -z -w 1 $GLUSTER_SERVER_IP $PORT &
done

# Wait for all background processes
wait

echo "All connections sent."
