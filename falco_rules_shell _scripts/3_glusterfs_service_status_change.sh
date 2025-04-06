#!/bin/bash

echo "Triggering GlusterFS service stop..."
systemctl stop glusterd

# Wait a bit before restarting
sleep 5

echo "Triggering GlusterFS service restart..."
systemctl restart glusterd
