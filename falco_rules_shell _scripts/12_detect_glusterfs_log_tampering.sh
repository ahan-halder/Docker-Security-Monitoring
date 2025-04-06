#!/bin/bash

# File paths to simulate tampering
LOG_FILE="/var/log/glusterfs/fake_log.log"
VOLUME_FILE="/var/lib/glusterd/fake_volume.vol"

# Make sure the script is not executed as a glusterd/glusterfsd process
echo "Simulating unauthorized access/modification to GlusterFS system files..."

# 1. Create fake log file and write to it
sudo bash -c "echo 'fake log entry' >> $LOG_FILE"

# 2. Rename it
sudo mv "$LOG_FILE" "${LOG_FILE}.bak"

# 3. Create fake volume metadata and change permissions
sudo bash -c "echo 'volume data' > $VOLUME_FILE"
sudo chmod 777 "$VOLUME_FILE"

# 4. Delete the fake volume file
sudo rm -f "$VOLUME_FILE"

echo "Tampering simulation complete. Check Falco logs for alerts."
