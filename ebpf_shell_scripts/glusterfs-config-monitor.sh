#!/bin/bash

# File: trigger_glusterfs_protection.sh

# Exit on error
set -e

GLUSTERFS_CONF_DIR="/etc/glusterfs"
TEST_FILE="$GLUSTERFS_CONF_DIR/test_kill.txt"
TEST_SCRIPT="$GLUSTERFS_CONF_DIR/evil_script.sh"

echo " Triggering protected access to $GLUSTERFS_CONF_DIR (should cause SIGKILL)..."

# Check if /etc/glusterfs exists
if [ ! -d "$GLUSTERFS_CONF_DIR" ]; then
    echo " Directory $GLUSTERFS_CONF_DIR does not exist. Aborting test."
    exit 1
fi

# Create a dummy file (as root or pre-setup)
sudo touch "$TEST_FILE"
sudo chmod 644 "$TEST_FILE"

# Try to read the file (should be killed)
echo " Trying to open file: $TEST_FILE"
(cat "$TEST_FILE" > /dev/null) || echo " Process killed during open"

# Create a dummy script
sudo bash -c "echo -e '#!/bin/bash\necho Evil access attempt' > $TEST_SCRIPT"
sudo chmod +x "$TEST_SCRIPT"

# Try to execute the script (should be killed)
echo "Trying to exec file: $TEST_SCRIPT"
("$TEST_SCRIPT") || echo " Process killed during exec"

# Optional cleanup
# sudo rm -f "$TEST_FILE" "$TEST_SCRIPT"

echo " Trigger script completed. Check eBPF logs for killed processes."
