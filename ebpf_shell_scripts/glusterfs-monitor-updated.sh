#!/bin/bash

# File: trigger_glusterfs_events.sh

# Exit on error
set -e

MOUNT_POINT="/mnt1/glusterfs"
TEST_FILE="$MOUNT_POINT/testfile.txt"
TEST_SCRIPT="$MOUNT_POINT/test_exec.sh"

# Ensure the mount point exists
if [ ! -d "$MOUNT_POINT" ]; then
    echo " GlusterFS mount point $MOUNT_POINT does not exist."
    exit 1
fi

echo " Triggering GlusterFS-related file open and execve events..."

# Create a test file to trigger openat
echo "Hello from GlusterFS monitor test." > "$TEST_FILE"
cat "$TEST_FILE" > /dev/null

# Create an executable script in GlusterFS mount to trigger execve
echo -e "#!/bin/bash\necho Hello from inside GlusterFS script!" > "$TEST_SCRIPT"
chmod +x "$TEST_SCRIPT"
"$TEST_SCRIPT"

# Optional cleanup
# rm -f "$TEST_FILE" "$TEST_SCRIPT"

echo " Trigger complete. Monitor should have logged open and execve events."
