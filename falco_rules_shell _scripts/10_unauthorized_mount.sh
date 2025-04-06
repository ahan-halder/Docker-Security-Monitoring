#!/bin/bash

# Directory to use as a mount point
MOUNT_POINT="/mnt1/glusterfs/fake_mount"

# Create the mount point directory if it doesn't exist
mkdir -p "$MOUNT_POINT"

# Create a temporary file to use as a fake filesystem
MOUNT_IMG="/tmp/fake_fs.img"
dd if=/dev/zero of="$MOUNT_IMG" bs=1M count=10 status=none
mkfs.ext4 "$MOUNT_IMG" > /dev/null 2>&1

echo "Attempting unauthorized mount..."

# Try to mount it as a normal user (if you’re root, simulate a custom non-syste>
sudo mount "$MOUNT_IMG" "$MOUNT_POINT"

echo "Mount command executed. Check Falco logs for unauthorized mount detection>

