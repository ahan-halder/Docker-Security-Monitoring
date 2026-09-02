#!/bin/bash

# Ensure the file exists
touch /etc/glusterfs/test_falco.conf

# Access the file using a non-gluster process (e.g., cat)
echo "Triggering Falco rule by reading GlusterFS config file..."
cat /etc/glusterfs/test_falco.conf > /dev/null

# Modify the file (optional - also triggers the same rule)
echo "Appending to test file..."
echo "# Falco test entry" >> /etc/glusterfs/test_falco.conf
