#!/bin/bash

# Name of the container to use (already running)
CONTAINER_NAME="readonly_container1"

# Test file path inside the container
TEST_FILE="/mnt1/falco_trigger.txt"

# Message to write
MESSAGE="Falco test: readonly container attempted write"

echo "Triggering Falco rule from $CONTAINER_NAME..."

# Execute write operation inside the readonly-named container
docker exec "$CONTAINER_NAME" bash -c "echo '$MESSAGE' > $TEST_FILE"

# Confirm write attempt
if [ $? -eq 0 ]; then
    echo "Write attempted to $TEST_FILE from $CONTAINER_NAME"
else
    echo "Failed to write from $CONTAINER_NAME. Check if /mnt1 is mounted."
fi
