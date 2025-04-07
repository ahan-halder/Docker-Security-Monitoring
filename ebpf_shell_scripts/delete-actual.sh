#!/bin/bash

# --- CONFIG ---
TARGET_DIR="/mnt1"
NUM_FILES=300

# --- FILE CREATION ---
echo "Creating $NUM_FILES files in $TARGET_DIR..."
cd "$TARGET_DIR" || exit 1

for i in $(seq 1 $NUM_FILES); do
    touch "/mnt1/file$i"
done

# --- MASS DELETE ---
echo "Deleting files..."
rm /mnt1/file{1..300}

echo "Done. Check your monitor output for alerts."
