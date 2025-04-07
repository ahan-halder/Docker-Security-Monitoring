#!/bin/bash

# --- CONFIG ---
TARGET_DIR="/mnt1"

# --- MASS READS ---
echo "Reading files..."
cat /mnt1/mass-opens/file{1..300}.txt

echo "Done. Check your monitor output for alerts."
