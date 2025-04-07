#!/bin/bash

# Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo)."
  exit 1
fi

# Create a test .log file in /mnt1/
mkdir -p /mnt1/
echo "This is a dummy GlusterFS log file." > /mnt1/testfile.log

# Function to simulate unauthorized access using cat (will be killed)
unauthorized_access() {
  echo "[*] Spawning unauthorized process to read log file..."
  cat /mnt1/testfile.log &
  echo "  >> PID: $!"
  sleep 2
}

# Function to simulate authorized access (should not be killed)
authorized_access() {
  echo "[*] Simulating glusterd (authorized process)..."
  (
    exec -a glusterd cat /mnt1/testfile.log
  ) &
  echo "  >> PID: $!"
  sleep 2
}

echo "[*] Testing unauthorized access:"
unauthorized_access

sleep 5

echo "[*] Testing authorized access (should not be killed):"
authorized_access

sleep 5

echo "[*] Cleaning up..."
rm -f /mnt1/testfile.log

echo "[*] Test completed."
