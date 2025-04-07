#!/bin/bash

set -e

USERNAME="testuser"
TESTFILE="/mnt1/testfile.txt"

# Always delete the user at the end
cleanup() {
    echo "[*] Cleaning up..."
    sudo pkill -u "$USERNAME" 2>/dev/null || true
    sudo userdel -r "$USERNAME" 2>/dev/null || true
    echo "[+] User $USERNAME deleted."
}
trap cleanup EXIT

# If user already exists, delete first
if id "$USERNAME" &>/dev/null; then
    echo "[!] User $USERNAME already exists. Removing..."
    sudo userdel -r "$USERNAME" || true
fi

# Create user and set password
sudo useradd -m "$USERNAME"
echo "$USERNAME:test123" | sudo chpasswd

# Run command as testuser
sudo -u "$USERNAME" bash <<EOF
echo "[+] Running as $USERNAME..."
mkdir -p /mnt1
touch "$TESTFILE"
echo "Hello from testuser!" > "$TESTFILE"
echo "[+] Contents of $TESTFILE:"
cat "$TESTFILE"
EOF

