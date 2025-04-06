#!/bin/bash

# Target directory (under GlusterFS mount)
TARGET_DIR="/mnt1/test_malicious_files"

# Suspicious file names
FILES=("dropper.exe" "startup.bat" "payload.ps1" "autorun.vbs")

# Ensure the directory exists
mkdir -p "$TARGET_DIR"

echo "[*] Creating suspicious files in $TARGET_DIR..."

for FILENAME in "${FILES[@]}"; do
  FILE_PATH="$TARGET_DIR/$FILENAME"
  echo "echo 'Malicious simulation' > $FILE_PATH"
  echo 'Malicious simulation' > "$FILE_PATH"
  echo "[+] Created: $FILE_PATH"
done

echo "[✓] Done. These should trigger your Falco rule if it's active and watching /mnt1."
