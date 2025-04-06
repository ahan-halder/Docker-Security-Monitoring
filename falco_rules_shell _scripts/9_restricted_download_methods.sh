#!/bin/bash

# Temporary download path
DOWNLOAD_PATH="/tmp/test_download.html"

# Attempt to download a file using curl
echo "Attempting restricted download with curl..."
curl -s https://example.com -o "$DOWNLOAD_PATH"

echo "Download complete. Check Falco logs for rule trigger."

# Cleanup
rm -f "$DOWNLOAD_PATH"
