#!/bin/bash

# --- PROCESS ---
echo "Readonly container creating file..."
docker exec -it readonly_container1 touch /mnt1/somefile.txt

echo "Done. Check your monitor output for alerts."
