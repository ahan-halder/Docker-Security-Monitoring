#!/bin/bash

# Ensure mount directory exists
mkdir -p /mnt1

# Trigger 'open' by creating and reading a file
echo "Hello from GlusterFS test!" > /mnt1/test_file.txt
cat /mnt1/test_file.txt

# Trigger 'execve' by running a simple script from /mnt1
echo -e "#!/bin/bash\necho GlusterFS execve test" > /mnt1/test_exec.sh
chmod +x /mnt1/test_exec.sh
/mnt1/test_exec.sh

echo "[+] Triggered file open and execution in /mnt1/"
