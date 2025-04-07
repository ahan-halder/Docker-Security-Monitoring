mkdir -p /mnt1/test
cd /mnt1/test
python3 -c "with open('bigfile.txt', 'wb') as f: f.write(b'0' * 1024 * 1024 * 12)"
ls
