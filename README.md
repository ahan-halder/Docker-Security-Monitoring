# IE Executive Project
Team members:
1. Aashi Kumari
2. Prabhav S Korwar
3. Ahan Halder
---
# Installation Guide

## Installing Docker

### Step 1: Update the package repository
```sh
sudo apt update
```

### Step 2: Install prerequisite packages
```sh
sudo apt install -y ca-certificates curl gnupg
```

### Step 3: Add Docker’s official GPG key
```sh
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.gpg > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.gpg
```

### Step 4: Set up the Docker repository
```sh
echo \ 
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \ 
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
```

### Step 5: Install Docker
```sh
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Step 6: Verify Installation
```sh
docker --version
```
---
## Installing GlusterFS

### Step 1: Update the package repository
```sh
sudo apt update
```

### Step 2: Install GlusterFS
```sh
sudo apt install -y glusterfs-server
```

### Step 3: Start and enable the GlusterFS service
```sh
sudo systemctl start glusterd
sudo systemctl enable glusterd
```

### Step 4: Verify GlusterFS installation
```sh
glusterfs --version
```
---
## Creating a Three-Node Volume on GlusterFS

### Step 1: Add peers to the GlusterFS cluster
Run the following command on one node to add other nodes to the cluster:
```sh
gluster peer probe <node2>
gluster peer probe <node3>
```
Verify the peer status:
```sh
gluster peer status
```

### Step 2: Create a distributed-replicated volume
Run the following command on any one node:
```sh
gluster volume create myvol replica 3 transport tcp <node1>:/data/brick1 <node2>:/data/brick1 <node3>:/data/brick1 force
```

### Step 3: Start the volume
```sh
gluster volume start myvol
```

### Step 4: Verify the volume status
```sh
gluster volume info
```

### Step 5: Mount the GlusterFS volume
On client machines, install the GlusterFS client package:
```sh
sudo apt install -y glusterfs-client
```
Create a mount point and mount the volume:
```sh
sudo mkdir -p /mnt/glusterfs
sudo mount -t glusterfs <node1>:/myvol /mnt/glusterfs
```

To make the mount persistent, add the following line to `/etc/fstab`:
```sh
<node1>:/myvol /mnt/glusterfs glusterfs defaults,_netdev 0 0
```
---
## Deleting a GlusterFS Volume

### Step 1: Unmount the volume (if mounted)
On all client machines, unmount the volume:
```sh
sudo umount /mnt/glusterfs
```

### Step 2: Stop the volume
Run the following command on any node:
```sh
gluster volume stop myvol
```

### Step 3: Delete the volume
```sh
gluster volume delete myvol
```

### Step 4: Verify the volume deletion
```sh
gluster volume info
```

Ensure that the volume no longer appears in the output.
---
## Installing Falco

### Step 1: Add the Falco repository
```sh
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt update
```

### Step 2: Install Falco
```sh
sudo apt install -y falco
```

### Step 3: Start and enable Falco service
```sh
sudo systemctl start falco
sudo systemctl enable falco
```

### Step 4: Verify Falco installation
```sh
falco --version
```
---
## Installing Grafana

### Step 1: Add the Grafana repository
```sh
sudo apt install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
sudo apt update
```

### Step 2: Install Grafana
```sh
sudo apt install -y grafana
```

### Step 3: Start and enable the Grafana service
```sh
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

### Step 4: Verify Grafana installation
```sh
grafana-server --version
```

### Step 5: Access Grafana Web Interface
Open a web browser and go to:
```
http://localhost:3000
```
Default credentials:
- Username: `admin`
- Password: `admin` (you will be prompted to change it on first login)
---
## Restarting Services
To restart any of the installed services, use the following commands:

### Restart Docker
```sh
sudo systemctl restart docker
```

### Restart GlusterFS
```sh
sudo systemctl restart glusterd
```

### Restart Falco
```sh
sudo systemctl restart falco
```

### Restart Grafana
```sh
sudo systemctl restart grafana-server
```
---
## Reinstalling Services
If you need to reinstall any of the services, follow these steps:

### Reinstall Docker
```sh
sudo apt remove --purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Reinstall GlusterFS
```sh
sudo apt remove --purge -y glusterfs-server
sudo apt install -y glusterfs-server
```

### Reinstall Falco
```sh
sudo apt remove --purge -y falco
sudo apt install -y falco
```

### Reinstall Grafana
```sh
sudo apt remove --purge -y grafana
sudo apt install -y grafana
```
