#!/bin/bash

# This script will trigger the Falco rule by executing a gluster volume command
# Make sure you have gluster installed and the user has appropriate permissions

echo "Triggering gluster volume command..."

# Run a gluster volume command to match the Falco rule
gluster volume info
