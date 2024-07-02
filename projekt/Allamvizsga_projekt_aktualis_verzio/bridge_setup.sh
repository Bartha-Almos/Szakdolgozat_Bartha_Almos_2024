#!/bin/bash

# Create a bridge named br0
sudo ip link add name br0 type bridge

# Bring up the bridge
sudo ip link set dev br0 up

# Bring up eth0 and add it to the bridge
sudo ip link set eth0 up
sudo ip link set eth0 master br0

# Bring up eth1 and add it to the bridge
sudo ip link set eth1 up
sudo ip link set eth1 master br0

# Show bridge information
sudo bridge link

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
