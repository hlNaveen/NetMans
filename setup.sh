#!/bin/bash

echo "This script sets relevant permissions to run the packet sniffer."

sudo chmod 766 /dev/bpf0
sudo chmod 766 /dev/bpf1
sudo chmod 766 /dev/bpf2
