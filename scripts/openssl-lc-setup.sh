#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2025 Marvell.

set -euo pipefail

log_info()  { echo "[INFO] $*"; }
log_error() { echo "[ERROR] $*" >&2; }

# Remove and insert the octeon_ep kernel module
if lsmod | grep -i '^octeon_ep' >/dev/null 2>&1; then
	log_info "Removing existing octeon_ep kernel module..."
	sudo rmmod octeon_ep >/dev/null 2>&1 || { log_error "Failed to remove octeon_ep module"; exit 1; }
else
	log_info "octeon_ep kernel module not loaded, skipping removal."
fi

log_info "Loading octeon_ep kernel module..."
sudo modprobe octeon_ep

# Check dmesg logs to confirm successful PF driver load
log_info "Checking dmesg for PF driver load..."
if ! dmesg | grep -i "octeon_ep: Loaded successfully" | tail -1 >/dev/null 2>&1; then
	log_error "octeon_ep: Loaded successfully ! not found in dmesg."
	exit 1
fi

# Extract the chip string (e.g., cn10ka or cn93xx) from dmesg and export it
CHIP_STRING=$(dmesg | grep -oP 'Setting up OCTEON \KCN[0-9A-Z]+' | tail -1)
if [[ -z "$CHIP_STRING" ]]; then
	log_error "Failed to extract CHIP_STRING from dmesg."
	exit 1
fi
export CHIP_STRING
log_info "Detected CHIP_STRING: $CHIP_STRING"

# Extract and export the SDP_DEV_BDF based on the chip string
SDP_DEV_BDF=$(dmesg | grep -i "Setting up OCTEON $CHIP_STRING PF" | grep -oP '0000:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]' | tail -1)
if [[ -z "$SDP_DEV_BDF" ]]; then
	log_error "Failed to extract SDP_DEV_BDF from dmesg."
	exit 1
fi
export SDP_DEV_BDF
log_info "Detected SDP_DEV_BDF: $SDP_DEV_BDF"

sleep 1  # Ensure the system is ready for further operations

# Enable SR-IOV with 1 VF
log_info "Enabling SR-IOV with 1 VF..."
echo 1 > /sys/bus/pci/devices/$SDP_DEV_BDF/sriov_numvfs

# Get the PCI BDF of the new VF
VF_BDF_PATH="/sys/bus/pci/devices/$SDP_DEV_BDF/virtfn0"
if [[ ! -e "$VF_BDF_PATH" ]]; then
	log_error "VF path $VF_BDF_PATH does not exist."
	exit 1
fi
VF_BDF=$(basename "$(readlink "$VF_BDF_PATH")")
export VF_BDF
log_info "VF PCI BDF: $VF_BDF"

# Allocate hugepages
log_info "Allocating 1500 hugepages..."
echo 1500 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

# Load the vfio-pci module
log_info "Loading vfio-pci module..."
sudo modprobe vfio-pci

# Allow VFIO without IOMMU
log_info "Enabling unsafe_noiommu_mode for VFIO..."
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

# Bind the device to the vfio-pci driver
VENDOR_DEVICE_ID=$(dmesg | grep -i "pci $VF_BDF: \[" | grep -oP '\[\K[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(?=\])' | tail -1)
VENDOR_ID=${VENDOR_DEVICE_ID%%:*}
DEVICE_ID=${VENDOR_DEVICE_ID##*:}
log_info "Vendor ID: $VENDOR_ID, Device ID: $DEVICE_ID"
if [[ -z "$VENDOR_ID" ]]; then
	log_error "Failed to extract VENDOR_ID for $VF_BDF."
	exit 1
fi

sleep 1  # Wait for the system to apply the changes

log_info "Binding $VF_BDF ($VENDOR_ID:$DEVICE_ID) to vfio-pci driver..."
echo "$VENDOR_ID $DEVICE_ID" > /sys/bus/pci/drivers/vfio-pci/new_id

# Find the network interface name corresponding to the SDP_DEV_BDF PCI device
SDP_NET_IF=$(ls /sys/bus/pci/devices/$SDP_DEV_BDF/net 2>/dev/null | head -n 1)
if [[ -z "$SDP_NET_IF" ]]; then
	log_error "Failed to find network interface for $SDP_DEV_BDF."
	exit 1
fi

# Assign IP address 192.168.1.2 to the interface using ifconfig
log_info "Assigning IP 192.168.1.2 to $SDP_NET_IF..."
sudo ifconfig "$SDP_NET_IF" 192.168.1.2 up

log_info "Setup complete."
