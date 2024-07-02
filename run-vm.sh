#!/bin/bash

# Get a kernel and rootfs
arch=`uname -m`
dest_kernel="hello-vmlinux.bin"
dest_rootfs="hello-rootfs.ext4"
image_bucket_url="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/$arch"

if [ ${arch} = "x86_64" ]; then
    kernel="${image_bucket_url}/kernels/vmlinux.bin"
    rootfs="${image_bucket_url}/rootfs/bionic.rootfs.ext4"
elif [ ${arch} = "aarch64" ]; then
    kernel="${image_bucket_url}/kernels/vmlinux.bin"
    rootfs="${image_bucket_url}/rootfs/bionic.rootfs.ext4"
else
    echo "Cannot run firecracker on $arch architecture!"
    exit 1
fi

echo "Downloading $kernel..."
curl -fsSL -o $dest_kernel $kernel

echo "Downloading $rootfs..."
curl -fsSL -o $dest_rootfs $rootfs

echo "Saved kernel file to $dest_kernel and root block device to $dest_rootfs."

# Start firecracker
echo "Starting firecracker"
firecracker --api-sock /tmp/firecracker.socket &
firecracker_pid=$!

# Set the guest kernel and rootfs
rch=`uname -m`
kernel_path=$(pwd)"/hello-vmlinux.bin"

if [ ${arch} = "x86_64" ]; then
    curl --unix-socket /tmp/firecracker.socket -i \
      -X PUT 'http://localhost/boot-source'   \
      -H 'Accept: application/json'           \
      -H 'Content-Type: application/json'     \
      -d "{
            \"kernel_image_path\": \"${kernel_path}\",
            \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
       }"
elif [ ${arch} = "aarch64" ]; then
    curl --unix-socket /tmp/firecracker.socket -i \
      -X PUT 'http://localhost/boot-source'   \
      -H 'Accept: application/json'           \
      -H 'Content-Type: application/json'     \
      -d "{
            \"kernel_image_path\": \"${kernel_path}\",
            \"boot_args\": \"keep_bootcon console=ttyS0 reboot=k panic=1 pci=off\"
       }"
else
    echo "Cannot run firecracker on $arch architecture!"
    exit 1
fi

rootfs_path=$(pwd)"/hello-rootfs.ext4"
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/drives/rootfs' \
  -H 'Accept: application/json'           \
  -H 'Content-Type: application/json'     \
  -d "{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"${rootfs_path}\",
        \"is_root_device\": true,
        \"is_read_only\": false
   }"

# Start the guest machine
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/actions'       \
  -H  'Accept: application/json'          \
  -H  'Content-Type: application/json'    \
  -d '{
      "action_type": "InstanceStart"
   }'

# Kill the firecracker process to exit the workflow
sleep 20
kill -9 $firecracker_pid
