#!/usr/bin/env bash
set -euo pipefail

if [ ! -c /dev/kvm ]; then
    sudo modprobe kvm_intel 2>/dev/null || sudo modprobe kvm_amd 2>/dev/null || true
fi
if [ ! -c /dev/kvm ]; then
    echo "::notice::KVM device unavailable. The CloudHV Unix API regression ran without a VM."
    exit 0
fi

sudo apt-get install -y --no-install-recommends qemu-utils cloud-image-utils fdisk zstd
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/images/alpine"

source=$(sed -n 's/^CLOUD_HYPERVISOR_VERSION="\([^"]*\)"$/\1/p' install.sh)
curl -fsSL --retry 3 --connect-timeout 15 \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$source/cloud-hypervisor-static" \
    -o "$work/cloud-hypervisor"
chmod 0755 "$work/cloud-hypervisor"
curl -fsSL --retry 3 --connect-timeout 15 \
    https://github.com/narwhal-cloud/images/releases/download/vm-latest/cloudhv-alpine-amd64.tar.zst \
    -o "$work/alpine.tar.zst"
tar --zstd -xf "$work/alpine.tar.zst" -C "$work/images/alpine"
go test -c ./manager/cloudhv -o "$work/cloudhv.test"
sudo unshare --net env RUNMAN_TEST_KVM_BINARY="$work/cloud-hypervisor" \
    RUNMAN_TEST_KVM_IMAGES="$work/images" "$work/cloudhv.test" -test.v -test.run '^TestBootCloudHVOnKVM$'
