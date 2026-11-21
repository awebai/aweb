set -eu
cd /job
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data network-config
qemu-img create -q -f qcow2 -F raw -b /base/disk.raw disk.qcow2
exec qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -smp 10 -m 44G \
    -display none -serial file:/job/serial.log -monitor none -no-reboot \
    -drive file=disk.qcow2,format=qcow2,if=virtio,discard=unmap \
    -drive file=seed.iso,format=raw,media=cdrom,readonly=on \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:aa:bb:01
