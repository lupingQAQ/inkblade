#!/bin/sh
# setup-alpine.sh -- run INSIDE the Alpine live ISO (QEMU TCG guest).
#
# Installs Alpine to /dev/vda in sys mode using the answer file fetched from the
# host-side HTTP server (QEMU user-net gateway 10.0.2.2), injects the lab SSH
# public key for root, then powers the VM off so it can be booted from disk.
#
# Called by provision_alpine.py; not meant to be run on a real machine: it
# erases /dev/vda.
set -eu

BASE="${BASE:-http://10.0.2.2:8000}"

echo "[setup-alpine.sh] fetching answer file from $BASE"
wget -q -O /tmp/answers "$BASE/answers"
wget -q -O /tmp/authorized_keys "$BASE/authorized_keys"

echo "[setup-alpine.sh] installing Alpine (sys mode, /dev/vda)"
setup-alpine -f /tmp/answers

echo "[setup-alpine.sh] injecting root SSH key"
mkdir -p /mnt
for part in /dev/vda3 /dev/vda2 /dev/vda1; do
    if mount "$part" /mnt 2>/dev/null; then
        echo "[setup-alpine.sh] mounted $part"
        break
    fi
done
if [ ! -d /mnt/etc ]; then
    echo "[setup-alpine.sh] ERROR: cannot mount installed root" >&2
    exit 3
fi
mkdir -p /mnt/root/.ssh
cp /tmp/authorized_keys /mnt/root/.ssh/authorized_keys
chmod 700 /mnt/root/.ssh
chmod 600 /mnt/root/.ssh/authorized_keys

# Keep a serial console on the installed system: kernel messages on ttyS0 and a
# getty on ttyS0, so the QEMU console stays usable if SSH ever breaks.
if [ -f /mnt/boot/extlinux.conf ]; then
    sed -i 's/^APPEND /APPEND console=ttyS0,115200 /' /mnt/boot/extlinux.conf
fi
sed -i 's|^#ttyS0::respawn|ttyS0::respawn|' /mnt/etc/inittab 2>/dev/null || true

sync
umount /mnt

echo "PROVISION-OK"
sync
poweroff
