#!/bin/sh
# Run explicitly from the trusted first initramfs after mounting the ESP.
# The secret source must already be present in RAM or supplied through a trusted channel.
set -eu
if [ "$#" -ne 2 ]; then
    echo 'Usage: enroll-once.sh ESP_MOUNT SECRET64_PATH' >&2
    exit 2
fi
esp=$1
secret_source=$2
base="$esp/EFI/TPMBOOT"
test -f /tpmboot/enrollment.bin
test -f "$base/enroll.request"
test ! -e "$base/sealed.bin"
initrdctl enroll --authorize-enrollment /tpmboot/enrollment.bin \
    "$base/manifest.bin" "$base/public.bin" "$secret_source" "$base/sealed.bin"
rm "$base/enroll.request"
sync
echo 'Enrollment committed. Reboot through the same dedicated EFI entry.'

