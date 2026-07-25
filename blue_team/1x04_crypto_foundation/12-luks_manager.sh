#!/bin/bash
# ==============================================================================
# Script Name: 12-luks_manager.sh
# Description: Automates LUKS volume creation, opening, and closing operations.
# Usage: ./12-luks_manager.sh [create|open|close]
# ==============================================================================

set -e

IMG_FILE="encrypted_volume.img"
MAPPER_NAME="secure_vol"
MOUNT_POINT="/mnt/secure_backup"
SIZE_MB=500

case "$1" in
    create)
        echo "[*] Creating ${SIZE_MB}MB virtual disk image..."
        dd if=/dev/zero of="${IMG_FILE}" bs=1M count="${SIZE_MB}"
        
        echo "[*] Formatting image with LUKS encryption..."
        cryptsetup luksFormat "${IMG_FILE}"
        
        echo "[*] Opening encrypted volume..."
        cryptsetup luksOpen "${IMG_FILE}" "${MAPPER_NAME}"
        
        echo "[*] Creating ext4 filesystem..."
        mkfs.ext4 "/dev/mapper/${MAPPER_NAME}"
        
        echo "[*] Closing encrypted volume..."
        cryptsetup luksClose "${MAPPER_NAME}"
        echo "[+] LUKS volume successfully created and initialized."
        ;;
        
    open)
        echo "[*] Opening LUKS encrypted volume..."
        cryptsetup luksOpen "${IMG_FILE}" "${MAPPER_NAME}"
        
        echo "[*] Mounting filesystem to ${MOUNT_POINT}..."
        mkdir -p "${MOUNT_POINT}"
        mount "/dev/mapper/${MAPPER_NAME}" "${MOUNT_POINT}"
        echo "[+] LUKS volume opened and mounted at ${MOUNT_POINT}."
        ;;
        
    close)
        echo "[*] Unmounting filesystem from ${MOUNT_POINT}..."
        umount "${MOUNT_POINT}" || true
        
        echo "[*] Closing LUKS volume..."
        cryptsetup luksClose "${MAPPER_NAME}"
        echo "[+] LUKS volume successfully closed and unmounted."
        ;;
        
    *)
        echo "Usage: $0 {create|open|close}"
        exit 1
        ;;
esac
