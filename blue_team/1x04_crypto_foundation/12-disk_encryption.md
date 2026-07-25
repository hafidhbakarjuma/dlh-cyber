# Task 12 — The Disk Encryption Lab

## Summary of Lab Activities: Disk Encryption & LUKS

* **Part 1 — LUKS Setup & Execution:** Created a 500 MiB virtual disk container, formatted it securely with LUKS, opened the device mapper (`secure_vol`), initialized an ext4 filesystem, wrote and verified a test file, and safely unmounted and closed the volume.
* **Part 2 — Verification:** Confirmed that running `strings` on the raw image yields pure binary noise without the test data, proving that encryption at rest successfully protects data against physical theft. A full reopen and read cycle successfully retrieved the exact test file contents, confirming data integrity.
* **Part 3 — Automation & Bug Fixing:** Implemented `12-luks_manager.sh` to handle `create`, `open`, and `close` operations. Resolved an initial filesystem initialization bug where `create` only ran `luksFormat` by ensuring the script automatically opens the volume, builds the `ext4` filesystem, and closes it.

## Part 1 — LUKS Setup & Execution
* `dd if=/dev/zero of=encrypted_volume.img bs=1M count=500` → 500 MiB file created
* `sudo cryptsetup luksFormat encrypted_volume.img` → Confirmed overwrite, set passphrase, formatted successfully
* `sudo cryptsetup luksOpen encrypted_volume.img secure_vol` → Opened, mapped to `/dev/mapper/secure_vol`
* `sudo mkfs.ext4 /dev/mapper/secure_vol` → ext4 filesystem created, journal enabled
* `sudo mount /dev/mapper/secure_vol /mnt/secure_vol` and `echo "MedDefense LUKS test data - patient record placeholder" | sudo tee /mnt/secure_vol/testfile.txt` → Test file written and confirmed readable
* `sudo umount /mnt/secure_vol` and `sudo cryptsetup luksClose secure_vol` → Unmounted and closed successfully

---

## Part 2 — Verification
* `strings encrypted_volume.img | head -50` → Pure binary noise, no readable trace of the test data. This proves encryption at rest works: raw access to the file (e.g., a stolen drive) yields nothing meaningful without the passphrase.
* **Reopen cycle:** `sudo cryptsetup luksOpen encrypted_volume.img secure_vol`, `sudo mount /dev/mapper/secure_vol /mnt/secure_vol`, `cat /mnt/secure_vol/testfile.txt` → `"MedDefense LUKS test data - patient record placeholder"` — data fully intact after close/reopen.
* `sudo umount /mnt/secure_vol` and `sudo cryptsetup luksClose secure_vol` → Closed successfully.

---

## Part 3 — The LUKS Automation Script
* See `12-luks_manager.sh`. Supports `create`, `open`, and `close` modes. Tested full cycle (`create` $\rightarrow$ `open` $\rightarrow$ `write/read` $\rightarrow$ `close`) successfully.
* **Bug Fix Note:** Initial version had a bug where `create` only ran `luksFormat` without building a filesystem, causing `open` to fail with *"wrong fs type, bad option, bad superblock."* This was fixed by having `create` also open the volume, run `mkfs.ext4`, and then close it before finishing.


# Part 4: MedDefense Backup Encryption Design (NAS-01)

### 1. Encryption Level Selection
* **Selected Level:** Volume-level encryption (LUKS / dm-crypt).
* **Justification:** Volume-level encryption provides a strong balance of security and administrative manageability for backup storage pools. Unlike file-level encryption (which leaves directory structures, metadata, and backup container names exposed), volume-level encryption fully protects the entire filesystem layer at rest while supporting high-throughput sequential read/write operations required for nightly database dumps.

### 2. Performance Impact & Overhead
* **Performance Overhead:** Utilizing modern AES-NI hardware acceleration instructions, block-level encryption overhead typically results in less than 3% to 5% CPU utilization impact during heavy backup ingestion. Given MedDefense's hardware specifications, write throughput degradation remains well within acceptable operational thresholds.

### 3. Key Storage Architecture
* **Key Storage Location:** Encryption keys or automated keyfiles must NOT be stored on NAS-01 itself.
* **Reasoning:** Storing the decryption key alongside the encrypted data defeats the fundamental purpose of encryption at rest; an attacker who compromises NAS-01 via network lateral movement or physical theft would instantly recover both the data and the key. Instead, keys will be managed via a centralized enterprise Key Management Service (KMS) or hardware-backed Vault, requiring manual or secure out-of-band injection during system boot.

### 4. Key Loss Implications
* **Recovery Implications:** If the master encryption key and recovery passphrases are permanently lost, all backup data on NAS-01 becomes irrecoverably destroyed.
* **Mitigation:** Implementing strict escrow procedures, multi-person split-knowledge passphrases, and secure offline hardware token backups stored in a bank vault.

### 5. Integration with Offsite Backup Replication
* **Cloud Replica Security:** Yes, the offsite cloud replica must also be fully encrypted at rest.
* **Key Ownership:** It must be encrypted using MedDefense’s independently managed customer-held encryption keys (BYOK - Bring Your Own Key) rather than cloud provider default keys. This ensures that even if cloud infrastructure storage buckets are misconfigured or exposed to third parties, the data remains entirely unreadable without MedDefense's private key hierarchy.
