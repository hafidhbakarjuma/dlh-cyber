# The Disk Encryption Lab & NAS-01 Backup Design

## Summary of Lab Activities: Disk Encryption & LUKS
* **Part 1 — LUKS Setup & Execution:** Created a 500 MiB virtual disk container, formatted it securely with LUKS, opened the device mapper (`secure_vol`), initialized an ext4 filesystem, wrote and verified a test file, and safely unmounted and closed the volume.
* **Part 2 — Verification:** Confirmed that running `strings` on the raw image yields pure binary noise without the test data, proving that encryption at rest successfully protects data against physical theft. A full reopen and read cycle successfully retrieved the exact test file contents, confirming data integrity.
* **Part 3 — Automation & Bug Fixing:** Implemented `12-luks_manager.sh` to handle `create`, `open`, and `close` operations. Resolved an initial filesystem initialization bug where `create` only ran `luksFormat` by ensuring the script automatically opens the volume, builds the `ext4` filesystem, and closes it.

---

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

---

## Part 4: MedDefense Backup Encryption Design (NAS-01)

### 1. Encryption Level Selection
* **Selected Level:** Volume-level encryption (LUKS / dm-crypt). *(Note: Full-disk encryption is reserved for local host endpoints like employee laptops; NAS-01 utilizes volume-level encryption to secure individual storage arrays and backup pools).*
* **Justification:** Volume-level encryption provides a strong balance of security and administrative manageability for backup storage pools. Unlike file-level encryption (which leaves directory structures, metadata, and backup container names exposed), volume-level encryption fully protects the entire filesystem layer at rest while supporting high-throughput sequential read/write operations required for nightly database dumps.

### 2. Performance Impact & Overhead
* **Performance Overhead:** Utilizing modern AES-NI hardware acceleration instructions, block-level encryption overhead typically results in less than 3% to 5% CPU utilization impact during heavy backup ingestion. Given MedDefense's hardware specifications, write throughput degradation remains well within acceptable operational thresholds.

### 3. Key Storage Architecture
* **Key Storage Location:** Encryption keys or automated keyfiles must **NOT** be stored on NAS-01 itself. Storing a decryption key alongside the encrypted volume creates a single point of failure and renders encryption useless. Instead, keys are stored securely off-device within an enterprise Key Management Service (KMS) or injected via secure out-of-band keyfiles during boot.

### 4. Lost-Key Impact & Recovery Procedure
* **Lost-Key Impact:** Because LUKS utilizes robust cryptographic ciphers (AES-256), losing the master key or passphrase without an escrow backup renders the entire backup repository permanently and mathematically unrecoverable. 
* **Recovery Procedure:** MedDefense mitigates this catastrophic risk by enforcing an M-of-N split-knowledge recovery model (Shamir's Secret Sharing), storing emergency backup key shards in secure offline hardware tokens kept in separate physical bank safety deposit boxes.

### 5. Cloud Replica Encryption & Key Ownership
* **Cloud Replica Protection:** When MedDefense replicates backup data pools to cloud object storage (e.g., AWS S3), the cloud replica must also remain strictly encrypted at rest (e.g., Server-Side Encryption with Customer-Managed Keys - SSE-KMS). 
* **Key Ownership:** MedDefense maintains exclusive ownership of the decryption keys via a dedicated KMS keystore. Cloud providers never hold or have access to raw plaintext keys, ensuring that even if cloud object storage buckets are misconfigured or exposed externally, the underlying patient backup data remains unreadable ciphertext.
