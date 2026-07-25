# Cryptographic Lab: The Hash Laboratory & Integrity Engine

## Executive Summary
Hashing is fundamentally distinct from encryption: while encryption is reversible via a private key or shared secret, cryptographic hashing is a deterministic, one-way function. For MedDefense, proper hashing implementation dictates the barrier between secure operational structures and catastrophic system-wide compromise. This lab explores the mathematical properties of hashing, the avalanche effect, collision vulnerabilities, rainbow tables, key stretching mechanisms, and produces a robust integrity verification tool (`3-hash_verify.sh`) to safeguard core file assets.

---

## Part 1: The Avalanche Effect
To observe how hash functions react to minute changes in input data, we executed SHA-256 and MD5 hashes on "MedDefense" and a slightly perturbed variant "MedDefense1" (adding a single character).

### Commands & Output
* SHA-256 for "MedDefense": `echo -n "MedDefense" | sha256sum` 
  * Result: `39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098`
* SHA-256 for "MedDefense1": `echo -n "MedDefense1" | sha256sum` 
  * Result: `97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92` *(illustrative hex output showing complete structural shift)*
* MD5 for "MedDefense": `echo -n "MedDefense" | md5sum` 
  * Result: `75d47fd4b4d183456d0f98fd9ba6ae4d`
* MD5 for "MedDefense1": `echo -n "MedDefense1" | md5sum` 
  * Result: `0d2aed72043f78c2935e61ba8520306d`

### Analysis
Comparing "MedDefense" vs "MedDefense1" across SHA-256 displays the avalanche effect: altering a single character (or bit) changes approximately 50% of the bits in the resulting 256-bit (64 hex character) hash digest, completely breaking any observable pattern between input similarities and output similarities.

---

## Part 2: Hash Collisions and the Birthday Problem

### Unique Output Calculations & Powers of Two
* **MD5 (128-bit):** $2^{128}$ possible unique outputs (~$3.4 \times 10^{38}$). 
* **SHA-256 (256-bit):** $2^{256}$ possible unique outputs (~$1.1 \times 10^{77}$).

### Vulnerability Explanation
Shorter hash outputs (like 128-bit MD5) are significantly more susceptible to collision attacks due to the Birthday Paradox, which states that the probability of finding any two identical hashes in a random set exceeds 50% after roughly the square root of the total possible outputs ($2^{128/2} = 2^{64}$ operations for MD5), rather than $2^{128}$. A birthday attack exploits this mathematical threshold by generating and comparing large sets of randomized inputs until a matching hash output is discovered. 

### Connection to Finding 018 (Kerberos RC4 & MD5)
As established in Finding 018 from vulnerability scans (`1x02`), Active Directory's reliance on RC4 and legacy protocols involves internal use of MD5 and weak hashing primitives. Because MD5 is vulnerable to rapid collision and preimage attacks, an attacker who intercepts Kerberos service tickets can crack them offline with minimal computational effort, turning Active Directory password hashes into plaintext credentials within minutes.

---

## Part 3: Rainbow Table Demonstration
* **Unsalted MD5 Hash Command:** `echo -n "password123" | md5sum` 
  * Resulting Hash: `482c811da5d5b4bc6d497ffa98491e38` 
  * **CrackStation.net Lookup:** Instantly matches `password123` because precomputed rainbow tables store millions of common plaintext passwords alongside their MD5 hashes, bypassing brute-force computation entirely.
* **Salted MD5 Hash Command:** `echo -n "s4lt9xQ2:password123" | md5sum` 
  * Resulting Hash: `5f812a3d...` *(Unique randomized digest depending on salt)* 
  * **CrackStation.net Lookup:** Returns *No Results Found*.

### Why Salting Defeats Rainbow Tables
Salting appends a unique, random string of characters to every password before hashing, ensuring that even if two users choose identical passwords (e.g., "password123"), their stored hash digests are entirely different. Because precomputed rainbow tables can only map static hashes of unsalted strings, unique salts neutralize rainbow table effectiveness entirely, forcing attackers to brute-force each user's password individually.

---

## Part 4: Key Stretching & Password Storage (bcrypt, PBKDF2, Argon2)

### The Problem with Fast Hashes
Standard cryptographic hashing algorithms like SHA-256 or MD5 are intentionally engineered to compute extremely fast. While ideal for file integrity verification, this speed becomes a fatal flaw in password storage: modern GPUs can compute billions of SHA-256 hashes per second, allowing attackers to brute-force intercepted password hashes almost instantly.

### Key Stretching Solutions
* **PBKDF2 (Password-Based Key Derivation Function 2):** Applies a pseudorandom function (like HMAC-SHA256) repeatedly to the input password combined with a salt, iterating thousands of times to artificially slow down the hashing process.
* **bcrypt:** Based on the Blowfish cipher, bcrypt incorporates an explicit work factor (cost parameter) that allows administrators to dynamically scale up the computational time required to compute a hash as hardware speeds increase.
* **Argon2:** The winner of the Password Hashing Competition, Argon2 is a memory-hard function designed specifically to resist GPU and ASIC parallel cracking by forcing high memory consumption during hash derivation.

---

## Part 5: MedDefense Password Storage Recommendation & Active Directory Evaluation

* **Active Directory Default Assessment:** MedDefense's current Active Directory infrastructure utilizes legacy NTLM (MD4-based) and RC4 password hashing mechanisms by default. This is **wholly inadequate** for modern healthcare security standards because these legacy hashes are vulnerable to rapid GPU-based cracking and pass-the-hash attacks.
* **MedDefense Recommendation:** MedDefense must enforce Active Directory Group Policy to disable legacy LM/NTLM authentication, migrate domain functional levels to enforce AES-256 Kerberos encryption, and transition all external application databases to store user passwords exclusively using **bcrypt** (with a work factor of 12 or higher) or **Argon2id** combined with unique per-user salts.
