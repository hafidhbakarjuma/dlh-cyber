# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Lab: The Key Exchange & MITM Analysis

---

## Executive Summary

Symmetric encryption requires both communicating parties to share an identical secret key, yet transmitting that key across an insecure network exposes it to interception. In 1976, Diffie and Hellman introduced a mathematical breakthrough allowing two parties to establish a shared secret over a public channel without ever transmitting the secret itself. This lab simulates the Diffie-Hellman key exchange via OpenSSL, explains the mechanics for non-cryptographers (such as CFO Robert Kim), examines the vulnerability to Man-in-the-Middle (MITM) attacks, and bridges the gap to Public Key Infrastructure (PKI) certificates.

---

## Part 1: The Diffie-Hellman Simulation

To execute a simulated Diffie-Hellman key exchange between Alice and Bob using OpenSSL, we performed the following operational sequence:

### 1. Generate Shared DH Parameters
```bash
openssl dhparam -out dhparams.pem 2048
```
*Output Summary:* Generates a 2048-bit prime modulus and generator, establishing the shared mathematical foundation for both parties.

### 2. Generate Alice's Private and Public Keys
```bash
# Generate Alice's private key
openssl genpkey -paramfile dhparams.pem -out alice_key.pem

# Extract Alice's public key
openssl pkey -in alice_key.pem -pubout -out alice_pub.pem
```

### 3. Generate Bob's Private and Public Keys
```bash
# Generate Bob's private key
openssl genpkey -paramfile dhparams.pem -out bob_key.pem

# Extract Bob's public key
openssl pkey -in bob_key.pem -pubout -out bob_pub.pem
```

### 4. Derive the Shared Secret from Both Sides
```bash
# Alice derives the shared secret using Bob's public key
openssl pkeyutl -derive -inkey alice_key.pem -peerkey bob_pub.pem -out alice_secret.bin

# Bob derives the shared secret using Alice's public key
openssl pkeyutl -derive -inkey bob_key.pem -peerkey alice_pub.pem -out bob_secret.bin
```

### 5. Compare the Secrets
```bash
diff alice_secret.bin bob_secret.bin
```
*Result:* No output from `diff`, confirming that `alice_secret.bin` and `bob_secret.bin` are **byte-for-byte identical**.

---

## Part 2: Explanation for Non-Cryptographers (Robert Kim, CFO)

Imagine Alice and Bob are trying to lock a secret treasure chest and send it back and forth, but an eavesdropper named Eve is watching their every move. Instead of passing a key, Alice and Bob each take a public bucket of yellow paint (the shared public parameters), mix in their own secret colors that they keep strictly to themselves, and exchange the resulting mixed shades across the room for Eve to see. Because of unique mathematical properties, when Alice takes the shade Bob sent and mixes it with her hidden color, and Bob does the exact same thing with Alice's shade, they both independently end up with the exact same final color—their shared secret key. Eve sees the intermediate, mixed paint cans passing back and forth across the network, but because reverse-engineering the original secret colors from the mixed shades is mathematically impossible, Eve cannot figure out the final secret color.

---

## Part 3: The Man-in-the-Middle (MITM) Attack

### Vulnerability Mechanics
While plain Diffie-Hellman protects against passive eavesdroppers (like Eve just listening), it provides zero authentication, making it completely vulnerable to active Man-in-the-Middle (MITM) attacks. An attacker positioned between Alice and Bob intercepts Alice's public key and replaces it with her own, performing a separate DH exchange with Alice while simultaneously doing the same with Bob. Consequently, the attacker establishes two independent shared secrets—one with Alice and one with Bob—allowing the attacker to transparently intercept, read, modify, and re-encrypt all traffic passing between them without either party realizing it.

### Application to MedDefense
If the site-to-site VPN tunnels connecting Central, Westside, and HQ rely on Diffie-Hellman key exchange without strict certificate-based authentication, an attacker positioned on the network path could execute a MITM attack, impersonating endpoints and compromising all traversing medical and administrative traffic. **Certificates prevent this vulnerability** by binding public keys to verified digital identities using a trusted Public Key Infrastructure (PKI), ensuring that Alice and Bob mathematically verify *who* they are exchanging keys with before any data flows.

---
