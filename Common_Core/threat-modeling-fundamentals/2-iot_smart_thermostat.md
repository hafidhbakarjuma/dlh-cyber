# IoT Security Threat Analysis

## 1. IoT-Specific Threats

Unlike web apps, IoT devices have unique vectors due to their proximity to hardware and local network reliance:

### Physical Interface Exposure

Unauthorized access via JTAG, UART, or USB debug ports left active on the PCB.

### Lack of Hardware-Based Root of Trust

Without secure boot or a Trusted Platform Module (TPM), attackers can replace the firmware with malicious versions.

### Insecure Default Credentials

Devices often ship with hardcoded, shared manufacturer credentials that are easily brute-forced.

### Side-Channel Attacks

Measuring power consumption or electromagnetic emissions to extract cryptographic keys stored in volatile memory.

### Firmware Extraction & Analysis

Using SPI Flash dumps to reverse-engineer the binary, discovering hidden APIs or hardcoded API keys for cloud services.

---

## 2. Physical Access Attack Chain

If an attacker gains physical possession of the device, the following chain of compromise is likely:

### Step 1: Reconnaissance

The attacker inspects the PCB for hidden headers (e.g., serial console pins).

### Step 2: Access

Using a logic analyzer or UART-to-USB bridge, they tap into the boot process to gain a root shell.

### Step 3: Extraction

They dump the flash memory content, which contains configuration files, Wi-Fi credentials, and cloud API tokens.

### Step 4: Manipulation

They modify the firmware binary to create a "backdoored" version that pings a malicious server, then re-flash the modified image.

### Potential Impact

Total device control, lateral movement into the home network via stored Wi-Fi credentials, and botnet enrollment (e.g., Mirai-style attacks).

---

## 3. Securing the OTA Update Process

The Over-The-Air (OTA) update mechanism is the most sensitive feature. To ensure integrity, the following controls are essential:

### Code Signing (Asymmetric Encryption)

The device must verify the firmware signature using a public key burned into hardware. If the signature doesn't match the private key held by the manufacturer, the device rejects the update.

### Secure Boot

The device performs a cryptographic chain-of-trust check upon power-on, ensuring only verified, authenticated firmware can execute.

### Encrypted Channels (TLS)

All firmware downloads must occur over a mutual-TLS (mTLS) connection to prevent Man-in-the-Middle (MITM) interception.

### Rollback / Anti-Rollback Protection

The device must store version numbers in secure storage to prevent an attacker from downgrading the firmware to an older, vulnerable version.

### Staged Rollouts & Hash Verification

Verify the SHA-256 hash of the entire image before the update is committed to the active partition.

---

## Understanding the Differences

IoT security differs fundamentally from web security because the device is the boundary. In a web app, the server is the boundary; in IoT, the physical device is a persistent, accessible, and often unmonitored perimeter.
