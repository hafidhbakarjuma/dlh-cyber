# MedDefense Health Systems
# The CVSS Deconstruction

## Objective

The Common Vulnerability Scoring System (CVSS) v3.1 provides a standardized method for measuring the severity of security vulnerabilities. Understanding how each metric contributes to the final score allows security analysts to prioritize vulnerabilities based on actual risk rather than relying only on the numerical score.

The NIST CVSS v3.1 Calculator was used throughout this exercise to analyze, construct, and compare vulnerability scores.

NIST Calculator:

https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

---

# Exercise 1 – CVSS Deconstruction

## Vulnerability

**Finding 001**

**CVE-2021-44790**

Vector:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Base Score:

**9.8 (Critical)**

---

## Metric Breakdown

### AV – Attack Vector

**Selected Value**

```
N = Network
```

### Meaning

The vulnerability can be exploited remotely over the network without physical or local access.

### Other Possible Values

| Value | Meaning | Effect on Score |
|--------|---------|----------------|
| N | Network | Highest score |
| A | Adjacent Network | Slightly lower |
| L | Local | Lower |
| P | Physical | Lowest |

### Why Network?

Apache HTTP Server accepts HTTP requests over TCP port 80, allowing an attacker anywhere on the network to exploit the vulnerability.

---

### AC – Attack Complexity

**Selected Value**

```
L = Low
```

### Meaning

No special conditions are required.

Attackers only need to send a specially crafted HTTP request.

### Other Values

| Value | Meaning |
|--------|---------|
| L | Low |
| H | High |

### Why Low?

No race conditions, timing attacks, or unusual configurations are required.

---

### PR – Privileges Required

**Selected Value**

```
N = None
```

### Meaning

No authentication is required before exploitation.

### Other Values

| Value | Meaning |
|--------|---------|
| N | None |
| L | Low |
| H | High |

### Why None?

Any remote attacker can send the malicious request without logging into the server.

---

### UI – User Interaction

**Selected Value**

```
N = None
```

### Meaning

No legitimate user needs to perform any action.

### Other Values

| Value | Meaning |
|--------|---------|
| N | None |
| R | Required |

### Why None?

The exploit works automatically once the malicious request reaches the server.

---

### S – Scope

**Selected Value**

```
U = Unchanged
```

### Meaning

Only the vulnerable Apache server is affected.

### Other Values

| Value | Meaning |
|--------|---------|
| U | Unchanged |
| C | Changed |

### Why Unchanged?

The vulnerability compromises the web server itself rather than another security authority.

---

### C – Confidentiality

**Selected Value**

```
H = High
```

### Meaning

Attackers can completely access confidential information.

### Other Values

| Value | Meaning |
|--------|---------|
| N | None |
| L | Low |
| H | High |

### Why High?

Remote code execution allows attackers to read application files, credentials, and sensitive data.

---

### I – Integrity

**Selected Value**

```
H = High
```

### Meaning

Attackers can completely modify system files and application data.

### Other Values

| Value | Meaning |
|--------|---------|
| N | None |
| L | Low |
| H | High |

### Why High?

An attacker can execute arbitrary commands and alter server data.

---

### A – Availability

**Selected Value**

```
H = High
```

### Meaning

Attackers can fully disrupt services.

### Other Values

| Value | Meaning |
|--------|---------|
| N | None |
| L | Low |
| H | High |

### Why High?

Remote code execution could crash or completely take over the web server.

---

# What Happens if Attack Vector Changes?

Original:

```
AV:N
```

Modified:

```
AV:L
```

New Vector

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Using the NIST CVSS Calculator:

| Vector | Score |
|---------|------:|
| Original | 9.8 |
| Modified | 8.4 |

## Why Does the Score Change?

Changing the Attack Vector from **Network** to **Local** means an attacker must already have access to the target machine before exploiting the vulnerability.

This significantly reduces the number of potential attackers and lowers the overall risk.

---

# Exercise 2 – CVSS Construction

## Given Characteristics

- Exploitable only from the local network
- Complex exploitation
- Low privileges required
- No user interaction
- Scope unchanged
- High confidentiality impact
- No integrity impact
- No availability impact

---

## Manual CVSS Vector

```
CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
```

---

## NIST Calculator Result

| Metric | Value |
|---------|------|
| Base Score | **4.9** |
| Severity | **Medium** |

---

## Why?

The vulnerability:

- cannot be exploited over the Internet
- requires privileged access
- requires difficult attack conditions
- only exposes confidential information

These restrictions lower the score significantly.

---

# Exercise 3 – CVSS Comparison

## Finding A

Finding 001

Apache mod_lua Buffer Overflow

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Score:

**9.8 (Critical)**

---

## Finding B

Finding 010

BD Alaris Infusion Pump

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
```

Score:

**7.5 (High)**

---

# Side-by-Side Comparison

| Metric | Finding 001 | Finding 010 |
|---------|-------------|-------------|
| Attack Vector | Network | Network |
| Attack Complexity | Low | Low |
| Privileges Required | None | None |
| User Interaction | None | None |
| Scope | Unchanged | Unchanged |
| Confidentiality | High | None |
| Integrity | High | None |
| Availability | High | High |

---

# Key Differences

The first five metrics are identical.

The major differences are the impact metrics:

| Metric | Finding 001 | Finding 010 |
|---------|-------------|-------------|
| Confidentiality | High | None |
| Integrity | High | None |
| Availability | High | High |

Finding 001 allows attackers to:

- steal sensitive data
- modify system data
- disrupt services

Finding 010 primarily causes denial of service and does not compromise confidentiality or integrity.

---

# Which Metrics Have the Greatest Impact?

The metrics that most significantly influence the final score are:

1. **Attack Vector (AV)** – Remote attacks receive higher scores than local attacks.
2. **Privileges Required (PR)** – Vulnerabilities requiring no authentication score much higher.
3. **Confidentiality (C)** – Complete disclosure of sensitive information greatly increases severity.
4. **Integrity (I)** – The ability to modify data substantially raises the score.
5. **Availability (A)** – Total service disruption increases the overall impact.

While Attack Complexity, Scope, and User Interaction also affect the score, the combination of remote exploitation with high impacts on Confidentiality, Integrity, and Availability is what produces Critical (9.0–10.0) CVSS scores.

---

# Conclusion

This exercise demonstrates that a CVSS score is more than a single number—it is a structured representation of exploitability and impact. By deconstructing an existing vector, constructing a new one from defined characteristics, and comparing different vulnerabilities, it becomes clear how individual metrics influence the final severity rating. Security analysts use this understanding to prioritize remediation efforts, evaluate business risk, and make informed vulnerability management decisions.
