# 15. The Medical IoT Assessment

This report evaluates vulnerabilities in connected medical devices at MedDefense, emphasizing the distinction between IT data risks and clinical patient safety risks.

---

## BD Alaris Assessment
* **Vulnerability Description:** BD Alaris systems are affected by multiple critical vulnerabilities, including CVE-2023-30559 (input validation issues), CVE-2023-30560 (authentication bypass), and CVE-2023-30562 (insufficient data authenticity verification). These vulnerabilities could allow attackers to alter device configurations or tamper with infusion parameters.
* **Vendor Mitigation:** BD explicitly recommends segmenting Alaris units onto a dedicated VLAN, restricting external access to the Systems Manager (SM) server, and implementing strict SSL certificate validation.
* **Implementation Status:** Based on the scan report, these vulnerabilities persist, indicating that MedDefense has not yet implemented the recommended segmentation or firmware remediation.

---

## Philips IntelliVue Assessment
* **Exposed Data:** These monitors transmit real-time, life-critical physiological data and clinical information across HL7 ports.
* **Attacker Impact:** Because these interfaces are unauthenticated and reside on the flat network, an attacker could intercept sensitive patient vitals, inject false monitoring data to cause clinical panic, or disrupt the connection to the central station, creating a dangerous "blind spot" in patient care.

---

## Patient Safety Dimension
Medical device vulnerabilities represent an existential risk to human life, far exceeding the financial or reputational impact of a standard IT breach. While a compromised workstation leads to the exfiltration of PHI (a data privacy issue), a compromised infusion pump can lead to incorrect medication delivery or dosage termination, potentially resulting in direct patient injury or fatality. These are life-critical systems where availability and integrity are literally matters of life and death.

---

## Remediation Challenges
Patching medical devices is significantly more difficult than patching general-purpose IT infrastructure due to:
1. **Regulatory Constraints:** Medical devices are strictly governed by regulatory bodies (e.g., FDA). A "patch" is often classified as a formal device design change, requiring extensive re-validation, documentation, and potentially new regulatory clearance before deployment.
2. **Operational Continuity:** Unlike an IT server that can be rebooted during a maintenance window, medical devices are used in 24/7 clinical environments. Patching requires complex coordination to ensure zero downtime and that substitute equipment is immediately available for patient care.
3. **Vendor Dependency:** Medical device security is entirely dependent on the manufacturer's lifecycle management. If a vendor does not provide a patch for a specific model, there is no "community fix" or alternative path, often forcing providers to rely on fragile compensating controls rather than true remediation.
