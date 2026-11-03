# MedDefense SAML SSO Configuration Reference

## Realm Configuration Summary
- **Realm Name**: `meddefense`
- **Display Name**: MedDefense Health Systems
- **Session Idle Timeout**: 30 minutes
- **Brute Force Protection**: Enabled, with a threshold of 5 failed attempts before temporary lockout.

---

## Client Configuration Summary
- **Client ID**: `meddefense-portal`
- **Assertion Consumer Service (ACS) URL**: `http://localhost:5000/saml/acs`
- **NameID Format**: `email`
- **Signing Behavior**: Signed assertions and signed documents are enforced to maintain cryptographic integrity and prevent tampering.
- **Attribute Mapper**: `MedDefenseRole` configured to map user roles into the SAML assertion.

---

## Test Users and Role Attributes
- **d.walsh**: Assigned clinical and administrative roles within the `meddefense` realm (`ClinicalStaff`).
- **r.kim**: Assigned security and IT administrative roles within the `meddefense` realm (`SecurityAdmin`).

---

## Annotated SAML Assertion: d.walsh
```xml
<!-- Issuer identifying the Keycloak Identity Provider -->
<saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>

<!-- NameID specifying the user's principal identity in email format -->
<saml:Subject>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">d.walsh@meddefense.local</saml:NameID>
</saml:Subject>

<!-- Conditions establishing validity windows -->
<saml:Conditions NotBefore="2026-03-30T10:00:00Z" NotOnOrAfter="2026-03-30T10:05:00Z"/>

<!-- Authentication Statement detailing login time and method -->
<saml:AuthnStatement AuthnInstant="2026-03-30T10:00:00Z">
  <saml:AuthnContext>
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </saml:AuthnContext>
</saml:AuthnStatement>

<!-- Attribute Statement containing role mappings -->
<saml:AttributeStatement>
  <saml:Attribute Name="MedDefenseRole">
    <saml:AttributeValue>ClinicalStaff</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>

<!-- Cryptographic Signature ensuring integrity and non-repudiation -->
<ds:Signature>
  <!-- Signature details validating the issuer and assertion payload -->
</ds:Signature>
```

---

## Assertion Expiration and Replay Prevention
SAML assertions include strict temporal boundaries (`NotBefore` and `NotOnOrAfter` timestamps). Service Providers (SPs) must validate that the current time falls precisely within this window. By enforcing short validity windows (e.g., 5 minutes) and ensuring that the SP tracks processed Assertion IDs or relies on single-use checks, systems prevent replay attacks where an intercepted valid assertion is re-transmitted by an attacker to gain unauthorized session access.

---

## Assertion Signing Risk Explanation
Cryptographic signing of assertions and documents ensures that the message has not been altered in transit by an adversary performing a Man-in-the-Middle (MitM) attack or XML signature wrapping. If assertions are unsigned or improperly verified, an attacker could manipulate the `NameID` or `AttributeStatement` (e.g., escalating a standard user role to `DomainAdmin` or `ClinicalAdmin`), allowing complete unauthorized access to protected healthcare resources and electronic Protected Health Information (ePHI).

---

## Off-Boarding and Centralized Identity Impact
Implementing a centralized IdP (Keycloak) replaces fragmented, application-specific password delegation with a single point of authentication and lifecycle management. When clinical or administrative staff leave MedDefense, disabling their account in Keycloak immediately terminates access across all integrated systems (Epic, PACS, pharmacy systems, and communication platforms). This eliminates the risk of dormant, orphaned accounts persisting across disparate silos—a critical vulnerability that contributed to past security incidents.