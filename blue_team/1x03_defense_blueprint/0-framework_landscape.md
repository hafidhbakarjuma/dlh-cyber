# Framework Comparison and Strategy: MedDefense Health Systems

## Part 1: Three-Framework Summary

| Framework | Publisher | Primary Altitude | Core Structure |
| :--- | :--- | :--- | :--- |
| **NIST CSF 2.0** | NIST | Strategic | 6 Functions (Govern, Identify, Protect, Detect, Respond, Recover)[cite: 3] |
| **CIS Controls v8** | CIS | Operational | 18 Controls / 153 Safeguards (grouped into 3 IGs)[cite: 3] |
| **ISO 27001:2022** | ISO/IEC | Assurance | 10 Clauses + Annex A (93 controls for an ISMS)[cite: 3] |

*   **NIST CSF 2.0**: Provides an outcome-based, common language for leadership to manage cybersecurity risk at a governance level without prescribing specific technical controls[cite: 3].
*   **CIS Controls v8**: Acts as a prioritized, prescriptive "how-to" guide, offering concrete actions for technical implementation based on real-world attack data[cite: 3].
*   **ISO 27001**: Establishes the requirements for an Information Security Management System (ISMS), focusing on management, documentation, and continuous improvement, often used for third-party certification[cite: 3].

## Part 2: Relationship Map

These frameworks are not competitors; they represent three layers of a single, unified security program[cite: 3]:
1.  **NIST CSF (Strategy)**: Defines *what* success looks like (e.g., "We need to Protect our EHR database")[cite: 3].
2.  **CIS Controls (Implementation)**: Provides the *how* by offering a testable worklist (e.g., implementing specific safeguards for access control)[cite: 3].
3.  **ISO 27001 (Governance)**: Provides the *proof* by wrapping the program in a management system that controls documentation, ownership, and internal audit, producing an audit-ready state[cite: 3].

## Part 3: MedDefense Framework Selection

**Recommendation**: Adopt **NIST CSF 2.0** as the strategic backbone and **CIS Controls v8 (IG1, expanding to IG2)** as the operational implementation layer. **Defer** formal ISO 27001 certification[cite: 3].

### Justification for MedDefense
*   **Resource Constraints**: With a team of only one analyst and one deputy CISO, the administrative overhead required for ISO 27001 certification—such as formal internal audits and document control cycles—is unsustainable[cite: 3].
*   **Regulatory Alignment**: HIPAA requires a documented, defensible program rather than a specific framework; NIST CSF mapped to CIS Safeguard evidence provides a clear narrative for auditors[cite: 3].
*   **Operational Focus**: CIS Controls IG1 (56 essential safeguards) is designed for limited-expertise teams, providing a concrete, ordered worklist rather than abstract goals[cite: 3].
*   **Future-Proofing**: If MedDefense requires formal ISO 27001 certification later, the foundation built via CSF and CIS maps directly to Annex A controls, significantly reducing the future transition effort[cite: 3].

## Budget Allocation ($120,000)

| Item | Cost |
| :--- | :--- |
| **Previously Approved Initiatives** | $105,000 |
| **Remaining Budget** | **$15,000** |

The remaining **$15,000** will be utilized for:
1.  **Staff Training**: Attaining professional development in NIST CSF and CIS implementation[cite: 3].
2.  **Tooling**: Automating evidence collection for CIS safeguards to reduce manual analyst labor[cite: 3].
3.  **Documentation**: Developing a baseline "Statement of Applicability" to maintain an audit-ready posture for the Board without the immediate cost of a formal certification audit[cite: 3].
