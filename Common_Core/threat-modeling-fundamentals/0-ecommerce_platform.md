# E-commerce Platform Threat Model

You are threat modeling an e-commerce platform where users can:

- Browse products (no authentication required)
- Add items to cart (no authentication required)
- Checkout and pay (authentication required)
- View order history (authentication required)

The system architecture includes:

- React frontend
- Node.js API backend
- PostgreSQL database
- Stripe payment integration


---

## 1. STRIDE Threats for the Checkout Process

STRIDE Threat Analysis: Checkout Process

## Tampering

Threat Description: A user attempts to manipulate the checkout process by modifying the product price or total transaction amount within the client-side request before it reaches the Node.js API.

Potential Impact: The business suffers a direct financial loss because the user successfully pays less than the intended price.

Suggested Mitigation: Implement robust server-side validation. Never trust pricing data sent from the client; always recalculate totals on the backend by fetching the authoritative price from your secure database.

## Information Disclosure

Threat Description: An attacker performs a man-in-the-middle attack to intercept the communication stream between the user's browser and the backend, attempting to capture Personally Identifiable Information (PII) or sensitive payment tokens.

Potential Impact: The compromise of sensitive customer records and payment details, leading to data breaches and regulatory violations.

Suggested Mitigation: Enforce Transport Layer Security (TLS). Ensure all data in transit is encrypted using HTTPS (ideally TLS 1.3) and implement HTTP Strict Transport Security (HSTS) to prevent protocol downgrade attacks.

## Elevation of Privilege

Threat Description: An attacker attempts to manipulate the request metadata to submit a checkout request using a stolen session token or another user’s user_id.

Potential Impact: Unauthorized transactions where one user successfully completes a purchase that is charged to another customer’s account.

Suggested Mitigation: Implement strict authorization checks. The backend must explicitly validate that the authenticated session ID associated with the request matches the account ID attempting to perform the checkout.

---

## 2. Identifying Trust Boundaries

Trust boundaries define where security controls must be enforced because the level of trust changes.

### Frontend / Backend Boundary
- Between the user's React browser and the Node.js API
- Client-side is **untrusted**
- Server-side is **trusted**
- All incoming requests must be validated and treated as potentially malicious

### API / Stripe Gateway Boundary
- Between Node.js backend and Stripe payment infrastructure
- External service interaction using API keys
- Requires secure authentication and secret management

### Backend / Database Boundary
- Between Node.js application and PostgreSQL database
- Database contains highly sensitive data
- Must use parameterized queries to prevent injection attacks

---

## 3. DREAD Scoring: SQL Injection in Product Search

Assumption: Product search input is directly used in a database query.

Example vulnerable query:
```sql
SELECT * FROM products WHERE name LIKE '%user_input%';
```

| Factor | Score (1-10) | Justification |
|--------|--------------|-------|---------------------------------------------------------------------------------|
|Factor	                | Score	|   Justification                                                                 |
| **Damage**            | 8     |   Successful injection could expose the entire user or product database         |
| **Reproducibility**   | 10    |   Once vulnerable, the attack can be repeated consistently                      |
| **Exploitability**    | 9     |   Easily exploitable using tools like sqlmap                                    |
| **Affected Users**    | 10    |   All users are potentially impacted                                            |   
| **Discoverability**   | 10    |   Search bar is publicly accessible and easy to find                            |

---

### Total Score: 47 / 50 (Critical Risk)

**Conclusion:**  
This is a critical security risk. Immediate mitigation is required by implementing **parameterized queries (prepared statements)** so that user input is treated strictly as data, not executable SQL code.

---

## End of Report