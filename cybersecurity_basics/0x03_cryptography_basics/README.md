# CRYPTOGRAPGHY BASIC

A collection of bash scripts covering password hashing and cracking techniques.

TASKS

0. SHA-1 Hash — 0-sha1.sh

	Hashes a password using the SHA-1 algorithm and stores the result in 0_hash.txt

1. SHA-256 Hash — 1-sha256.sh

	Hashes a password using the SHA-256 algorithm and stores the result in 1_hash.txt.

2. MD5 Hash — 2-md5.sh

	Hashes a password using the MD5 algorithm and stores the result in 2_hash.txt.

3. Salted SHA-512 Hash — 3-password_hash.sh

	Generates a random 16-character salt, combines it with the password, and hashes using SHA-512 via 

	OpenSSL. Result stored in 3_hash.txt.

4. Crack MD5 with John — 4-wordlist_john.sh
	
	Cracks MD5 hashes from hash.txt using John the Ripper in wordlist mode with the RockYou wordlist. 
	
	Cracked passwords stored in 4-password.txt.

5. Crack NTLM with John — 5-windows_john.sh
	
	Cracks Windows NTLM (NT) hashes using John the Ripper with the RockYou wordlist. 
	
	Cracked passwords stored in 5-password.txt.

6. Crack SHA-256 with John — 6-crack_john.sh
	
	Cracks SHA-256 hashes from crack.txt using John the Ripper with the RockYou wordlist. 
	
	Cracked passwords stored in 6-password.txt.

7. Crack MD5 with Hashcat — 7-crack_hashcat.sh
	
	Cracks MD5 hashes from hash.txt using Hashcat in dictionary attack mode with the RockYou wordlist. 
	
	Cracked passwords stored in 7-password.txt.

8. Combine Wordlists with Hashcat — 8-combination_hashcat.sh
	
	Combines two wordlists using Hashcat's combination attack mode, 
	
	printing every possible concatenation of words from both lists.

9. Crack with Combined Wordlists — 9-attack_hashcat.sh
	
	Cracks an MD5 hash using Hashcat's combination attack with wordlist1.txt and wordlist2.txt. 
	
	Cracked password stored in 9-password.txt.

TOOLS USED

	sha1sum, sha256sum, md5sum — built-in Linux hashing utilities

	openssl — cryptographic toolkit for salted hashing

	john — John the Ripper password cracker
	
	hashcat — GPU-accelerated password cracker
	
	rockyou.txt — popular wordlist at /usr/share/wordlists/rockyou.txt
