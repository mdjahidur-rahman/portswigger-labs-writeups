# PortSwigger Labs Write-ups

Short, professional write-ups of web security labs I solved blind, written as I learn cybersecurity.

Author: Md Jahidur Rahman Jahid

## What this is

Each file is one lab from the PortSwigger Web Security Academy — a public practice lab, not a real website. I found the weakness, exploited it in the lab, and wrote down how to fix it and how a SOC analyst would spot it.

Every write-up follows the same shape:

- Summary
- Steps to Reproduce (including the payloads that did not work)
- Evidence (screenshots and the raw request)
- Impact
- Remediation
- Detection (SOC)
- References

## Write-ups

### SQL injection

| Lab | Vulnerability | File |
|---|---|---|
| SQL injection attack, listing the database contents on Oracle | SQL Injection (CWE-89) | [sqli/sqli-lab1-union-oracle-writeup.md](SQLi/sqli-lab1-union-oracle-writeup.md) |
| Blind SQL injection with conditional responses | Blind SQL Injection (CWE-89) | [sqli/sqli-lab2-blind-conditional-writeup.md](SQLi/sqli-lab2-blind-conditional-writeup.md) |
| SQL injection with filter bypass via XML encoding | SQL Injection, WAF bypass (CWE-89) | [sqli/sqli-lab3-xml-filter-bypass-writeup.md](SQLi/sqli-lab3-xml-filter-bypass-writeup.md) |

### Path traversal

| Lab | Vulnerability | File |
|---|---|---|
| File path traversal, traversal sequences stripped with superfluous URL-decode | Path Traversal (CWE-22) | [path-traversal/path-traversal-lab4-writeup.md](Path_Traversal/path-traversal-lab4-writeup.md) |
| File path traversal, validation of file extension (null byte bypass) | Path Traversal (CWE-22) | [path-traversal/path-traversal-lab6-writeup.md](Path_Traversal/path-traversal-lab6-writeup.md) |

### OS command injection

| Lab | Vulnerability | File |
|---|---|---|
| OS command injection, simple case | OS Command Injection (CWE-78) | [command-injection/os-command-injection-lab1-writeup.md](OS_Command_Injection/os-command-injection-lab1-writeup.md) |
| Blind OS command injection with time delays | Blind OS Command Injection (CWE-78) | [command-injection/os-command-injection-lab2-writeup.md](OS_Command_Injection/os-command-injection-lab2-writeup.md) |
| Blind OS command injection with output redirection | Blind OS Command Injection (CWE-78) | [command-injection/os-command-injection-lab3-writeup.md](OS_Command_Injection/os-command-injection-lab3-writeup.md) |
| Blind OS command injection with out-of-band interaction | Blind OS Command Injection (CWE-78) | [command-injection/os-command-injection-lab4-writeup.md](OS_Command_Injection/os-command-injection-lab4-writeup.md) |

### Authentication

| Lab | Vulnerability | File |
|---|---|---|
| Username enumeration via response timing | Username Enumeration (CWE-208) | [Authentication/auth-enum-response-timing-writeup.md](Authentication/auth-enum-response-timing-writeup.md) |
| Broken brute-force protection, multiple credentials per request | Brute-Force Protection Bypass (CWE-307) | [Authentication/auth-bruteforce-multi-credentials-writeup.md](Authentication/auth-bruteforce-multi-credentials-writeup.md) |
| 2FA broken logic | Broken 2FA (CWE-287) | [Authentication/auth-2fa-broken-logic-writeup.md](Authentication/auth-2fa-broken-logic-writeup.md) |
| Password reset poisoning via middleware | Password Reset Poisoning (CWE-640) | [Authentication/auth-password-reset-poisoning-writeup.md](Authentication/auth-password-reset-poisoning-writeup.md) |
| Offline password cracking | Weak Password Hash in Cookie (CWE-916) | [Authentication/auth-offline-password-cracking-writeup.md](Authentication/auth-offline-password-cracking-writeup.md) |

### Cross-site request forgery (CSRF)

| Lab | Vulnerability | File |
|---|---|---|
| CSRF with token validation depending on the request method | CSRF (CWE-352) | [CSRF/csrf-lab2-writeup.md](CSRF/csrf-lab2-writeup.md) |
| CSRF with token not tied to the user session | CSRF (CWE-352) | [CSRF/csrf-lab4-writeup.md](CSRF/csrf-lab4-writeup.md) |
| CSRF with token tied to non-session cookie | CSRF + CRLF Injection (CWE-352, CWE-113) | [CSRF/csrf-lab5-writeup.md](CSRF/csrf-lab5-writeup.md) |

## Notes

- All testing was done only in PortSwigger practice labs, with permission from the lab itself.
- No real credentials, real company names, or real systems are in these files. Session cookies and recovered passwords in screenshots are blacked out.
- Screenshots live in each topic folder's `Images/` folder — keep that folder with the markdown files, or the images will not show.
- CSRF lab 5 (token tied to non-session cookie) was solved with guided coaching, not blind — it is scheduled for a blind redo in the Dec 14–20 review week.
