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

## Planned write-ups (not written yet)

| Topic | Lab |
|---|---|
| Authentication | Username enumeration via different responses |
| Authentication | 2FA simple bypass |
| Authentication | Broken brute-force protection |
| Authentication | Password reset broken logic |
| Authentication | Offline password cracking |

## Notes

- All testing was done only in PortSwigger practice labs, with permission from the lab itself.
- No real credentials, real company names, or real systems are in these files. Session cookies and recovered passwords in screenshots are blacked out.
- Screenshots live in each topic folder's `Images/` folder — keep that folder with the markdown files, or the images will not show.
- Command Injection lab 5 (blind, out-of-band data exfiltration) is not included: I understand the process, but Burp Collaborator showed no interaction, so it is not verified as solved. It is parked to the Dec 14–20 review week.
