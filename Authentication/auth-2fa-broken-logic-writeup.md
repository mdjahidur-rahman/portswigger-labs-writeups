# 2FA Broken Logic

| Field | Detail |
|---|---|
| Lab | 2FA broken logic |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Two-factor authentication bypass via client-controlled cookie |
| CWE | CWE-287: Improper Authentication |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The login has two steps: password first, then a 4-digit code sent
by email. But the second step does not check that the person
entering the code is the person who passed the first step. It
decides whose code to check from a `verify` cookie — and the cookie
is set by the browser, so the attacker can change it. Log in as
your own low-privilege user, change the cookie to the victim's
name, and the code page now checks the victim's code. The code is
only 4 digits and there is no rate limiting, so it can be
brute-forced.

## Steps to Reproduce

1. Log in with your own credentials (`wiener:peter`). After the
   password step, the application redirects to `/login2` and asks
   for the 4-digit security code.
2. Intercept the code submission in Burp Suite. Notice the request
   carries a `verify` cookie naming the user being verified:

```http
POST /login2 HTTP/1.1
Cookie: verify=wiener; session=<token>

csrf=<token>&mfa-code=1234
```

3. Prove the cookie controls the check. In Repeater, change the
   cookie to the victim's username and send the request:

```http
Cookie: verify=carlos; session=<token>
```

   The server answers `200 OK` and asks for carlos's code — it
   never checks that the password step was passed for carlos.
4. Brute-force carlos's code. Send the `POST /login2` request to
   Burp Intruder with `verify=carlos`, and mark the code as the
   payload position:

```http
csrf=<token>&mfa-code=§1234§
```

   Use a Sniper attack with the Brute forcer payload type,
   character set `0123456789`, length 4 (10,000 combinations).
   There is no lockout on the code, so the whole range can be
   tested.
5. Find the correct code. All wrong codes return `200 OK` with
   "Incorrect security code". One code returns a `302` redirect to
   `/my-account` — that is carlos's code. (Code found: ___)
6. Open the logged-in session. Right-click the `302` response in
   Intruder and use "Request in browser → In original session",
   then open the given URL — the browser loads the account page
   logged in as `carlos`.

## Evidence

[Screenshot: the POST /login2 request showing the verify=wiener
cookie — to be added]

[Screenshot: the same request with verify=carlos, accepted by the
server — to be added]

[Screenshot: Intruder results, one 302 response among the
"Incorrect security code" responses — to be added]

[Screenshot: the browser showing carlos's account page — to be
added]

## Impact

An attacker who can swap the `verify` cookie can:

- Skip the password step entirely for any user — the only thing
  standing between the attacker and the account is a 4-digit code.
- Brute-force that code without limit, because the code check has
  no rate limiting or lockout.
- Take over any account, including an administrator's, with no
  password and no access to the victim's email.

Two-factor authentication is supposed to add a second lock. Here
the second lock checks a name tag the attacker writes themselves.

## Remediation

- Bind the second factor to the server-side session: store which
  user passed the password step on the server, never in a
  client-controlled cookie.
- Rate-limit code attempts (for example, 5 tries, then lock the
  verification for a period) and expire each code after a short
  time.
- Invalidate the whole login attempt after repeated wrong codes,
  forcing a fresh password login.
- Log verification attempts per account and alert on brute-force
  patterns.

## Detection (SOC)

- Alert on a `verify` cookie value that does not match the user who
  passed the password step in the same session.
- Alert on many `/login2` attempts for one account in a short
  time — the shape of a code brute-force.
- Alert on a successful `/login2` for a user whose password step
  happened under a different username or session.

## References

- PortSwigger — 2FA broken logic: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
