# Username Enumeration via Response Timing

| Field | Detail |
|---|---|
| Lab | Username enumeration via response timing |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Username enumeration via timing side-channel |
| CWE | CWE-208: Observable Timing Discrepancy |
| Severity | Medium |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The login page returns the same generic error message for a wrong
username and a wrong password, so the error message leaks nothing.
But the response time leaks everything: when the username exists,
the server checks the submitted password (an expensive hashing
operation) before answering; when it does not exist, the server
answers at once. With a very long password, the delay becomes big
enough to measure, so each username can be tested with a simple
question — fast answer, or slow answer?

## Steps to Reproduce

1. Test the login form. Submit a random username and password and
   note the generic error message: "Invalid username or password."
   After 3 failed attempts the IP is blocked for 30 minutes — the
   lab has IP-based brute-force protection.
2. Bypass the IP block. The application trusts the
   `X-Forwarded-For` header, so each request can carry a different
   spoofed IP address and the block never triggers. Add the header
   to the request:

```http
POST /login HTTP/1.1
Host: <lab-id>.web-security-academy.net
X-Forwarded-For: 1
Content-Type: application/x-www-form-urlencoded

csrf=<token>&username=wiener&password=peter
```

3. Prove the timing difference. Log in with a valid username (your
   own, `wiener`) and a very long password (about 100 characters),
   and time the response. Then try an invalid username with the same
   long password. The valid username takes much longer, because the
   server only runs the password check when the user exists.
4. Enumerate usernames with Burp Intruder. Send the login request
   to Intruder and use a Pitchfork attack with two payload
   positions:

```http
X-Forwarded-For: §1§
csrf=<token>&username=§wiener§&password=<100-character string>
```

   - Payload 1 (X-Forwarded-For): numbers 1–100, to spoof a fresh
     IP for each request.
   - Payload 2 (username): the candidate username list.
   - Password: one fixed very long string.
   - Set the resource pool to 1 concurrent request, so the timings
     are not distorted by parallel requests.
5. Find the valid username. In the attack results, add the
   "Response received" column and sort by it. Most usernames answer
   in roughly the same short time. One username takes far longer —
   that user exists. (Username found: ___)
6. Brute-force that user's password. Run a second Intruder attack
   with the username fixed, the password as the payload position,
   and the `X-Forwarded-For` rotation still in place. The correct
   password returns a `302` redirect instead of `200 OK`.
   (Password found: ___)
7. Log in with the found username and password, and open the
   account page to solve the lab.

## Evidence

[Screenshot: the login request in Repeater with the X-Forwarded-For
header — to be added]

[Screenshot: Intruder results sorted by response time, one username
clearly slower than the rest — to be added]

[Screenshot: the password brute-force results, one 302 response
among the 200s — to be added]

## Impact

An attacker who can enumerate usernames can:

- Build a list of real accounts, which is the first step of every
  password attack — no more guessing blindly.
- Brute-force passwords against known accounts, or target those
  users with phishing.
- Combine the timing leak with the `X-Forwarded-For` bypass to run
  the whole attack without ever being blocked.

A timing difference of a few hundred milliseconds is enough — the
attacker only needs "slower than the rest", not an exact number.

## Remediation

- Make the login take the same time whether the username exists or
  not: always run the password check (against a dummy hash when the
  user does not exist), or add a fixed delay to every failed login.
- Do not trust `X-Forwarded-For` for rate limiting unless it comes
  from a known, trusted proxy — otherwise the attacker picks their
  own IP address.
- Rate-limit login attempts per account as well as per IP, and use
  CAPTCHA or temporary lockout after repeated failures.
- Keep the generic error message — it is the one thing this login
  page already does right.

## Detection (SOC)

- Alert on many login attempts from one source where the
  `X-Forwarded-For` header changes on every request.
- Alert on login requests carrying unusually long password values
  (timing probes).
- Alert on a burst of failed logins followed by one success for the
  same username — the shape of an enumeration-then-brute-force
  attack.

## References

- PortSwigger — Username enumeration via response timing: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
- CWE-208: https://cwe.mitre.org/data/definitions/208.html
