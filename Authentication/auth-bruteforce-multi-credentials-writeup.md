# Broken Brute-Force Protection, Multiple Credentials per Request

| Field | Detail |
|---|---|
| Lab | Broken brute-force protection, multiple credentials per request |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Brute-force protection bypass via JSON array |
| CWE | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The login form locks the account after 3 failed attempts, so a
normal brute-force attack gets blocked almost at once. But the
login data is sent as JSON, and the `password` field accepts an
array instead of a single string. The server checks every password
in the array one by one — and the rate limiter counts the whole
request as a single attempt. The entire password list can be tested
in one request.

## Steps to Reproduce

1. Test the login form. Log in as `carlos` with a wrong password 3
   times. After the third attempt the application answers: "You
   have made too many incorrect login attempts. Please try again
   in 1 minute(s)."
2. Intercept the login request in Burp Suite and send it to
   Repeater. Notice the request body is JSON, not a normal form:

```json
{"csrf":"<token>","username":"carlos","password":"wrong"}
```

3. Prove the array is accepted. Replace the single password with a
   short array of dummy values and send the request:

```json
{"csrf":"<token>","username":"carlos","password":["a","b","c"]}
```

   The server accepts the request and answers with the normal
   "Invalid username or password" message — it processed all three
   values as one attempt.
4. Send the whole password list in one request. Build a JSON array
   from the candidate password list and put it in the `password`
   field:

```json
{"csrf":"<token>","username":"carlos","password":["<password 1>","<password 2>","<password 3>","..."]}
```

5. Read the result. The server tries each password in the array.
   When it reaches the correct one, the response is a `302`
   redirect to the account page instead of `200 OK`.
   (Password found: ___)
6. Open the logged-in session. Right-click the `302` response in
   Burp and use "Show response in browser", then open the given URL
   — the browser loads the account page logged in as `carlos`.

## Evidence

[Screenshot: the JSON login request in Repeater, before and after
changing the password to an array — to be added]

[Screenshot: the single request with the full password array,
returning a 302 redirect — to be added]

[Screenshot: the browser showing carlos's account page — to be
added]

## Impact

An attacker who can smuggle a whole wordlist into one request can:

- Brute-force any account's password with a single HTTP request,
  making request-based rate limiting useless.
- Test thousands of passwords without triggering a lockout, a
  CAPTCHA, or any alert based on failed-attempt counts.
- Take over the account and use it from there.

The lockout is still working exactly as designed — it just counts
the wrong thing. It counts requests, while the attacker counts
passwords.

## Remediation

- Validate the type of every login field: the `password` must be a
  single string. Reject arrays, objects, or anything else with a
  `400 Bad Request`.
- Count authentication attempts per password checked, not per HTTP
  request.
- Keep the lockout, and add a CAPTCHA after repeated failures.
- Use a slow password hash (bcrypt, Argon2) so each guess costs
  real time even if the attacker reaches the check.

## Detection (SOC)

- Alert on login requests where the password field is a JSON array
  or any non-string value.
- Alert on login requests with an unusually large body for a login
  form (a wordlist smuggled into one request).
- Alert on a single login request followed by a successful
  authentication for an account with recent failed attempts.

## References

- PortSwigger — Broken brute-force protection, multiple credentials per request: https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-multiple-credentials-per-request
- CWE-307: https://cwe.mitre.org/data/definitions/307.html
