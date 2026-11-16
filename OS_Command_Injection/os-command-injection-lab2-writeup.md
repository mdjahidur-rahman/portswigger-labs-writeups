# Blind OS Command Injection with Time Delays

| Field | Detail |
|---|---|
| Lab | Blind OS command injection with time delays |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Blind OS Command Injection (time-based) |
| CWE | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| Severity | High |
| Date | 13 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The feedback form passes user-supplied input into a shell command on the
server without validation. The command output is never shown in the
response, so the injection is blind — but it can still be proven: a
10-second `ping` delay in the response time confirms the command ran.

## Steps to Reproduce

1. Submit the feedback form and intercept the POST request in Burp Suite.
   Send it to Repeater. The request has five fields: `csrf`, `name`,
   `email`, `subject`, and `message`.
2. Test each field with a time-delay payload: `ping -c 10 127.0.0.1`.
   If the command runs, the response takes about 10 seconds.
3. `&` before the payload in all fields did not work — in a form body,
   `&` separates parameters, so it cut the payload off instead of
   reaching the shell.
4. A single `|` did not work either — it pipes output into the next
   command, and `ping` does not read piped input.
5. `||` in the `email` field worked:

```http
POST /feedback/submit HTTP/1.1
Host: 0a23007404d56bd983da283a001c0099.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=[REDACTED]

csrf=[REDACTED]&name=wiener&email=wiener@40gm.com||ping -c 10 127.0.0.1||&subject=what+is+love&message=jghvkghjvkhgvk
```

Why `||` works: it means OR — run the command on the right only if the
one on the left fails. `wiener@40gm.com` is not a real command, so it
fails, and `ping` runs. The trailing `||` joins cleanly onto the rest of
the application's own command.

## Evidence

Burp Repeater — injected request (left) and the response (right). The
response body is only `{}`, with no command output — this is a blind
injection. The proof is the response time at the bottom right:
**9,691 millis**, about 10 seconds, matching the `ping -c 10` delay.

![Burp Repeater — blind time-delay command injection, 9,691 ms response](images/os-command-injection-lab2-repeater.png)

Response (extract):

```text
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{}
```

Response time: 9,691 ms (normal responses return in well under a second).

## Impact

An attacker who can run OS commands on the server can:

- Run any command, even without seeing the output — for example,
  exfiltrating data to an external server, or delaying responses.
- Read sensitive files and configuration (including credentials).
- Steal or modify application data.
- Take full control of the server in the worst case.

Blind injection is not less dangerous than visible injection — the
attacker only needs a different way to confirm and exploit it.

## Remediation

- Never build shell commands from user input. Use safe APIs or libraries
  instead of invoking the shell.
- If a shell call is unavoidable, validate the input strictly — for an
  email field, accept only a valid email format (allowlist) and reject
  everything else.
- Run the application with the least privilege needed, so a successful
  injection exposes as little as possible.
- Do not return shell or script errors to the client.

## Detection (SOC)

- Alert on web requests where input fields contain command separators
  (`||`, `|`, `;`) or command words such as `ping`, `sleep`, `whoami`,
  or `id`.
- Alert on unusually slow responses (for example, ~10 seconds) to
  normally fast endpoints such as form submissions.
- Alert on unexpected child processes (shell commands, `ping`) spawned
  by the web server process.

## References

- PortSwigger — Blind OS command injection: https://portswigger.net/web-security/os-command-injection/blind
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
