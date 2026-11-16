# File Path Traversal — Traversal Sequences Stripped with Superfluous URL-Decode

| Field | Detail |
|---|---|
| Lab | File path traversal, traversal sequences stripped with superfluous URL-decode |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | Path Traversal (filter bypass via URL encoding) |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The application loads images through a `filename` parameter and strips
`../` traversal sequences from the input — but it URL-decodes the input
*again* after stripping them. A double URL-encoded traversal sequence
survives the first decode as harmless text, passes the filter, and the
second decode turns it back into `../`, letting an attacker read files
outside the intended directory, such as `/etc/passwd`.

## Steps to Reproduce

1. Open a product image in a new tab and intercept the request in Burp
   Suite. Send it to Repeater. The image is loaded through a URL
   parameter, for example:

```text
GET /image?filename=1.jpg
```

2. Use the `filename` parameter as the injection point and test it with
   path traversal payloads, one at a time:
   - Absolute path: `/etc/passwd` — did not work.
   - Plain traversal: `../../../etc/passwd` — did not work. The
     application strips the `../` sequences.
   - Nested traversal: `....//....//....//etc/passwd` — did not work.
     (This trick beats a filter that strips `../` once, leaving `../`
     behind from the overlap — but not this one.)
   - URL-encoded traversal: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` —
     did not work. The server decodes the input once before the filter
     runs, so this becomes plain `../` and gets stripped.
   - Double URL-encoded traversal — worked:

```http
GET /image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd HTTP/1.1
Host: [lab].web-security-academy.net
Cookie: session=[REDACTED]
```

Why it works: `%252e` is the double-encoded form of `.` — `%25` is
the encoded `%` sign. The server's first decode turns `%252e` into
`%2e`, which does not look like `../`, so the filter leaves it alone.
The application then URL-decodes the input a second time (the
"superfluous" decode), turning `%2e` into `.` — and the result is
`../../../etc/passwd`, which is read.

3. The response returns the contents of `/etc/passwd`, proving the
   traversal worked.

## Evidence

The double-encoded payload with only two traversal levels returned
400 "No such file" — not enough levels to climb out of the images
directory:

![Two traversal levels — 400 No such file](images/path-traversal-lab4-attempt.png)

With three levels, the same payload returned 200 and the contents of
`/etc/passwd`:

![Three traversal levels — /etc/passwd contents returned](images/path-traversal-lab4-success.png)

Response (extract):

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
peter:x:1201:1201::/home/peter:/bin/bash
```

## Impact

An attacker who can traverse outside the intended directory can:

- Read sensitive files on the server, such as `/etc/passwd`,
  application configuration, and source code.
- Read credentials and secrets stored in files, which can lead to
  further access.
- In some cases, combine file read with other flaws to take control
  of the server.

## Remediation

- Never build file paths from user input. Use an allowlist of
  permitted files, or map input to files with an ID lookup instead
  of a path.
- If a path must be built from input, validate the final resolved
  path: after all decoding, check that it still sits inside the
  intended directory, and reject anything else.
- Decode input once, at the start — then filter. Never filter first
  and decode afterwards, because decoding can re-create the very
  sequences the filter just removed.
- Run the application with the least privilege needed, so a
  successful traversal exposes as little as possible.

## Detection (SOC)

- Alert on web requests where a file parameter contains traversal
  sequences (`../`, `..\\`) or their URL-encoded forms (`%2e%2e%2f`,
  `%252e`, `..%2f`, `..%5c`).
- Alert on requests for sensitive files such as `/etc/passwd` or
  configuration files through image or download endpoints.
- Alert on responses from image endpoints that return text content
  instead of an image.

## References

- PortSwigger — Path traversal: https://portswigger.net/web-security/file-path-traversal
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
