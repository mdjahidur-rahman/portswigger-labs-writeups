# SQL Injection with Filter Bypass via XML Encoding

| Field | Detail |
|---|---|
| Lab | SQL injection with filter bypass via XML encoding |
| Platform | PortSwigger Web Security Academy |
| Vulnerability | SQL Injection (WAF bypass via XML entity encoding) |
| CWE | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| Severity | High |
| Date | 15 November 2026 |
| Author | Md Jahidur Rahman Jahid |

## Summary

The stock check feature sends `productId` and `storeId` to the
application in XML format, and the `storeId` value goes into a SQL
query. A web application firewall (WAF) blocks plain SQL injection
payloads — but it checks the input *before* the XML parser decodes
it. Encoding the payload as XML entities hides it from the WAF; the
parser then decodes it back into SQL, and the injection runs.

## Steps to Reproduce

1. Find the injection point. The stock check sends an XML body, for
   example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

   Intercept the `POST /product/stock` request in Burp Suite and send
   it to Repeater.
2. Prove the input is evaluated. Replace the IDs with a small maths
   expression:

```xml
<productId>1+1</productId>
<storeId>1+1</storeId>
```

   The normal request (`productId` 1, `storeId` 1) returns 888 units.
   With `1+1` in both fields, the application returns 135 units —
   the stock for a different store. The input is evaluated, so this
   is the injection point.
3. Try a UNION attack to find the number of columns:

```xml
<storeId>1 UNION SELECT NULL</storeId>
```

   Blocked. The WAF flags the request as a potential attack and
   rejects it.
4. Bypass the WAF with XML entity encoding. Because the input is XML,
   characters can be written as entities — for example, `U` can be
   written as `&#x55;` (hex entity) or `&#85;` (decimal entity).
   The WAF reads the encoded text and does not recognise it as SQL,
   so it lets the request through. The XML parser then decodes it
   *after* the WAF check, and the database receives the real payload.
   In Burp, the Hackvertor extension does this encoding
   (highlight the input, right-click, Extensions > Hackvertor >
   Encode > dec_entities / hex_entities). Hackvertor must be
   installed first (Extender > BApp Store) — without it, the
   `<@hex_entities>` tags are sent as plain text and nothing is
   encoded. The payload also has to be the *only* SQL in the
   request: a plain `UNION SELECT` left in another field (for
   example `productId`) will still trip the WAF.
5. Find the number of columns. The query returns a single column —
   asking for more than one returns 0 units, which means an error.
   So the stolen data must be squeezed into one column.
6. Steal the usernames and passwords, joined into one column with
   `||` and separated by `~`:

```xml
<storeId>1 UNION SELECT username || '~' || password FROM users</storeId>
```

   (Sent entity-encoded, as in step 4.) The response returns the
   usernames and passwords, separated by `~`.
7. Log in with the administrator's credentials to solve the lab.

## Why the bypass works

The WAF and the XML parser read the input at different times, and
the WAF reads it first:

1. The attacker sends the payload encoded as XML entities.
2. The WAF checks the encoded text, sees no SQL keywords, and lets
   it through.
3. The XML parser decodes the entities back into plain SQL.
4. The database runs the decoded SQL.

The filter and the parser disagree about what the input is — and that
disagreement is the vulnerability.

## Evidence

Normal request — `productId` 1, `storeId` 1, returns 888 units:

![Normal stock check — 888 units](images/sqli-lab3-normal.png)

Step 2, the `1+1` probe — evaluated, returns 135 units:

![1+1 probe — input is evaluated, 135 units](images/sqli-lab3-probe.png)

Step 3 — plain `UNION SELECT` blocked by the WAF, 403 "Attack
detected":

![Plain UNION SELECT blocked — 403 Attack detected](images/sqli-lab3-blocked.png)

Step 4, first bypass attempt — still 403 "Attack detected". Two
things were wrong: Hackvertor was not installed yet, so the
`<@hex_entities>` tags went out as plain text, and the `productId`
still contained a plain `UNION SELECT`, which the WAF caught on its
own. The fix is to install Hackvertor and put the payload only in
the `storeId`, with `productId` back to 1:

![Bypass attempt before Hackvertor was installed — still blocked](images/sqli-lab3-hackvertor.png)

## Impact

An attacker who can inject SQL through the stock check can:

- Read the full database: usernames, passwords, and any other
  stored data.
- Log in as any user, including the administrator, using the stolen
  credentials.
- Change or delete data, and in some setups run commands on the
  database server.

A WAF that can be bypassed with encoding gives a false sense of
security — the application underneath is still fully vulnerable.

## Remediation

- Use parameterized queries (prepared statements) for all database
  queries — never build SQL by joining user input into the query
  string. This fixes the injection itself, so no bypass matters.
- Do not rely on the WAF as the fix. A WAF is a safety net, not a
  repair.
- If input must be decoded, decode it fully *before* any security
  check runs, so the check sees the same text the database will see.
- Validate the `storeId` against an allowlist (digits only) and
  reject anything else.
- Store passwords hashed (for example bcrypt), never in plain text.

## Detection (SOC)

- Alert on web requests where XML input contains SQL keywords
  (`UNION`, `SELECT`, `FROM`) or their entity-encoded forms
  (`&#x55;`, `&#85;`, and similar).
- Alert on requests to the stock check endpoint that return
  usernames, emails, or password-like strings.
- Alert on repeated blocked-then-allowed request patterns against
  the same endpoint — probing followed by a bypass attempt.

## References

- PortSwigger — SQL injection with filter bypass via XML encoding: https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
