# CVE
# Security Advisory — SQL Injection in managevideos2.php (parameter editassid)

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-XX**
> **Publication Date:** <dd/mm/2026>
> **Last Updated:** <dd/mm/2026>
> **Severity:** High
> **CVSS:** <preencher> — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
> **CWE:** CWE-89: SQL Injection
> **Status:** Unpatched

---

## 1. Executive Summary

A flaw has been found in **mathurvishal CloudClassroom-PHP-Project** up to commit `5dadec098bfbf3300d60c3494db3fb95b66e7be`. The **managevideos2.php** endpoint allows remote authenticated attackers to inject arbitrary SQL statements via the `editassid` parameter during video update functionality, due to improper input validation.

Successful exploitation may result in unauthorized read/modification of database content, including credential disclosure and manipulation of course/video records.

Disclosure follows responsible/coordinated policy; formal vendor notification is planned (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component        | Affected Versions | Fixed Version | Status   |
| --------------------------- | ------------------ | -------------- | -------- |
| CloudClassroom-PHP-Project  | Up to `5dadec0`    | None           | Affected |
| Component: managevideos2.php | —                 | None           | Affected |

- **Repository / Ecosystem:** <https://github.com/mathurvishal/CloudClassroom-PHP-Project>
- **Evaluated Stack:** PHP + MySQLi, <preencher SO/versão Apache>, <preencher versão MySQL/MariaDB>

### Unaffected Products
- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **SQL Injection** in the component **managevideos2.php**.

The `editassid` parameter is used to build the SQL query executed when a faculty member updates a video record, without proper sanitization or parameter binding, allowing an attacker to alter the query logic.

**Root cause (source code snippet):**

`src/managevideos2.php`, line 22:
```php
$sql = "SELECT * FROM video WHERE V_id=$make";
```

`src/managevideos2.php`, line 75:
```php
$sql = "UPDATE `video` SET V_Title='$V_Title', V_Url='$V_Url', V_Remarks='$V_Remarks' WHERE V_id=$make";
```

The variable `$make` is derived from the unsanitized `editassid` request parameter and interpolated directly into both the `SELECT` (line 22) and `UPDATE` (line 75) statements without prepared statements or type casting, as flagged by static analysis (rule: `php.lang.security.injection.tainted-sql-string`). User data flows into a manually-constructed SQL string, which is a classic SQL injection sink.

### Necessary Conditions
- Authentication: Required (authenticated faculty session)
- User Interaction: None
- Attack Vector: Remote (network) — method GET/POST via `editassid`
- Preconditions: Valid faculty account on the platform

---

## 4. Impact

Exploitation may allow:
- Unauthorized read of database content (course/user data, credentials)
- Unauthorized modification of video/course records
- Potential full database compromise depending on privileges of the DB user

### Impact on Confidentiality
High — an attacker can read sensitive data stored in the database.

### Impact on Integrity
High — video/course records can be altered.

### Impact on Availability
None — no direct availability impact observed.

---

## 5. Classification

### CVSS
- **Score:** <preencher>
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

| Metric | Value |
| --- | --- |
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | Low (L) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

### CWE
- CWE-89: SQL Injection

### CAPEC
- CAPEC-66 – SQL Injection

---

## 6. Exploitation Scenario

1. Authenticate as a faculty user on the platform.
2. Navigate to the "Update Videos" functionality (`managevideos2.php`).
3. Send a request with a manipulated `editassid` parameter containing SQL injection payloads.
4. Observe altered application behavior / data returned confirming injection.
5. Automate extraction with `sqlmap` for full database enumeration.

---

## 7. Technical Evidence

### Affected Component
```
File(s): managevideos2.php
Parameter(s): editassid
Method: GET/POST · Authentication: Required (faculty session)
```

### Example Request
```
GET /managevideos2.php?editassid=4 HTTP/1.1
Host: 172.25.44.135:9292
Cookie: PHPSESSID=<sessão de faculty>
```

### Observed Response
`<preencher com o output/evidência da exploração — ex. erro SQL, dados extraídos>`

### Result
Reproduced live in authorized lab (`http://172.25.44.135:9292/`) on <dd/mm/2026>, in a non-destructive manner.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments.

```
curl -s -G "http://172.25.44.135:9292/managevideos2.php" \
  --data-urlencode "editassid=<payload>" \
  -H "Cookie: PHPSESSID=<sessão>"

sqlmap -u "http://172.25.44.135:9292/managevideos2.php?editassid=4" \
  --cookie="PHPSESSID=<sessão>" -p editassid --batch --dbs
```

### PoC Limitations
- Does not cause intentional unavailability.
- Does not remove or modify third-party data beyond the authorized test scope.
- Does not create persistence or backdoor.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Access an instance of CloudClassroom-PHP-Project.
2. Authenticate with a faculty account.
3. Access `managevideos2.php` (parameter: `editassid`).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable behavior.
6. Compare with expected safe behavior (properly validated/parameterized input).

---

## 10. Mitigation

- Use prepared statements with parameter binding (`mysqli`/PDO) for all queries involving `editassid`.
- Enforce type casting for numeric identifiers (`(int)$editassid`).
- Do not echo raw SQL errors (`mysqli_error()`) to the client.
- Apply least-privilege database accounts.

Additional compensatory measures:
- Restrict access to affected component (network/ACL/WAF).
- Apply WAF rules to block common SQLi patterns.
- Review logs for suspicious `editassid` values.

---

## 11. Fix

**No official fix available as of this advisory date (unpatched product).**

### Recommended Change to Vendor
- Parameterize all queries using `editassid`.
- Validate/cast input as integer before use in SQL.
- Remove verbose SQL error output.

---

## 12. Detection and Indicators

- Requests to `managevideos2.php` with `UNION`, `SELECT`, single quotes, or `-- ` in parameter `editassid`.
- Database error messages reflected in responses.
- Static analysis: flagged by semgrep rule `php.lang.security.injection.tainted-sql-string` at `src/managevideos2.php:22` and `:75`. Details: <https://sg.run/lZYG>

### Example Log Search
```
grep -Ei "(union|select|--\s|')" access.log | grep "managevideos2.php"
```

---

## 13. Disclosure Timeline

| Date | Event |
| --- | --- |
| <dd/mm/2026> | Vulnerability identified |
| <dd/mm/2026> | Confirmed dynamically in authorized lab |
| (pending) | Vendor notification |
| (pending) | CVE requested/reserved |
| (pending) | Fix made available |
| (pending) | Advisory publication |

---

## 14. Vendor Communication

- **Vendor:** Vishal Mathur (`mathurvishal`)
- **Channel used:** <preencher>
- **Date of first notification:** (pending)
- **Response status:** Awaiting notification/response

---

## 15. Credits

- **Researcher:** <preencher nome/contacto>
- **Organization:** Independent security research
- **Contact:** <preencher>

---

## 16. References

- <https://cwe.mitre.org/>
- <https://www.first.org/cvss/calculator/3.1>
- <https://github.com/mathurvishal/CloudClassroom-PHP-Project>

---

## 17. Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | <dd/mm/2026> | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive and security improvement purposes.

Information presented was obtained in an authorized environment and disclosed responsibly. The author does not encourage use of this information for unauthorized access, service interruption, privacy violation or any illegal activity.

Use of information in this document is solely the reader's responsibility.

---

## 19. Contact

- **Email:** <preencher>
- **Repository:** <https://github.com/mathurvishal/CloudClassroom-PHP-Project>
