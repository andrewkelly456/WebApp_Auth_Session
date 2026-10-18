# Vulnerability Log

## VULN-01: Plaintext Password Storage

**Location:** `routes/auth.js` - `POST /api/register`, `POST /api/login`

**Description:**
User passwords are stored in the `users.password` column with no hashing, salting, or encryption of any kind. The raw value submitted at registration is inserted directly into the database and compared directly (`===`) at login.

**Why it's dangerous:**
Anyone who gains access to the database - via a leaked backup, an exposed/misconfigured DB instance, an insider, a stolen snapshot, etc. - immediately obtains every user's real, usable login password. No cracking, no rainbow tables, no brute force required. This also enables credential-stuffing attacks against other sites, since most users reuse passwords.

**CWE Reference:** CWE-256 (Plaintext Storage of a Password)

**Real-world fix:**
Hash passwords with a slow, salted algorithm designed for passwords (bcrypt, scrypt, or Argon2) - never a fast general-purpose hash like MD5/SHA-256 alone. Compare using the library's constant-time verify function, never a direct string comparison. 

**Status:** Exploited - see ATTACK_LOG.md, Attack #1

## VULN-02: Predictable / Sequential Session Tokens

**Location:** `routes/auth.js` - `POST /api/login` (token generation), `middleware/session.js` - `requireSession` (token validation)

**Description:**
Session tokens are generated as `sess_<userId>_<sequentialNumber>`, where `sequentialNumber` is simply the current total row count in the `sessions` table plus one. Both components are small, predictable integers with no cryptographic randomness involved. The validation logic (`requireSession`) only checks whether a submitted token exists as a row in the `sessions` table - it performs no additional identity verification (e.g. binding to an IP, user agent, or re-checking a password).

**Why it's dangerous:**
An attacker with no credentials at all can enumerate small integer combinations for both the user ID and session number, sending each as a forged `Cookie` header to any protected endpoint. Any guess that happens to match a real, currently-active session grants full impersonation of that user - no password, no cracking, no brute-force of a large keyspace required, since the actual search space is tiny (sequential small integers).

**CWE Reference:** CWE-330 (Use of Insufficiently Random Values),
CWE-384 (Session Fixation family)

**Real-world fix:**
Generate session tokens using a cryptographically secure random value (e.g. Node's `crypto.randomBytes(32).toString('hex')`), long enough and random enough that guessing is computationally infeasible. Never derive tokens from predictable data like counters, timestamps, or user IDs.

**Status:** Exploited - see ATTACK_LOG.md, Attack #2.

## VULN-03: Missing Cookie Security Flags (HttpOnly, Secure, SameSite)

**Location:** `routes/auth.js` - `POST /api/login` (`res.cookie('session_token', sessionToken)`)

**Description:**
The session cookie is set with no additional attributes at all. It is missing `HttpOnly` (so client-side JavaScript can read it directly via `document.cookie`), `Secure` (so it would be transmitted even over plain unencrypted HTTP) and `SameSite` (so it may be sent along with cross-site requests).

**Why it's dangerous:**
Without `HttpOnly`, any JavaScript that manages to execute on the page - via an XSS vulnerability elsewhere, a malicious browser extension, a compromised third-party script/ad, etc. - can read the session token directly out of `document.cookie` and exfiltrate it to an attacker, leading immediately to full session hijacking (identical impact to VULN-02's exploitation step, just a different theft method). Without `Secure`, the token could be intercepted in transit on an unencrypted network. Without `SameSite`, the cookie may ride along on requests triggered by a malicious third-party site, enabling CSRF-style abuse.

**CWE Reference:** CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag), CWE-614 (Sensitive Cookie Without 'Secure' Flag)

**Real-world fix:**
Set all three flags when issuing the cookie, e.g.:
`res.cookie('session_token', sessionToken, { httpOnly: true, secure: true, sameSite: 'strict' })` (`secure: true` requires serving over HTTPS, which should be the norm in production).

**Status:** Exploited - see ATTACK_LOG.md, Attack #3. 

## VULN-04: Logout Does Not Invalidate Session Server-Side

**Location:** `routes/auth.js` - `POST /api/logout`

**Description:**
The logout endpoint only calls `res.clearCookie('session_token')`, which removes the cookie from the client's browser. It never deletes or invalidates the corresponding row in the `sessions` table on the server.

**Why it's dangerous:**
The session token itself remains fully valid indefinitely after "logout." Anyone holding a copy of that token - captured before logout via any of the methods demonstrated in VULN-02/VULN-03 (guessing, cookie theft via missing HttpOnly, network interception, etc.) - can continue using it to impersonate the user with zero indication to the real user that their session is still active and exploitable. The UI shows "logged out", but server-side nothing changed at all.

**CWE Reference:** CWE-613 (Insufficient Session Expiration)

**Real-world fix:**
On logout, delete the matching row from the `sessions` table 
(`DELETE FROM sessions WHERE session_token = ?`) in addition to clearing the cookie, so the token is rejected by `requireSession` immediately afterward.

**Status:** Exploited - see ATTACK_LOG.md, Attack #4