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