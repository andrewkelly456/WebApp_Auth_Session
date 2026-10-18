# Vulnerability Log

## VULN-01: Plaintext Password Storage

**Location:** `routes/auth.js` - `POST /api/register`, `POST /api/login`

**Desription**
User passwords are stored in the `users.password` column with no hashing, salting, or encryption of any kind. The raw value submitted at registration is inserted directly into the database and compared directly (`===`) at login.

**Why it's dangerous:**
Anyone who gains access to the database - via a leaked backup, an exposed/misconfigured DB instance, an insider, a stolen snapshot, etc. - immediately obtains every user's real, usable login password. No cracking, no rainbow tables, no brute force required. This also enables credential-stuffing attacks against other sites, since most users reuse passwords.

**CWE Reference:** CWE-256 (Plaintext Storage of a Password)

**Real-world fix:**
Hash passwords with a slow, salted algorithim desigined for passwords (bcrypt, scrypt, or Agon2) - never a fast general-purpose hash like MD5/SHA-256 alone. Compare using the library's constant-time verify function, never a direct string comparison. 

**Status:** Exploited - see ATTACK_LOG.md, Attack #1