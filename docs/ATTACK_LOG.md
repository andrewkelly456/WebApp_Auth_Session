# Attack Log

## Attack #1: Plaintext Password Extraction & Account Takeover

**Target vulnerability:** VULN-01 (Plaintext Password Storage) - see VULNERABILITIES.md

**Date:** 2026-10-18

**Setup:**
- Registered a victim account via `POST /api/register`:
`username: victim_alice`, a realistic strong password.

**Attack steps:**
1. Assumed the position of an attacker who obtained read access to the application's MySQL database (mechanism out of scope for this project - e.g. leaked backup, exposed DB port, insider access).
2. Ran `SELECT username, email, password FROM users;` directly against the database .
3. Read the victim's password straight from the `password` column in cleartext - no cracking or hashing to break.
4. Submitted that exact value to `POST /api/login` as `victim_alice`.
5. Received `200 OK` - "Login successful" - confirming full authentication as the vctim using only data pulled from the database.

**Result:** Complete accoutn takeover with zero computational effort. Password strength was irreleveant; the only "protection" was the database's own access control, which we assumed was already bypassed.

**Impact:** 
- Full account takeover for any user in the table
- Credential reuse risk: since users often reuse passwords across sites, this plaintext exposure could compromise victim's accounts elsewhere too

**Fix (not yet applied in this app):**
Hash password with bcrypt/Argon2  before storing; never store or log raw passwords anywhere.