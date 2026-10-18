# Attack Log

## Attack #1: Plaintext Password Extraction & Account Takeover

**Target vulnerability:** VULN-01 (Plaintext Password Storage) - see VULNERABILITIES.md

**Date:** 2026-10-18

**Setup:**
- Registered a victim account via `POST /api/register`:
`username: victim_alice`, a realistic strong password.

**Attack steps:**
1. Assumed the position of an attacker who obtained read access to the application's MySQL database (mechanism out of scope for this project - e.g. leaked backup, exposed DB port, insider access).
2. Ran `SELECT username, email, password FROM users;` directly against the database.
3. Read the victim's password straight from the `password` column in cleartext - no cracking or hashing to break.
4. Submitted that exact value to `POST /api/login` as `victim_alice`.
5. Received `200 OK` - "Login successful" - confirming full authentication as the victim using only data pulled from the database.

**Result:** Complete account takeover with zero computational effort. Password strength was irrelevant; the only "protection" was the database's own access control, which we assumed was already bypassed.

**Impact:** 
- Full account takeover for any user in the table
- Credential reuse risk: since users often reuse passwords across sites, this plaintext exposure could compromise victim's accounts elsewhere too

**Fix (not yet applied in this app):**
Hash passwords with bcrypt/Argon2 before storing; never store or log raw passwords anywhere.

## Attack #2: Session Token Enumeration & Hijacking

**Target vulnerability:** VULN-02 (Predictable Session Tokens) - see VULNERABILITIES.md

**Date:** 2026-10-19

**Setup:**
- Registered and logged in a victim account (`victim_bob`) to generate a live session, simulating a real user active elsewhere.
- Logged in with the attacker's own legitimate account (`testuser`) to observe the token format and establish a reference point for the current session-counter range.

**Attack steps:**
1. Observed own token (`sess_1_15`), confirming the format `sess_<userId>_<sequentialNumber>` and that both values are small, predictable integers.
2. Wrote `attacks/vuln2_session_bruteforce.ps1`, which iterates userId 1-10 and sessionNumber 1-20 (200 total guesses), sending each as a forged `Cookie` header to `GET /api/account` via `curl.exe`. 
3. Never submitted any password for any guessed account - the script only ever touched the protected endpoint directly with forged cookies
4. Script returned multiple confirmed hits, including `sess_6_14` (`victim_bob`'s real session, created in Setup) and several other real users' live sessions (`kevin`, `bob`) discovered incidentally in the same scan.

**Result:** Full account impersonation for multiple real users, achieved purely by enumerating a small, predictable integer space - zero credentials, zero password cracking required.

**Impact:**
- Complete session hijacking / account takeover for any user with an active session
- Attack cost is trivial: 200 HTTP requests completed in seconds
- Additionally exposed that old sessions are never invalidated (`kevin` had 12 simultaneously valid sessions from past logins) - compounding the exposure window

**Fix (not yet applied in this app):**
Replace sequential token generation with `crypto.randomBytes(32).toString('hex')` or equivalent cryptographically secure random generation. 