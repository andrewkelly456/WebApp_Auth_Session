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

## Attack #3: Session Cookie Theft via Missing HttpOnly Flag

**Target vulnerability:** VULN-03 (Missing Cookie Security Flags) - see VULNERABILITIES.md

**Date:** 2026-10-19

**Setup:**
- Logged in normally through `http://localhost:3000/login.html` to obtain a valid session cookie.
- Confirmed via DevTools (Application -> Cookies) that `session_token` has no `HttpOnly`, `Secure` or `SameSite` attributes set.

**Attack steps:**
1. Opened the browser DevTools Console on the application's own page (simulating any script that manages to execute on the page - e.g. via an XSS bug elsewhere, a malicious browser extension, or a compromised third-party script/ad; no actual injection vulnerability was built, since that is outside this project's auth/session-only scope).
2. Ran `document.cookie` in the console - the full session token was returned directly as a plain string, proving client-side script has unrestricted read access to it.
3. Extracted the token value from the output.
4. Replayed it from a separate terminal via `curl.exe -s -b "session_token=<stolen_value>" http://localhost:3000/api/account`
5. Received the full account data back, confirming the stolen token grants complete session hijacking - identical impact to Attack #2, via a different theft method. 

**Result:** Full session hijacking achieved purely by reading `document.cookie`, with zero network interception or server-side access required.

**Impact:**
- Any script execution on the page (XSS, malicious extension, compromised dependency) immediately compromises every logged-in user's session
- Demonstrates that fixing VULN-02 (random tokens) alone would not be sufficient - a long random token is just as readable via `document.cookie` as a predictable one if `HttpOnly` is not set
- Missing `Secure` and `SameSite` represent additional, separate exposure (network interception and cross-site request riding, respectively) not directly exercised in this attack

**Fix (not yet applied in this app):**
Set `httpOnly: true`, `secure: true` and `sameSite: 'strict'` on the cookie at creation time.

## Attack #4: Session Reuse After Logout

**Target vulnerability:** VULN-04 (Logout Does Not Invalidate Session Server-Side) - see VULNERABILITIES.md

**Date:** 2026-10-19

**Setup:**
- Logged in normally, capturing the active `session_token` value via `document.cookie` before taking any further action.

**Attack steps:**
1. Captured the session token (`sess_7_20`) immediately after login, while it was still a legitimate, actively-used session.
2. Clicked **Logout** on `account.html`. Confirmed via DevTools that the `session_token` cookie was removed from the browser.
3. From a separate terminal, replayed the captured (pre-logout) token:
`curl.exe -s -b "session_token=sess_7_20" http://localhost:3000/api/account`
4. Received the full account data back - identical to a legitimately logged in request - despite the UI confirming logout had succeeded.
5. Queried the database directly (`SELECT * FROM sessions WHERE session_token = 'sess_7_20'`) and confirmed the row was still present, completely untouched by the logout action.

**Result:** A token captured before logout remains fully exploitable indefinitely after the user believes they have logged out, with no server-side invalidation ever occurring.

**Impact:**
- Any prior session theft (via VULN-02 guessing or VULN-03 cookie theft) remains exploitable forever, even after the legitimate user logs out - logout provides a false sense of security with no actual protection
- Compounds every other session vulnerability in this app; there is currently no mechanism anywhere that ever removes a session once created

**Fix (not yet applied in this app):**
Delete the corresponding `sessions` row on logout
(`DELETE FROM sessions WHERE session_token = ?`), not just the client-side cookie. 