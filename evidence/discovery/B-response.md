Static security review: Baseline Secure Coding API

Scope and method. I read the two supplied files (baseline_secure_coding_api.py and the context prompt) and nothing else. I ran no code and used no outside material. Line numbers refer to the supplied file. Where a statement depends on Flask, Werkzeug or pathlib behaviour, it reflects my understanding of current versions and is marked as such. Finding no other issues would not prove the code is safe.

Assumed access policy (the code does not define one). The context names three roles but does not say who may do what. I assume this policy and flag it as inferred wherever it matters:

Students may read only their own profile and grades.
Professors may read and update grades only for their assigned courses.
Admins have full access.
Teaching materials may be read only by authenticated users, and only files inside materials/.

Systemic root cause. /login authenticates users and stores user, role, student_id and courses in the session (lines 91–94). Only /me (line 105) ever reads them. No endpoint checks authentication or authorization. That one gap drives F1–F3 and part of F4.

Findings table
ID	Title	Location	Severity (my estimate)	Confidence
F1	Anyone, even without logging in, can change or create grades	update_grade, L128–142	Critical	High
F2	Anyone can read any student’s grades (IDOR, missing authentication)	get_grades, L122–126	High	High
F3	Anyone can read any student’s profile, including email (IDOR)	get_profile, L115–120	High	High
F4	Path traversal / arbitrary file read	download_file, L144–148	Critical	High
F5	Hard-coded, guessable SECRET_KEY lets attackers forge sessions	L8	High (latent today)	High
F6	Debug mode on all interfaces; possible remote code execution via the Werkzeug console	L158–159	High (only when run directly)	Medium
F7	Error handler leaks details and turns every error into a 500	handle_error, L150–155 (+ L117, L124, L130–134)	Medium	High
F8	No validation of grade input; integrity problems and unbounded growth	update_grade / find_grade, L56–60, L130–140	Medium	High
F9	Weak credential handling: plaintext, hard-coded, no throttling	L36–43, L82–96	Medium	High
F10	Session lifecycle: logout cannot revoke a cookie; role kept as a stale snapshot	L91–101	Medium	Medium–High
F11	Session cookie settings and missing CSRF protection	Config (absent), L82, L98, L128	Low–Medium	Medium
Supporting explanations
F1: Unauthenticated grade modification
Code fact: update_grade reads student_id, course_id and grade from the JSON body (L130–134). It then overwrites an existing row or appends a new one (L136–140). It never reads flask.session.
Attacker input and path: a JSON body sent to POST /grades/update → find_grade → the record is changed in place or appended to GRADES.
Missing control: no authentication check. No check that the role is professor or admin, and none that course_id is in session["courses"].
Preconditions and impact: only network access is needed. Any student, or anyone at all, can set any grade, including their own. Academic integrity is fully compromised.
Test: without a cookie, send POST /grades/update with body {"student_id":1001,"course_id":"SRS","grade":20}. A 200 response followed by a changed value at GET /grades/1001 confirms it. Repeat as alice, and as prof_srs with course_id:"SSD" (a course she isn’t assigned). Under the assumed policy, both should be refused.
Uncertainty: the code is unambiguous. Only the exact policy, such as whether admins may edit grades, is assumed.
F2: Unauthorized grade disclosure
Code fact: L124–126 return every grade row for any student_id in the URL. No session check.
Input and path: URL path segment → int() → filter over GRADES → JSON response.
Missing control: no authentication check and no object-level authorization (for a student, sid == session["student_id"]; for a professor, rows limited to their courses).
Impact: anyone can read every student’s grades, and the IDs are small sequential integers, so enumeration is trivial.
Test: without a cookie, GET /grades/1002 should return 401. Logged in as alice, the same request should return 403. Logged in as prof_srs, it should return SRS rows only.
Confidence: high on the code. Exactly what professors should see is assumed.
F3: Unauthorized profile disclosure (PII)
Code fact: L117–120 return the full profile (name, email, program) for any ID, with no session check.
Missing control: the same as F2. In addition, a 404 for unknown IDs versus 200 for real ones confirms which student IDs exist.
Impact: students’ personal data is exposed, which may raise GDPR concerns given the uc.pt domain. The exposed emails also help with phishing.
Test: request GET /students/1002/profile without a cookie and logged in as alice. Both should be refused.
Uncertainty: the code doesn’t say whether professors or admins may see profiles.
F4: Path traversal / arbitrary file read
Code fact: target = MATERIALS_DIR / raw_path (L147), then send_file(target) (L148). There is no normalization, no check that the result stays inside the folder, and no authentication check.
Input and path: query parameter path → pathlib join → send_file.
Root cause (library behaviour; high confidence):
pathlib throws away the base path when the right-hand side is absolute: MATERIALS_DIR / "/etc/passwd" becomes /etc/passwd.
../ segments are kept and resolved by the operating system.
send_file with a path argument applies no directory restriction.
Impact:
An attacker can read any file the process can read. That includes the app’s own source (../baseline_secure_coding_api.py), which exposes SECRET_KEY (F5) and every password (F9).
It also exposes system files such as /etc/passwd, /proc/self/environ and /etc/machine-id, which feed into F6.
With F7, error messages tell the attacker whether a file exists.
Tests:
GET /files?path=../baseline_secure_coding_api.py
GET /files?path=/etc/passwd
GET /files?path=..%2f..%2fetc%2fhosts
The expected result is a 400 or 404 for all three. GET /files?path=srs-summary.txt should still succeed for an authenticated user.
Uncertainty: whether materials should be public isn’t stated. The traversal is a flaw regardless of that answer.
F5: Hard-coded, guessable SECRET_KEY
Code fact: SECRET_KEY = "dev-secret-key" (L8). Flask’s default sessions are cookies signed (not encrypted) with this key.
Input and path: an attacker-built cookie is accepted as the session.
Root cause: a secret that is guessable, hard-coded and committed in source, readable via F4.
Impact: an attacker can forge any session, for example {"user":"admin1","role":"admin"}. Today only /me trusts the session, so the impact is latent. It becomes a full authorization bypass as soon as role checks based on the session are added to fix F1–F3, which is why it matters now.
Test: sign a session payload with this key (using Flask’s own serializer in a test harness) and send it to /me. If it shows admin1, forgery works. After the fix, the same cookie must be rejected.
F6: Debug server on 0.0.0.0
Code fact: app.run(debug=True, host="0.0.0.0") (L159). This only applies when the file is run directly.
Inferred behaviour (medium confidence; depends on the Werkzeug version):
Debug mode turns on the Werkzeug debugger.
The @app.errorhandler(Exception) handler probably catches most exceptions before the interactive traceback page appears.
The debugger’s /console route may still be reachable. It is protected by a PIN that is derived from host details (machine-id, network MAC address, username, module path). F4 can read those, so the PIN can be computed. Result: remote code execution.
Debug mode also turns on the auto-reloader and verbose behaviour.
Preconditions: started with python file.py and reachable over the network.
Test: check whether GET /console serves the PIN prompt. Separately, check whether host files needed to derive the PIN can be read via F4.
Uncertainty: whether the PIN can be derived depends on the version, and on whether the process can read those host files.
F7: Verbose, catch-all error handler
Code fact: every exception (L150–155) returns str(exc) and the exception class name, with status 500. Exceptions are easy to trigger:
int() on non-numeric input (L117, L124)
data is None, or a key is missing (L130–134)
a missing file or a directory passed to send_file (L148, e.g. path= empty)
Root cause: internal details are reflected to clients. Because a handler for Exception also catches Flask’s HTTPException, genuine 404/405/415 responses are likely rewritten as 500 (library behaviour; medium–high confidence).
Impact:
Absolute paths on the server are disclosed (e.g. a FileNotFoundError message).
Differing messages reveal which files exist, which helps exploit F4.
Wrong status codes cause monitoring and client-logic errors.
Test: GET /files?path=nope and GET /grades/abc should return a generic message with the correct status code and no paths or exception types.
F8: No validation of grade input
Code fact: no type, range or existence checks.
{"student_id":"1001"} (a string) doesn’t match the integer 1001 in find_grade, so a duplicate row is appended.
grade can be any JSON value (-5, 999, "A+", an object).
Records for students or courses that don’t exist are created.
Each new key pair grows GRADES without limit.
Inferred requirement: grades must lie within the grading scale (e.g. 0–20, given the Portuguese context; this is an assumption). Student and course IDs must refer to real records.
Impact: corrupted or ambiguous records, since reads then return duplicates. An attacker can also fill memory, a denial-of-service risk, and with F1 needs no login to do it.
Test: submit a string ID, an out-of-range grade, an unknown course, and a very large number of distinct pairs. Expect 400 responses and no growth in GRADES.
F9: Credential handling
Code facts:
Passwords are stored in plaintext in source (L36–43) and compared with != (L88).
There is no rate limiting or lockout.
The demo passwords are trivial.
Impact:
Anyone who reads the source (F4, or the repository) gets every account, including admin1.
Online brute-force is unthrottled.
The != comparison may leak timing information. This risk is low and theoretical.
The failure message is the same for unknown user and wrong password, which is good, but the code path differs, so a small timing difference is possible.
Uncertainty: the context calls this a teaching dataset, so the issue is the pattern, not these specific passwords.
Test: check that stored credentials are salted hashes. Send N failed logins and confirm throttling kicks in.
F10: Session lifecycle
Code fact: the session is a signed client-side cookie. logout (L100) only tells the browser to clear it. Login doesn’t clear existing session data before writing new values (L91–94). Role and courses are copied into the cookie at login.
Inferred behaviour (Flask default; medium–high confidence):
A cookie captured before logout keeps verifying until its signature age limit (about 31 days by default). Logout therefore cannot revoke it.
A change to a user’s role or course assignments isn’t reflected until they log in again.
Impact: a stolen cookie can be replayed after logout. Authorization decisions would rest on stale data once checks exist.
Test: copy the cookie, call /logout, replay the old cookie to /me. Expect user: null after the fix.
F11: Cookie settings and CSRF
Code facts:
No SESSION_COOKIE_SECURE or SESSION_COOKIE_SAMESITE is set (Flask defaults: Secure off; SameSite not set).
The app runs over plain HTTP.
No endpoint has CSRF protection.
Notes:
/login and /logout accept form posts, so login-CSRF and forced logout are possible. Risk: low.
get_json() on /grades/update probably rejects non-JSON content types in recent Flask, which limits classic form-based CSRF there. That defence depends on behaviour I haven’t verified.
The issue matters once F1 is fixed with cookie-based authentication.
Impact depends on deployment: for example, whether a TLS-terminating proxy sits in front of the app, which isn’t stated.
Test: inspect the Set-Cookie attributes. Submit a cross-origin form post to /login and /logout. Try POST /grades/update with Content-Type: text/plain.
Assumptions and limits
The access policy above is inferred, not specified. F1–F3 are gaps against that assumed policy, but the complete absence of any check is a code fact.
I assessed only behaviour visible in this file. Deployment details (proxy, TLS, WSGI server, Flask and Werkzeug versions) are unknown and affect F6, F7 and F11.
I excluded race conditions on the shared in-memory lists and the risk of serving active content (e.g. HTML) from materials/. With no upload feature and a dataset described as a teaching simplification, neither is reachable from this code.