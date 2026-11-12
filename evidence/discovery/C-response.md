Static security review: Baseline Secure Coding API

Scope and assumptions. I only read the two attached files and executed nothing. I don’t know which Flask/Werkzeug versions you use, so where behaviour depends on version I assume a current release (Flask ≥ 2.3, Werkzeug ≥ 2.3) and say so in the finding. Severities are my own rating. Tags in the details:

[Fact]: shown directly by the code.
[Req]: a gap measured against your R1–R7.
[Inferred]: depends on runtime, deployment or a policy you didn’t state.
Findings table
ID	Title	Location	Req	Severity	Confidence
F-01	Protected endpoints have no authentication	get_profile L115–120, get_grades L122–126, update_grade L128–142, download_file L144–148	R1, R7	Critical	High
F-02	Grade updates have no authorization (role or course)	update_grade L128–142	R3, R4	Critical	High
F-03	Path traversal / absolute path gives arbitrary file read	download_file L146–148	R6	Critical	High
F-04	Hard-coded secret key; authorization attributes kept in a client-side signed cookie, so sessions can be forged	L8, login L91–94	R1, R4	High	High
F-05	Grade read IDOR; no per-record filtering or deny	get_grades L122–126	R2, R3, R4	High	High
F-06	Profile IDOR; professors can read profiles	get_profile L115–120	R2, R3	High	High
F-07	Grade-update input is not validated, so invalid or new records are saved	update_grade L130–140, find_grade L56–60	R5, R7	High	High
F-08	Global handler leaks exception text and paths and turns every error into 500	handle_error L150–155	R7	Medium	High (version-dependent detail)
F-09	Student identifier parsing is too lenient; bad input gives 500	L117, L124	R5, R7	Low–Medium	High
F-10	Debug mode on and bound to all interfaces	L158–159	(R7, inferred)	Medium	Medium
F-11	Session weaknesses: no server-side revocation, stale privileges, cookie hardening	L91–100, app config	(R1/R4, inferred)	Low–Medium	Medium
F-12	Plaintext hard-coded credentials, no brute-force control	L36–43, L88	outside R1–R7	Low	Medium
F-13	Shared mutable state with no synchronisation; unbounded growth	L50, L136–140	R7 (integrity), inferred	Low	Medium
Supporting explanations
F-01: Protected endpoints have no authentication
Location: get_profile, get_grades, update_grade, download_file.
Input and path: any anonymous HTTP request goes straight to the data access.
Root cause: [Fact] none of the four handlers reads flask.session. There is no decorator and no before_request hook. Only /me (L105) checks for "user". [Req] R1 requires authentication, and R7 requires 401 for anonymous requests.
Preconditions and impact: network access only. Anyone can read every profile and grade, change grades, and read files (combined with F-03).
Test: with no cookie, send GET /students/1001/profile, GET /grades/1001, POST /grades/update with valid JSON, and GET /files?path=srs-summary.txt. Each should return 401, and the update must leave GRADES unchanged.
Confidence: high.
F-02: Grade updates have no authorization
Location: update_grade L128–142.
Input and path: the JSON body student_id, course_id, grade goes to find_grade, then to an in-place write (L140) or an append (L138).
Root cause: [Fact] the handler never checks role or session["courses"]. [Req] Under R3, only professors on their assigned courses and admins may update. Under R4, holding a role is not enough. Under R7, a denied update must not change data.
Preconditions and impact: none (see F-01). Even once authentication is added, student bob could set his own grade to 20, and prof_srs could change the SSD grade of 1001. This breaks academic-record integrity.
Test: each should return 403 with GRADES unchanged afterwards:
as bob, {"student_id":1002,"course_id":"SRS","grade":20};
as prof_srs, {"student_id":1001,"course_id":"SSD","grade":0}.
Controls: prof_srs updating SRS and admin1 updating SSD should both return 200.
Confidence: high.
F-03: Path traversal / arbitrary file read
Location: download_file L146–148.
Input and path: the query parameter path becomes MATERIALS_DIR / raw_path, which goes to send_file.
Root cause: [Fact] there is no canonicalisation and no check that the path stays inside the directory. With pathlib, joining an absolute right operand discards the base: MATERIALS_DIR / "/etc/passwd" becomes /etc/passwd. ../ segments are also left unresolved. send_file has no confinement of its own, unlike send_from_directory or safe_join.
Preconditions and impact: read access to anything the process can read. That includes the application source, which holds SECRET_KEY (leading to F-04), plus system files and environment files.
Test: each should be rejected (400 or 404), and none may return the file:
?path=../baseline_secure_coding_api.py
?path=/etc/passwd
?path=..%2F..%2Fetc%2Fpasswd
a symlink inside materials/ that points outside it
Controls: ?path=srs-summary.txt should return 200 when authenticated. ?path= (empty) currently resolves to the directory itself and should give a clean 4xx (see F-08).
Assumption: the symlink case depends on how a fix resolves paths, so include it in the test.
Confidence: high.
F-04: Hard-coded secret key and client-side authorization state
Location: L8 and login L91–94.
Input and path: an attacker-crafted session cookie is read as trusted role, student_id and courses.
Root cause: [Fact] SECRET_KEY = "dev-secret-key" is a constant in the source. Flask’s default sessions are signed client-side cookies, and login stores the role, ID and courses in them. [Inferred] Any authorization you add later that trusts these session fields can be bypassed by anyone who knows the key. The key is in the repository, and F-03 also exposes it.
Preconditions and impact: the attacker knows the key, from the repository, from F-03, or by guessing a well-known dev value. They can forge {"user":"admin1","role":"admin"} and get full admin. Fixing F-01 alone does not close this: any student can read the source through F-03 and forge an admin cookie.
Test: sign a cookie with itsdangerous and the known key, setting role admin, and send it to /me and /grades/update. A hardened app should reject it, because the key is not hard-coded and authorization is derived from server-side user records.
Confidence: high for the fact. Exploitability depends on F-01/F-03 or repository access.
F-05: Grade read IDOR; no per-record filtering
Location: get_grades L122–126.
Input and path: the path parameter student_id goes to int(), then to an unfiltered list comprehension.
Root cause: [Fact] every row for any ID is returned, and the requester is never considered. [Req] Under R2, students see only their own grades. Under R3, professors see only their courses’ rows, so prof_srs asking for 1001 should get only the SRS row, not SSD. Under R4, a request with no permitted records must be denied. [Fact] Today, an empty result returns 200 [].
Test:
alice → /grades/1002: expect 403.
prof_srs → /grades/1001: expect exactly 1 row (SRS).
admin1 → /grades/1001: expect 2 rows.
prof_srs → /grades/<id with only SSD rows>: expect 403.
Assumption: R4 doesn’t say whether a student asking for their own ID with zero grades gets 403 or 200 [], and doesn’t say how to answer for a non-existent ID (404 vs 403, which would reveal whether the ID exists). Both need a policy decision.
Confidence: high.
F-06: Profile IDOR; professors can read profiles
Location: get_profile L115–120.
Root cause: [Fact] the profile, including email and programme, is returned for any ID to any caller. [Req] Under R2, students may read only their own profile. Under R3, professors may read no profiles, and admins may read all.
Impact: disclosure of personal data. IDs are small and sequential, so they are easy to enumerate.
Test:
alice → /students/1002/profile: expect 403.
prof_srs → /students/1001/profile: expect 403.
alice → her own profile, or admin1 → any profile: expect 200.
Assumption: as in F-05, whether a non-existent ID returns 404 or 403 is a policy choice.
Confidence: high.
F-07: Grade-update input is not validated
Location: update_grade L130–140.
Root cause: [Fact] values are used directly with no type, range or existence checks. A missing record causes an insert (L137–138) rather than a rejection. [Req] R5 and R7 are violated in these cases:
Input	What happens now
grade is -5, 21, "A" or true	Stored as-is. JSON true arrives as Python True, and isinstance(True, int) is true, so a naive check would accept it.
NaN or Infinity	[Inferred] Python’s json accepts these by default, so they would be stored and later serialised as non-standard JSON.
student_id 9999 or "1001" (string), or course_id "XYZ"	A new row is appended. A string ID never matches the integer comparison in get_grades, so the row is a hidden orphan. 1001.0 matches 1001 because Python compares them equal.
Missing key	KeyError, returned as 500 with "'grade'". Nothing is written, because the error happens before the write.
Non-object body (null, [], "x")	TypeError, returned as 500.
Wrong Content-Type	Flask ≥ 2.1 raises 415, which F-08 turns into a 500.
Impact: records corrupted or invented, and wrong status codes. With no authentication (F-01), anyone can append rows without limit (see F-13).
Test: snapshot GRADES, send each malformed case above as an authorised user, and check that each returns 400 (or 415 for content type) and that GRADES is identical afterwards.
Confidence: high, except the NaN behaviour, which is medium.
F-08: Error handler leaks details and turns every error into 500
Location: handle_error L150–155.
Root cause: [Fact] it returns str(exc) and the exception class name for every exception. [Inferred, Flask behaviour] An Exception handler also catches HTTPException, so 404, 405, 415 and any future abort(401/403) come back as 500.
Examples of leaks:
FileNotFoundError / IsADirectoryError from send_file include the absolute server path, e.g. '/…/materials/x'.
ValueError from int() echoes the input.
KeyError and TypeError reveal internal structure.
Test:
/files?path=nope.txt: expect 404 with no path in the body.
/grades/abc: expect 400.
/nonexistent: expect 404, not 500.
DELETE /login: expect 405.
In every case, check that the body has no type field and no file paths.
Confidence: high that it leaks. Medium on HTTPException capture, which is version-dependent.
F-09: Student identifier parsing is too lenient
Location: L117 and L124.
Root cause: [Fact] the default string converter is passed to int(). Python’s int() accepts "-1", "0", "+1001", "1_001", surrounding whitespace (%201001%20) and non-ASCII Unicode digits. Non-numeric input raises ValueError, which F-08 turns into a 500. [Req] R5 requires positive integers and R7 requires a 400 for bad input.
Impact: low today. Several spellings mapping to one ID is a risk if a later authorization check compares the raw string to the session ID.
Test: for each of abc, -1, 0, 1_001, +1001 and Arabic-Indic digits, expect 400. 1001 as the right user should succeed.
Confidence: high.
F-10: Debug mode on all interfaces
Location: L159, debug=True, host="0.0.0.0".
Root cause: [Fact] the debug server is enabled and bound to every interface whenever the module is run directly. [Inferred] The Werkzeug debugger allows code execution if its PIN is obtained. Because the catch-all handler intercepts exceptions in routes, the interactive debugger page may never be reached, which lowers exploitability. Debug mode also enables the reloader and fuller errors.
Preconditions: started via python file.py and reachable over the network. Not relevant under a WSGI server.
Test: check how it is deployed. Request /console and see whether the Werkzeug console responds.
Confidence: medium.
F-11: Session weaknesses
Location: L91–100 and app config.
Root cause: [Fact] logout clears only the client’s copy of the session. [Inferred] A captured cookie stays valid after logout, and role or course changes don’t take effect until the user logs in again. [Inferred] SESSION_COOKIE_SECURE and SAMESITE are not set. Login CSRF is possible because /login accepts form posts. CSRF against /grades/update is mostly blunted by Flask’s JSON content-type requirement, but that depends on the version.
Test:
Copy a cookie, call /logout, then replay the cookie on /me. A hardened app should treat it as logged out.
Inspect the Set-Cookie attributes.
Confidence: medium.
F-12: Credential handling
Location: L36–43 and L88.
Root cause: [Fact] passwords are weak, in plaintext, in the source, and compared with !=, which is not constant-time. There is no rate limiting or lockout. R1–R7 don’t cover this, so I list it for completeness and accept the teaching-environment framing.
Test: send repeated failed logins and check that throttling kicks in.
Confidence: medium (policy unknown).
F-13: Shared state with no synchronisation and unbounded growth
Location: L50 and L136–140.
Root cause: [Fact] the check-then-append against the global list has no lock. [Inferred] On a threaded or multi-worker server, concurrent requests can insert duplicate rows, and find_grade then returns the first one, so reads go stale. With F-01 and F-07, an anonymous user can append rows without limit and exhaust memory.
Test: send many concurrent updates for a new (student, course) pair and count the rows afterwards.
Confidence: medium. You said the in-memory store is not production, so this is low priority.
Limits

Finding nothing here would not prove anything was safe. I didn’t assess dependency versions, deployment (TLS, reverse proxy, CORS), logging, or behaviour under a production WSGI server.

The fixes interact: F-01 alone is not enough while F-03 and F-04 remain, because any authenticated student could read the key and forge an admin session.