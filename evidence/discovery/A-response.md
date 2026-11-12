Static security review: baseline_secure_coding_api.py

This review covers only the attached source and prompt. I didn’t run any code. Line numbers refer to the uploaded file.

Assumed security policy (inferred, not stated in the code)

The source contains no written policy. The data model (role, student_id, courses) suggests the rules below, and I treat them as assumptions:

P1. Every data endpoint requires an authenticated session. The exceptions are / and /login.
P2. A student may read only their own profile and grades.
P3. A professor may read and update grades only for courses listed in courses. An admin may do anything.
P4. A grade is an integer from 0 to 20 (the Portuguese scale, guessed from the uc.pt emails) for a student and course that already exist.
P5. /files serves only files inside materials/. Whether anonymous users may download materials is unknown.

One code fact underlies several findings: flask.session is read only in /me. No other endpoint checks who the caller is.

Findings
ID	Title	Location	Severity (est.)	Confidence
F-01	Path traversal and arbitrary file read	download_file, L144–148	Critical	High
F-02	Anyone can change or create grades without logging in	update_grade, L128–142	Critical	High
F-03	Werkzeug debugger enabled and reachable on all interfaces	__main__, L158–159	High (conditional)	Medium
F-04	Unauthenticated access to student profiles by ID (PII exposure)	get_profile, L115–120	High	High
F-05	Unauthenticated access to grades by ID	get_grades, L122–126	High	High
F-06	Hard-coded, guessable SECRET_KEY allows forged sessions	L8	High (latent)	High (fact) / Medium (impact)
F-07	Grade-update input not validated; storage can grow without limit	update_grade, L130–140	Medium	High
F-08	Error details returned to the client; all errors become 500	handle_error, L150–155	Medium	High
F-09	Passwords stored in plaintext, hard-coded and weak; no brute-force protection	USERS L36–43, login L82–96	Medium	High
F-10	Weak session lifecycle and cookie settings	login/logout, app config	Low–Medium	Medium
F-11	No CSRF protection on form POSTs (login CSRF)	login, logout	Low	Medium
F-12	Race condition when updating grades in shared memory	find_grade + append, L136–140	Low	Medium
Details
F-01: Path traversal and arbitrary file read
Code fact: raw_path comes straight from ?path= and is joined as MATERIALS_DIR / raw_path, then passed to send_file. There is no normalisation, no check that the result stays inside MATERIALS_DIR, and no authentication.
Root cause: pathlib keeps .. segments without resolving them. If the right-hand side is an absolute path, pathlib throws away the base directory entirely, so MATERIALS_DIR / "/etc/passwd" becomes /etc/passwd. Two controls are missing: a containment check (resolve() followed by is_relative_to) and an authentication check.
Preconditions and impact: Network access only. An attacker can read any file the process can read: the application source (which includes the secret key and passwords), /etc/passwd, /proc/self/environ (which would expose secrets even if they were moved to environment variables), and the inputs needed to calculate the debugger PIN (see F-03).
Test: Send GET /files?path=../<app filename>.py, GET /files?path=/etc/passwd and GET /files?path=..%2f..%2fetc%2fhostname. A 200 response containing the file confirms the finding. A unit test should also check that every served path resolves inside MATERIALS_DIR.
Uncertainty: The source filename on disk is assumed. The impact depends on the OS user’s file permissions.
F-02: Anyone can change or create grades without logging in
Code fact: The endpoint takes a JSON body (student_id, course_id, grade) and passes it to find_grade, which then updates or appends a row. It never reads the session or checks a role.
Root cause: No authentication, and no authorisation against P3 (professor plus course_id in session["courses"], or admin). Students can’t be told apart from staff.
Impact: Anyone can change any grade, including their own, or insert rows for any student and course. This destroys the integrity of academic records.
Test: With no cookie, send curl -X POST /grades/update -H 'Content-Type: application/json' -d '{"student_id":1001,"course_id":"SRS","grade":20}', then GET /grades/1001. Repeat while logged in as alice and as prof_srs with course_id:"SSD". Under P3, all three should be rejected.
F-03: Werkzeug debugger enabled and reachable on all interfaces
Code fact: app.run(debug=True, host="0.0.0.0").
Root cause: A development configuration with the interactive debugger is exposed on every network interface.
Data flow: The errorhandler(Exception) handler catches most exceptions, so traceback pages will rarely appear. Werkzeug’s /console endpoint, however, is served by the debugger middleware regardless of that handler, and it is protected only by a PIN. The PIN is derived from values F-01 can read: the username, the module path, the MAC address from /sys/class/net/*/address, /etc/machine-id and /proc/self/cgroup. Chaining F-01 into F-03 is a well-known path to remote code execution.
Preconditions: The app is started with python file.py, not a production WSGI server. The Werkzeug version matters: newer releases restrict debugger access by host and lock out after repeated wrong PINs. WERKZEUG_DEBUG_PIN must not be set to off.
Test: Check that GET /console responds from a non-local host. Separately, confirm the PIN inputs can be read through F-01. Don’t attempt the full exploit outside a lab.
Confidence: Medium, because it depends on the version and how the app is launched.
F-04 / F-05: Unauthenticated access to profiles and grades by ID
Code fact: student_id comes from the URL path and goes into a direct lookup or filter. There are no session checks.
Root cause: Missing authentication (P1) and a missing ownership or relationship check (P2/P3). IDs are sequential (1001, 1002), so they’re easy to enumerate.
Impact: Names, emails and programmes (PII, relevant under GDPR) and every student’s grades are disclosed to anyone who can reach the server.
Test: With no cookie, request GET /students/1002/profile and GET /grades/1002. Repeat while logged in as alice. Under P2, both should get 401/403. Also enumerate IDs 1000–1010.
Note: A non-numeric ID raises a ValueError that surfaces as a 500 (see F-08).
F-06: Hard-coded, guessable SECRET_KEY
Code fact: SECRET_KEY = "dev-secret-key". Flask’s default sessions are client-side cookies signed with this key, and they are not encrypted.
Root cause: A low-entropy secret written into source control. It can also be read through F-01.
Impact: Anyone can forge a session such as {"user":"admin1","role":"admin"}. Today’s impact is limited because no endpoint authorises from the session except /me, which just repeats it back. It becomes critical as soon as access checks are added that trust session["role"], which is the natural fix for F-02, F-04 and F-05.
Test: Sign a cookie with Flask’s session serializer using the known key, then call GET /me. The forged identity being returned confirms the finding.
F-07: Grade-update input not validated
Code fact: student_id, course_id and grade are used with no checks on type, range or existence. get_json() may raise an error or return None. Missing keys raise KeyError. MAX_CONTENT_LENGTH isn’t set.
Impact: The data can be corrupted in several ways:
Grades like -5, "A" or nested objects can be stored.
Rows can be created for students or courses that don’t exist.
"1001" (a string) doesn’t match 1001 (an integer), so it silently creates a duplicate row that GET /grades/1001 never shows.
Rows can be appended without limit, which exhausts memory and gives a denial of service.
Test: Send each malformed payload and check what was stored. Under P4, each should get a 400. Then send a loop of unique course_id values while watching memory use.
F-08: Error details returned to the client
Code fact: str(exc) and the exception class name are sent to the client. The handler also catches HTTPException, so a 404, 405 or 415 comes back as a 500.
Impact:
FileNotFoundError messages expose absolute filesystem paths.
The different error types (FileNotFoundError, PermissionError, IsADirectoryError) tell an attacker which files exist, which helps with F-01.
Monitoring sees the wrong status codes.
Test: Request GET /files?path=nope (look for an absolute path in the body), GET /files?path= (look for a directory error) and GET /no-such-route (expect 500 instead of 404).
F-09: Plaintext, hard-coded, weak passwords; no brute-force protection
Code fact: Passwords are stored as plain strings in source and compared with !=. There is no rate limiting or lockout.
Impact: Anyone who can read the source (including through F-01) gets every credential. Online guessing is unlimited. The non-constant-time comparison is a theoretical timing leak and of little practical concern here.
Test: Review the source. Script about 1,000 failed logins against admin1 and confirm none are throttled.
Assumption: The demo data may be intentional, but the same pattern would be a real flaw in production.
F-10: Weak session lifecycle and cookie settings
Code facts:
logout only clears the cookie on the client side.
The role and courses are copied into the cookie at login and never checked again.
SESSION_COOKIE_SECURE and SESSION_COOKIE_SAMESITE aren’t set.
app.run serves plain HTTP.
Impact: A stolen or copied cookie keeps working after logout until the signature’s maximum age (31 days by default). Revoking a user’s role takes effect only when they log in again. Cookies can be sent over HTTP.
Test: Log in, save the cookie, log out, then replay the cookie to /me. If it still returns the user, the finding is confirmed.
Uncertainty: The deployment (TLS at a reverse proxy, for example) may reduce part of this.
F-11: No CSRF protection on form POSTs
Code fact: /login and /logout accept form posts without a token, and SameSite isn’t set.
Impact: Login CSRF: an attacker can log a victim into the attacker’s account. This is low impact here. /grades/update is protected only by accident, because recent Flask versions of get_json() require a JSON content type. That protection would disappear with force=True or older Flask versions, and it would start to matter once cookie authentication is added.
Test: Submit an auto-posting form from another origin to /login and check whether the victim’s browser ends up with the attacker’s session.
F-12: Race condition when updating grades
Code fact: Finding the row and then appending or updating it is not atomic. The development server runs requests in threads by default.
Impact: Two concurrent first-time updates can create duplicate rows. After that, find_grade updates the first row while get_grades returns both, so the records disagree.
Test: Send about 50 parallel updates for a new (student, course) pair and count how many rows exist.
Limits of this review
Not checked: the Flask and Werkzeug versions, how the app is launched and deployed (WSGI server, proxy, TLS), filesystem permissions and dependencies. These change the severity of F-01, F-03 and F-10.
The policy is inferred. P1–P5 should be confirmed against the actual requirements. In particular, I don’t know whether /files and /students/* are meant to be public.
Not exhaustive. A short list of findings doesn’t mean the code is safe. The fixes for F-02, F-04 and F-05 will add authorisation logic that depends on F-06 and F-10, so that new code needs its own review.