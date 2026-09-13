# Höckeler Event Planung v25 – Multi-User Foundation

This version upgrades the existing planner into a multi-user application while keeping the current event, person, template, shift, assignment, graphical planning, CSV, Excel, backup and PDF workflows.

## Added in v25

- Login/accounts with signed 12-hour sessions.
- Roles: **Admin**, **Event Manager**, **Employee**.
- PostgreSQL persistence through `DATABASE_URL`; local JSON remains only as a development fallback when PostgreSQL is not configured.
- Employee availability: available, preferred and unavailable days/times.
- Week/calendar planning view.
- Automatic overlap, availability and daily work-hour warnings when assigning a person.
- Daily work-hour calculation based on assigned shift duration and each person's configured maximum.
- Shift swap requests with manager/admin approval or rejection.
- In-app notifications for new shift assignments and swap requests.
- Existing Excel export plus CSV and printable/PDF graphical planning export.
- Mobile responsive employee view showing only the employee's assigned shifts.
- Existing Schichtleiter functionality is preserved in shifts, templates, planning overview and PDF output.

## Quick start with PostgreSQL

The easiest test setup is Docker Compose:

```bash
docker compose up --build
```

Open `http://localhost:8080`.

Initial login defaults to:

- Username: `admin`
- Password: `ChangeMe123!`

Change `AUTH_SECRET`, database password and bootstrap password before production use.

## Run without Docker

Install Python 3.11+ and:

```bash
pip install -r requirements.txt
export DATABASE_URL='postgresql://user:password@server:5432/hoeckeler'
export AUTH_SECRET='a-long-random-secret'
python server.py
```

If `DATABASE_URL` is not set or PostgreSQL is unavailable, the app uses `data.json` as a development fallback so the existing standalone workflow still starts.

## Role behavior

**Admin** can manage everything, including accounts and backups. **Event Manager** can manage events, people, templates, shifts, assignments, availability, planning and swaps. **Employee** gets a simplified experience for their own availability, assigned shifts, swap requests and notifications.

## Production notes

v25 is the multi-user foundation. For Internet-facing production deployment, put it behind HTTPS/reverse proxy, change all default secrets, back up PostgreSQL, and restrict database/network access. For larger deployments, the next architectural step is normalizing the current PostgreSQL state document into relational tables and adding an external mail/push delivery provider for notifications.

## v26 login fix

The public frontend (`/`, `/index.html`, CSS, JavaScript and images) is now served before authentication checks. Protected `/api/...` endpoints still require login. This fixes the browser showing `{"error": "login required"}` instead of the login form.

## v27 – Drag & Drop Schichtplan

- Planung now contains a shift-centric board.
- People are draggable modules and can be dropped directly onto existing shifts.
- Multiple shifts for the same event/date are shown as separate drop targets.
- Assigned people are visible directly inside each shift and can be removed with ×.
- Existing schedule-conflict, availability and daily-work-hour checks still run on every drop.
- The existing template → person drag/drop planner remains available.

## v28 – Separate Schichtkalender

- The graphical shift overview moved out of Planung into its own **Schichtkalender** menu.
- Planung stays focused on drag & drop assignments.
- Calendar presentation is now day-by-day: the day is fixed on the left and all shifts run horizontally from left to right.
- Shift cards show time, event, Schichtleiter, coverage and assigned people.
- Event, day and person filters are available directly in Schichtkalender.
- The graphical PDF export moved with the calendar and exports the new calendar layout.

## v29 – Dashboard redesign

- Removed the logo from the top header.
- Centered the welcome banner on the dashboard.
- Replaced the old dashboard shift list with a compact **Schichtkalender** preview.
- Dashboard calendar shows upcoming days as rows and shifts horizontally from left to right.
- Shift cards show time, staffing coverage and Schichtleiter.
- Clicking a dashboard calendar shift opens the full Schichtkalender.

## v30 – Availability, Week Planner & Smart Warnings

- Employee availability/absence management with available, preferred, unavailable, vacation and sick statuses.
- Optional time windows for availability.
- New week planner showing people as rows and Monday–Sunday as columns.
- Weekly planned hours per employee.
- Smarter warnings for understaffed shifts, missing Schichtleiter, unavailability, overlaps and daily-hour limits.
- Availability state is reused directly in planning logic.

## v31 – Employee Portal, Publishing & Shift Swaps

- New mobile-oriented employee portal under **Meine Schichten**.
- Employees see only shifts belonging to published events.
- Event managers/admins can keep events as **Entwurf** and publish them when the plan is ready.
- Employees can submit shift swap requests from their own shift list.
- Swap requests are tracked with pending/status state.
- Employee view focuses on the next shift, upcoming shifts and swap requests.
- Manager navigation remains separated from the employee experience.

## v32 – Operational workflow
- Cleaned duplicate legacy views.
- Manager swap approval now validates a replacement and basic conflicts.
- Notification badge and mark-all-read.
- Dashboard planning warnings.
- Employee self-service availability with vacation/sick states.

## v33 – Planning intelligence
- ICS calendar export for published employee shifts.
- Staffing suggestions ranked by availability, conflicts/rest and current workload.
- Workload/fairness dashboard.
- Configurable minimum rest-time rule with server-side assignment and swap checks.

## v34 – Production hardening
- Audit log for important planning/account actions.
- User self-service password change.
- New passwords use PBKDF2-SHA256 with 600,000 iterations; existing hashes remain compatible.
- Login throttling after repeated failed attempts.
- Optional Secure session cookies.
- PostgreSQL can fail closed instead of silently switching to JSON.
- Fixed Docker volume name `hoeckeler_event_planner_postgres` prevents a new empty database volume when the release folder changes.
- Security response headers and schema versioning.
- Excel export column alignment fixed after removal of the old Person role field.

For HTTPS production deployment, use a TLS reverse proxy and set `COOKIE_SECURE=true`.

## v35 – Employee self-assignment

- Employees can now add themselves to open shifts directly from **Meine Schichten**.
- Only shifts belonging to published events are offered.
- Only future shifts with remaining capacity are shown.
- Self-assignment checks:
  - existing assignment
  - shift capacity
  - unavailable/vacation/sick status
  - availability time windows
  - shift overlaps
  - configured minimum rest time
  - maximum daily work hours
- Conflicting shifts are blocked in the employee portal.
- Successful self-assignment creates a normal assignment and notifies admins/event managers.
- The action is recorded in the audit log.

## v36 – Self-service workflow
- Per-event self-signup mode: disabled, direct, or manager approval.
- Optional event employee pools restrict which employees can see/sign up for an event.
- Employees can confirm assigned shifts.
- Full shifts allow employees to join a waiting list.
- Managers can approve signup requests and promote people from waiting lists.
- Notifications and audit records are created for the new workflows.

## v37 – Skills & automatic planning
- Skills/qualifications master list.
- Assign qualifications to employees and requirements to shifts.
- Employee self-signup is blocked when required qualifications are missing.
- Staffing suggestions now consider event-team membership and skills.
- Automatic planning proposal fills open positions using current availability, rest-time and workload rules.
- Automatic planning is preview-only until a manager explicitly applies the proposal.

## v38 – Event operations & reports
- Event Cockpit with staffing, confirmations, event-team size and open planning issues.
- Shift instructions: meeting point, clothing, contact and detailed tasks/instructions.
- Employees see these instructions with their shifts.
- Manager-entered effective/actual hours per assignment.
- Planned-vs-actual hours report by employee and event.
- Confirmation statistics and CSV report export.
- No employee check-in/check-out functionality is included.

## v39 – Email notifications
- Generic SMTP configuration, STARTTLS, test email.
- Internal notifications automatically create email delivery attempts for linked employees with email addresses.
- Admin delivery counters and recent failures.
- Email failures do not block scheduling operations.

## v40 – Event cloning
- Clone an existing event to a new name/start date.
- Shift dates move by the same date offset.
- Shift skill requirements and instructions are retained.
- Event team can be copied optionally.
- Existing assignments are opt-in and disabled by default.
- Availability, confirmations, swaps and waiting lists are never copied.
- New cloned event starts as Draft.

## v41 – Installable PWA / mobile
- Web App Manifest and standalone display mode.
- Service worker caches only the application shell; API data remains network-backed.
- Install button appears when the browser supports PWA installation.
- Offline banner and centralized blocking of offline write operations.
- When connectivity returns the app refreshes state from the server.
- No offline self-signup, swap, availability or assignment writes are queued, avoiding synchronization conflicts.

### PWA note
For installation outside localhost, serve the application over HTTPS. Browsers generally require a secure context for service workers/PWA installation.

## v42 – PWA install status / always-visible install button

- The **App installieren** button is now always visible in the employee portal.
- The UI shows the current installability state:
  - ready to install
  - already installed
  - HTTPS required
  - browser-specific manual installation instructions
  - service-worker registration failure
- If the native browser installation prompt is available, the button opens it.
- On iPhone/iPad, the button explains the Safari **Share → Add to Home Screen** flow.
- On Android/desktop browsers without a native prompt, the button points users to the browser installation menu.
- The app still requires HTTPS for normal PWA installation outside localhost.

## v43 – Complete calendar, notification preferences & password reset

### Calendar export
The employee `.ics` export now includes the complete published shift information:
- event and shift name
- start/end
- event location
- shift leader
- current staffing level
- employee confirmation status
- required qualifications
- meeting point
- clothing
- contact
- detailed instructions/tasks
- shift notes and event notes

### Employee notification preferences
Each user can independently enable or disable:
- email notifications
- SMS notifications

The corresponding email address / mobile number is taken from the linked employee/person profile.

### SMS
Administrators can configure a generic HTTPS SMS webhook. The application sends JSON:
`{"to":"...","message":"...","sender":"..."}`

An optional Bearer token is supported. This keeps the planner provider-independent.

### Password reset
Employees can now use **Passwort vergessen?** directly on the login page:
1. enter username
2. receive a six-digit reset code through configured email/SMS delivery
3. enter the code and choose a new password

Codes expire after 15 minutes and are single-use. Logged-in users can still change their password normally using the existing current-password form.

## v44 – Employee & Notification Experience

### Live calendar subscription
Each employee has a private, random calendar feed URL. The URL can be added once to Outlook, Apple Calendar or another calendar application that supports subscribed ICS feeds. The feed always contains the current published assignments and all detailed shift information. Employees can regenerate the token to invalidate an old link.

### Re-confirmation after important changes
Changing a shift's name, leader, date, time, meeting point, clothing, instructions or contact invalidates existing confirmations for that shift and notifies assigned employees. Changing an event location does the same for every assigned shift in that event.

### Automatic reminders
A daemon reminder worker checks hourly. By default:
- shift reminders: 7 and 1 day before
- availability deadline reminders: 3 and 1 day before
- unconfirmed shift reminders explicitly tell the employee that confirmation is still required

Managers can change the reminder-day lists, enable/disable automatic reminders, or run the reminder check immediately. A reminder log prevents duplicate reminders for the same threshold.

### Availability deadlines
Events can have an availability deadline and can lock availability. Event cards show responses versus expected employees and include a **Fehlende erinnern** action. Employees see relevant deadlines in their mobile portal.

### Mobile employee home
The next shift card now prominently shows location, leader, meeting point, clothing, instructions, contact and confirmation status, with a direct confirmation button.

### Security
Calendar subscription URLs are bearer secrets. Anyone who has the URL can read that employee's published shift calendar. Employees can regenerate the token at any time.

## v45 – Production & GitHub Pages deployment

v45 prepares the application for a real production system plus an isolated GitHub Pages test frontend.

### Deployment architecture
- **Production:** Caddy HTTPS → Python application → dedicated production PostgreSQL.
- **Test frontend:** GitHub Pages from the `develop` branch.
- **Test API:** Caddy HTTPS → separate test application → separate test PostgreSQL.
- The combined `docker-compose.server.yml` runs both backend environments with one Caddy reverse proxy.

### GitHub Pages
The frontend now supports `window.HOECKELER_CONFIG.API_BASE_URL`, so the same UI can call a separate test API. All static asset, manifest and service-worker paths are repository-subdirectory safe.

`develop` deploys the static test frontend automatically through `.github/workflows/deploy-pages.yml`.
`main` remains the production branch. Production deployment is deliberately manual through the GitHub Actions workflow.

### Security hardening
- exact-origin credentialed CORS
- CSRF token validation for authenticated write requests
- secure/cross-site cookie modes
- production startup refuses known unsafe defaults
- password-reset request throttling
- SMTP password and SMS bearer token are no longer returned in `/api/state`
- expanded security headers
- test notification redirection prevents messages from reaching real employee addresses/numbers

### Test-system safety
`TEST_MODE=true`:
- prefixes email subjects with `[TEST]`
- requires `TEST_EMAIL_REDIRECT`
- requires `TEST_SMS_REDIRECT`
- displays a prominent **TESTSYSTEM** banner in the frontend

### Operations
Included:
- production/test/combined Docker Compose files
- Caddy configurations
- environment templates
- PostgreSQL backup script
- CI validation workflow
- GitHub Pages deployment workflow
- manual production deployment workflow
- detailed `DEPLOYMENT.md`

### Important
For the cleanest browser authentication behavior, use a custom GitHub Pages domain such as `test-planung.example.ch` together with `test-api.example.ch`.

## v46 – event.hoeckeler.ch

This build is preconfigured for:

- `https://event.hoeckeler.ch` — GitHub Pages frontend
- `https://api.event.hoeckeler.ch` — Python/PostgreSQL backend

Push `main` to deploy the frontend. See `EVENT-HOECKELER-DEPLOYMENT.md` for DNS, HTTPS, Docker and firewall steps.
