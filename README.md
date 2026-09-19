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

## v45 – UI performance, bulk scheduling, bulk user management, personal settings

### Performance
- The full-page re-render that used to run after every save or refresh was rebuilding around 35 sections regardless of which tab was open. The heaviest sections (Schichtkalender, Wochenplaner, Employee-Portal, Signups, Event-Cockpit, Reports) now only render while their tab is actually visible, cutting the work done on every action without changing what you see.

### Faster event scheduling
- The "Neue Schicht" form now accepts several dates at once, creating the same shift on every selected day in one submit.
- Every existing shift has a **Duplizieren** button to copy it onto additional dates without re-entering its details.

### Bulk user management
- The Konten view now has selection checkboxes, a "Alle auswählen" toggle and a bulk action bar for admins: Aktivieren, Deaktivieren, Rolle setzen and Löschen across multiple accounts at once.
- Individual accounts also gained direct Aktivieren/Deaktivieren and Löschen buttons (previously only editable via the API).
- All bulk actions are recorded in the audit log.

### Personal settings
- Each account can now choose a **Startansicht** (default view after login) under "Meine Benachrichtigungen" in Einstellungen — e.g. managers can land directly on Planung, employees on Meine Schichten. Leaving it on "Dashboard" keeps the previous behavior.

## v46 – Active/inactive people, list search, bulk shift assignment

### People active/inactive
- Person records now have an Aktiv/Inaktiv status, alongside the existing Aktiv/Inaktiv status on Konten.
- Toggle it per person in the Personen view (Aktivieren/Deaktivieren button, status badge, "Inaktive anzeigen" filter to hide them by default).
- Inactive people are automatically excluded from the Planner people palette and from staffing suggestions/automatic planning, so employees who left don't clutter new scheduling — their history and past assignments are untouched.

### List search
- Added search boxes to Events, Schichten, Schichtvorlagen and Konten (matching the existing Personen search), filtering by name, location, notes, linked event/leader or role.

### Bulk shift assignment
- The "Zuweisen" panel on each shift now shows a checklist of available people instead of a single dropdown. Check as many as needed and assign them all in one submit.
- Scheduling conflicts are collected and confirmed once for the whole batch, instead of one-by-one.

## v48 – Invite links

- Admins can now invite people by email instead of creating accounts by hand: **Konten → Per Link einladen**. Enter an email, role, and optionally link a person record — this creates a 7-day invite link, emails it automatically if SMTP is configured, and always shows a copyable link as a fallback.
- The invited person opens the link, is shown their email/role, and picks their own username, display name and password — no admin-set password involved. Accepting logs them straight in.
- Pending invites are listed with status (offen/angenommen/abgelaufen/zurückgezogen); admins can copy the link again or revoke a pending invite at any time.
- Invite tokens are signed and expire automatically; nothing is stored that lets a stale or revoked link be reused.

## v49 – Automatic person linking

- Accepting an invite that wasn't pre-linked to a person now automatically creates a matching Person record (using the name and email the invitee entered) and links the new account to it — no manual follow-up needed.
- Konten now shows a **Verknüpfen** control on any account missing a person link: pick an existing Person, or click "Neue Person erstellen & verknüpfen" to generate one from the account's display name in one step.
- New **"Unverknüpfte Konten automatisch mit Person verknüpfen"** button in Konten creates and links a Person for every currently-unlinked account in one pass — useful for catching up existing accounts created before this existed.

## v50 – Create person + account in one step

- Person and Konto are still two separate records under the hood (a Person can exist without ever logging in — e.g. someone scheduled but without app access — and a Konto can exist without a Person, like a pure admin account), but you no longer have to create them one after another by hand.
- The **Neue Person** form (Personen view, admin only) now has an optional "Gleichzeitig ein Benutzerkonto für diese Person anlegen" checkbox. Ticking it lets you pick a role and either:
  - send an invite link to the email entered above (same invite flow as before), or
  - set a username and password directly, right there.
- Submitting creates the Person and the linked Konto (or invite) together in one action — nothing left to link up afterward.

## v51 – Account status visible on every person

- The Personen list (admin only) now shows each person's account status directly: a linked Konto (name/username/role), a pending invitation, or "Kein Konto verknüpft".
- People without an account get an **Einladen** button right there — no need to go find them in Konten first. Requires an email address on the person.
- Pending invitations shown on a person can be copied, resent by email, or revoked directly from Personen, the same as from Konten.
- New **Erneut senden** action for any pending invite (Personen or Konten) re-sends the same link by email without creating a duplicate invitation.

## v52 – Simplified employee view

- Employees now land on **Meine Schichten** after login by default (instead of the manager-oriented Dashboard) — no setup needed, though the existing Startansicht setting can still override it.
- **Dashboard** and **Schichtkalender** are hidden from the employee sidebar entirely — both are manager-facing overviews across every person's shifts; Meine Schichten already gives employees the equivalent for their own schedule. Managers/admins are unaffected.
- Inside Meine Schichten, the secondary "App installieren" / "Kalender abonnieren" / ".ics herunterladen" controls are now tucked behind a collapsed "App & Kalender-Abo" toggle instead of sitting at the top of the page, so the next shift and open shifts are the first thing an employee sees. Nothing was removed — it's one tap away.
- Net effect: an employee's sidebar is now just Meine Schichten, Schichttausch, Benachrichtigungen and Einstellungen.

## v47 – Self-service account settings for every role

- The **Einstellungen** view is now reachable by every account, not just admins/managers — employees can now change their own password and edit their profile, which wasn't possible before (SMTP/SMS/reminder/planning-rule configuration stay admin/manager-only within that same view).
- New **Mein Profil** panel: any account can update its display name and, if linked to a person, its email and phone number (used for notifications and the calendar feed).
- Password change, notification preferences and the Startansicht (default view) picker were already self-service but were unreachable for employees before this release — they're now available to everyone from the same Einstellungen view.

## v53 – Event Builder, Archiv & Event-Dokumente

- Neue Event Library mit getrennten Ansichten für aktive und archivierte Events.
- Event Builder erstellt Event und beliebig viele generierte Schichten in einem Schritt.
- Schichtgenerator kann eine Schicht über einen Datumsbereich für mehrere Eventtage erzeugen.
- Event duplizieren kopiert optional Schichten/Qualifikationen, Event-Team, Zuweisungen und Dokumente; die Kopie startet immer als Entwurf.
- Archivieren erhält historische Schichten, Zuweisungen und Reports und kann rückgängig gemacht werden.
- PDFs/JPG/PNG/WebP bis 20 MB können einem Event zugeordnet werden; Dokumente können für Mitarbeitende sichtbar oder manager-intern sein.
- Event-Dateien liegen persistent im Upload-Verzeichnis und nicht im JSON/PostgreSQL-Zustand.
