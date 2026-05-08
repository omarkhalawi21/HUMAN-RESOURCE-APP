# Hassad HR — User Guide

Practical reference for the HR person running the app day-to-day. If you've never used it before, read once start to finish; after that use the table of contents to jump to what you need.

**Live URL**: https://omarkhalawi21.github.io/HUMAN-RESOURCE-APP/

---

## Table of contents

1. [Signing in](#signing-in)
2. [First-time setup (admin)](#first-time-setup-admin)
3. [Adding an employee](#adding-an-employee)
4. [Daily attendance](#daily-attendance)
5. [Leave requests](#leave-requests)
6. [Issuing a warning](#issuing-a-warning)
7. [Salary advances](#salary-advances)
8. [Running monthly payroll](#running-monthly-payroll)
9. [Renewing IQAMA / Baladiya](#renewing-iqama--baladiya)
10. [Issuing certificates](#issuing-certificates)
11. [Generating reports for evidence](#generating-reports-for-evidence)
12. [Backup & data export](#backup--data-export)
13. [Common problems & fixes](#common-problems--fixes)

---

## Signing in

- Open the live URL in any modern browser (Chrome, Safari, Firefox)
- Enter your work email + password and click **Login**
- Forgot your password? Click **Forgot your password?** under the form, type your email, and a reset link is emailed to you

The first time you sign in on a new device, allow **pop-ups** for the site — every printable document opens in a pop-up window. (Safari: top menu → Safari → Settings for omarkhalawi21.github.io → Pop-up Windows → Allow.)

---

## First-time setup (admin)

Run through this once, before anyone else uses the app.

1. **Settings → Company panel** — fill in:
   - Legal entity name (appears on every printed document, e.g. "Hassad Al-Khobar Trading Company")
   - Commercial registration number
   - Address lines 1–3
   - Work day start/end times (drives "late" detection)
   - Currency (SAR for Saudi)
   - Check "Capture location on clock-in" if you want geofencing

2. **Upload the company stamp** — Settings → scroll to the stamp section → upload a transparent PNG/JPG of your official stamp. It will appear at the bottom-right of every printed HR document.

3. **Add your branches** — Settings → Branches panel → "Add branch":
   - Name (e.g. KHOBAR, RAYYAN, FAISALIYAH)
   - Address
   - Latitude/Longitude — easiest way: stand at the branch and click "Use my current location", or look up the coordinates on Google Maps
   - Radius — 100–200m is usually right; bigger if employees clock in from a parking lot
   - Toggle **Active**

4. **Promote a second admin** — Settings → Users & accounts panel → find another HR person → click "make admin". You don't want a single point of failure.

---

## Adding an employee

1. **Employees** in the sidebar → **+ Add employee** (top-right)
2. **Basic info tab**: First name, Last name, Email, Phone, Nationality, Role (job title), Department, Branch, Joining date, Monthly salary, Status (Active)
3. **Shift & Off-days tab**: each day of the week has its own start/end time and an "Off-day" checkbox. Quick buttons:
   - **Set Fri+Sat off** — standard Saudi weekend
   - **Set Fri off only** — half-Saturday work
   - **Copy Mon's hours to all working days** — quickest setup
4. **IQAMA & Baladiya tab**: enter both numbers and expiry dates if you have them. The system warns you 30 days before either expires.
5. Click **Save**.

The employee then needs to **sign up** at the live URL using the same email — they'll get a link to create their own password. They cannot clock in until they've done this.

---

## Daily attendance

**For employees** (each person on their own phone/computer):
- Open the live URL → log in → the dashboard shows a big **Clock In** button
- Tap it. If geofencing is on, the browser asks for location permission once.
- At end of shift, tap **Clock Out**

**For admins** to see what's happening:
- **Dashboard** — today's attendance snapshot (who's in, who's out, who's on leave) with a date and branch filter
- **Attendance → All Employees Today** tab — same info, table form
- **Attendance → All History** tab — date-range filter; you can also export to CSV here

If someone forgets to clock out, you can edit their record manually (admin only).

---

## Leave requests

**Employees** request:
1. Leave page → **Request Leave**
2. Pick type (Annual, Sick, Personal), start + end dates, reason
3. Submit → it shows up in Pending

**Admin** decides:
1. Leave page → Pending Approvals tab
2. **Approve** or **Reject** for each request
3. Approved leave automatically deducts from the employee's balance and shows them as "On leave" on attendance for those dates

---

## Issuing a warning

1. **Warnings** in the sidebar → **+ Issue warning**
2. Pick the employee, severity (Verbal / Written / **Final Written**), type (e.g. "Lateness", "Insubordination"), date of incident
3. Write the reason (what happened) and management comments (what corrective action is expected)
4. Click Save → confirm "Open the warning letter for printing?" → the official letter pops up

**Print or save as PDF** from the popup. The letter has the company letterhead, employee details (including IQAMA from their profile), description of the violation, action taken, and signature lines for employee and manager.

Hand the printed letter to the employee, get them to sign, scan it, and upload the scan to **Archive** for the file.

---

## Salary advances

**Employee requests**:
- Salary Advances page → Request Advance → enter amount, reason, and pick repayment plan (deduct from next payroll, spread over 2 months, or manual)

**Admin decides**:
- Salary Advances → Pending tab → Approve or Reject
- Approved advances are **automatically deducted** when you next run payroll (the run-payroll modal shows the deduction in the live preview before you confirm)

To **print the slip** for record-keeping: click the printer icon next to any advance row.

---

## Running monthly payroll

1. **Payroll** page → click **Run Payroll** (admin only)
2. The modal opens with the current month pre-selected. **Live preview** shows:
   - Number of employees being paid
   - Total base salary
   - Total advance deductions (if any)
   - Total net to pay
   - How many advances will be marked repaid
3. If a payroll for that period already exists, you get a clear amber warning before running again
4. Click **Run payroll** → payslips are generated for every active employee

After running:
- **Open Report** generates the multi-employee Payroll Report with department breakdown
- Click any individual payslip's download icon to print just that one

**Workflow with your bank (WPS)**:
1. Run payroll in the app
2. Click **Export CSV** to get the per-employee net amounts
3. Upload the CSV to your bank's WPS portal to actually transfer the money
4. Once the bank confirms, the payroll status in the app stays "Paid" — done

---

## Renewing IQAMA / Baladiya

When **Documents** in the sidebar shows an amber badge, someone's documents are expiring within 30 days.

1. **Documents** page → find the employee → click **Renew**
2. The modal pre-fills the new expiry dates: **+3 months for IQAMA**, **+1 year for Baladiya** from today (Saudi standard)
3. Adjust if needed → Save
4. The previous expiry date is shown below each new field for reference

---

## Issuing certificates

1. **Certificates** in the sidebar
2. Pick a type:
   - **Employee of the Month** (one per month)
   - **Certificate of Appreciation** (general recognition)
   - **Certificate of Completion** (training, projects)
   - **Custom** (your own title and message)
3. Pick the recipient, edit the title and message
4. Save → click "Open the certificate now?" to download as PDF

The Employee of the Month certificate also shows on the Certificates page hero and on the recipient's dashboard.

---

## Generating reports for evidence

The **attendance evidence** report is the official document you'd give to GOSI, the Ministry, a court, or anyone asking "did this employee actually show up to work":

1. **Attendance** → **All History** tab
2. Filter by date range, employee, branch, status as needed
3. Click **Print as evidence**
4. Print or save as PDF — has the letterhead, filter summary, statistics, full record table, signature lines

For payroll evidence, use **Payroll → Open Report** for the period in question.

---

## Backup & data export

The data lives in Supabase (cloud), but you should still keep a local backup.

**Weekly recommended**:
1. Settings → scroll to bottom → **Download backup**
2. The download is a JSON file with all employees, attendance, leave, payroll, warnings, advances, certificates, and document tracking
3. Store it somewhere safe — encrypted USB, password-manager attachment, locked Google Drive folder
4. **Don't email it** — it contains everyone's personal data including salaries

**Per-screen exports**:
- Employees → Export CSV
- Attendance → All History → Export CSV
- Payroll → CSV
- Reports → Export

---

## Common problems & fixes

**Employee can't log in**
- They probably haven't signed up yet. Send them the live URL — they need to use the same email you entered when creating their record, then click "Create one" under the login form.

**Clock-in fails with "outside branch radius"**
- Either the branch coordinates are wrong (Settings → Branches → Edit → "Use my current location" while at the branch), or the radius is too small (try 200m).

**Print preview comes up blank**
- Pop-ups are blocked. Safari: top menu → Safari → Settings for this site → Pop-up Windows → Allow. Then try again.

**Modal won't close after save**
- The save errored — look for a red toast at the top right. Most common: the employee's email is already in use by another record.

**"Storage full" toast**
- Browser localStorage is full. Won't break anything (we save to Supabase), just means the photo/stamp upload didn't cache. Try a smaller image.

**Lost admin access**
- If your account is locked out, ask any other admin to demote and re-promote you, or use **Forgot password**. If no other admin exists, you'll need to manually flip `is_admin` to `true` in the Supabase dashboard's Table Editor on the employees table.

---

## Who to contact

For app bugs or feature requests: open an issue at https://github.com/omarkhalawi21/HUMAN-RESOURCE-APP/issues

For Saudi labor law / payroll compliance questions: your accountant or labor lawyer, not this app.
