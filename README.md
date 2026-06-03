# Hassad

Single-file operations web app for Hassad Coffee Roasters. Attendance, leave, payroll, warnings, advances, certificates, inventory counts, bakery transfers, checklists, maintenance, receipts/OCR, resources (SOPs & training), IQAMA/Baladiya tracking, and printable company documents.

## Features

- **Attendance** — daily clock-in / clock-out with automatic late detection, optional GPS geofencing per branch
- **Employee directory** — add, edit, search, filter by department or branch
- **Leave requests** — submit, manager approves/rejects, balance tracking
- **Payroll** — monthly run with live preview, automatic advance deduction, printable payslip + payroll report
- **Warnings** — issue verbal/written/final warnings, printable letter on official letterhead
- **Salary advances** — request, approve, repaid in next payroll or installments
- **Certificates** — Employee of the Month, Appreciation, Completion, Custom
- **Documents** — IQAMA + Baladiya number/expiry tracking, auto-renewal periods, expiry alerts
- **Archive** — upload company-wide PDFs, Word docs, images
- **Reports** — date-ranged attendance, leave, and payroll summaries
- **Bilingual** — English and العربية with full RTL
- **Printable templates** — every official document uses the Hassad letterhead

## How it runs

Static HTML file deployed to GitHub Pages. Backend is Supabase (Auth + Postgres) for core tables (employees, attendance, leave, payroll, branches, warnings, advances, certificates, archive, employee extras, company stamp).

**Live**: https://app.hasadco.sa/ (custom domain via Souq T2 → GitHub Pages, HTTPS via Let's Encrypt). Legacy URL `https://omarkhalawi21.github.io/HUMAN-RESOURCE-APP/` still serves the same content during the cutover window.

**Local development**: open `index.html` in any modern browser. Connects to the same Supabase project.

## First-time setup (new deployment)

If you're standing this up on a fresh Supabase project:

1. **Apply the schema + RLS**: Supabase dashboard → SQL Editor → New query → paste `supabase-rls.sql` → Run. The script is idempotent.
2. **Sign up** at the deployed URL — the **first user to sign up automatically becomes admin** (handled by a server-side trigger). Subsequent signups are regular employees.
3. From the admin account, go to **Settings** to fill in company info, work hours, currency, and upload the company stamp.
4. Either pre-add each employee from **Employees → Add Employee**, or have them self-register with the live URL. The signup form collects name, email, phone, position, and branch — admin then fills in salary/schedule from the directory.

## Security

The Supabase publishable key in `index.html` is safe to ship **only because Row Level Security is enforced on every table**. Without RLS, any logged-in employee could self-promote to admin or wipe data via browser DevTools.

`supabase-rls.sql` is the source of truth — re-run it any time you change schema. The policies cover: admin-only mutations on employees/payroll/branches/warnings/certificates/archive, self-only inserts on attendance and leave requests, and a database trigger that prevents anyone from changing their own admin status.

## Backups

`.github/workflows/backup.yml` takes a nightly AES-256-encrypted dump of the `public` schema and attaches it as a GitHub Release artifact. Last 30 days retained automatically. **Two repo secrets required** — `SUPABASE_DB_URL` (direct connection, port 5432) and `BACKUP_PASSPHRASE` — see the workflow file's header for setup. Restore procedure documented in [RESTORE.md](RESTORE.md) — walk through it once before launch.

## Launching

For a fresh deployment, the engineering side (above) is necessary but not sufficient — there's also a one-time data-entry pass to seed branches, holidays, count items, employees, SOPs, etc. The full pre-launch checklist (with the order of operations) is in [LAUNCH_CHECKLIST.md](LAUNCH_CHECKLIST.md). Print it, tick boxes as you go.

## Tech

- Plain HTML + CSS + vanilla JavaScript, single file
- **Tailwind self-hosted** — pre-built `tailwind.css` committed to the repo, no CDN dependency
- Supabase JS SDK pinned to v2.45.4 with SRI integrity check
- CSP meta tag restricting external resources to declared CDNs

## Building Tailwind CSS

The compiled `tailwind.css` is committed and served as-is by GitHub Pages — you don't need to build to deploy. Only rebuild when you add new utility classes to `index.html` that aren't already in the CSS.

One-time setup (per machine):
```bash
npm install
```

Rebuild after adding new Tailwind classes:
```bash
npm run build
```

This regenerates `tailwind.css` from `tailwind.input.css` + `tailwind.config.js`, scanning `index.html` and `HR_USER_GUIDE.md` for class names. Commit the updated `tailwind.css` along with your code change.

For live development:
```bash
npm run watch
```
…leaves the compiler running and rebuilds on save.

## Roadmap

- Real-time updates via Supabase subscriptions
- Webcam selfie verification on clock-in
- Calendar export for leave (.ics)
- Payslip PDF generation (in-app, no popup)
- Email notifications on leave / warning issuance
- Mobile app

## License

MIT — do whatever you'd like with it.
