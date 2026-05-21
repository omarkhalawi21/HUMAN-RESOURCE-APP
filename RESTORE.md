# Restoring from an automated backup

The nightly `.github/workflows/backup.yml` produces an encrypted gzipped SQL dump of the **public schema** for every day, attached to a dated GitHub Release tag named `backup-YYYY-MM-DDTHH-MM-SSZ`. The last 30 days are kept; older ones are pruned automatically.

This file is the **restore drill**. Walk it through end-to-end at least once *before* you ever need it in anger — on launch day the steps should feel familiar, not novel.

---

## What's in the backup (and what isn't)

### Included

- Every table in the `public` schema with all rows: `companies`, `employees`, `employee_extras`, `attendance`, `leave_requests`, `payroll`, `branches`, `warnings`, `advances`, `deductions`, `certificates`, `archive_documents` (full base64 file content), `receipts` (full base64 + OCR), `inventory_*`, `maintenance_requests`, `tasks`, `checklists`, `checklist_runs`, `daily_counts`, `weekly_counts`, `expiry_checks`, `bakery_*`, `personal_todo_lists`, `holidays`.
- All RLS policies + check constraints + triggers + functions in the `public` schema (same as re-running `supabase-rls.sql`).

### NOT included

- **`auth.users`** — Supabase Auth user accounts (emails, hashed passwords, OAuth identities) live in the `auth` schema, which the workflow deliberately skips. Restoring to a fresh Supabase project means those accounts don't exist yet. **Plan**: see "Restoring auth users" below.
- **`storage.objects`** — if/when you use Supabase Storage. Currently the HR app stores everything as base64 inside `public.*_documents` / `public.receipts.data_url`, so this isn't a concern today.
- **Pooled connection state** (which is ephemeral anyway).

If your worst-case scenario is "the whole project was wiped, I need to rebuild from zero", you'll restore `public` from this backup, then re-create the auth users (see below). For "I made a mistake in the last few hours and need to roll back one table", look at the **partial restore** section.

---

## Full restore — happy path

**You need**: `gpg`, `gunzip`, `psql` (any recent Postgres client, 14+ works), the `BACKUP_PASSPHRASE` you stored in your password manager, and a destination Supabase project (either a fresh one OR your existing one if you're willing to drop and recreate).

### Step 1 — Download the backup

Open the repo's **Releases** page on GitHub, find the release tagged `backup-<YYYY-MM-DDTHH-MM-SSZ>` for the day/minute you want. Download the single `.sql.gz.gpg` artifact.

Or via CLI:

```bash
gh release download backup-2026-05-21T03-00-00Z \
  --repo omarkhalawi21/HUMAN-RESOURCE-APP \
  --pattern "*.sql.gz.gpg"
```

### Step 2 — Decrypt

```bash
gpg --decrypt --output backup.sql.gz hassad-hr-backup-2026-05-21T03-00-00Z.sql.gz.gpg
# Enter the BACKUP_PASSPHRASE when prompted.
```

You should now have `backup.sql.gz` — about the same size as the encrypted file.

### Step 3 — Decompress

```bash
gunzip backup.sql.gz
# Produces backup.sql, a plain-text SQL file. Inspect with `less backup.sql` if curious.
```

### Step 4 — Prepare the destination Supabase project

⚠️ **Best practice: never restore directly onto prod first.** Create a side-project Supabase database, restore there, confirm the data looks right, *then* decide whether to swap your app's connection details or replay the data over prod.

Get the destination project's **direct** (port 5432, not pooled 6543) connection string from Supabase Dashboard → Project Settings → Database → Connection string → URI → "Direct connection".

### Step 5 — Apply the dump

The backup was created with `--clean --if-exists`, so it DROPs any existing tables/policies first, then recreates them with data. Safe to run against an empty database or an existing project (with data loss, obviously).

```bash
psql "postgresql://postgres.<dest-ref>:<dest-password>@aws-0-<region>.pooler.supabase.com:5432/postgres" \
  --single-transaction \
  --set ON_ERROR_STOP=on \
  --file backup.sql
```

`--single-transaction` ensures the whole restore succeeds or rolls back as one unit — no half-restored states.

### Step 6 — Re-run `supabase-rls.sql` if your dump is older than a recent block

If the backup pre-dates a SQL migration you've since applied (e.g., backup from May 15, you applied block 61 on May 20), copy-paste `supabase-rls.sql` from the repo's `main` branch into the destination's SQL editor and run it. The file is idempotent — re-running on the restored DB just makes sure the newest blocks are present.

### Step 7 — Smoke test

Point a copy of `index.html` at the destination project (temporarily edit the `SUPABASE_URL` constant near the top), open it, sign in as a known user, walk through Dashboard / Employees / Payroll / Attendance. Confirm counts and a handful of records match what you remember.

---

## Restoring auth users

Auth users are NOT in the backup (they live in Supabase's `auth` schema, which we deliberately don't dump because re-importing it would break internal Supabase plumbing on a fresh project).

After a full public-schema restore into a new project, employees can't sign in because their `auth.users` rows are missing. Options:

### Option A — Force-recreate via the password-reset flow (manual, easiest for small teams)

1. In Supabase Dashboard → Authentication → Users, manually invite each employee by email. Supabase sends them a "set your password" email.
2. The trigger `handle_new_user` (set up in `supabase-rls.sql`) creates the matching `employees` row on signup — but in our restore case the employees row already exists. The trigger handles this gracefully (it uses `ON CONFLICT`), so the new auth user simply gets linked to the existing employee record by matching email.
3. Sanity-check: after each employee resets their password, log in as them and confirm they see the expected dashboard.

For ~30 employees this is a half-day of clicking and a wave of "please reset your password" emails. Annoying but bounded.

### Option B — Programmatic via the Supabase Admin API (faster for larger teams)

Use a script that reads `public.employees.email` from the restored DB and calls `supabase.auth.admin.createUser({ email, email_confirm: true })` for each, then triggers `inviteUserByEmail` so they get a magic link to set a password.

I can write this script if you need it — say the word.

### Option C — Backup `auth.users` too

You can extend the workflow to dump `auth.users` + `auth.identities` and restore both. **Trade-off**: imports involve Supabase-internal columns that occasionally change; you'd want to test the restore drill after every Supabase platform update. Not worth it for a small team.

---

## Partial restore — "I broke one table"

If you only need to roll back one or two tables (e.g., someone bulk-deleted payroll for May), don't full-restore. Instead:

1. Decrypt + decompress as above to get `backup.sql`.
2. Extract just the table you need with `grep`/`awk` or any text editor — the SQL file is plain text, with sections clearly delimited by `-- Data for Name: <table>` headers.
3. Manually `DELETE FROM payroll WHERE period='2026-05';` then `\copy` or paste the relevant INSERTs into the SQL editor.

This is more surgical and avoids stomping on data added since the backup.

---

## Pre-launch drill checklist

Before going live, do this end-to-end **once** so the procedure is muscle memory:

- [ ] Create a throwaway Supabase project ("hassad-hr-restore-drill" or similar)
- [ ] Verify GitHub Actions has run at least one backup successfully (check the Actions tab + Releases page)
- [ ] Download yesterday's backup artifact
- [ ] Decrypt with the passphrase (confirms the passphrase in your password manager is correct)
- [ ] Decompress, inspect the first 100 lines of the SQL to confirm it looks like a real dump
- [ ] Restore into the drill project via `psql --single-transaction`
- [ ] Point a local copy of `index.html` at the drill project, sign in, confirm data is intact
- [ ] Delete the drill project to avoid surprise billing

If any step fails, fix it now — not at 2 AM after a real incident.

---

## Where to file issues

- Workflow failing in GitHub Actions → check the Actions tab for the run log; common issues are listed in the workflow file's header.
- Decryption failing → wrong passphrase. The `BACKUP_PASSPHRASE` in GitHub Secrets is the source of truth.
- Restore failing partway → run with `--echo-errors` and `--no-single-transaction` to see exactly which statement broke; usually a Supabase platform schema change since the dump was taken.
