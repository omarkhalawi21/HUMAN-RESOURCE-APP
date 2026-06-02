# Hassad — Launch checklist

Everything HR / Operations / Admin needs to do **before flipping the app to live use**, in roughly the order it should happen. Tick boxes as you go.

This complements the existing docs:
- [`README.md`](README.md) — how the app is built and deployed
- [`HR_USER_GUIDE.md`](HR_USER_GUIDE.md) — day-to-day usage reference
- [`RESTORE.md`](RESTORE.md) — disaster-recovery procedure
- [`PRIVACY_NOTICE.md`](PRIVACY_NOTICE.md) and [`CONSENT_FORM.md`](CONSENT_FORM.md) — PDPL paperwork templates

> ⚠️ **This checklist is a one-time thing.** After launch, day-to-day data entry happens organically through the app's normal flows. This doc just captures what must exist on day 1.

---

## 1. Infrastructure pre-flight (✅ already shipped — verify only)

The engineering side is done. Spot-check before launch:

- [ ] **Latest app deployed** — `main` branch is what `omarkhalawi21.github.io/HUMAN-RESOURCE-APP/` serves (GitHub Pages auto-deploys on every merge to `main`). Open the URL, hard-refresh (Cmd+Shift+R), confirm you see the current build.
- [ ] **SQL migrations are live on prod Supabase** — blocks 49–60 applied & verified. Run this diagnostic in the prod project's SQL editor; expect all 5 `true`:
  ```sql
  SELECT
    EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='personal_todo_lists') AS block_59_ok,
    EXISTS (SELECT 1 FROM pg_constraint WHERE conname='leave_requests_leave_type_chk') AS block_60_check_ok,
    EXISTS (SELECT 1 FROM pg_policies WHERE policyname='archive_select_role_scoped') AS block_60_archive_ok,
    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='branches' AND column_name='is_head_office') AS block_58_ok,
    EXISTS (SELECT 1 FROM pg_constraint WHERE conname='employees_system_role_chk' AND pg_get_constraintdef(oid) LIKE '%marketing%') AS marketing_role_ok;
  ```
- [ ] **Nightly backup workflow has run at least once successfully** — Repo → Actions → "Nightly DB backup" should show a green run from the last 24 hours. Releases page should have a `backup-<timestamp>` artifact.
- [ ] **Both GitHub Secrets are present** — Repo → Settings → Secrets and variables → Actions: `SUPABASE_DB_URL` and `BACKUP_PASSPHRASE` should both be listed (you'll never see the values again, just confirm the names).
- [ ] **Apple Passwords (or your password manager) has both:** the Supabase prod DB password, AND the `BACKUP_PASSPHRASE`. Losing either is recoverable only by full reset.

---

## 2. Company-level settings (admin, ~10 min)

Sign in as admin → **Settings**:

- [ ] **Company name** — `Hassad Coffee Roasters` (or your legal trading name; appears on every printed payslip / warning / certificate)
- [ ] **Legal name + registration number** — `Hassad Al-Khobar Trading Company` / `7037495061` (or current). These print on official documents.
- [ ] **Address lines 1–3** — KSA / Eastern Province / Khobar 33425 (or current registered address). Used in the letterhead.
- [ ] **Currency** — `SAR`
- [ ] **Work start / Work end** — defaults for the schedule when a new employee is added (you can override per employee later). E.g., `09:00` / `17:00`.
- [ ] **Require location on clock-in** — should be **on**. Without it, geofencing is disabled.
- [ ] **Upload company stamp** — PNG with transparency ideally. Appears on every printed payslip / warning / certificate.
- [ ] **Language** — pick the company default (`English` or `العربية`). Individual users can still toggle per session.

---

## 3. Branches with GPS geofencing (admin, ~15 min)

Settings → **Branches** → **Add branch** for each of:

For **each** branch:
- [ ] **Name** — `KHOBAR`, `RAYYAN`, `FAISALIYAH`, `HEADOFFICE` (uppercase by convention — matches `SUGGESTED_BRANCHES`)
- [ ] **Address** — street / district / city (optional but useful for the printed reports)
- [ ] **Latitude / Longitude** — easiest path: physically stand inside the branch and click **"Use my current location"** on your phone. Otherwise paste from Google Maps (right-click on the location → coordinates appear → copy).
- [ ] **Radius** — `150 m` is the default and fits most. Use `50 m` for a single small shop, `300 m` for a block-sized building, `500 m` for a multi-building campus.
- [ ] **Active** — yes.
- [ ] **Head office checkbox** — tick ONLY for `HEADOFFICE`. This restricts clock-in there to admin/operations/accounting/marketing roles only.

After all four are added: open the app on your phone, walk to each branch, try to clock in. Should succeed at the right branch, fail with *"You are XXm from BRANCH"* at the others.

---

## 4. KSA holidays for the year (admin, ~5 min)

Sidebar → **Holidays** → **Add holiday** for each:

- [ ] All 2026 KSA public holidays (Eid al-Fitr, Eid al-Adha, Saudi National Day, Founding Day, etc.) — at minimum the ones falling in the current and next 3 months. Without these, the payroll **holiday overtime calculation (1.5×)** won't trigger.
- [ ] Add new holidays as they're announced; they affect any payroll run that includes the holiday's month.

---

## 5. Inventory & ops catalogs (admin, ~30 min)

The count features (daily, weekly, expiry) and bakery need their item lists seeded before floor staff can use them.

### 5a. Daily count items
Sidebar → **Daily Count** → top-right gear / settings → **Add item** for each. These are typically:
- [ ] Cash drawer items (opening float, closing float)
- [ ] High-turnover ingredients (milk, beans, syrups)
- [ ] Anything baristas should count per shift

Each item gets: name, unit (e.g. "ml", "kg", "ea"), category, whether it tracks waste, and a sort order.

### 5b. Weekly count items
Sidebar → **Weekly Count** → settings → **Add item** for each. Typically:
- [ ] Cups, lids, sleeves, napkins (consumables you buy weekly)
- [ ] Each gets: name, unit, category, sort order.

### 5c. Expiry-check items
Sidebar → **Expiry Check** → settings → **Add item** for each:
- [ ] Dairy (whole, oat, almond, etc.)
- [ ] Anything else with a "use by" date that needs weekly inspection

### 5d. Bakery (if you run a central bakery)
- [ ] **Bakery products** (finished goods: cookies, brownies, cakes…) — Bakery → Transfers → settings → Add product
- [ ] **Bakery ingredients** (flour, sugar, eggs…) — Bakery → Stock → settings → Add ingredient

### 5e. Suppliers
Sidebar → **Suppliers** → **Add supplier** for the vendors you actually use. Not blocking for launch, but nice to have for the receipt and inventory workflows.

### 5f. Inventory items
Sidebar → **Inventory** → **Add item** for the SKUs you stock. Also not blocking — can grow organically.

---

## 6. People (HR, ~half a day with one admin)

The bulk of the data-entry work. For each employee:

- [ ] **Email** — must be unique and real (used for login + password reset). If an employee doesn't have email, give them a `firstname.lastname@hassadcoffee.com`-style alias and forward to their phone.
- [ ] **First + last name** — appears everywhere.
- [ ] **Phone** — optional but useful for HR contact.
- [ ] **Nationality** — for IQAMA tracking.
- [ ] **Job title** — free-text (e.g. "Senior Barista", "Roastery Manager"). Different from system role.
- [ ] **System role** — admin/hr/operations/accounting/marketing/head_barista/roaster/barista/maintenance/bakery/employee. This drives permissions and dashboard visibility. **Choose carefully** — admin is the only role that can change other people's roles, and only ~2-3 people should be admin.
- [ ] **Department** — for grouping in reports (e.g. "Barista", "Roastery", "Operations").
- [ ] **Branch** — KHOBAR / RAYYAN / FAISALIYAH / HEADOFFICE. Critical: floor staff at branches need this set so their My Work page shows the right checklists. Office staff (admin/ops/accounting/marketing) → HEADOFFICE.
- [ ] **Joining date** — affects tenure-related calculations (vacation accrual etc.)
- [ ] **Monthly salary in SAR** — base wage. Holiday OT and bonuses are added on top.
- [ ] **Schedule** — per-day shift start/end, off-days. Default is "9-to-5 Mon–Sat, Fri off" but most baristas will need a custom shift pattern.
- [ ] **IQAMA number + expiry** (for non-Saudi staff) and **Baladiya/health card number + expiry** (for food handlers). The Documents page flags these when they're <30 days from expiring.

For each employee, after adding them in the app:
- [ ] **Trigger Supabase Auth invite** — Supabase Dashboard → Authentication → Users → "Invite user" with their email. They get a "set your password" email.
- [ ] **They sign in and confirm** — the new auth user is linked to the existing employee record by matching email (the `handle_new_user` trigger handles this).

Aim for **3 admins maximum** (yourself + 1 backup HR + 1 backup ops). Everyone else is a more specific role.

---

## 7. Resources / SOPs upload (admin, ~20 min)

Sidebar → **Resources** (admin/HR see an Upload button there; also accessible via Archive):

- [ ] **Hassad Recipes** PDF
- [ ] **Operations Manual** PDF
- [ ] Any safety / opening / closing SOPs you have
- [ ] Brand guidelines for baristas
- [ ] Training videos (or links to where they live — drop a doc with the URL)

These show up immediately on the Resources tab for baristas / head baristas / roasters.

---

## 8. Per-branch checklists (admin, ~15 min)

The "Opening", "Closing", etc. checklists for Barista role are **pre-seeded** (from PR #120 — they were imported from the printed branch checklist PDF). Verify in **Work Management → Checklists**:

- [ ] All 8 Barista checklists are visible: Opening, Morning Tasks, Handover Tasks, Evening Prep (Mise en place), Closing Checklist, Weekly Cleaning Tasks, Monthly Cleaning Tasks, Maintenance Tasks.
- [ ] Spot-check one — open it, confirm items list looks correct for your branches.
- [ ] If you want department-specific lists (Roaster, Bakery, Chef, etc.), add them via the same page.

Note that floor staff at each branch tick the same checklist templates but each branch has its own independent state — KHOBAR ticking "Espresso machine on" doesn't affect RAYYAN's view.

---

## 9. PDPL compliance (HR, ~half a day across the team)

KSA Personal Data Protection Law requires consent before collecting employee data. For every employee:

- [ ] Distribute [`PRIVACY_NOTICE.md`](PRIVACY_NOTICE.md) — they should read and understand what data the app collects and why.
- [ ] Have them sign a printed copy of [`CONSENT_FORM.md`](CONSENT_FORM.md) — file the signed copies physically and/or scan to the Archive (admin → Archive → category "Contract").
- [ ] Make sure the company's PDPL Data Protection Officer (or whoever owns this — likely you) is named in the privacy notice.

Without signed consent forms on file, you have a real PDPL exposure even if the technical RLS is tight.

---

## 10. People readiness (training, ~half a day)

- [ ] **Admin / HR walkthrough** — sit with the people who'll use the app daily. Cover: adding employees, running payroll (especially the new 50%-cap warning banner and the partial-failure retry banner), issuing warnings, approving leave, viewing the Compliance tab.
- [ ] **At least one head barista per branch trained on the floor flows** — clock in/out, ticking checklists, viewing Resources, raising maintenance requests. They become the local helpdesk for their branch.
- [ ] **Backup-download cadence assigned to someone** — recommend weekly: download yesterday's encrypted artifact from the GitHub Releases page to your laptop / a secure backup drive. This is belt-and-braces beyond the cron itself. ~30 sec/week.
- [ ] **Incident escalation path defined** — when an admin/floor staff hits a real problem (the app won't load, clock-in fails for everyone at a branch, payroll preview shows wrong numbers): who do they call? Document it in HR_USER_GUIDE.md or a sticky note by the till.

---

## 11. Day-of launch checks (just before going live)

- [ ] **Test login on iOS Safari + Android Chrome from a real phone** — both should sign in and show the right dashboard. Phone is the primary device for floor staff.
- [ ] **Walk to one branch, try to clock in** — geofence should accept you; clock out a few minutes later, hours should reflect correctly.
- [ ] **Open Run Payroll preview** (don't actually run it) — should show the new yellow 50%-cap warning banner if anyone's deductions exceed half their salary, and a clean preview otherwise. Cancel out.
- [ ] **Open My Work for a barista account** — should show today's checklists, with the items they need to tick.
- [ ] **Open Resources for a barista account** — should show the SOPs / training PDFs you uploaded.
- [ ] **Verify Reset everything button works as expected** — open the modal, see the typed-confirm flow, the row counts, the recovery banner. **Then click Cancel** — don't actually wipe.

---

## 12. Ongoing routines (post-launch)

Not pre-launch, but worth documenting now so the rhythm starts on day 1:

- [ ] **Daily** — admins glance at dashboard for overdue tasks, expiring documents, pending leave requests.
- [ ] **Weekly** — download last night's backup as a belt-and-braces copy; review the Compliance tab; check that all branches are running checklists.
- [ ] **Monthly** — payroll run on the agreed date; review Spend Report; renew expiring IQAMA / Baladiya documents.
- [ ] **Quarterly** — review system roles (anyone left? anyone need promoted?); review SOP/training material relevance.
- [ ] **Annually** — refresh KSA holidays for the new year; review PDPL practices.

---

## What's deliberately NOT in this checklist

- **Supabase Pro upgrade ($25/mo for native daily backups + PITR)** — optional, recommended for grown-up production but not blocking. The free GitHub Actions backup covers the essentials.
- **Custom domain (`hr.hassadcoffee.com`)** — branding polish, ~30 min of DNS work, can happen any time before or after launch.
- **Migrating from GitHub Pages to a paid host** — not needed at current scale. GitHub Pages is fine for an internal app of this size.
- **Mobile app shell (iOS/Android wrapper)** — out of scope. The PWA-style web app works on phones already.

---

## Help, in roughly the order to ask

1. **Search this repo's [`HR_USER_GUIDE.md`](HR_USER_GUIDE.md)** for day-to-day usage questions
2. **Check the GitHub repo Issues tab** for known problems
3. **For real bugs:** file a GitHub issue with a screenshot and the steps to reproduce
4. **For data-loss incidents:** open [`RESTORE.md`](RESTORE.md), don't panic, follow the steps

---

Good luck with launch. ☕
