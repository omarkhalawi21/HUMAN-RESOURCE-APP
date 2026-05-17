# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single deployable `index.html` (~14k lines) — plain HTML + vanilla JS, no framework, no bundler — for Hassad Coffee Roasters. Backend is Supabase (Auth + Postgres). Deployed static to GitHub Pages; the same file run locally connects to the same Supabase project. All application logic lives in one large inline `<script>` in `index.html`.

## Commands

```bash
npm install            # one-time, per machine (only dependency is tailwindcss)
npm run build          # rebuild tailwind.css from tailwind.input.css + tailwind.config.js
npm run watch          # rebuild on save during development
```

- **Tailwind**: the compiled `tailwind.css` is **committed and served as-is**. Only run `npm run build` when you add Tailwind utility classes to `index.html` that aren't already compiled, and commit the regenerated `tailwind.css` with your change. The config scans `index.html` and `HR_USER_GUIDE.md`.
- **Inline `<style>` trick**: a `<style>` block in `<head>` loads *after* `tailwind.css`, so same-specificity overrides placed there (e.g. shadow/color tweaks) win **without** a Tailwind rebuild.
- **No test runner.** The de-facto correctness gate before committing is a JS syntax check of the inline script: extract the `<script>…</script>` body to a temp file and run `node --check` on it. Always do this after editing `index.html`.
- **There is no dev server in-repo.** Opening `index.html` in a browser only renders the login screen without a real Supabase session; dashboard/CRUD surfaces need authentication.

## The SQL migration workflow (most important operational rule)

`supabase-rls.sql` is the schema + RLS source of truth. It is:

- **Append-only and numbered.** New schema goes in a new numbered block at the end (`-- 42. …`), before the `-- DONE.` marker. Never rewrite earlier blocks.
- **Fully idempotent** (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, `CREATE OR REPLACE`, drop-then-create policies inside `DO $$` loops, seed inserts guarded by `WHERE NOT EXISTS`). Re-running the whole file on a partially-migrated DB is safe.
- **Not run by merging a PR.** Merging only ships frontend. The SQL must be pasted into the Supabase SQL editor by the user, manually. Treat "run the SQL" as a hard prerequisite, not a footnote.

When a change adds a SQL block: front-load the exact block in the PR body **and** in chat (don't ask "want the SQL?"), phrased as a required pre-merge step. After it runs, have the user execute a diagnostic `SELECT` (existence + policy counts + seed counts) and confirm it returns the expected `true / true / N` row. **"Success. No rows returned" is the DDL response and proves nothing** — only the diagnostic confirms the schema actually changed. If a later migration errors with "column/relation does not exist" for something shipped earlier, suspect skipped migrations and have the user re-paste the entire idempotent file.

RLS per table follows a 4-policy shape (SELECT / INSERT / UPDATE / DELETE) using SQL helpers `is_admin()` and `has_role(ARRAY[...])`. The publishable Supabase key in `index.html` is safe **only** because RLS is enforced on every table — never weaken that.

## Architecture

**Routing & render.** A single `render()` switches on a route via a `case` dispatch. New pages require three wirings: add the key to the `routes` whitelist array, add a `case` in `render()`'s dispatch, and add a `navItems` entry. `navItems` entries carry `show:` predicates (role gating) and optional `parent` for `subgroupMeta` collapsible sidebar groups. The dashboard route fans out through `renderRoleDashboard()` by `currentRole()`.

**Roles.** `employees.system_role` (text enum, NOT NULL) is the single source of truth; the legacy `is_admin` boolean has been dropped. SQL: `is_admin()`, `has_role(text[])`. JS: `currentRole()`, `realRole()`, `isAdmin()`, `hasRole(...roles)`, `canManagePeople()` (= admin+hr). Admins have a session-only **"view as role"** override that all gates honor automatically (so never bypass `hasRole`/`currentRole`). Self-change of role is blocked by a DB trigger.

**DB ↔ JS mapping.** Every table has `mapXFromDb(r)` (snake→camel) and `xToDb(j)` (camel→snake) converters. Mappers coerce numerics to `Number` or `null`. Follow this convention for any new table; don't read raw snake_case columns elsewhere.

**Modals.** `openModal(title, bodyHTML, onSave, opts)` / `closeModal()`. Transient upload/edit state is held in module-level `_xxx` vars; **any new transient modal var must be cleared in `closeModal()`**.

**Data loading discipline (performance-critical).** `loadAll()` bulk-loads small/bounded tables once into a module-level `state` object via one parallel `Promise.all`. **Unbounded time-series are never bulk-loaded**: attendance is capped to a rolling window; `inventory_movements` is capped; the count series (`daily_counts`, `weekly_counts`, `expiry_checks`) are loaded **on demand per `branch|YYYY-MM`** into `state.*Cache`, guarded by an in-flight `Set`, and a fetch error caches `[]` deliberately to prevent a refetch loop. Bounded cross-branch "today/recent" slices (e.g. `dailyCountsToday`, the alert loads) are the only count rows in `loadAll`. When adding a growing table, follow the on-demand-per-month pattern, not bulk load.

**Count subsystem (daily / weekly / expiry).** Three parallel features share a shape: a small branch-agnostic catalog table (bulk-loaded) + an unbounded per-(item,branch,period) records table (on-demand, `UNIQUE(item_id,branch,period)`, upsert on that key). They are intentionally **mirrored-but-separate** (`dc*`/`wc*`/`ec*`, `renderDailyCount`/`renderWeeklyCount`/`renderExpiryCheck`) — do not merge them into one abstraction; that separation is a deliberate, owner-confirmed preference. Genuinely generic helpers *are* shared (e.g. `dcNum`, the `wc*` UTC week helpers `wcMonday`/`wcAddDays`/`wcWeeksInMonth`, `prevYm`, `lastCounted`, `daysUntil`). Week math must be done in **UTC** (`Date.UTC` + `getUTC*`/`setUTC*`) — mixing local-midnight `Date` with `toISOString()` skews dates by a day at the app's UTC+3.

**Edge Function.** `supabase/functions/ocr-receipt/index.ts` calls Claude Vision for receipt OCR; needs the `ANTHROPIC_API_KEY` Supabase secret. The frontend calls it first and falls back to client-side Tesseract.js if it 404s or errors.

**CSP.** A `<meta>` CSP tag restricts external resources to declared CDNs (jsdelivr, etc.). Adding any new external script/CDN dependency requires updating the CSP allowlist or it fails silently.

## Conventions specific to this repo

- After editing `index.html`: `node --check` the extracted inline script before committing; rebuild Tailwind only if you introduced new utility classes.
- New page = routes whitelist + `render()` case + `navItems` entry (+ `show:` role gate).
- New growing table = on-demand per-branch+month cache, not `loadAll` bulk.
- New transient modal state = cleanup in `closeModal()`.
- SQL change = new numbered idempotent block in `supabase-rls.sql` + front-loaded SQL + post-run diagnostic.
- Don't reintroduce `is_admin` (dropped); gate via `hasRole`/`currentRole` so the admin "view as role" preview keeps working.

## Other docs

`README.md` (deploy/first-time setup, security rationale), `HR_USER_GUIDE.md` (end-user guide, scanned by Tailwind), `PRIVACY_NOTICE.md`, `CONSENT_FORM.md`.
