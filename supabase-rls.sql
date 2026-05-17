-- =============================================================
-- Hassad HR — Supabase Row Level Security (RLS) policies
-- =============================================================
-- WHAT THIS DOES
--   Locks down every table the app touches so the JS client
--   cannot bypass admin checks via DevTools. Without these
--   policies any logged-in employee can promote themselves
--   to admin, wipe payroll, or read other employees' data.
--
-- HOW TO APPLY
--   1. Open the Supabase dashboard for your project.
--   2. Go to: SQL Editor → New query.
--   3. Paste this entire file.
--   4. Click Run. (It is idempotent — safe to re-run.)
--   5. Test by logging in as a non-admin (e.g. khaled) and
--      running this in the browser console:
--        await sb.from('employees').update({is_admin:true})
--          .eq('user_id', (await sb.auth.getUser()).data.user.id);
--      You should get a permission error. Before this file is
--      applied, that call SUCCEEDS.
--
-- WHAT MIGHT BREAK
--   - If your `employees` table is missing any of the columns
--     referenced below (is_admin, user_id, status, etc.), the
--     trigger or policies will fail. Adjust column names if
--     your schema diverges.
--   - The `handle_new_user` trigger creates an employee row on
--     signup. If you already have a trigger doing this, drop
--     it first or reconcile.
-- =============================================================

-- -------------------------------------------------------------
-- 0. Helpers
-- -------------------------------------------------------------

-- is_admin() — true if the current authenticated user maps to
-- an employee row with is_admin = true. SECURITY DEFINER so it
-- can read employees regardless of the caller's RLS scope (it
-- would otherwise infinite-loop through its own policies).
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.employees
    WHERE user_id = auth.uid()
      AND is_admin = true
  );
$$;

REVOKE ALL ON FUNCTION public.is_admin() FROM public;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated;

-- -------------------------------------------------------------
-- 1. Auto-create employee row on signup
--    First user becomes admin; everyone else is a regular employee.
--    This is the safe place for that logic — never trust the
--    client to set is_admin on signup.
-- -------------------------------------------------------------
-- Self-service signup. The signup form on the live site collects
-- name, email, password, phone, branch, and position; the trigger
-- creates the employee row from that metadata. Admin reviews each
-- new employee in the directory and fills in salary, schedule, etc.
--
-- Logic, in order:
--   1. If this auth user is already linked to an employee row, no-op.
--   2. If HR has pre-added a row with this email and no user_id yet,
--      link them and merge any new metadata (phone, position, branch)
--      that HR didn't already fill in.
--   3. Otherwise: create a fresh employees row from the signup
--      metadata. First-ever signup is bootstrapped as admin.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  is_first       boolean;
  invited_emp_id uuid;
  meta           jsonb;
  new_emp_id     uuid;
  signup_branch  text;
BEGIN
  meta := COALESCE(NEW.raw_user_meta_data, '{}'::jsonb);
  signup_branch := NULLIF(TRIM(COALESCE(meta->>'branch', '')), '');

  -- 1. Already linked.
  IF EXISTS (SELECT 1 FROM public.employees WHERE user_id = NEW.id) THEN
    RETURN NEW;
  END IF;

  -- 2. HR pre-added this email — link to existing row, fill in any
  --    metadata they didn't enter (case-insensitive email match;
  --    auth lowercases email but employees may have any casing).
  SELECT id INTO invited_emp_id
    FROM public.employees
   WHERE LOWER(email) = LOWER(NEW.email)
     AND user_id IS NULL
   ORDER BY hire_date NULLS LAST
   LIMIT 1;

  IF invited_emp_id IS NOT NULL THEN
    UPDATE public.employees
       SET user_id   = NEW.id,
           phone     = COALESCE(NULLIF(TRIM(phone),'')    , NULLIF(TRIM(meta->>'phone'),'')),
           job_title = COALESCE(NULLIF(TRIM(job_title),''), NULLIF(TRIM(meta->>'role'),''),  job_title)
     WHERE id = invited_emp_id;

    -- Branch lives on employee_extras. Upsert the row.
    IF signup_branch IS NOT NULL THEN
      INSERT INTO public.employee_extras (employee_id, branch)
      VALUES (invited_emp_id, signup_branch)
      ON CONFLICT (employee_id) DO UPDATE
        SET branch = COALESCE(NULLIF(TRIM(public.employee_extras.branch),''), EXCLUDED.branch);
    END IF;

    RETURN NEW;
  END IF;

  -- 3. New self-service signup. First-ever becomes admin (status =
  --    'active' so they can immediately set up the company); everyone
  --    else lands as 'pending' awaiting admin approval. The JS shows
  --    a "pending approval" gate to anyone with status='pending'.
  SELECT NOT EXISTS (SELECT 1 FROM public.employees) INTO is_first;

  INSERT INTO public.employees (
    user_id, email, first_name, last_name, phone,
    is_admin, status, job_title, department, hire_date, salary
  ) VALUES (
    NEW.id,
    NEW.email,
    COALESCE(meta->>'first_name', ''),
    COALESCE(meta->>'last_name', ''),
    NULLIF(TRIM(meta->>'phone'), ''),
    is_first,
    CASE WHEN is_first THEN 'active' ELSE 'pending' END,
    COALESCE(NULLIF(TRIM(meta->>'role'), ''), CASE WHEN is_first THEN 'Admin'      ELSE 'Employee' END),
    COALESCE(NULLIF(TRIM(meta->>'role'), ''), CASE WHEN is_first THEN 'Management' ELSE 'General'  END),
    CURRENT_DATE,
    0
  )
  RETURNING id INTO new_emp_id;

  -- Branch lives on employee_extras.
  IF signup_branch IS NOT NULL AND new_emp_id IS NOT NULL THEN
    INSERT INTO public.employee_extras (employee_id, branch)
    VALUES (new_emp_id, signup_branch)
    ON CONFLICT (employee_id) DO UPDATE SET branch = EXCLUDED.branch;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- -------------------------------------------------------------
-- 2. Prevent self-promotion / privilege escalation on employees
--    RLS can gate the row but not which columns change. A trigger
--    enforces: non-admins cannot edit anyone's row, and nobody
--    (not even an admin) can flip their own is_admin flag.
-- -------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.enforce_employee_update_rules()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Nobody changes their own admin status (use another admin to demote).
  IF NEW.user_id = auth.uid()
     AND NEW.is_admin IS DISTINCT FROM OLD.is_admin THEN
    RAISE EXCEPTION 'You cannot change your own admin status';
  END IF;

  -- Don't allow rewiring user_id post-hoc.
  IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'user_id is immutable';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_employee_update_rules_trigger ON public.employees;
CREATE TRIGGER enforce_employee_update_rules_trigger
  BEFORE UPDATE ON public.employees
  FOR EACH ROW EXECUTE FUNCTION public.enforce_employee_update_rules();

-- -------------------------------------------------------------
-- 3. Enable RLS on every table
-- -------------------------------------------------------------
ALTER TABLE public.companies       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.employees       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attendance      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.leave_requests  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payroll         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.branches        ENABLE ROW LEVEL SECURITY;

-- Drop any existing policies (idempotent re-run).
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('companies','employees','attendance','leave_requests','payroll','branches')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- -------------------------------------------------------------
-- 4. COMPANIES
--    Single-row table. Everyone reads; only admins update.
-- -------------------------------------------------------------
CREATE POLICY "companies_select_authenticated"
  ON public.companies FOR SELECT
  TO authenticated USING (true);

CREATE POLICY "companies_update_admin"
  ON public.companies FOR UPDATE
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- -------------------------------------------------------------
-- 5. EMPLOYEES
--    Read: any authenticated user (the directory).
--    Insert/Delete: admin only.
--    Update: admin only — non-admins never UPDATE this table
--    in the current app. (Profile-edit by self is not exposed.)
-- -------------------------------------------------------------
CREATE POLICY "employees_select_authenticated"
  ON public.employees FOR SELECT
  TO authenticated USING (true);

CREATE POLICY "employees_insert_admin"
  ON public.employees FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin());

CREATE POLICY "employees_update_admin"
  ON public.employees FOR UPDATE
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "employees_delete_admin"
  ON public.employees FOR DELETE
  TO authenticated
  USING (public.is_admin());

-- -------------------------------------------------------------
-- 6. ATTENDANCE
--    Read: authenticated (dashboards show team-wide stats).
--    Insert: authenticated user can clock in for THEIR own
--      employee row; admins can insert for anyone.
--    Update: same — own row OR admin.
--    Delete: admin only (e.g. resetState bulk delete).
-- -------------------------------------------------------------
CREATE POLICY "attendance_select_authenticated"
  ON public.attendance FOR SELECT
  TO authenticated USING (true);

CREATE POLICY "attendance_insert_self_or_admin"
  ON public.attendance FOR INSERT
  TO authenticated
  WITH CHECK (
    public.is_admin()
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = attendance.employee_id
        AND e.user_id = auth.uid()
    )
  );

CREATE POLICY "attendance_update_self_or_admin"
  ON public.attendance FOR UPDATE
  TO authenticated
  USING (
    public.is_admin()
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = attendance.employee_id
        AND e.user_id = auth.uid()
    )
  )
  WITH CHECK (
    public.is_admin()
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = attendance.employee_id
        AND e.user_id = auth.uid()
    )
  );

CREATE POLICY "attendance_delete_admin"
  ON public.attendance FOR DELETE
  TO authenticated
  USING (public.is_admin());

-- -------------------------------------------------------------
-- 7. LEAVE REQUESTS
--    Read: authenticated.
--    Insert: own row only (or admin).
--    Update (decide): admin only.
--    Delete: admin only.
-- -------------------------------------------------------------
CREATE POLICY "leave_requests_select_authenticated"
  ON public.leave_requests FOR SELECT
  TO authenticated USING (true);

CREATE POLICY "leave_requests_insert_self_or_admin"
  ON public.leave_requests FOR INSERT
  TO authenticated
  WITH CHECK (
    public.is_admin()
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = leave_requests.employee_id
        AND e.user_id = auth.uid()
    )
  );

CREATE POLICY "leave_requests_update_admin"
  ON public.leave_requests FOR UPDATE
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "leave_requests_delete_admin"
  ON public.leave_requests FOR DELETE
  TO authenticated
  USING (public.is_admin());

-- -------------------------------------------------------------
-- 8. PAYROLL
--    Read: authenticated (employees see their own payslips
--    via a client-side filter; if you want stricter privacy
--    swap the SELECT policy for the commented-out version).
--    Insert/Update/Delete: admin only.
-- -------------------------------------------------------------
CREATE POLICY "payroll_select_authenticated"
  ON public.payroll FOR SELECT
  TO authenticated USING (true);

-- Stricter alternative — uncomment to replace the policy above:
-- CREATE POLICY "payroll_select_self_or_admin"
--   ON public.payroll FOR SELECT
--   TO authenticated
--   USING (
--     public.is_admin()
--     OR EXISTS (
--       SELECT 1 FROM public.employees e
--       WHERE e.id = payroll.employee_id
--         AND e.user_id = auth.uid()
--     )
--   );

CREATE POLICY "payroll_insert_admin"
  ON public.payroll FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin());

CREATE POLICY "payroll_update_admin"
  ON public.payroll FOR UPDATE
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "payroll_delete_admin"
  ON public.payroll FOR DELETE
  TO authenticated
  USING (public.is_admin());

-- -------------------------------------------------------------
-- 9. BRANCHES
--    Read: authenticated. All mutations: admin only.
-- -------------------------------------------------------------
CREATE POLICY "branches_select_authenticated"
  ON public.branches FOR SELECT
  TO authenticated USING (true);

CREATE POLICY "branches_insert_admin"
  ON public.branches FOR INSERT
  TO authenticated
  WITH CHECK (public.is_admin());

CREATE POLICY "branches_update_admin"
  ON public.branches FOR UPDATE
  TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "branches_delete_admin"
  ON public.branches FOR DELETE
  TO authenticated
  USING (public.is_admin());

-- =============================================================
-- 10. V2 FEATURE TABLES
--    These were originally stored in the browser's localStorage —
--    single-device-only and tamperable. Migrating them server-side
--    so they're real records.
-- =============================================================

CREATE TABLE IF NOT EXISTS public.warnings (
  id          uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  severity    text not null,
  type        text,
  date        date,
  reason      text,
  notes       text,
  issued_by   uuid references public.employees(id),
  issued_at   timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS warnings_employee_idx ON public.warnings(employee_id);

CREATE TABLE IF NOT EXISTS public.advances (
  id                  uuid primary key default gen_random_uuid(),
  employee_id         uuid not null references public.employees(id) on delete cascade,
  amount              numeric(12,2) not null default 0,
  reason              text,
  requested_at        date not null default current_date,
  status              text not null default 'pending',
  deduct_from_payroll text,
  installments_paid   integer not null default 0,
  decided_by          uuid references public.employees(id),
  decided_at          date,
  repaid_at           date
);
CREATE INDEX IF NOT EXISTS advances_employee_idx ON public.advances(employee_id);
CREATE INDEX IF NOT EXISTS advances_status_idx   ON public.advances(status);

CREATE TABLE IF NOT EXISTS public.certificates (
  id          uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  type        text not null,
  title       text,
  period      text,
  message     text,
  issued_by   uuid references public.employees(id),
  issued_at   date not null default current_date
);
CREATE INDEX IF NOT EXISTS certificates_employee_idx ON public.certificates(employee_id);

CREATE TABLE IF NOT EXISTS public.archive_documents (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  category    text,
  mime        text,
  size        bigint,
  data_url    text,
  description text,
  uploaded_by uuid references public.employees(id),
  uploaded_at date not null default current_date
);

CREATE TABLE IF NOT EXISTS public.employee_extras (
  employee_id     uuid primary key references public.employees(id) on delete cascade,
  schedule        jsonb,
  iqama_number    text,
  iqama_expiry    date,
  baladiya_number text,
  baladiya_expiry date,
  branch          text,
  nationality     text
);

ALTER TABLE public.companies
  ADD COLUMN IF NOT EXISTS company_stamp text;

-- Letterhead fields shown at the top of every printed HR document.
-- Defaults match the existing Hassad letterhead so the migration is
-- a no-op for the live deployment until the admin edits them.
ALTER TABLE public.companies
  ADD COLUMN IF NOT EXISTS legal_name text,
  ADD COLUMN IF NOT EXISTS registration_number text,
  ADD COLUMN IF NOT EXISTS address_line1 text,
  ADD COLUMN IF NOT EXISTS address_line2 text,
  ADD COLUMN IF NOT EXISTS address_line3 text;

-- PDPL consent fields. `consent_at` NULL = employee has not yet given
-- digital consent and must do so on next login. `consent_version` lets
-- us bump the privacy notice version and re-prompt everyone if it
-- changes materially. GPS and photo are optional opt-ins; cross-border
-- and the privacy notice acknowledgement are implicit when consent_at
-- is set (the app is unusable without them).
ALTER TABLE public.employees
  ADD COLUMN IF NOT EXISTS consent_at      timestamptz,
  ADD COLUMN IF NOT EXISTS consent_version text,
  ADD COLUMN IF NOT EXISTS consent_gps     boolean,
  ADD COLUMN IF NOT EXISTS consent_photo   boolean;

-- Offboarding fields. When an employee leaves, mark them as terminated
-- (rather than deleting) so all their attendance/payroll/warning history
-- is preserved for audit and statutory retention. The `status` column
-- already exists with values like 'active' / 'on_leave'; we add
-- 'terminated' as a third value. The trio below records when, why,
-- and who actioned it.
ALTER TABLE public.employees
  ADD COLUMN IF NOT EXISTS termination_date   date,
  ADD COLUMN IF NOT EXISTS termination_reason text,
  ADD COLUMN IF NOT EXISTS terminated_by      uuid REFERENCES public.employees(id);

-- record_consent() lets an authenticated employee write ONLY their
-- consent fields, without granting them general UPDATE on employees
-- (which would let them change their own salary, admin flag, etc.).
-- SECURITY DEFINER bypasses RLS for this specific operation;
-- the WHERE clause locks it to the caller's own row.
CREATE OR REPLACE FUNCTION public.record_consent(
  p_gps     boolean,
  p_photo   boolean,
  p_version text DEFAULT '1.0'
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  UPDATE public.employees
     SET consent_at      = NOW(),
         consent_version = p_version,
         consent_gps     = COALESCE(p_gps,   false),
         consent_photo   = COALESCE(p_photo, false)
   WHERE user_id = auth.uid();
END;
$$;

REVOKE ALL ON FUNCTION public.record_consent(boolean, boolean, text) FROM public;
GRANT EXECUTE ON FUNCTION public.record_consent(boolean, boolean, text) TO authenticated;

-- -------------------------------------------------------------
-- 11. RLS for v2 tables
-- -------------------------------------------------------------
ALTER TABLE public.warnings          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.advances          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificates      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.archive_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.employee_extras   ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('warnings','advances','certificates','archive_documents','employee_extras')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- WARNINGS — all authenticated read; admin only mutations.
CREATE POLICY "warnings_select_authenticated"
  ON public.warnings FOR SELECT TO authenticated USING (true);
CREATE POLICY "warnings_insert_admin"
  ON public.warnings FOR INSERT TO authenticated WITH CHECK (public.is_admin());
CREATE POLICY "warnings_update_admin"
  ON public.warnings FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "warnings_delete_admin"
  ON public.warnings FOR DELETE TO authenticated USING (public.is_admin());

-- ADVANCES — read all; employees may insert their own pending request;
-- decide/update/delete is admin only.
CREATE POLICY "advances_select_authenticated"
  ON public.advances FOR SELECT TO authenticated USING (true);
CREATE POLICY "advances_insert_self_or_admin"
  ON public.advances FOR INSERT TO authenticated
  WITH CHECK (
    public.is_admin()
    OR (
      status = 'pending'
      AND decided_by IS NULL
      AND decided_at IS NULL
      AND repaid_at IS NULL
      AND EXISTS (
        SELECT 1 FROM public.employees e
        WHERE e.id = advances.employee_id AND e.user_id = auth.uid()
      )
    )
  );
CREATE POLICY "advances_update_admin"
  ON public.advances FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "advances_delete_admin"
  ON public.advances FOR DELETE TO authenticated USING (public.is_admin());

-- CERTIFICATES — admin only mutations.
CREATE POLICY "certificates_select_authenticated"
  ON public.certificates FOR SELECT TO authenticated USING (true);
CREATE POLICY "certificates_insert_admin"
  ON public.certificates FOR INSERT TO authenticated WITH CHECK (public.is_admin());
CREATE POLICY "certificates_update_admin"
  ON public.certificates FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "certificates_delete_admin"
  ON public.certificates FOR DELETE TO authenticated USING (public.is_admin());

-- ARCHIVE DOCUMENTS — admin only mutations.
CREATE POLICY "archive_select_authenticated"
  ON public.archive_documents FOR SELECT TO authenticated USING (true);
CREATE POLICY "archive_insert_admin"
  ON public.archive_documents FOR INSERT TO authenticated WITH CHECK (public.is_admin());
CREATE POLICY "archive_update_admin"
  ON public.archive_documents FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "archive_delete_admin"
  ON public.archive_documents FOR DELETE TO authenticated USING (public.is_admin());

-- EMPLOYEE EXTRAS — admin only mutations (the employee modal and
-- the renew-documents modal are admin-only screens).
CREATE POLICY "employee_extras_select_authenticated"
  ON public.employee_extras FOR SELECT TO authenticated USING (true);
CREATE POLICY "employee_extras_insert_admin"
  ON public.employee_extras FOR INSERT TO authenticated WITH CHECK (public.is_admin());
CREATE POLICY "employee_extras_update_admin"
  ON public.employee_extras FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "employee_extras_delete_admin"
  ON public.employee_extras FOR DELETE TO authenticated USING (public.is_admin());

-- =============================================================
-- 12. RECEIPTS (accounting)
--    Scanned/uploaded receipts for the accounting workflow.
--    Image is stored as a base64 data URL (same pattern as
--    archive_documents) so no Storage bucket is required.
--    SELECT is admin-only because receipts contain financial
--    info; this becomes admin-or-accounting once roles land.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.receipts (
  id            uuid primary key default gen_random_uuid(),
  vendor        text not null,
  receipt_date  date not null default current_date,
  amount        numeric(12,2) not null default 0,
  currency      text,
  category      text,
  notes         text,
  mime          text,
  size          bigint,
  data_url      text,
  uploaded_by   uuid references public.employees(id),
  uploaded_at   timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS receipts_date_idx ON public.receipts(receipt_date DESC);

ALTER TABLE public.receipts ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'receipts'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "receipts_select_admin"
  ON public.receipts FOR SELECT TO authenticated USING (public.is_admin());
CREATE POLICY "receipts_insert_admin"
  ON public.receipts FOR INSERT TO authenticated WITH CHECK (public.is_admin());
CREATE POLICY "receipts_update_admin"
  ON public.receipts FOR UPDATE TO authenticated
  USING (public.is_admin()) WITH CHECK (public.is_admin());
CREATE POLICY "receipts_delete_admin"
  ON public.receipts FOR DELETE TO authenticated USING (public.is_admin());

-- =============================================================
-- 13. SYSTEM ROLE ENUM (multi-department permission model)
--    Adds `system_role` to employees as the new permission key.
--    The legacy `is_admin` boolean is kept and stays in sync via
--    the frontend (employeeToDb sets both); this is intentional
--    so partial deployments don't lock anyone out. A future PR
--    can drop `is_admin` once all RLS reads from `system_role`.
-- =============================================================

ALTER TABLE public.employees
  ADD COLUMN IF NOT EXISTS system_role text DEFAULT 'employee';

ALTER TABLE public.employees
  DROP CONSTRAINT IF EXISTS employees_system_role_chk;
ALTER TABLE public.employees
  ADD CONSTRAINT employees_system_role_chk
  CHECK (system_role IS NULL OR system_role IN (
    'admin','hr','operations','barista','head_barista',
    'inventory','accounting','maintenance','employee'
  ));

-- Backfill: anyone currently is_admin becomes 'admin'. Cannot use
-- `WHERE system_role IS NULL` here because the ADD COLUMN above
-- carries DEFAULT 'employee', so existing rows immediately have a
-- non-null value and the IS NULL filter would silently skip them
-- (this masked admins as 'employee' on first migrate). The condition
-- below is also idempotent for re-runs.
UPDATE public.employees
   SET system_role = 'admin'
 WHERE is_admin = true
   AND system_role IS DISTINCT FROM 'admin';

-- BEFORE INSERT trigger: if system_role wasn't supplied, derive it from
-- is_admin so the existing handle_new_user trigger keeps working unchanged.
CREATE OR REPLACE FUNCTION public.sync_employee_system_role()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.system_role IS NULL THEN
    NEW.system_role := CASE WHEN NEW.is_admin THEN 'admin' ELSE 'employee' END;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS sync_employee_system_role_trigger ON public.employees;
CREATE TRIGGER sync_employee_system_role_trigger
  BEFORE INSERT ON public.employees
  FOR EACH ROW EXECUTE FUNCTION public.sync_employee_system_role();

-- is_admin() now reads from system_role. Falls back to the legacy boolean
-- for any row where the backfill hasn't run (defence in depth).
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.employees
    WHERE user_id = auth.uid()
      AND (system_role = 'admin' OR is_admin = true)
  );
$$;

-- New helper for future per-role policies (e.g. accounting can SELECT receipts).
CREATE OR REPLACE FUNCTION public.has_role(roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.employees
    WHERE user_id = auth.uid()
      AND COALESCE(system_role, CASE WHEN is_admin THEN 'admin' ELSE 'employee' END) = ANY(roles)
  );
$$;
REVOKE ALL ON FUNCTION public.has_role(text[]) FROM public;
GRANT EXECUTE ON FUNCTION public.has_role(text[]) TO authenticated;

-- Block self-change of system_role (parallel to the existing is_admin block).
-- Demotion or role change must be done by a different admin.
CREATE OR REPLACE FUNCTION public.enforce_employee_update_rules()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.user_id = auth.uid()
     AND NEW.is_admin IS DISTINCT FROM OLD.is_admin THEN
    RAISE EXCEPTION 'You cannot change your own admin status';
  END IF;
  IF NEW.user_id = auth.uid()
     AND NEW.system_role IS DISTINCT FROM OLD.system_role THEN
    RAISE EXCEPTION 'You cannot change your own role';
  END IF;
  IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'user_id is immutable';
  END IF;
  RETURN NEW;
END;
$$;

-- =============================================================
-- 14. RECEIPTS RLS — broaden to admin OR accounting
--    The accounting role is the day-to-day owner of receipts.
--    Admins keep full access for oversight. All other roles
--    are still blocked from this financial data.
-- =============================================================
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'receipts'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "receipts_select_admin_or_accounting"
  ON public.receipts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','accounting']));
CREATE POLICY "receipts_insert_admin_or_accounting"
  ON public.receipts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','accounting']));
CREATE POLICY "receipts_update_admin_or_accounting"
  ON public.receipts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','accounting']))
  WITH CHECK (public.has_role(ARRAY['admin','accounting']));
CREATE POLICY "receipts_delete_admin_or_accounting"
  ON public.receipts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','accounting']));

-- =============================================================
-- 15. HR TABLES — broaden mutations to admin OR hr
--    HR role now manages people: employees, schedules, leave
--    decisions, payroll, branches, warnings, advances,
--    certificates, archive uploads. SELECT was already
--    `authenticated` for these — no change there.
--    Settings (companies update), backup/restore, reset, and
--    role assignment stay strictly admin via the frontend.
-- =============================================================
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN (
        'employees','employee_extras','leave_requests','payroll',
        'branches','warnings','advances','certificates',
        'archive_documents'
      )
      AND cmd <> 'SELECT'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- EMPLOYEES — insert/update/delete: admin or hr
CREATE POLICY "employees_insert_hr"
  ON public.employees FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "employees_update_hr"
  ON public.employees FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "employees_delete_hr"
  ON public.employees FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- EMPLOYEE_EXTRAS — same scope
CREATE POLICY "employee_extras_insert_hr"
  ON public.employee_extras FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "employee_extras_update_hr"
  ON public.employee_extras FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "employee_extras_delete_hr"
  ON public.employee_extras FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- LEAVE_REQUESTS — insert kept as self-or-hr; update/delete: admin or hr
CREATE POLICY "leave_requests_insert_self_or_hr"
  ON public.leave_requests FOR INSERT TO authenticated
  WITH CHECK (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = leave_requests.employee_id
        AND e.user_id = auth.uid()
    )
  );
CREATE POLICY "leave_requests_update_hr"
  ON public.leave_requests FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "leave_requests_delete_hr"
  ON public.leave_requests FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- PAYROLL — admin or hr
CREATE POLICY "payroll_insert_hr"
  ON public.payroll FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "payroll_update_hr"
  ON public.payroll FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "payroll_delete_hr"
  ON public.payroll FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- BRANCHES — admin or hr
CREATE POLICY "branches_insert_hr"
  ON public.branches FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "branches_update_hr"
  ON public.branches FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "branches_delete_hr"
  ON public.branches FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- WARNINGS — admin or hr
CREATE POLICY "warnings_insert_hr"
  ON public.warnings FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "warnings_update_hr"
  ON public.warnings FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "warnings_delete_hr"
  ON public.warnings FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- ADVANCES — insert kept as self-or-hr; decide(update)/delete: admin or hr
CREATE POLICY "advances_insert_self_or_hr"
  ON public.advances FOR INSERT TO authenticated
  WITH CHECK (
    public.has_role(ARRAY['admin','hr'])
    OR (
      status = 'pending'
      AND decided_by IS NULL
      AND decided_at IS NULL
      AND repaid_at IS NULL
      AND EXISTS (
        SELECT 1 FROM public.employees e
        WHERE e.id = advances.employee_id AND e.user_id = auth.uid()
      )
    )
  );
CREATE POLICY "advances_update_hr"
  ON public.advances FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "advances_delete_hr"
  ON public.advances FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- CERTIFICATES — admin or hr
CREATE POLICY "certificates_insert_hr"
  ON public.certificates FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "certificates_update_hr"
  ON public.certificates FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "certificates_delete_hr"
  ON public.certificates FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- ARCHIVE_DOCUMENTS — admin or hr
CREATE POLICY "archive_insert_hr"
  ON public.archive_documents FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "archive_update_hr"
  ON public.archive_documents FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "archive_delete_hr"
  ON public.archive_documents FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']));

-- =============================================================
-- 16. INVENTORY (admin or inventory role)
--    Tracks stock items: name, category, unit, quantity on hand,
--    reorder threshold, supplier, optional branch, notes. Designed
--    for a coffee roastery's daily ops (beans, milk, cups, etc.).
--    SELECT is restricted (operational data) — admin or inventory only.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_items (
  id                 uuid primary key default gen_random_uuid(),
  name               text not null,
  sku                text,
  category           text,
  unit               text default 'units',
  quantity           numeric(12,2) not null default 0,
  reorder_threshold  numeric(12,2) not null default 0,
  supplier           text,
  branch             text,
  notes              text,
  created_by         uuid references public.employees(id),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS inventory_items_name_idx     ON public.inventory_items(LOWER(name));
CREATE INDEX IF NOT EXISTS inventory_items_category_idx ON public.inventory_items(category);

-- Auto-update updated_at on every UPDATE.
CREATE OR REPLACE FUNCTION public.touch_inventory_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS inventory_items_touch_updated_at ON public.inventory_items;
CREATE TRIGGER inventory_items_touch_updated_at
  BEFORE UPDATE ON public.inventory_items
  FOR EACH ROW EXECUTE FUNCTION public.touch_inventory_updated_at();

ALTER TABLE public.inventory_items ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'inventory_items'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "inventory_select_admin_or_inventory"
  ON public.inventory_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','inventory']));
CREATE POLICY "inventory_insert_admin_or_inventory"
  ON public.inventory_items FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','inventory']));
CREATE POLICY "inventory_update_admin_or_inventory"
  ON public.inventory_items FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','inventory']))
  WITH CHECK (public.has_role(ARRAY['admin','inventory']));
CREATE POLICY "inventory_delete_admin_or_inventory"
  ON public.inventory_items FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','inventory']));

-- =============================================================
-- 17. MAINTENANCE REQUESTS (work orders)
--    Anyone can submit a request for their own equipment / area.
--    Maintenance + admins manage and resolve them. Non-admins can
--    only SELECT requests they personally reported (so the bell
--    doesn't ring for the whole company on every broken cup).
-- =============================================================
CREATE TABLE IF NOT EXISTS public.maintenance_requests (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  description  text,
  branch       text,
  location     text,
  asset        text,
  priority     text not null default 'normal'
    CHECK (priority IN ('low','normal','high','urgent')),
  status       text not null default 'open'
    CHECK (status IN ('open','in_progress','resolved','cancelled')),
  reported_by  uuid references public.employees(id),
  assigned_to  uuid references public.employees(id),
  resolution   text,
  resolved_at  timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS maintenance_status_idx     ON public.maintenance_requests(status);
CREATE INDEX IF NOT EXISTS maintenance_priority_idx   ON public.maintenance_requests(priority);
CREATE INDEX IF NOT EXISTS maintenance_reporter_idx   ON public.maintenance_requests(reported_by);

-- Auto-touch updated_at; also stamps resolved_at the moment status flips
-- to 'resolved' (only if not already set).
CREATE OR REPLACE FUNCTION public.touch_maintenance_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  IF NEW.status = 'resolved' AND OLD.status IS DISTINCT FROM 'resolved'
     AND NEW.resolved_at IS NULL THEN
    NEW.resolved_at := now();
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS maintenance_touch_updated_at ON public.maintenance_requests;
CREATE TRIGGER maintenance_touch_updated_at
  BEFORE UPDATE ON public.maintenance_requests
  FOR EACH ROW EXECUTE FUNCTION public.touch_maintenance_updated_at();

ALTER TABLE public.maintenance_requests ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'maintenance_requests'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- SELECT: admin/maintenance see everything; others see only their own.
CREATE POLICY "maintenance_select_self_or_admin"
  ON public.maintenance_requests FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','maintenance'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = maintenance_requests.reported_by
        AND e.user_id = auth.uid()
    )
  );

-- INSERT: any authenticated user can submit, but only as themselves
-- (reported_by must point to their own employee row). Admin/maintenance
-- may also insert on someone else's behalf.
CREATE POLICY "maintenance_insert_self_or_admin"
  ON public.maintenance_requests FOR INSERT TO authenticated
  WITH CHECK (
    public.has_role(ARRAY['admin','maintenance'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = maintenance_requests.reported_by
        AND e.user_id = auth.uid()
    )
  );

-- UPDATE / DELETE: admin or maintenance only.
CREATE POLICY "maintenance_update_admin"
  ON public.maintenance_requests FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','maintenance']))
  WITH CHECK (public.has_role(ARRAY['admin','maintenance']));
CREATE POLICY "maintenance_delete_admin"
  ON public.maintenance_requests FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','maintenance']));

-- =============================================================
-- 18. DROP STANDALONE INVENTORY ROLE
--    Inventory is now a Head Barista responsibility (small shop)
--    or admin oversight. The standalone 'inventory' role is removed
--    from the system_role enum and any existing rows are migrated
--    to 'head_barista' (the natural successor). The inventory_items
--    table's RLS policies are swapped from 'inventory' to
--    'head_barista' so the same code paths keep working.
-- =============================================================

-- 1. Migrate any existing 'inventory' role rows to 'head_barista'.
UPDATE public.employees
   SET system_role = 'head_barista'
 WHERE system_role = 'inventory';

-- 2. Replace the CHECK constraint without 'inventory'.
ALTER TABLE public.employees
  DROP CONSTRAINT IF EXISTS employees_system_role_chk;
ALTER TABLE public.employees
  ADD CONSTRAINT employees_system_role_chk
  CHECK (system_role IS NULL OR system_role IN (
    'admin','hr','operations','barista','head_barista',
    'accounting','maintenance','employee'
  ));

-- 3. Re-issue the inventory_items policies with the new role list.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'inventory_items'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- SELECT is broader than write: admin/hr/operations get read-only
-- analytics on their dashboards, head_barista gets the full management
-- view, and writes are still locked down to head_barista or admin.
CREATE POLICY "inventory_select_admin_hr_ops_headbarista"
  ON public.inventory_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','hr','operations','head_barista']));
CREATE POLICY "inventory_insert_admin_or_headbarista"
  ON public.inventory_items FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "inventory_update_admin_or_headbarista"
  ON public.inventory_items FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "inventory_delete_admin_or_headbarista"
  ON public.inventory_items FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- =============================================================
-- 19. ROASTER ROLE
--    Adds the 'roaster' system role for staff who manage green
--    beans + the daily roasted-bean shelf. They get write access
--    to inventory_items so they can update bean counts.
-- =============================================================

-- Extend the system_role CHECK constraint with 'roaster'.
ALTER TABLE public.employees
  DROP CONSTRAINT IF EXISTS employees_system_role_chk;
ALTER TABLE public.employees
  ADD CONSTRAINT employees_system_role_chk
  CHECK (system_role IS NULL OR system_role IN (
    'admin','hr','operations','barista','head_barista','roaster',
    'accounting','maintenance','employee'
  ));

-- Re-issue inventory_items policies with the new role list. SELECT
-- now also includes roaster (already had admin/hr/operations/
-- head_barista). Writes are admin / head_barista / roaster.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'inventory_items'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "inventory_select_roles"
  ON public.inventory_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','hr','operations','head_barista','roaster']));
CREATE POLICY "inventory_insert_roles"
  ON public.inventory_items FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "inventory_update_roles"
  ON public.inventory_items FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "inventory_delete_roles"
  ON public.inventory_items FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']));

-- =============================================================
-- 20. INVENTORY MOVEMENTS (audit/history ledger)
--    Captures every change to an inventory_items.quantity over
--    time so the roaster can reproduce the spreadsheets they
--    were keeping (daily roasting log, weekly snapshots,
--    inter-branch transfers). The current quantity stays on
--    inventory_items.quantity (faster reads, simpler list view);
--    movements are the historical record kept in sync by the
--    frontend on every adjust/log action.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_movements (
  id           uuid primary key default gen_random_uuid(),
  item_id      uuid not null references public.inventory_items(id) on delete cascade,
  qty_delta    numeric(12,2) not null,
  type         text not null default 'adjust'
    CHECK (type IN ('adjust','roast','transfer','restock','sale','other')),
  branch       text,
  occurred_at  date not null default current_date,
  notes        text,
  recorded_by  uuid references public.employees(id),
  created_at   timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS inventory_movements_item_idx     ON public.inventory_movements(item_id);
CREATE INDEX IF NOT EXISTS inventory_movements_occurred_idx ON public.inventory_movements(occurred_at DESC);
CREATE INDEX IF NOT EXISTS inventory_movements_type_idx     ON public.inventory_movements(type);

ALTER TABLE public.inventory_movements ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'inventory_movements'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- SELECT mirrors inventory_items SELECT: anyone who can see stock
-- can see how it moved. Writes are roaster-shaped (admin, head
-- barista, roaster) — same group that adjusts inventory.
CREATE POLICY "inventory_movements_select_roles"
  ON public.inventory_movements FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','hr','operations','head_barista','roaster']));
CREATE POLICY "inventory_movements_insert_roles"
  ON public.inventory_movements FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "inventory_movements_update_roles"
  ON public.inventory_movements FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "inventory_movements_delete_roles"
  ON public.inventory_movements FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']));

-- =============================================================
-- 21. INVENTORY MOVEMENTS — add 'pickup' type
--    Faisaliyah cafe pulls roasted beans straight off the roaster
--    shelf without a transfer event. Distinct from 'sale'
--    (storefront retail) and 'transfer' (out to Khobar/Rayyan).
-- =============================================================
ALTER TABLE public.inventory_movements
  DROP CONSTRAINT IF EXISTS inventory_movements_type_check;
ALTER TABLE public.inventory_movements
  ADD CONSTRAINT inventory_movements_type_check
  CHECK (type IN ('adjust','roast','transfer','restock','sale','pickup','other'));

-- =============================================================
-- 22. OPERATIONS — approve/reject leave requests
--    SELECT on attendance/leave_requests was already authenticated
--    so team-wide visibility needs no policy change — the JS UI
--    gate was what hid the "All" tabs from non-HR roles. That
--    gate now also lets Operations in.
--
--    For approvals: direct UPDATE on leave_requests + employees
--    stays admin/hr only. Operations approves via this RPC, which
--    runs SECURITY DEFINER and atomically updates both rows
--    (employee balance decrement would otherwise be blocked by
--    the strict employees UPDATE policy).
-- =============================================================
CREATE OR REPLACE FUNCTION public.decide_leave_request(
  p_id uuid,
  p_decision text
)
RETURNS public.leave_requests
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_req public.leave_requests;
  v_bal_field text;
  v_caller_id uuid;
BEGIN
  IF NOT public.has_role(ARRAY['admin','hr','operations']) THEN
    RAISE EXCEPTION 'Not authorized to decide leave requests';
  END IF;

  IF p_decision NOT IN ('approved','rejected') THEN
    RAISE EXCEPTION 'Decision must be approved or rejected';
  END IF;

  SELECT id INTO v_caller_id
  FROM public.employees
  WHERE user_id = auth.uid()
  LIMIT 1;

  UPDATE public.leave_requests
     SET status = p_decision,
         decided_by = v_caller_id,
         decided_at = now()
   WHERE id = p_id
  RETURNING * INTO v_req;

  IF v_req.id IS NULL THEN
    RAISE EXCEPTION 'Leave request % not found', p_id;
  END IF;

  IF p_decision = 'approved' THEN
    v_bal_field := 'leave_' || v_req.leave_type;
    EXECUTE format(
      'UPDATE public.employees SET %I = GREATEST(0, COALESCE(%I,0) - $1) WHERE id = $2',
      v_bal_field, v_bal_field
    ) USING v_req.days, v_req.employee_id;
  END IF;

  RETURN v_req;
END;
$$;

GRANT EXECUTE ON FUNCTION public.decide_leave_request(uuid, text) TO authenticated;

-- =============================================================
-- 23. SUPPLIERS (admin / head_barista / roaster manage)
--     Promotes the legacy `inventory_items.supplier` text column to
--     a first-class entity so contact info can be stored centrally
--     and items can reference suppliers by id. The legacy `supplier`
--     text column is kept for backwards compatibility; new items
--     pick from the suppliers list via supplier_id.
--     SELECT mirrors inventory_items SELECT (admin/hr/operations/
--     head_barista/roaster). Writes are admin/head_barista/roaster.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.suppliers (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  contact_name  text,
  phone         text,
  email         text,
  notes         text,
  created_by    uuid references public.employees(id),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS suppliers_name_idx ON public.suppliers(LOWER(name));

CREATE OR REPLACE FUNCTION public.touch_suppliers_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS suppliers_touch_updated_at ON public.suppliers;
CREATE TRIGGER suppliers_touch_updated_at
  BEFORE UPDATE ON public.suppliers
  FOR EACH ROW EXECUTE FUNCTION public.touch_suppliers_updated_at();

ALTER TABLE public.suppliers ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'suppliers'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "suppliers_select_roles"
  ON public.suppliers FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','hr','operations','head_barista','roaster']));
CREATE POLICY "suppliers_insert_roles"
  ON public.suppliers FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "suppliers_update_roles"
  ON public.suppliers FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "suppliers_delete_roles"
  ON public.suppliers FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']));

-- Add the FK column on inventory_items. Nullable; legacy `supplier`
-- text column stays put as a fallback so old rows still render.
ALTER TABLE public.inventory_items
  ADD COLUMN IF NOT EXISTS supplier_id uuid REFERENCES public.suppliers(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS inventory_items_supplier_id_idx ON public.inventory_items(supplier_id);

-- =============================================================
-- 24. SUPPLIERS — Phase 2: backfill legacy text & drop column
--     Phase 1 (block 23) added the suppliers table and a nullable
--     supplier_id FK on inventory_items, but kept the old free-text
--     `supplier` column as a fallback display. Phase 2 walks that
--     legacy column, creates / matches a suppliers row per distinct
--     non-empty name (case-insensitive), points each item's new
--     supplier_id at the right row, and then drops the legacy
--     column.
--
--     Wrapped in a DO block guarded on the column's existence so
--     re-runs after the drop are no-ops (fully idempotent).
-- =============================================================
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'inventory_items'
      AND column_name = 'supplier'
  ) THEN
    -- 1. Create supplier rows for any legacy text without a match.
    --    DISTINCT ON picks one canonical case per LOWER(trim(name))
    --    key so case-variants don't insert as duplicates.
    INSERT INTO public.suppliers (name)
    SELECT legacy.canon_name
    FROM (
      SELECT DISTINCT ON (LOWER(trim(supplier)))
        trim(supplier) AS canon_name
      FROM public.inventory_items
      WHERE supplier IS NOT NULL
        AND trim(supplier) <> ''
      ORDER BY LOWER(trim(supplier)), trim(supplier)
    ) AS legacy
    WHERE NOT EXISTS (
      SELECT 1 FROM public.suppliers s
      WHERE LOWER(s.name) = LOWER(legacy.canon_name)
    );

    -- 2. Link items to suppliers by case-insensitive name match.
    --    Skip items that already have a supplier_id set (from
    --    post-Phase-1 picks via the dropdown).
    UPDATE public.inventory_items ii
    SET supplier_id = s.id
    FROM public.suppliers s
    WHERE ii.supplier_id IS NULL
      AND ii.supplier IS NOT NULL
      AND trim(ii.supplier) <> ''
      AND LOWER(s.name) = LOWER(trim(ii.supplier));

    -- 3. Drop the legacy column. After this point the inventory
    --    items only carry supplier_id, the FK is the single source
    --    of truth.
    ALTER TABLE public.inventory_items DROP COLUMN supplier;
  END IF;
END $$;

-- =============================================================
-- 25. MAINTENANCE — photo attachment columns
--     Adds optional photo fields to maintenance_requests so a
--     reporter can attach an image of the broken thing (data URL
--     stored inline, same pattern as receipts/archive_documents).
--     RLS already covers the table; no policy changes needed.
-- =============================================================
ALTER TABLE public.maintenance_requests
  ADD COLUMN IF NOT EXISTS photo_mime     text,
  ADD COLUMN IF NOT EXISTS photo_size     integer,
  ADD COLUMN IF NOT EXISTS photo_data_url text;

-- =============================================================
-- 26. ASSETS (admin / maintenance manage)
--     Promotes the legacy `maintenance_requests.asset` text column
--     to a first-class entity so equipment / machines can carry
--     serial numbers, warranty dates, branch, and notes. Maintenance
--     requests link to an asset via a new nullable asset_id FK.
--     Phase 1 only: the legacy free-text `asset` column on
--     maintenance_requests is kept as fallback display.
--
--     SELECT is broad (anyone who can see requests can see asset
--     names so dropdowns work). Writes are admin / maintenance.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.assets (
  id                uuid primary key default gen_random_uuid(),
  name              text not null,
  category          text,
  branch            text,
  serial_number     text,
  purchased_at      date,
  warranty_expires  date,
  notes             text,
  created_by        uuid references public.employees(id),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS assets_name_idx     ON public.assets(LOWER(name));
CREATE INDEX IF NOT EXISTS assets_category_idx ON public.assets(category);
CREATE INDEX IF NOT EXISTS assets_branch_idx   ON public.assets(branch);

CREATE OR REPLACE FUNCTION public.touch_assets_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS assets_touch_updated_at ON public.assets;
CREATE TRIGGER assets_touch_updated_at
  BEFORE UPDATE ON public.assets
  FOR EACH ROW EXECUTE FUNCTION public.touch_assets_updated_at();

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'assets'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "assets_select_roles"
  ON public.assets FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','hr','operations','maintenance','head_barista','roaster']));
CREATE POLICY "assets_insert_roles"
  ON public.assets FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','maintenance']));
CREATE POLICY "assets_update_roles"
  ON public.assets FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','maintenance']))
  WITH CHECK (public.has_role(ARRAY['admin','maintenance']));
CREATE POLICY "assets_delete_roles"
  ON public.assets FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','maintenance']));

-- FK column on maintenance_requests. Nullable; legacy `asset` text
-- column stays put as fallback so old rows still render.
ALTER TABLE public.maintenance_requests
  ADD COLUMN IF NOT EXISTS asset_id uuid REFERENCES public.assets(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS maintenance_requests_asset_id_idx ON public.maintenance_requests(asset_id);

-- =============================================================
-- 27. ASSETS — Phase 2: backfill legacy text & drop column
--     Phase 1 (block 26) added the assets table and a nullable
--     asset_id FK on maintenance_requests, but kept the old free-
--     text `asset` column as a fallback display. Phase 2 walks
--     that legacy column, creates / matches an assets row per
--     distinct non-empty name (case-insensitive), points each
--     request's asset_id at the right row, and then drops the
--     legacy column.
--
--     Wrapped in a DO block guarded on the column's existence so
--     re-runs after the drop are no-ops (fully idempotent).
-- =============================================================
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'maintenance_requests'
      AND column_name = 'asset'
  ) THEN
    -- 1. Create asset rows for any legacy text without a match.
    --    DISTINCT ON picks one canonical case per LOWER(trim(name))
    --    key so case-variants don't insert as duplicates.
    INSERT INTO public.assets (name)
    SELECT legacy.canon_name
    FROM (
      SELECT DISTINCT ON (LOWER(trim(asset)))
        trim(asset) AS canon_name
      FROM public.maintenance_requests
      WHERE asset IS NOT NULL
        AND trim(asset) <> ''
      ORDER BY LOWER(trim(asset)), trim(asset)
    ) AS legacy
    WHERE NOT EXISTS (
      SELECT 1 FROM public.assets a
      WHERE LOWER(a.name) = LOWER(legacy.canon_name)
    );

    -- 2. Link requests to assets by case-insensitive name match.
    --    Skip requests that already have an asset_id set (from
    --    post-Phase-1 picks via the dropdown).
    UPDATE public.maintenance_requests mr
    SET asset_id = a.id
    FROM public.assets a
    WHERE mr.asset_id IS NULL
      AND mr.asset IS NOT NULL
      AND trim(mr.asset) <> ''
      AND LOWER(a.name) = LOWER(trim(mr.asset));

    -- 3. Drop the legacy column. asset_id is the single source of
    --    truth from here on.
    ALTER TABLE public.maintenance_requests DROP COLUMN asset;
  END IF;
END $$;

-- =============================================================
-- 28. DROP LEGACY is_admin COLUMN
--     system_role has been the source of truth since block 13.
--     The legacy boolean is_admin column was kept as a fallback
--     (defence in depth). Now: rewrite every SQL function that
--     still reads it, rewrite the signup trigger that still
--     writes it, and drop the column.
--
--     Each statement is individually idempotent. Order matters:
--       (a) Resync any drift first (guarded on column existence).
--       (b) Rewrite every function/trigger that references the
--           column so they no longer touch it.
--       (c) Drop the sync trigger + its function that only
--           existed to keep system_role and is_admin in sync.
--       (d) Drop the column.
-- =============================================================

-- (a) Resync drift. Any row with is_admin=true but a non-admin
--     system_role gets promoted. Inverse (is_admin=false but
--     system_role='admin') is intentionally NOT downgraded —
--     system_role is the new truth, preserve admin if either says so.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'employees' AND column_name = 'is_admin'
  ) THEN
    UPDATE public.employees
       SET system_role = 'admin'
     WHERE is_admin = true
       AND system_role IS DISTINCT FROM 'admin';
  END IF;
END $$;

-- (b1) Signup trigger: insert system_role instead of is_admin.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  is_first       boolean;
  invited_emp_id uuid;
  meta           jsonb;
  new_emp_id     uuid;
  signup_branch  text;
BEGIN
  meta := COALESCE(NEW.raw_user_meta_data, '{}'::jsonb);
  signup_branch := NULLIF(TRIM(COALESCE(meta->>'branch', '')), '');

  IF EXISTS (SELECT 1 FROM public.employees WHERE user_id = NEW.id) THEN
    RETURN NEW;
  END IF;

  SELECT id INTO invited_emp_id
    FROM public.employees
   WHERE LOWER(email) = LOWER(NEW.email)
     AND user_id IS NULL
   ORDER BY hire_date NULLS LAST
   LIMIT 1;

  IF invited_emp_id IS NOT NULL THEN
    UPDATE public.employees
       SET user_id   = NEW.id,
           phone     = COALESCE(NULLIF(TRIM(phone),'')    , NULLIF(TRIM(meta->>'phone'),'')),
           job_title = COALESCE(NULLIF(TRIM(job_title),''), NULLIF(TRIM(meta->>'role'),''),  job_title)
     WHERE id = invited_emp_id;

    IF signup_branch IS NOT NULL THEN
      INSERT INTO public.employee_extras (employee_id, branch)
      VALUES (invited_emp_id, signup_branch)
      ON CONFLICT (employee_id) DO UPDATE
        SET branch = COALESCE(NULLIF(TRIM(public.employee_extras.branch),''), EXCLUDED.branch);
    END IF;

    RETURN NEW;
  END IF;

  SELECT NOT EXISTS (SELECT 1 FROM public.employees) INTO is_first;

  INSERT INTO public.employees (
    user_id, email, first_name, last_name, phone,
    system_role, status, job_title, department, hire_date, salary
  ) VALUES (
    NEW.id,
    NEW.email,
    COALESCE(meta->>'first_name', ''),
    COALESCE(meta->>'last_name', ''),
    NULLIF(TRIM(meta->>'phone'), ''),
    CASE WHEN is_first THEN 'admin'  ELSE 'employee' END,
    CASE WHEN is_first THEN 'active' ELSE 'pending'  END,
    COALESCE(NULLIF(TRIM(meta->>'role'), ''), CASE WHEN is_first THEN 'Admin'      ELSE 'Employee' END),
    COALESCE(NULLIF(TRIM(meta->>'role'), ''), CASE WHEN is_first THEN 'Management' ELSE 'General'  END),
    CURRENT_DATE,
    0
  )
  RETURNING id INTO new_emp_id;

  IF signup_branch IS NOT NULL AND new_emp_id IS NOT NULL THEN
    INSERT INTO public.employee_extras (employee_id, branch)
    VALUES (new_emp_id, signup_branch)
    ON CONFLICT (employee_id) DO UPDATE SET branch = EXCLUDED.branch;
  END IF;

  RETURN NEW;
END;
$$;

-- (b2) is_admin() reads only system_role.
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.employees
    WHERE user_id = auth.uid()
      AND system_role = 'admin'
  );
$$;

-- (b3) has_role() drops the legacy fallback. system_role has a
--      DEFAULT 'employee' on the column, so NULL shouldn't occur,
--      but we coalesce defensively to 'employee' just in case.
CREATE OR REPLACE FUNCTION public.has_role(roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.employees
    WHERE user_id = auth.uid()
      AND COALESCE(system_role, 'employee') = ANY(roles)
  );
$$;

-- (b4) Self-change rule: only system_role is protected now.
CREATE OR REPLACE FUNCTION public.enforce_employee_update_rules()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.user_id = auth.uid()
     AND NEW.system_role IS DISTINCT FROM OLD.system_role THEN
    RAISE EXCEPTION 'You cannot change your own role';
  END IF;
  IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'user_id is immutable';
  END IF;
  RETURN NEW;
END;
$$;

-- (c) Drop the BEFORE-INSERT trigger that copied is_admin -> system_role
--     and its function — both become dead with the column gone.
DROP TRIGGER  IF EXISTS sync_employee_system_role_trigger ON public.employees;
DROP FUNCTION IF EXISTS public.sync_employee_system_role();

-- (d) Tighten system_role to NOT NULL now that it's the only source of truth.
--     Any straggler with NULL gets the 'employee' default first so the
--     constraint can be added without error. Idempotent on re-runs.
UPDATE public.employees SET system_role = 'employee' WHERE system_role IS NULL;
ALTER TABLE public.employees ALTER COLUMN system_role SET NOT NULL;

-- (e) Cheap insurance for the RLS hot path. is_admin() and has_role()
--     both filter public.employees by user_id, called by every RLS-gated
--     operation. The table has no PK-related index on this column.
CREATE INDEX IF NOT EXISTS employees_user_id_idx ON public.employees(user_id);

-- (f) Drop the column. After this, system_role is the single source of truth.
ALTER TABLE public.employees DROP COLUMN IF EXISTS is_admin;

-- =============================================================
-- 29. MAINTENANCE — thumbnail column for photo attachments
--     PR #51 added inline data-URL photos on maintenance_requests.
--     At a few dozen requests each ~1 MB, the bulk load pulls tens
--     of MB on every page visit. This adds a small JPEG thumbnail
--     (generated client-side at upload time, ~5-15 KB) so the list
--     can render thumbnails cheaply. The bulk load query is updated
--     to skip the full photo_data_url; the full image is fetched
--     on demand when the user clicks a thumbnail.
--
--     Pre-migration rows have photo_data_url but a NULL thumb. The
--     UI shows a placeholder + still fetches the full on click.
-- =============================================================
ALTER TABLE public.maintenance_requests
  ADD COLUMN IF NOT EXISTS photo_thumb_data_url text;

-- =============================================================
-- 30. RECEIPTS — persist OCR-extracted text
--     PR #48 added Tesseract.js OCR. The extracted text was used
--     to pre-fill vendor/date/amount on the Add Receipt modal but
--     wasn't saved with the receipt. This column persists the raw
--     OCR output so the eye-icon preview on a saved receipt can
--     show the extracted text (per user request), not just the
--     photo. Legacy receipts have NULL — UI falls back to the
--     photo preview path for those.
-- =============================================================
ALTER TABLE public.receipts
  ADD COLUMN IF NOT EXISTS ocr_text text;

-- =============================================================
-- 31. RECEIPTS — structured extraction blob (jsonb)
--     Holds merchant address/phone/tax id, receipt no, time,
--     subtotal, tax, payment method, card type, and line items
--     for the rich preview. Top-level columns still own the
--     searchable fields. NULL on legacy / Tesseract receipts.
-- =============================================================
ALTER TABLE public.receipts
  ADD COLUMN IF NOT EXISTS extracted_data jsonb;

-- =============================================================
-- 32. DAILY COUNT — item catalog (cafe-floor barista daily sheet)
--     Distinct from inventory_items (a single current-qty model).
--     Daily count is a per-branch, per-day time series of on-hand
--     counts for fast-moving perishables / beans / pastries. This
--     table is the branch-agnostic catalog of WHAT gets counted;
--     the numbers live in daily_counts (block 33). tracks_waste =
--     pastry-style items that also log a daily expired/wasted
--     figure. SELECT broad (admin/head_barista/barista/operations);
--     catalog writes admin/head_barista only.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.daily_count_items (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  unit          text not null default 'pcs',     -- pcs | g | kg
  category      text not null default 'other',   -- milk|pastry|espresso|v60|retail_250g|premium|boxes|other
  tracks_waste  boolean not null default false,
  sort_order    int not null default 0,
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS daily_count_items_sort_idx ON public.daily_count_items(sort_order);

ALTER TABLE public.daily_count_items ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='daily_count_items'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "dci_select_floor_or_ops"
  ON public.daily_count_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']));
CREATE POLICY "dci_insert_admin_or_head_barista"
  ON public.daily_count_items FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "dci_update_admin_or_head_barista"
  ON public.daily_count_items FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "dci_delete_admin_or_head_barista"
  ON public.daily_count_items FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- Seed the Rayyan daily-sheet catalog. Idempotent: only fires when
-- the table is empty, so re-running the file never duplicates.
INSERT INTO public.daily_count_items (name, unit, category, tracks_waste, sort_order)
SELECT v.name, v.unit, v.category, v.tracks_waste, v.sort_order
FROM (VALUES
  ('Full Fat',            'pcs','milk',        false, 10),
  ('Low Fat',             'pcs','milk',        false, 20),
  ('Almond Milk',         'pcs','milk',        false, 30),
  ('Free Lactose',        'pcs','milk',        false, 40),
  ('Coconut Milk',        'pcs','milk',        false, 50),
  ('Naqi Water',          'pcs','milk',        false, 60),
  ('Cookies',             'pcs','pastry',      true,  70),
  ('Crunchy',             'pcs','pastry',      true,  80),
  ('Brownies',            'pcs','pastry',      true,  90),
  ('Crunchy Cake',        'pcs','pastry',      true, 100),
  ('Lemon Cake',          'pcs','pastry',      true, 110),
  ('Tiramisu',            'pcs','pastry',      true, 120),
  ('Marble Cake',         'pcs','pastry',      true, 130),
  ('Colombia ESP',        'kg', 'espresso',    false,140),
  ('Guji ESP',            'kg', 'espresso',    false,150),
  ('V60 Manos',           'kg', 'v60',         false,160),
  ('V60 Ethiopia',        'kg', 'v60',         false,170),
  ('V60 Brazil',          'kg', 'v60',         false,180),
  ('V60 Grape',           'kg', 'v60',         false,190),
  ('V60 Panama',          'kg', 'v60',         false,200),
  ('V60 Beni Suliman',    'kg', 'v60',         false,210),
  ('V60 Chel-Chel',       'kg', 'v60',         false,220),
  ('V60 Candy',           'kg', 'v60',         false,230),
  ('Ethiopia Gadeb',      'kg', 'v60',         false,240),
  ('C.O.D-Oromio',        'kg', 'v60',         false,250),
  ('250g Ethiopia',       'pcs','retail_250g', false,260),
  ('250g Brazil',         'pcs','retail_250g', false,270),
  ('250g Narino',         'pcs','retail_250g', false,280),
  ('250g Oromio',         'pcs','retail_250g', false,290),
  ('250g Manos',          'pcs','retail_250g', false,300),
  ('Premium Beni Suliman','pcs','premium',     false,310),
  ('Premium Grape',       'pcs','premium',     false,320),
  ('Premium Panama',      'pcs','premium',     false,330),
  ('Premium Chel-Chel',   'pcs','premium',     false,340),
  ('Offer Box (Offline)', 'pcs','boxes',       false,350),
  ('Offer Box (Online)',  'pcs','boxes',       false,360),
  ('Drip Bag (E)',        'pcs','boxes',       false,370),
  ('Drip Bag (B)',        'pcs','boxes',       false,380),
  ('Drip Bag (C)',        'pcs','boxes',       false,390)
) AS v(name,unit,category,tracks_waste,sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.daily_count_items);

-- =============================================================
-- 33. DAILY COUNT — recorded numbers (per item, per branch, per day)
--     One row per (item_id, branch, count_date); the page upserts
--     on that key so re-saving a day overwrites cleanly. qty =
--     on-hand count, waste_qty = expired/wasted that day (pastry
--     items), note = free text ("shortage 1"). Loaded on demand
--     per branch+month — NOT bulk-loaded (the series grows
--     unbounded; same perf discipline as attendance/maintenance).
--     SELECT + write admin/head_barista/barista (barista needs
--     write — the daily count is literally their job); destructive
--     delete stays admin/head_barista.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.daily_counts (
  id           uuid primary key default gen_random_uuid(),
  item_id      uuid not null references public.daily_count_items(id) ON DELETE CASCADE,
  branch       text not null,
  count_date   date not null,
  qty          numeric(12,2),
  waste_qty    numeric(12,2),
  note         text,
  recorded_by  uuid references public.employees(id),
  recorded_at  timestamptz not null default now(),
  UNIQUE (item_id, branch, count_date)
);
CREATE INDEX IF NOT EXISTS daily_counts_branch_date_idx ON public.daily_counts(branch, count_date);

ALTER TABLE public.daily_counts ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='daily_counts'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "dc_select_floor_or_ops"
  ON public.daily_counts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']));
CREATE POLICY "dc_insert_floor"
  ON public.daily_counts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "dc_update_floor"
  ON public.daily_counts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "dc_delete_admin_or_head_barista"
  ON public.daily_counts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- =============================================================
-- 34. DAILY COUNT — received_qty (mid-day deliveries / transfers)
--     Stock that arrived during the day, recorded alongside the
--     end-of-day count. Lets the page compute true consumption:
--     used = yesterday + received − today (without it, a restock
--     makes usage look negative). Nullable — legacy rows = no
--     receipt that day. No RLS change (same row, existing policies).
-- =============================================================
ALTER TABLE public.daily_counts
  ADD COLUMN IF NOT EXISTS received_qty numeric(12,2);

-- =============================================================
-- 35. ROASTER → DAILY COUNT mapping (dc_map)
--     Per roaster bean: which daily-count item each pack form
--     becomes when transferred to a cafe. jsonb keyed by pack:
--       { "loose": <dc_item_uuid>, "250": <uuid>, "125": <uuid> }
--     Any key may be absent/null (that pack just doesn't auto-post).
--     No RLS change — existing inventory_items policies cover it.
-- =============================================================
ALTER TABLE public.inventory_items
  ADD COLUMN IF NOT EXISTS dc_map jsonb;

-- =============================================================
-- 36. INCOMING TRANSFERS (receiver-confirms model)
--     A roaster dispatch creates a pending row for the destination
--     branch. The branch confirms it during their daily count —
--     qty pre-filled from dispatched_qty but editable; confirming
--     writes received_qty into daily_counts and stamps this row.
--     dispatched vs confirmed surfaces in-transit variance.
--     Quantities are in the target dc item's unit (pcs for
--     250g/125g packs, kg for loose). status: pending|confirmed|
--     rejected. SELECT broad (floor + ops); insert by whoever logs
--     roaster transfers (admin/head_barista); confirm/update by the
--     receiving floor (admin/head_barista/barista); delete admin/
--     head_barista.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.incoming_transfers (
  id                uuid primary key default gen_random_uuid(),
  dc_item_id        uuid not null references public.daily_count_items(id) ON DELETE CASCADE,
  to_branch         text not null,
  from_branch       text,
  transfer_date     date not null,
  pack              text not null,            -- loose | 250 | 125
  dispatched_qty    numeric(12,2) not null,
  status            text not null default 'pending',  -- pending | confirmed | rejected
  confirmed_qty     numeric(12,2),
  source_item_id    uuid references public.inventory_items(id) ON DELETE SET NULL,
  source_movement_id uuid references public.inventory_movements(id) ON DELETE SET NULL,
  created_by        uuid references public.employees(id),
  created_at        timestamptz not null default now(),
  confirmed_by      uuid references public.employees(id),
  confirmed_at      timestamptz
);
CREATE INDEX IF NOT EXISTS incoming_transfers_branch_status_idx
  ON public.incoming_transfers(to_branch, status);
CREATE INDEX IF NOT EXISTS incoming_transfers_date_idx
  ON public.incoming_transfers(transfer_date);

ALTER TABLE public.incoming_transfers ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='incoming_transfers'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "it_select_floor_or_ops"
  ON public.incoming_transfers FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations','roaster']));
CREATE POLICY "it_insert_transfer_loggers"
  ON public.incoming_transfers FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
-- Floor can only act on a row while it's still pending — once
-- confirmed/rejected it's immutable to them (no post-hoc qty edits
-- or re-confirms). Admins clean up via the delete policy.
CREATE POLICY "it_update_floor"
  ON public.incoming_transfers FOR UPDATE TO authenticated
  USING (status = 'pending' AND public.has_role(ARRAY['admin','head_barista','barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "it_delete_admin_or_head_barista"
  ON public.incoming_transfers FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- =============================================================
-- 37. INCOMING TRANSFERS — elevated reversal (Phase 2.1)
--     admin/head_barista may update an incoming_transfers row in
--     ANY status (not just pending), so deleting the source roaster
--     transfer can flip a confirmed row → 'reversed' and a pending
--     one → 'rejected'. The pending-only it_update_floor policy
--     stays for the normal barista confirm/reject flow; RLS is
--     permissive (OR) so both coexist. ('reversed' is just another
--     text value — no CHECK constraint on status.)
-- =============================================================
DROP POLICY IF EXISTS "it_update_admin_or_head_barista" ON public.incoming_transfers;
CREATE POLICY "it_update_admin_or_head_barista"
  ON public.incoming_transfers FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));

-- =============================================================
-- DONE.
--
-- Verification queries you can run in the SQL editor:
--   SELECT tablename, policyname, cmd
--     FROM pg_policies
--    WHERE schemaname='public'
--    ORDER BY tablename, cmd;
--
--   SELECT * FROM pg_trigger WHERE tgname IN
--     ('on_auth_user_created','enforce_employee_update_rules_trigger');
-- =============================================================
