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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
  USING (public.has_role(ARRAY['admin','operations']));

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
-- 38. WEEKLY COUNT — item catalog (storeroom consumables sheet)
--     Parallel to daily_count_items (block 32) but a weekly
--     cadence and a different catalog: cups/lids, coffee bags,
--     cleaning, paper goods, brew gear, retail boxes — the
--     "WEEKLY INVENTORY" tab of the branch sheet. No waste column
--     (the weekly sheet only tracks on-hand + purchase/transfer).
--     SELECT broad (admin/head_barista/barista/operations);
--     catalog writes admin/head_barista only.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.weekly_count_items (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  unit          text not null default 'pcs',     -- pcs | g | kg
  category      text not null default 'other',   -- cups_lids|coffee_bags|pantry|paper|cleaning|hygiene|brew_gear|retail|other
  sort_order    int not null default 0,
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS weekly_count_items_sort_idx ON public.weekly_count_items(sort_order);

ALTER TABLE public.weekly_count_items ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='weekly_count_items'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "wci_select_floor_or_ops"
  ON public.weekly_count_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']));
CREATE POLICY "wci_insert_admin_or_head_barista"
  ON public.weekly_count_items FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "wci_update_admin_or_head_barista"
  ON public.weekly_count_items FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "wci_delete_admin_or_head_barista"
  ON public.weekly_count_items FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- Seed the RAYYAN weekly-inventory catalog. Idempotent: only
-- fires when the table is empty, so re-running never duplicates.
INSERT INTO public.weekly_count_items (name, unit, category, sort_order)
SELECT v.name, v.unit, v.category, v.sort_order
FROM (VALUES
  ('7oz Cups',          'pcs','cups_lids',    10),
  ('9oz Cups',          'pcs','cups_lids',    20),
  ('12oz Cups',         'pcs','cups_lids',    30),
  ('Plastic Cups',      'pcs','cups_lids',    40),
  ('7oz Lids',          'pcs','cups_lids',    50),
  ('9oz Lids',          'pcs','cups_lids',    60),
  ('12oz Lids',         'pcs','cups_lids',    70),
  ('Red Lids',          'pcs','cups_lids',    80),
  ('2 Cup Holder',      'pcs','cups_lids',    90),
  ('4 Cup Holder',      'pcs','cups_lids',   100),
  ('125g Bag',          'pcs','coffee_bags', 110),
  ('250g Bag',          'pcs','coffee_bags', 120),
  ('2.5kg Bag',         'pcs','coffee_bags', 130),
  ('36 Inch Bag',       'pcs','coffee_bags', 140),
  ('Matcha Powder',     'g',  'pantry',      150),
  ('Sugar',             'kg', 'pantry',      160),
  ('Maple Syrup',       'pcs','pantry',      170),
  ('Choco Powder',      'g',  'pantry',      180),
  ('Choco Chips White', 'g',  'pantry',      190),
  ('Napkins',           'pcs','paper',       200),
  ('Tissue Roll',       'pcs','paper',       210),
  ('Mada Roll',         'pcs','paper',       220),
  ('Cashier Roll',      'pcs','paper',       230),
  ('Barista Wipes',     'pcs','cleaning',    240),
  ('Blue Micro Fibre',  'pcs','cleaning',    250),
  ('Naqi Water',        'pcs','cleaning',    260),
  ('80 Gallon Bag',     'pcs','cleaning',    270),
  ('30 Gallon Bag',     'pcs','cleaning',    280),
  ('Gloves (L)',        'pcs','hygiene',     290),
  ('Gloves (M)',        'pcs','hygiene',     300),
  ('Facemask',          'pcs','hygiene',     310),
  ('Ideio Kettle',      'pcs','brew_gear',   320),
  ('V60 Filter',        'pcs','brew_gear',   330),
  ('C.O.D Filters',     'pcs','brew_gear',   340),
  ('C.O.D Box',         'pcs','brew_gear',   350),
  ('Straws',            'pcs','brew_gear',   360),
  ('Wooden Stirrers',   'pcs','brew_gear',   370),
  ('Blue Cafec',        'pcs','brew_gear',   380),
  ('Cafec Powder',      'pcs','brew_gear',   390),
  ('Aeropress',         'pcs','brew_gear',   400),
  ('Stickers',          'pcs','retail',      410),
  ('Offer Box',         'pcs','retail',      420),
  ('Carton',            'pcs','retail',      430),
  ('Drip Box (E)',      'pcs','retail',      440),
  ('Drip Box (C)',      'pcs','retail',      450),
  ('Drip Box (B)',      'pcs','retail',      460),
  ('Envelope',          'pcs','retail',      470)
) AS v(name,unit,category,sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.weekly_count_items);

-- =============================================================
-- 39. WEEKLY COUNT — recorded numbers (per item, per branch, per week)
--     One row per (item_id, branch, week_start); week_start is the
--     Monday of that week. available_qty = on-hand at count time,
--     purchased_qty = what was bought/transferred in during the
--     week (the sheet's "PURCHASE/TRANSFER" column). The page
--     upserts on that key. Consumed = opening + purchased −
--     closing, derived in the UI. Loaded on demand per branch+
--     month — NOT bulk-loaded (the series grows unbounded; same
--     perf discipline as daily_counts/attendance). SELECT + write
--     admin/head_barista/barista; delete admin/head_barista.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.weekly_counts (
  id            uuid primary key default gen_random_uuid(),
  item_id       uuid not null references public.weekly_count_items(id) ON DELETE CASCADE,
  branch        text not null,
  week_start    date not null,
  available_qty numeric(12,2),
  purchased_qty numeric(12,2),
  note          text,
  recorded_by   uuid references public.employees(id),
  recorded_at   timestamptz not null default now(),
  UNIQUE (item_id, branch, week_start)
);
CREATE INDEX IF NOT EXISTS weekly_counts_branch_week_idx ON public.weekly_counts(branch, week_start);

ALTER TABLE public.weekly_counts ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='weekly_counts'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "wc_select_floor_or_ops"
  ON public.weekly_counts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']));
CREATE POLICY "wc_insert_floor"
  ON public.weekly_counts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "wc_update_floor"
  ON public.weekly_counts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "wc_delete_admin_or_head_barista"
  ON public.weekly_counts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- =============================================================
-- 40. EXPIRY CHECKLIST — item catalog (perishables checked weekly)
--     The "EXPIRED ITEMS CHECKLIST" tab of the branch sheet: a
--     small fixed list of perishables whose printed expiry date is
--     logged each week so staff pull stock before it's served.
--     Distinct from daily/weekly count (those track quantity; this
--     tracks the date stamped on the unit). Flat list (~11 items),
--     no category. SELECT broad (admin/head_barista/barista/
--     operations); catalog writes admin/head_barista only.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.expiry_check_items (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  sort_order    int not null default 0,
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS expiry_check_items_sort_idx ON public.expiry_check_items(sort_order);

ALTER TABLE public.expiry_check_items ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='expiry_check_items'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "eci_select_floor_or_ops"
  ON public.expiry_check_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']));
CREATE POLICY "eci_insert_admin_or_head_barista"
  ON public.expiry_check_items FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "eci_update_admin_or_head_barista"
  ON public.expiry_check_items FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "eci_delete_admin_or_head_barista"
  ON public.expiry_check_items FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- Seed the RAYYAN expiry-checklist catalog. Idempotent: only fires
-- when the table is empty, so re-running never duplicates.
INSERT INTO public.expiry_check_items (name, sort_order)
SELECT v.name, v.sort_order
FROM (VALUES
  ('Full Fat',          10),
  ('Low Fat',           20),
  ('Free Lactose',      30),
  ('Coconut Milk',      40),
  ('Almond Milk',       50),
  ('Maple Syrup',       60),
  ('Choco Chips',       70),
  ('Chocolate Powder',  80),
  ('Chocolate Flakes',  90),
  ('Matcha Powder',    100),
  ('Chocolate Bar',    110)
) AS v(name,sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.expiry_check_items);

-- =============================================================
-- 41. EXPIRY CHECKLIST — recorded checks (per item, branch, week)
--     One row per (item_id, branch, week_start); week_start is the
--     Monday of the checked week (same week model as weekly_counts).
--     expiry_date = the date printed on the stocked unit that week
--     (nullable: a row with only a note, or cleared, is allowed).
--     The page derives EXPIRED / EXPIRES SOON status from it.
--     Loaded on demand per branch+month — NOT bulk-loaded. SELECT +
--     write admin/head_barista/barista; delete admin/head_barista.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.expiry_checks (
  id            uuid primary key default gen_random_uuid(),
  item_id       uuid not null references public.expiry_check_items(id) ON DELETE CASCADE,
  branch        text not null,
  week_start    date not null,
  expiry_date   date,
  note          text,
  recorded_by   uuid references public.employees(id),
  recorded_at   timestamptz not null default now(),
  UNIQUE (item_id, branch, week_start)
);
CREATE INDEX IF NOT EXISTS expiry_checks_branch_week_idx ON public.expiry_checks(branch, week_start);

ALTER TABLE public.expiry_checks ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='expiry_checks'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "ec_select_floor_or_ops"
  ON public.expiry_checks FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']));
CREATE POLICY "ec_insert_floor"
  ON public.expiry_checks FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "ec_update_floor"
  ON public.expiry_checks FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "ec_delete_admin_or_head_barista"
  ON public.expiry_checks FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- =============================================================
-- 42. PER-ITEM REORDER THRESHOLD (low_at)
--     Replaces the crude universal LOW rule (≤2 pcs / ≤1 kg-g) in
--     Daily Count and Weekly Count with a configurable per-item
--     reorder point. NULL = fall back to the old unit-based default
--     (so un-configured / seeded items keep their current behaviour
--     — no backfill, no regression). OUT stays universal at qty ≤ 0
--     (zero stock is always out; not configurable). No RLS change —
--     existing *_count_items policies cover the new column.
-- =============================================================
ALTER TABLE public.daily_count_items
  ADD COLUMN IF NOT EXISTS low_at numeric(12,2);
ALTER TABLE public.weekly_count_items
  ADD COLUMN IF NOT EXISTS low_at numeric(12,2);

-- =============================================================
-- 43. BAKERY ROLE
--    Adds the 'bakery' system role for the central-bakery team that
--    produces finished goods (cookies, brownies, cakes) and tracks
--    raw-ingredient stock. They log daily per-branch transfer orders
--    and a stock/purchases sheet (those tables land in a later block
--    once the workflow is finalised). For now this just makes the
--    role assignable; the bakery user gets a dedicated dashboard.
-- =============================================================

-- Re-issue the system_role CHECK constraint with 'bakery' added.
-- (Latest re-issue wins when the idempotent file runs top-to-bottom.)
ALTER TABLE public.employees
  DROP CONSTRAINT IF EXISTS employees_system_role_chk;
ALTER TABLE public.employees
  ADD CONSTRAINT employees_system_role_chk
  CHECK (system_role IS NULL OR system_role IN (
    'admin','hr','operations','barista','head_barista','roaster',
    'accounting','maintenance','bakery','employee'
  ));

-- =============================================================
-- 44. BAKERY PRODUCTS — finished-goods catalog
--     The central bakery's finished products (cookies, brownies,
--     cakes) transferred daily to the branches. Branch-agnostic
--     catalog; the daily per-branch quantities live in
--     bakery_transfers (block 45). SELECT broad (admin/operations/
--     bakery); catalog writes admin/bakery only.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.bakery_products (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  sort_order    int not null default 0,
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS bakery_products_sort_idx ON public.bakery_products(sort_order);

ALTER TABLE public.bakery_products ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='bakery_products'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "bp_select_floor_or_ops"
  ON public.bakery_products FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','bakery']));
CREATE POLICY "bp_insert_admin_or_bakery"
  ON public.bakery_products FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bp_update_admin_or_bakery"
  ON public.bakery_products FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']))
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bp_delete_admin_or_bakery"
  ON public.bakery_products FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']));

-- Seed the bakery product catalog. Idempotent: only fires when the
-- table is empty, so re-running never duplicates.
INSERT INTO public.bakery_products (name, sort_order)
SELECT v.name, v.sort_order
FROM (VALUES
  ('Crunchy',       10),
  ('Cookies',       20),
  ('Brownies',      30),
  ('Crunchy Cake',  40),
  ('Lemon Cake',    50),
  ('Tiramisu',      60),
  ('Marble Cake',   70)
) AS v(name,sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.bakery_products);

-- =============================================================
-- 45. BAKERY TRANSFERS — daily finished-goods to branches
--     One row per (product_id, branch, transfer_date) = how many
--     of that product went to that branch that day. The page
--     upserts on that key; the monthly view sums per branch +
--     a grand total (mirrors the paper "MONTHLY TOTAL"). Loaded
--     on demand per month (all branches) — NOT bulk-loaded.
--     SELECT + write admin/bakery; SELECT also operations; delete
--     admin/bakery.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.bakery_transfers (
  id            uuid primary key default gen_random_uuid(),
  product_id    uuid not null references public.bakery_products(id) ON DELETE CASCADE,
  branch        text not null,
  transfer_date date not null,
  qty           numeric(12,2),
  recorded_by   uuid references public.employees(id),
  recorded_at   timestamptz not null default now(),
  UNIQUE (product_id, branch, transfer_date)
);
CREATE INDEX IF NOT EXISTS bakery_transfers_date_idx ON public.bakery_transfers(transfer_date);

ALTER TABLE public.bakery_transfers ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='bakery_transfers'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "bt_select_floor_or_ops"
  ON public.bakery_transfers FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','bakery']));
CREATE POLICY "bt_insert_admin_or_bakery"
  ON public.bakery_transfers FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bt_update_admin_or_bakery"
  ON public.bakery_transfers FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']))
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bt_delete_admin_or_bakery"
  ON public.bakery_transfers FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']));

-- =============================================================
-- 46. BAKERY INGREDIENTS — raw-ingredient catalog
--     The central bakery's raw ingredients (flour, sugar, butter,
--     chocolate, eggs…). Branch-agnostic catalog; the daily used
--     quantities live in bakery_stock (block 47). SELECT broad
--     (admin/operations/bakery); writes admin/bakery only.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.bakery_ingredients (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  sort_order    int not null default 0,
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS bakery_ingredients_sort_idx ON public.bakery_ingredients(sort_order);

ALTER TABLE public.bakery_ingredients ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='bakery_ingredients'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "bi_select_floor_or_ops"
  ON public.bakery_ingredients FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','bakery']));
CREATE POLICY "bi_insert_admin_or_bakery"
  ON public.bakery_ingredients FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bi_update_admin_or_bakery"
  ON public.bakery_ingredients FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']))
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bi_delete_admin_or_bakery"
  ON public.bakery_ingredients FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']));

-- Seed the bakery ingredient catalog. Idempotent: only fires when
-- the table is empty, so re-running never duplicates.
INSERT INTO public.bakery_ingredients (name, sort_order)
SELECT v.name, v.sort_order
FROM (VALUES
  ('Eggs',            10),
  ('Choc-Chips',      20),
  ('Choco Chip Dark', 30),
  ('Butter',          40),
  ('Cheese',          50),
  ('Vanilla Essence', 60),
  ('Lemon',           70),
  ('Coco Powder',     80),
  ('Flour',           90),
  ('Sugar',          100),
  ('Icing Sugar',    110),
  ('Brown Sugar',    120),
  ('Corn Starch',    130),
  ('Baking Powder',  140),
  ('Baking Soda',    150),
  ('Lady Finger',    160),
  ('Condensed Milk', 170),
  ('Oil',            180),
  ('Whipping Cream', 190),
  ('Blueberry Filling', 200),
  ('Herco Flakes',   210),
  ('Bananas',        220)
) AS v(name,sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.bakery_ingredients);

-- =============================================================
-- 47. BAKERY STOCK — daily raw-ingredient usage
--     One row per (ingredient_id, stock_date) = how much of that
--     ingredient was used at the bakery that day (no branch — the
--     bakery is one production site). The page upserts on that key;
--     the month grid shows ingredient × day with a monthly TOTAL
--     column (mirrors the paper "DAILY STOCK SHEET"). Loaded on
--     demand per month — NOT bulk-loaded. SELECT + write admin/
--     bakery; SELECT also operations; delete admin/bakery.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.bakery_stock (
  id            uuid primary key default gen_random_uuid(),
  ingredient_id uuid not null references public.bakery_ingredients(id) ON DELETE CASCADE,
  stock_date    date not null,
  used_qty      numeric(12,2),
  recorded_by   uuid references public.employees(id),
  recorded_at   timestamptz not null default now(),
  UNIQUE (ingredient_id, stock_date)
);
CREATE INDEX IF NOT EXISTS bakery_stock_date_idx ON public.bakery_stock(stock_date);

ALTER TABLE public.bakery_stock ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='bakery_stock'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "bs_select_floor_or_ops"
  ON public.bakery_stock FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','bakery']));
CREATE POLICY "bs_insert_admin_or_bakery"
  ON public.bakery_stock FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bs_update_admin_or_bakery"
  ON public.bakery_stock FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']))
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bs_delete_admin_or_bakery"
  ON public.bakery_stock FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']));

-- =============================================================
-- 48. BAKERY INGREDIENT PURCHASES — weekly + monthly buying
--     One row per (ingredient_id, ym) = that ingredient's Week 1-4
--     purchased quantities plus a separate monthly-purchase figure
--     (the paper "MONTHLY STOCK SHEET"; monthly ≠ sum of weeks, so
--     it's its own column). Reuses the bakery_ingredients catalog
--     (block 46). Month-scoped, loaded on demand per ym — NOT
--     bulk-loaded. SELECT + write admin/bakery; SELECT also
--     operations; delete admin/bakery. (Per-branch ingredient
--     transfers are intentionally not modelled — out of scope.)
-- =============================================================
CREATE TABLE IF NOT EXISTS public.bakery_ingredient_purchases (
  id            uuid primary key default gen_random_uuid(),
  ingredient_id uuid not null references public.bakery_ingredients(id) ON DELETE CASCADE,
  ym            text not null,                 -- 'YYYY-MM'
  w1            numeric(12,2),
  w2            numeric(12,2),
  w3            numeric(12,2),
  w4            numeric(12,2),
  monthly_purchase numeric(12,2),
  recorded_by   uuid references public.employees(id),
  recorded_at   timestamptz not null default now(),
  UNIQUE (ingredient_id, ym)
);
CREATE INDEX IF NOT EXISTS bakery_ingredient_purchases_ym_idx ON public.bakery_ingredient_purchases(ym);

ALTER TABLE public.bakery_ingredient_purchases ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='bakery_ingredient_purchases'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "bpur_select_floor_or_ops"
  ON public.bakery_ingredient_purchases FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','bakery']));
CREATE POLICY "bpur_insert_admin_or_bakery"
  ON public.bakery_ingredient_purchases FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bpur_update_admin_or_bakery"
  ON public.bakery_ingredient_purchases FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']))
  WITH CHECK (public.has_role(ARRAY['admin','bakery']));
CREATE POLICY "bpur_delete_admin_or_bakery"
  ON public.bakery_ingredient_purchases FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','bakery']));

-- =============================================================
-- 49. PUBLIC HOLIDAYS + payroll holiday-overtime hours
--     Company-wide holiday calendar, admin/HR managed. Saudi
--     official holiday dates are lunar / government-announced each
--     year, so they MUST be editable data — never hardcoded.
--     calcPayroll() cross-references attendance against this list:
--     any employee who clocked in AND out on a holiday date earns
--     1.5x their hourly rate (monthly salary / 30 days / standard
--     day length: 8h for Saudi nationals, 10h for other
--     nationalities) for hours worked, fed into the Bonus line.
--     payroll.holiday_ot_hours persists the worked-hours figure so
--     the payslip can show the breakdown after the run (attendance
--     can change later — the payslip must stay a fixed snapshot).
--     SELECT is broad (every employee can see the calendar; it
--     affects their own pay and is printed on payslips); writes are
--     admin/hr. UNIQUE(date) = one holiday entry per calendar day.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.holidays (
  id          uuid primary key default gen_random_uuid(),
  date        date not null unique,
  name        text not null,
  created_by  uuid references public.employees(id),
  created_at  timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS holidays_date_idx ON public.holidays(date);

ALTER TABLE public.holidays ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='holidays'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "holidays_select_all"
  ON public.holidays FOR SELECT TO authenticated
  USING (true);
CREATE POLICY "holidays_insert_admin_or_hr"
  ON public.holidays FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "holidays_update_admin_or_hr"
  ON public.holidays FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "holidays_delete_admin_or_hr"
  ON public.holidays FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

ALTER TABLE public.payroll ADD COLUMN IF NOT EXISTS holiday_ot_hours numeric(12,2);

-- =============================================================
-- 50. PAYROLL MANUAL ADJUSTMENTS
--     Per-employee ad-hoc deduction / bonus lines entered in the
--     Run Payroll preview BEFORE the run, so the payslip is correct
--     the first time and stays an immutable snapshot afterwards.
--     Stored as a jsonb array on the payroll row (read only with
--     the payslip, never queried independently — no separate table
--     needed): [{kind:'deduction'|'bonus', label, amount}]. The
--     rolled-up figures still land in payroll.bonus / .deductions
--     so the list view, report and CSV stay correct; the jsonb is
--     the itemised breakdown the payslip prints (audit trail —
--     KSA labour-law requires documented justification for wage
--     deductions). No RLS change: payroll policies already exist.
-- =============================================================
ALTER TABLE public.payroll ADD COLUMN IF NOT EXISTS adjustments jsonb;

-- =============================================================
-- 51. SALARY DEDUCTIONS REGISTER
--     Admin/HR records a deduction the day an incident happens
--     (e.g. caught stealing on the 2nd) against a target payroll
--     month. When payroll for that month is run, every pending
--     deduction whose period = that month is subtracted from the
--     employee's pay, itemised on the payslip (reuses block 50's
--     payroll.adjustments), and flipped to status='applied' with
--     applied_at set so a re-run never double-deducts (mirrors the
--     advances installments-bookkeeping pattern). A printable
--     deduction slip is generated from each row. RLS is admin/hr
--     only — disciplinary/financial data, not employee-visible.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.deductions (
  id            uuid primary key default gen_random_uuid(),
  employee_id   uuid not null references public.employees(id) ON DELETE CASCADE,
  amount        numeric(12,2) not null,
  reason        text not null,                       -- category label
  details       text,                                -- optional longer note
  incident_date date not null,                       -- when it happened
  period        text not null,                       -- 'YYYY-MM' payroll run it applies to
  status        text not null default 'pending',     -- pending | applied | cancelled
  applied_at    timestamptz,
  created_by    uuid references public.employees(id),
  created_at    timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS deductions_period_idx   ON public.deductions(period);
CREATE INDEX IF NOT EXISTS deductions_employee_idx ON public.deductions(employee_id);

ALTER TABLE public.deductions ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='deductions'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "deductions_select_admin_or_hr"
  ON public.deductions FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));
CREATE POLICY "deductions_insert_admin_or_hr"
  ON public.deductions FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "deductions_update_admin_or_hr"
  ON public.deductions FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "deductions_delete_admin_or_hr"
  ON public.deductions FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

-- =============================================================
-- 52. WORK MANAGEMENT — TASKS (Phase 1)
--     Lightweight task board so operations + admin collaborate
--     inside the app: assign a task to an employee, set a
--     department / priority / due date, track status. SELECT is
--     open to all authenticated users (collaborative board + the
--     assignee must see their own work + dashboard cards); INSERT/
--     DELETE are admin/operations; UPDATE is admin/operations OR
--     the assignee (so the person it's assigned to can move it
--     todo -> in_progress -> done). Phase 2 (checklists, in-app
--     notification centre) will build on this same table.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.tasks (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  description  text,
  department   text,
  assigned_to  uuid references public.employees(id) ON DELETE SET NULL,
  priority     text not null default 'normal',   -- low | normal | high | urgent
  status       text not null default 'todo',     -- todo | in_progress | done | blocked
  due_date     date,
  completed_at timestamptz,
  created_by   uuid references public.employees(id),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS tasks_status_idx     ON public.tasks(status);
CREATE INDEX IF NOT EXISTS tasks_department_idx ON public.tasks(department);
CREATE INDEX IF NOT EXISTS tasks_assigned_idx   ON public.tasks(assigned_to);

ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='tasks'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "tasks_select_all"
  ON public.tasks FOR SELECT TO authenticated
  USING (true);
CREATE POLICY "tasks_insert_admin_or_ops"
  ON public.tasks FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations']));
CREATE POLICY "tasks_update_admin_ops_or_assignee"
  ON public.tasks FOR UPDATE TO authenticated
  USING (
    public.has_role(ARRAY['admin','operations'])
    OR EXISTS (SELECT 1 FROM public.employees e
               WHERE e.id = tasks.assigned_to AND e.user_id = auth.uid())
  )
  WITH CHECK (
    public.has_role(ARRAY['admin','operations'])
    OR EXISTS (SELECT 1 FROM public.employees e
               WHERE e.id = tasks.assigned_to AND e.user_id = auth.uid())
  );
CREATE POLICY "tasks_delete_admin_or_ops"
  ON public.tasks FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

-- =============================================================
-- 53. WORK MANAGEMENT — CHECKLIST TEMPLATES (Phase 2)
--     Per-department reusable checklists (e.g. "Bakery opening
--     checklist"). Small bounded catalog — bulk-loaded like the
--     count-feature catalogs. Items embedded as a jsonb array
--     [{id,text}] (edited as a set; never queried individually).
--     SELECT open to all authenticated; manage = admin/operations.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.checklists (
  id          uuid primary key default gen_random_uuid(),
  department  text,
  title       text not null,
  items       jsonb not null default '[]'::jsonb,
  active      boolean not null default true,
  sort_order  integer default 0,
  created_by  uuid references public.employees(id),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
CREATE INDEX IF NOT EXISTS checklists_department_idx ON public.checklists(department);

ALTER TABLE public.checklists ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='checklists'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "checklists_select_all"
  ON public.checklists FOR SELECT TO authenticated USING (true);
CREATE POLICY "checklists_insert_admin_or_ops"
  ON public.checklists FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations']));
CREATE POLICY "checklists_update_admin_or_ops"
  ON public.checklists FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']))
  WITH CHECK (public.has_role(ARRAY['admin','operations']));
CREATE POLICY "checklists_delete_admin_or_ops"
  ON public.checklists FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

-- =============================================================
-- 54. WORK MANAGEMENT — CHECKLIST RUNS (Phase 2)
--     One row per (checklist, calendar day) holding the tick
--     state as jsonb { itemId: { done, by, at } }. This is an
--     unbounded time series, so it is NEVER bulk-loaded — the
--     frontend loads one YYYY-MM on demand and caches it (same
--     discipline as daily/weekly counts). UNIQUE(checklist_id,
--     run_date) so ticking upserts on that key.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.checklist_runs (
  id           uuid primary key default gen_random_uuid(),
  checklist_id uuid not null references public.checklists(id) ON DELETE CASCADE,
  run_date     date not null,
  state        jsonb not null default '{}'::jsonb,
  note         text,
  created_by   uuid references public.employees(id),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  UNIQUE (checklist_id, run_date)
);
CREATE INDEX IF NOT EXISTS checklist_runs_date_idx ON public.checklist_runs(run_date);

ALTER TABLE public.checklist_runs ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='checklist_runs'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "checklist_runs_select_all"
  ON public.checklist_runs FOR SELECT TO authenticated USING (true);
CREATE POLICY "checklist_runs_insert_admin_or_ops"
  ON public.checklist_runs FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations']));
CREATE POLICY "checklist_runs_update_admin_or_ops"
  ON public.checklist_runs FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']))
  WITH CHECK (public.has_role(ARRAY['admin','operations']));
CREATE POLICY "checklist_runs_delete_admin_or_ops"
  ON public.checklist_runs FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

-- =============================================================
-- 55. CHECKLIST RUNS — per-branch + branch-staff can tick
--     Every checklist is now completed independently per branch
--     (shared template, one run per checklist PER BRANCH per day),
--     mirroring the daily/weekly-count (item,branch,period) shape.
--     Branch lives on the run; the unique key gains `branch`.
--     Writes broaden from admin/operations to the branch-
--     operational roles so on-floor staff can tick their own
--     branch's checklist (branch correctness is UI-enforced via a
--     branch selector defaulting to the user's branch — same model
--     as Daily Count, which is role-gated, not branch-gated in
--     RLS). Idempotent: column add guarded, old 2-col unique
--     dropped + 3-col added inside a DO block, policies re-issued.
-- =============================================================
ALTER TABLE public.checklist_runs ADD COLUMN IF NOT EXISTS branch text;
-- Pre-branch rows (Phase 2a) get assigned to the first branch so
-- the new unique key is valid. Safe: checklists shipped same day.
UPDATE public.checklist_runs SET branch = 'KHOBAR'
  WHERE branch IS NULL OR TRIM(branch) = '';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint
             WHERE conname = 'checklist_runs_checklist_id_run_date_key') THEN
    ALTER TABLE public.checklist_runs
      DROP CONSTRAINT checklist_runs_checklist_id_run_date_key;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                 WHERE conname = 'checklist_runs_checklist_branch_date_key') THEN
    ALTER TABLE public.checklist_runs
      ADD CONSTRAINT checklist_runs_checklist_branch_date_key
      UNIQUE (checklist_id, branch, run_date);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS checklist_runs_branch_date_idx
  ON public.checklist_runs(branch, run_date);

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='checklist_runs'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "checklist_runs_select_all"
  ON public.checklist_runs FOR SELECT TO authenticated USING (true);
CREATE POLICY "checklist_runs_insert_floor"
  ON public.checklist_runs FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','bakery','chef','maintenance']));
CREATE POLICY "checklist_runs_update_floor"
  ON public.checklist_runs FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','bakery','chef','maintenance']))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','bakery','chef','maintenance']));
CREATE POLICY "checklist_runs_delete_admin_or_ops"
  ON public.checklist_runs FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

-- =============================================================
-- 56. SEED — Barista floor checklists (from the branch checklist
--     PDF). 5 daily routines split out + 3 merged weekly/monthly/
--     maintenance supersets (union across the per-branch printouts).
--     Each is a shared template completed PER BRANCH per day.
--     Item ids are stable short tokens so re-running the seed (or
--     later edits) never orphans saved tick state. Idempotent:
--     each insert is guarded by WHERE NOT EXISTS on the title, so
--     re-pasting the file is safe and edits made in-app are NOT
--     overwritten.
-- =============================================================
INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Opening Checklist', '[
  {"id":"op1","text":"TURN ON THE C.O.D MACHINE"},
  {"id":"op2","text":"TURN ON THE ESPRESSO MACHINE"},
  {"id":"op3","text":"WASH THE COD DISPENSERS"},
  {"id":"op4","text":"PREPARE C.O.D"},
  {"id":"op5","text":"PREPARE / ARRANGE THE BAR"},
  {"id":"op6","text":"FILL ALL THE GRINDERS"},
  {"id":"op7","text":"DO THE REQUIRED CALIBRATIONS, CHECK THE TDS & POST IN THE QUALITY GROUP"},
  {"id":"op8","text":"CLEAN THE TABLES & SEATS"},
  {"id":"op9","text":"TURN ON THE SCREEN & NECESSARY LIGHTS"},
  {"id":"op10","text":"COUNT THE PETTY CASH & OPEN THE TILL"},
  {"id":"op11","text":"FILL IN THE DAILY INVENTORY SHEET"}
]'::jsonb, true, 1
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Opening Checklist');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Morning Tasks', '[
  {"id":"mo1","text":"CLEANING THE SURFACE AREAS, TABLES & CHAIRS"},
  {"id":"mo2","text":"CLEAN BOTH MIRRORS (DOOR & CAFE)"},
  {"id":"mo3","text":"WATER THE PLANTS"},
  {"id":"mo4","text":"MOPPING THE SURFACES"},
  {"id":"mo5","text":"PREPARING FILTERS"},
  {"id":"mo6","text":"CLEANING / DUSTING THE SHELVES"},
  {"id":"mo7","text":"REFILLING THE BEANS ON THE SHELVES"},
  {"id":"mo8","text":"CHECKING BEANS STOCK & ORDERING"}
]'::jsonb, true, 2
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Morning Tasks');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Handover Tasks', '[
  {"id":"ha1","text":"REFILL THE CUPS ON THE CUP WARMER"},
  {"id":"ha2","text":"REFILLING SUGAR, STRAWS, COVERS & WOODEN STIRRERS"},
  {"id":"ha3","text":"CLEANING THE V60 SERVER AREA"},
  {"id":"ha4","text":"CLEANING THE ESPRESSO MACHINE TRAY"},
  {"id":"ha5","text":"CLEANING THE FLOORS"},
  {"id":"ha6","text":"REFILLING THE BEANS ON THE DISPLAY"}
]'::jsonb, true, 3
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Handover Tasks');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Evening Prep (Mise en place)', '[
  {"id":"ev1","text":"CHECK THE CLEANLINESS OF THE SHOP & CLEAN WHERE NECESSARY"},
  {"id":"ev2","text":"ORGANISE TABLES & CHAIRS, WIPE MIRROR & GLASS"},
  {"id":"ev3","text":"CHECK WHAT NEEDS TO BE REFILLED (CUPS, SUGAR, GLOVES, MASKS & COVERS)"},
  {"id":"ev4","text":"CHECK BAR STOCK FOR THE BEANS"},
  {"id":"ev5","text":"ENSURE YOU HAVE ENOUGH FILTERS; IF NOT, FOLD THEM"}
]'::jsonb, true, 4
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Evening Prep (Mise en place)');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Closing Checklist', '[
  {"id":"cl1","text":"EMPTY ALL THE BINS & THE NECESSARY BINS"},
  {"id":"cl2","text":"WASH ALL THE NECESSARY EQUIPMENT & PUT THEM TO DRY"},
  {"id":"cl3","text":"CLEAN ALL THE NECESSARY BAR AREAS AND LEAVE THEM SPARKLING CLEAN"},
  {"id":"cl4","text":"EMPTY ALL THE GRINDERS & MAKE SURE ALL THE BAGS ARE AIR TIGHT"},
  {"id":"cl5","text":"EMPTY ALL THE C.O.D DISPENSERS, RINSE THEM, ADD CHEMICAL & FILL WITH HOT WATER"},
  {"id":"cl6","text":"CLEAN ALL THE FLOORS AND LEAVE THEM SPARKLY CLEAN"},
  {"id":"cl7","text":"CLOSE THE TILL; PLACE MONEY & RECEIPTS IN THE ENVELOPE, SEAL & ADD DATE, NAME, SIGNATURE, AVAILABLE CASH, FOODICS CASH, CASHBOX & PETTY CASH"},
  {"id":"cl8","text":"SWITCH OFF ALL MACHINES (C.O.D, GRINDERS & COFFEE MACHINES) & LIGHTS"},
  {"id":"cl9","text":"PUT ALL THE SCALES TO CHARGE & ENSURE THEY ARE CHARGING"},
  {"id":"cl10","text":"CLOSE THE DOOR ON YOUR WAY & ENSURE IT IS LOCKED PROPERLY"}
]'::jsonb, true, 5
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Closing Checklist');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Weekly Cleaning Tasks', '[
  {"id":"wk1","text":"CLEANING ALL THE SHELVES (BAR & BEANS)"},
  {"id":"wk2","text":"CLEANING THE BAR AREA, ICE MAKER & BAR SHELVES"},
  {"id":"wk3","text":"CLEANING THE SHOP GLASSES"},
  {"id":"wk4","text":"CLEAN THE TRASH BINS"},
  {"id":"wk5","text":"DEEP CLEANING THE WASHROOMS"},
  {"id":"wk6","text":"CLEANING THE BAR FRIDGE & MAIN FRIDGE"},
  {"id":"wk7","text":"CLEAN UNDER THE STAIRCASE"},
  {"id":"wk8","text":"CLEAN THE UPSTAIRS AREA (BROOM & MOP)"},
  {"id":"wk9","text":"DUSTING, CLEANING & ORGANISING THE SHELVES (BEANS & STORAGE)"},
  {"id":"wk10","text":"CHECK BEANS ON THE DISPLAY ARE UP TO DATE (1 MONTH OLD AT MOST)"}
]'::jsonb, true, 6
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Weekly Cleaning Tasks');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Monthly Cleaning Tasks', '[
  {"id":"mn1","text":"COFFEE STAINS ON THE WALLS"},
  {"id":"mn2","text":"CLEAN THE BAR ORGANISERS"},
  {"id":"mn3","text":"CLEAN & DUST THE PLANTS"},
  {"id":"mn4","text":"ARRANGE THE BAR AREA SHELVES & CLEAN THEM"},
  {"id":"mn5","text":"CLEAN THE SINK AREA & ARRANGE THE NECESSARY"},
  {"id":"mn6","text":"CLEAN THE SHOP MIRRORS (FRONT & BEHIND)"},
  {"id":"mn7","text":"CLEANING THE CUP WARMER"}
]'::jsonb, true, 7
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Monthly Cleaning Tasks');

INSERT INTO public.checklists (department, title, items, active, sort_order)
SELECT 'Barista', 'Maintenance Tasks', '[
  {"id":"mt1","text":"BACK-FLUSH THE MACHINE WITH CHEMICAL & SOAK THE PORTAFILTERS (EVERY FRIDAY)"},
  {"id":"mt2","text":"CLEAN THE STEAM WANDS WITH BLUE CAFEC CHEMICAL (EVERY SATURDAY MORNING)"},
  {"id":"mt3","text":"CLEAN THE CUP WARMER, TOP OF THE MACHINE (EVERY SATURDAY MORNING)"}
]'::jsonb, true, 8
WHERE NOT EXISTS (SELECT 1 FROM public.checklists WHERE title = 'Maintenance Tasks');

-- =============================================================
-- 57. CHECKLIST RUNS — restrict ticking to barista roles
--     Owner decision: only baristas & head baristas (plus admin as
--     superuser) complete checklists. Narrows the block-55 write
--     policies from the broad floor set to admin/head_barista/
--     barista. SELECT stays open (managers/Compliance read all);
--     DELETE stays admin/operations. Idempotent: drop + recreate.
--     Keep the JS canTickChecklists() helper in sync with this.
-- =============================================================
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='checklist_runs'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "checklist_runs_select_all"
  ON public.checklist_runs FOR SELECT TO authenticated USING (true);
CREATE POLICY "checklist_runs_insert_barista"
  ON public.checklist_runs FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "checklist_runs_update_barista"
  ON public.checklist_runs FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']));
CREATE POLICY "checklist_runs_delete_admin_or_ops"
  ON public.checklist_runs FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations']));

-- =============================================================
-- 58. MARKETING ROLE + HEAD-OFFICE BRANCH FLAG
--     (a) Adds 'marketing' to the system_role CHECK constraint so
--         back-office marketing staff can be assigned that role.
--         (Latest re-issue wins when the file runs top-to-bottom.)
--     (b) Adds branches.is_head_office. A branch flagged true is a
--         geofenced clock-in location reserved for office roles
--         (admin/operations/accounting/marketing); floor staff are
--         rejected there. Enforcement is UI-side in clockIn() via
--         realRole() + the HEAD_OFFICE_ROLES constant — the app's
--         role-gated, UI-enforced branch model, NOT a per-row RLS
--         rule (mirrors the count/checklist branch convention).
--         Keep HEAD_OFFICE_ROLES in sync with the role list here.
-- =============================================================
ALTER TABLE public.employees
  DROP CONSTRAINT IF EXISTS employees_system_role_chk;
ALTER TABLE public.employees
  ADD CONSTRAINT employees_system_role_chk
  CHECK (system_role IS NULL OR system_role IN (
    'admin','hr','operations','barista','head_barista','roaster',
    'accounting','marketing','maintenance','bakery','employee'
  ));

ALTER TABLE public.branches
  ADD COLUMN IF NOT EXISTS is_head_office boolean NOT NULL DEFAULT false;

-- =============================================================
-- 59. PERSONAL TO-DO LISTS
--     Lightweight per-user lists for the office cluster (admin /
--     operations / accounting / hr / marketing). Each row is one
--     named list; items live in a jsonb array on the row, shape
--     [{id, text, done, doneAt, createdAt}]. Mirrors the
--     checklists.items pattern (concurrent edits = last-writer-
--     wins; fine for a personal list — no shared editors).
--
--     RLS is strict owner-only: each policy joins to employees by
--     auth.uid() so you can only ever see/edit/delete YOUR rows.
--     Role-gating is UI-only (canUsePersonalTodos() hides the
--     section from non-office roles); no need to encode roles in
--     RLS — if a barista somehow inserts a row, they just own a
--     private list. Keep canUsePersonalTodos() ↔ the office-
--     cluster list in sync.
--
--     ON DELETE CASCADE on owner_id: terminating/deleting an
--     employee cleans up their lists. Lists are personal, not
--     business records.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.personal_todo_lists (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id   uuid NOT NULL REFERENCES public.employees(id) ON DELETE CASCADE,
  name       text NOT NULL,
  items      jsonb NOT NULL DEFAULT '[]'::jsonb,
  sort_order int  NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS personal_todo_lists_owner_idx
  ON public.personal_todo_lists(owner_id);

ALTER TABLE public.personal_todo_lists ENABLE ROW LEVEL SECURITY;

-- Drop & recreate so this block is idempotent on re-paste.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='personal_todo_lists'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.personal_todo_lists', r.policyname);
  END LOOP;
END $$;

CREATE POLICY "personal_todo_lists_select_own"
  ON public.personal_todo_lists FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = personal_todo_lists.owner_id
        AND e.user_id = auth.uid()
    )
  );
CREATE POLICY "personal_todo_lists_insert_own"
  ON public.personal_todo_lists FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = personal_todo_lists.owner_id
        AND e.user_id = auth.uid()
    )
  );
CREATE POLICY "personal_todo_lists_update_own"
  ON public.personal_todo_lists FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = personal_todo_lists.owner_id
        AND e.user_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = personal_todo_lists.owner_id
        AND e.user_id = auth.uid()
    )
  );
CREATE POLICY "personal_todo_lists_delete_own"
  ON public.personal_todo_lists FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = personal_todo_lists.owner_id
        AND e.user_id = auth.uid()
    )
  );

-- =============================================================
-- 60. LOCKDOWN — narrow open SELECT policies + leave_type CHECK
--     Pre-merge audit (May 2026) flagged that warnings, advances,
--     certificates, archive_documents, and employee_extras all had
--     SELECT policies using USING(true) — every authenticated
--     employee could read every disciplinary record, advance amount,
--     IQAMA number, etc. via a single PostgREST call. This is a
--     PDPL concern for a KSA company.
--
--     Each policy below is narrowed to the minimum audience that
--     matches the existing UI gates:
--       - warnings / certificates / advances: admin+hr OR self.
--           (warnings is navigable by all roles; show:true on the
--           nav means floor staff *should* see their own record —
--           hence "OR self", not admin/hr-only.)
--       - archive_documents: admin+hr+operations see all (Archive
--           page audience); barista+head_barista+roaster see only
--           the Resources whitelist (sop/training/company_resource/
--           policy); others see nothing.  Keep
--           RESOURCES_CATEGORIES in index.html ↔ the category list
--           below in sync.
--       - employee_extras: admin+hr see all (employees directory,
--           renew-documents flow); everyone else sees only their
--           own row (so dcDefaultBranch() still works for floor
--           staff). IQAMA + Baladiya numbers are PII and were
--           previously visible to every authenticated user.
--
--     Plus a CHECK constraint on leave_requests.leave_type — without
--     it, a malformed value makes decide_leave_request() raise on
--     `leave_<bogus>` and rolls back the approval transaction.
--
--     Idempotent: drops both the legacy and the new policy names
--     before recreating; uses DROP CONSTRAINT IF EXISTS for the
--     CHECK. Safe to re-paste the whole file.
-- =============================================================

-- WARNINGS — admin/hr see all; employees see their own record.
DROP POLICY IF EXISTS "warnings_select_authenticated"  ON public.warnings;
DROP POLICY IF EXISTS "warnings_select_admin_hr_or_self" ON public.warnings;
CREATE POLICY "warnings_select_admin_hr_or_self"
  ON public.warnings FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = warnings.employee_id
        AND e.user_id = auth.uid()
    )
  );

-- ADVANCES — admin/hr see all; employees see their own requests.
DROP POLICY IF EXISTS "advances_select_authenticated"  ON public.advances;
DROP POLICY IF EXISTS "advances_select_admin_hr_or_self" ON public.advances;
CREATE POLICY "advances_select_admin_hr_or_self"
  ON public.advances FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = advances.employee_id
        AND e.user_id = auth.uid()
    )
  );

-- CERTIFICATES — admin/hr see all; employees see their own.
DROP POLICY IF EXISTS "certificates_select_authenticated"  ON public.certificates;
DROP POLICY IF EXISTS "certificates_select_admin_hr_or_self" ON public.certificates;
CREATE POLICY "certificates_select_admin_hr_or_self"
  ON public.certificates FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = certificates.employee_id
        AND e.user_id = auth.uid()
    )
  );

-- ARCHIVE DOCUMENTS — admin/hr/operations see all; floor roles
-- (barista/head_barista/roaster) see only the Resources whitelist.
-- IMPORTANT: keep the category list below ↔ JS RESOURCES_CATEGORIES
-- ('sop','training','company_resource','policy') in sync.
DROP POLICY IF EXISTS "archive_select_authenticated" ON public.archive_documents;
DROP POLICY IF EXISTS "archive_select_role_scoped"   ON public.archive_documents;
CREATE POLICY "archive_select_role_scoped"
  ON public.archive_documents FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr','operations'])
    OR (
      public.has_role(ARRAY['barista','head_barista','roaster'])
      AND category IN ('sop','training','company_resource','policy')
    )
  );

-- EMPLOYEE EXTRAS — admin/hr see all; everyone else sees their own
-- row (dcDefaultBranch() relies on self-read for floor staff).
DROP POLICY IF EXISTS "employee_extras_select_authenticated"   ON public.employee_extras;
DROP POLICY IF EXISTS "employee_extras_select_admin_hr_or_self" ON public.employee_extras;
CREATE POLICY "employee_extras_select_admin_hr_or_self"
  ON public.employee_extras FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (
      SELECT 1 FROM public.employees e
      WHERE e.id = employee_extras.employee_id
        AND e.user_id = auth.uid()
    )
  );

-- LEAVE_REQUESTS — pin leave_type to the three values the JS UI offers
-- and the leave_balances columns ('annual','sick','personal'). Without
-- this, a bogus value (anything else) makes decide_leave_request's
-- dynamic SQL raise on a missing 'leave_<bogus>' column.
ALTER TABLE public.leave_requests
  DROP CONSTRAINT IF EXISTS leave_requests_leave_type_chk;
ALTER TABLE public.leave_requests
  ADD CONSTRAINT leave_requests_leave_type_chk
  CHECK (leave_type IN ('annual','sick','personal'));

-- =============================================================
-- 61. WARNINGS — admin-editable National ID per warning
-- =============================================================
-- The printable warning letter prints a "National ID / Residency
-- Number" field that previously pulled exclusively from the
-- employee's IQAMA in their profile (employee_extras.iqama). Two
-- real-world issues with that:
--   (a) Sometimes the IQAMA hasn't been entered in the profile
--       when the first warning needs issuing — admin had to bail
--       out, update the profile, then come back, just to get the
--       ID on the printed letter.
--   (b) Admin may want to override per-warning (an old contract,
--       a different ID type for the specific incident's paper
--       trail, etc.).
-- This column carries an override. The printed letter falls back
-- to the employee profile when this is null, then to "—".
-- Added 2026-06-05.
ALTER TABLE public.warnings
  ADD COLUMN IF NOT EXISTS national_id text;

-- =============================================================
-- 62. EMPLOYEE LINKING FIX — relax user_id immutability to set-once
-- =============================================================
-- Bug found 2026-06-05 while inviting admin-pre-added employees:
-- Supabase Dashboard "Invite user" failed with
--    "Failed to invite user: user_id is immutable"
-- The same flow that lets a pre-added employee sign up via
-- app.hasadco.sa was also silently broken.
--
-- Root cause: the enforce_employee_update_rules trigger throws
-- `user_id is immutable` on ANY user_id change. That includes the
-- legitimate NULL → UUID transition that handle_new_user performs
-- when linking a freshly-created auth.users row to its pre-existing
-- employees row (the whole point of the "admin pre-adds, employee
-- signs up later" flow):
--
--   handle_new_user (AFTER INSERT on auth.users) does:
--     UPDATE public.employees
--        SET user_id = NEW.id, ...
--      WHERE id = invited_emp_id;  -- OLD.user_id is NULL
--
-- That UPDATE trips the BEFORE-UPDATE immutability trigger which
-- raises, the surrounding transaction rolls back, and the entire
-- auth.users row is rolled back with it. Net result: no login
-- account, invite/signup fails, admin sees the cryptic error.
--
-- Only the all-NEW-employee path worked (Omar, TEVIN at first
-- signup): there's no pre-existing employees row, handle_new_user
-- INSERTs one — INSERT doesn't fire the BEFORE-UPDATE trigger.
--
-- Fix: redefine the trigger function with set-once semantics.
--   NULL  → UUID   ALLOWED  (the linking case — the bug)
--   UUID  → UUID'  BLOCKED  (no post-hoc rewiring)
--   UUID  → NULL   BLOCKED  (no unlinking)
--
-- The trigger is BEFORE UPDATE so it still runs on every employees
-- UPDATE — only the rejection condition is loosened. Self-role
-- protection (a separate check in the same function) is unchanged.
--
-- This idempotently supersedes both earlier definitions of the
-- function (lines ~171 and ~1800 in this file).
CREATE OR REPLACE FUNCTION public.enforce_employee_update_rules()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Self-role-change protection unchanged.
  IF NEW.user_id = auth.uid()
     AND NEW.system_role IS DISTINCT FROM OLD.system_role THEN
    RAISE EXCEPTION 'You cannot change your own role';
  END IF;

  -- Set-once semantics on user_id. NULL → UUID is the linker case
  -- and is now allowed; everything else (UUID → different UUID,
  -- UUID → NULL) still throws.
  IF OLD.user_id IS NOT NULL
     AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'user_id is immutable once set';
  END IF;

  RETURN NEW;
END;
$$;

-- Re-attach the trigger to be safe (CREATE OR REPLACE FUNCTION
-- doesn't touch the trigger binding, but the trigger may have been
-- dropped during an earlier troubleshooting attempt). Idempotent.
DROP TRIGGER IF EXISTS enforce_employee_update_rules_trigger ON public.employees;
CREATE TRIGGER enforce_employee_update_rules_trigger
  BEFORE UPDATE ON public.employees
  FOR EACH ROW EXECUTE FUNCTION public.enforce_employee_update_rules();

-- =============================================================
-- 63. PERSONAL TO-DO LISTS — recurrence (daily/weekly/monthly)
-- =============================================================
-- Admins wanted "a list of duties I do daily — items uncheck themselves
-- overnight, same items reappear unchecked tomorrow." Same pattern works
-- for weekly chores (Monday reset) and monthly cycles (1st reset). Items
-- and their text stay; only the `done` flag resets at period boundaries.
-- Added 2026-06-05.
--
-- Implementation:
-- - `recurrence` text: 'once' (default = current behavior) | 'daily' |
--   'weekly' | 'monthly'. CHECK enforces valid values.
-- - `last_reset_date` date: tracks when the items were last reset. The
--   client checks this on render and (a) virtual-resets items for the
--   display, (b) fires an async DB write to bring the row in sync.
-- - Reset boundary by recurrence:
--     daily   → calendar day flip (local timezone)
--     weekly  → ISO Monday → Monday
--     monthly → 1st of the month
-- Backfill existing rows with recurrence='once' so behavior is unchanged
-- for everyone with non-recurring lists today.
ALTER TABLE public.personal_todo_lists
  ADD COLUMN IF NOT EXISTS recurrence text NOT NULL DEFAULT 'once';
ALTER TABLE public.personal_todo_lists
  ADD COLUMN IF NOT EXISTS last_reset_date date;

-- Constrain recurrence to the four supported values. Drop+recreate so
-- the constraint stays idempotent across re-runs.
ALTER TABLE public.personal_todo_lists
  DROP CONSTRAINT IF EXISTS personal_todo_lists_recurrence_chk;
ALTER TABLE public.personal_todo_lists
  ADD CONSTRAINT personal_todo_lists_recurrence_chk
  CHECK (recurrence IN ('once','daily','weekly','monthly'));

-- =============================================================
-- 64. JOB APPLICATIONS — public-facing application form
-- =============================================================
-- Hassad wants a public form (no login required) where people who
-- want to work for Hassad can submit their details. The data sits
-- waiting until HR has a position to fill, then HR reviews and either
-- moves them through interview → hired, or marks them rejected.
-- Added 2026-06-06.
--
-- Threat model
-- ------------
-- The form is intentionally open-access — anyone on the internet can
-- INSERT. That means:
--   - Spam / form abuse: rate-limited at the Supabase RPC layer + we
--     add a honeypot field client-side (a hidden input bots fill in;
--     real users don't).
--   - PII exposure: SELECT/UPDATE locked to admin+hr only via RLS.
--     Public users can post in but never read out. DELETE is admin-
--     only (PDPL right-to-delete).
-- A future Edge Function can layer Cloudflare Turnstile if abuse
-- becomes real; not needed for launch.
CREATE TABLE IF NOT EXISTS public.job_applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Personal
  first_name      text NOT NULL,
  last_name       text,
  email           text NOT NULL,
  phone           text,
  nationality     text,

  -- Position they want
  position        text NOT NULL,                     -- 'barista' | 'head_barista' | 'roaster' | 'bakery' | 'maintenance' | 'other'
  position_other  text,                              -- free text when position = 'other'
  branch_preference text,                            -- KHOBAR | RAYYAN | FAISALIYAH | ANY

  -- Background
  years_experience smallint,                         -- in coffee or this role
  previous_workplace text,

  -- Availability
  availability    text,                              -- 'full_time' | 'part_time' | 'flexible'
  earliest_start  date,

  -- KSA-specific
  iqama_status    text,                              -- 'valid' | 'expired' | 'transferable' | 'none'
  has_driving_license boolean,

  -- Open-ended
  why_hassad      text,

  -- Optional CV (path in the storage bucket below)
  cv_path         text,                              -- e.g. 'cvs/{application_id}/filename.pdf'

  -- HR workflow
  status          text NOT NULL DEFAULT 'new',       -- 'new' | 'reviewing' | 'interview' | 'hired' | 'rejected' | 'archived'
  reviewed_by     uuid REFERENCES public.employees(id),
  reviewed_at     timestamptz,
  hr_notes        text,
  source          text,                              -- where they heard about Hassad

  -- PDPL
  consent_given   boolean NOT NULL DEFAULT true,
  consent_at      timestamptz NOT NULL DEFAULT now(),

  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS job_applications_status_idx ON public.job_applications(status);
CREATE INDEX IF NOT EXISTS job_applications_created_idx ON public.job_applications(created_at DESC);

ALTER TABLE public.job_applications
  DROP CONSTRAINT IF EXISTS job_applications_status_chk;
ALTER TABLE public.job_applications
  ADD CONSTRAINT job_applications_status_chk
  CHECK (status IN ('new','reviewing','interview','hired','rejected','archived'));

ALTER TABLE public.job_applications
  DROP CONSTRAINT IF EXISTS job_applications_position_chk;
ALTER TABLE public.job_applications
  ADD CONSTRAINT job_applications_position_chk
  CHECK (position IN ('barista','head_barista','roaster','bakery','maintenance','cashier','other'));

ALTER TABLE public.job_applications
  DROP CONSTRAINT IF EXISTS job_applications_availability_chk;
ALTER TABLE public.job_applications
  ADD CONSTRAINT job_applications_availability_chk
  CHECK (availability IS NULL OR availability IN ('full_time','part_time','flexible'));

ALTER TABLE public.job_applications
  DROP CONSTRAINT IF EXISTS job_applications_iqama_chk;
ALTER TABLE public.job_applications
  ADD CONSTRAINT job_applications_iqama_chk
  CHECK (iqama_status IS NULL OR iqama_status IN ('valid','expired','transferable','none'));

ALTER TABLE public.job_applications ENABLE ROW LEVEL SECURITY;

-- INSERT: public (anon role) can submit. No SELECT auth required for the
--         insert itself. consent_given must be true (PDPL).
DROP POLICY IF EXISTS job_applications_insert_public ON public.job_applications;
CREATE POLICY job_applications_insert_public ON public.job_applications
  FOR INSERT
  WITH CHECK (consent_given = true);

-- SELECT: admin + operations only. Public CANNOT enumerate applications.
-- Owner-confirmed role gate (2026-06-06): the "Interview" pool is for
-- admin + operations. HR does not exist as a separate role in Hassad's
-- current setup; if it's added later, widen this to ARRAY['admin','hr',
-- 'operations'] and ship the corresponding JS canManagePeople()-style
-- widening on the renderer.
DROP POLICY IF EXISTS job_applications_select_admin_hr ON public.job_applications;
CREATE POLICY job_applications_select_admin_hr ON public.job_applications
  FOR SELECT
  USING (public.has_role(ARRAY['admin','operations']));

-- UPDATE: admin + operations. Used for status transitions + HR notes.
DROP POLICY IF EXISTS job_applications_update_admin_hr ON public.job_applications;
CREATE POLICY job_applications_update_admin_hr ON public.job_applications
  FOR UPDATE
  USING (public.has_role(ARRAY['admin','operations']))
  WITH CHECK (public.has_role(ARRAY['admin','operations']));

-- DELETE: admin only. PDPL right-to-delete + spam cleanup.
DROP POLICY IF EXISTS job_applications_delete_admin ON public.job_applications;
CREATE POLICY job_applications_delete_admin ON public.job_applications
  FOR DELETE
  USING (public.is_admin());

-- -------------------------------------------------------------
-- CV upload: Supabase Storage bucket 'applicant-cvs'
-- -------------------------------------------------------------
-- We DON'T create the bucket via SQL (Supabase's storage schema lives
-- outside our migration discipline). Instead, create it once via the
-- Supabase Dashboard → Storage → New bucket → 'applicant-cvs' →
-- PRIVATE (NOT public). Then run the policies below to allow public
-- uploads + admin/operations reads.
--
-- File naming convention enforced client-side:
--   applicant-cvs/{application_id}/{original_filename}
-- That way each CV is namespaced under the row it belongs to and we
-- can look it up from the application row's cv_path.
--
-- Note: these CREATE POLICY statements assume the bucket already
-- exists. If you re-run the file before creating the bucket, the
-- policies fail. After creating 'applicant-cvs', re-run this section.

-- Public anonymous upload: anyone can INSERT into the bucket as long
-- as it's the 'applicant-cvs' bucket. 5 MB limit + MIME whitelist
-- should be enforced client-side (we trust the network less, so the
-- review UI also validates before download).
DROP POLICY IF EXISTS applicant_cvs_public_insert ON storage.objects;
CREATE POLICY applicant_cvs_public_insert ON storage.objects
  FOR INSERT
  WITH CHECK (bucket_id = 'applicant-cvs');

-- Admin + operations can read (so admin/ops can preview/download the CV).
DROP POLICY IF EXISTS applicant_cvs_select_admin_hr ON storage.objects;
CREATE POLICY applicant_cvs_select_admin_hr ON storage.objects
  FOR SELECT
  USING (bucket_id = 'applicant-cvs' AND public.has_role(ARRAY['admin','operations']));

-- Admin only can DELETE (paired with row-deletion to satisfy PDPL).
DROP POLICY IF EXISTS applicant_cvs_delete_admin ON storage.objects;
CREATE POLICY applicant_cvs_delete_admin ON storage.objects
  FOR DELETE
  USING (bucket_id = 'applicant-cvs' AND public.is_admin());

-- =============================================================
-- 65. WARNING LETTER DIGITAL SIGNATURES
--     Employees acknowledge a warning by drawing a signature on their
--     phone; the issuing manager (admin/HR) signs the same way. Stored
--     as base64 PNG data-URLs on the warning row.
--
--     Why an RPC instead of a plain RLS UPDATE policy: an employee must
--     be able to set THEIR signature but NOTHING else (not reason,
--     severity, etc.). RLS is row-level, not column-level, so granting
--     employees UPDATE would let them rewrite the whole row. A
--     SECURITY DEFINER function with an explicit signer role is the
--     safe column-scoped path. Managers already have UPDATE via the
--     admin/HR policies, but route through the same RPC for symmetry.
-- =============================================================
ALTER TABLE public.warnings ADD COLUMN IF NOT EXISTS employee_signature text;
ALTER TABLE public.warnings ADD COLUMN IF NOT EXISTS employee_signed_at  timestamptz;
ALTER TABLE public.warnings ADD COLUMN IF NOT EXISTS manager_signature   text;
ALTER TABLE public.warnings ADD COLUMN IF NOT EXISTS manager_signed_at   timestamptz;

CREATE OR REPLACE FUNCTION public.sign_warning(p_id uuid, p_signature text, p_as text)
RETURNS public.warnings
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  w      public.warnings;
  my_emp uuid;
BEGIN
  IF p_signature IS NULL OR length(p_signature) < 50 THEN
    RAISE EXCEPTION 'Signature is empty';
  END IF;
  IF length(p_signature) > 400000 THEN
    RAISE EXCEPTION 'Signature image is too large';
  END IF;

  SELECT * INTO w FROM public.warnings WHERE id = p_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Warning not found'; END IF;

  IF p_as = 'manager' THEN
    IF NOT public.has_role(ARRAY['admin','hr']) THEN
      RAISE EXCEPTION 'Only admin or HR can sign as the manager';
    END IF;
    UPDATE public.warnings
       SET manager_signature = p_signature, manager_signed_at = now()
     WHERE id = p_id
     RETURNING * INTO w;

  ELSIF p_as = 'employee' THEN
    SELECT id INTO my_emp FROM public.employees WHERE user_id = auth.uid();
    IF my_emp IS NULL OR my_emp <> w.employee_id THEN
      RAISE EXCEPTION 'You can only sign your own warning';
    END IF;
    UPDATE public.warnings
       SET employee_signature = p_signature, employee_signed_at = now()
     WHERE id = p_id
     RETURNING * INTO w;

  ELSE
    RAISE EXCEPTION 'Invalid signer role: %', p_as;
  END IF;

  RETURN w;
END;
$$;
REVOKE ALL ON FUNCTION public.sign_warning(uuid, text, text) FROM public;
GRANT EXECUTE ON FUNCTION public.sign_warning(uuid, text, text) TO authenticated;

-- =============================================================
-- 66. ATTENDANCE — let HR (not just admin) correct attendance
--     So admin AND HR can "undo" a mistaken clock-out (clear clock_out)
--     on any employee's row. Keeps the self-update leg intact (employees
--     still clock in/out their own rows). Idempotent drop-then-create —
--     replaces the admin-only version from block ~early.
-- =============================================================
DROP POLICY IF EXISTS "attendance_update_self_or_admin" ON public.attendance;
CREATE POLICY "attendance_update_self_or_admin"
  ON public.attendance FOR UPDATE
  TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (SELECT 1 FROM public.employees e WHERE e.id = attendance.employee_id AND e.user_id = auth.uid())
  )
  WITH CHECK (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (SELECT 1 FROM public.employees e WHERE e.id = attendance.employee_id AND e.user_id = auth.uid())
  );

-- =============================================================
-- 67. LEAVE TRAVEL WORKFLOW — non-Saudi: flight ticket + exit visa
--     After an ANNUAL-leave request is approved, non-Saudi staff have a
--     post-approval process: book the flight ticket, then issue the exit
--     (re-entry) visa. This table tracks those two steps per leave request
--     and stores the uploaded ticket + visa documents as base64 data URLs
--     (mirrors archive_documents). One row per leave request (UNIQUE).
--     A step is "done" when its document is uploaded — status is derived
--     client-side from *_uploaded_at, so no status column is needed.
--
--     Visibility (owner-confirmed 2026-06-22): admin/hr manage; the
--     EMPLOYEE can read their OWN row (they need the ticket to travel).
--     So SELECT = admin/hr OR the employee who owns the linked leave.
--     INSERT/UPDATE = admin/hr; DELETE = admin. The data_url columns are
--     stripped from the client's bulk load and lazy-fetched on
--     preview/download (same discipline as archive_documents).
-- =============================================================
CREATE TABLE IF NOT EXISTS public.leave_travel (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  leave_id uuid NOT NULL UNIQUE REFERENCES public.leave_requests(id) ON DELETE CASCADE,

  ticket_data_url    text,
  ticket_mime        text,
  ticket_name        text,
  ticket_uploaded_at timestamptz,
  ticket_uploaded_by uuid REFERENCES public.employees(id),

  visa_data_url      text,
  visa_mime          text,
  visa_name          text,
  visa_uploaded_at   timestamptz,
  visa_uploaded_by   uuid REFERENCES public.employees(id),

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS leave_travel_leave_idx ON public.leave_travel(leave_id);

ALTER TABLE public.leave_travel ENABLE ROW LEVEL SECURITY;

-- SELECT: admin/hr, or the employee who owns the linked leave request.
DROP POLICY IF EXISTS leave_travel_select_admin_hr_or_self ON public.leave_travel;
CREATE POLICY leave_travel_select_admin_hr_or_self ON public.leave_travel
  FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (
      SELECT 1 FROM public.leave_requests lr
      JOIN public.employees e ON e.id = lr.employee_id
      WHERE lr.id = leave_travel.leave_id AND e.user_id = auth.uid()
    )
  );

-- INSERT: admin/hr only (they book the ticket + issue the visa).
DROP POLICY IF EXISTS leave_travel_insert_admin_hr ON public.leave_travel;
CREATE POLICY leave_travel_insert_admin_hr ON public.leave_travel
  FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));

-- UPDATE: admin/hr only.
DROP POLICY IF EXISTS leave_travel_update_admin_hr ON public.leave_travel;
CREATE POLICY leave_travel_update_admin_hr ON public.leave_travel
  FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr']))
  WITH CHECK (public.has_role(ARRAY['admin','hr']));

-- DELETE: admin only.
DROP POLICY IF EXISTS leave_travel_delete_admin ON public.leave_travel;
CREATE POLICY leave_travel_delete_admin ON public.leave_travel
  FOR DELETE TO authenticated
  USING (public.is_admin());

-- =============================================================
-- 68. ADVANCES vs LOANS — kind + installment months
--     The advances table now also stores LOANS. An advance is recovered
--     in full from the next payroll run; a loan is repaid in equal
--     installments over up to 2 months (installment_months). Existing
--     rows backfill to kind='advance' so behaviour is unchanged.
--     No RLS change — loans reuse the advances policies (same table).
-- =============================================================
ALTER TABLE public.advances
  ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'advance';
ALTER TABLE public.advances
  ADD COLUMN IF NOT EXISTS installment_months integer;

-- Belt-and-braces: any pre-existing NULL kind (shouldn't happen given the
-- DEFAULT, but safe if the column existed before) becomes 'advance'.
UPDATE public.advances SET kind = 'advance' WHERE kind IS NULL;

-- =============================================================
-- 69. INVENTORY SHIFTS — two-touchpoint per-shift stock (open + close)
--     A branch-floor inventory layer that REUSES the daily_count_items
--     catalog (same items / units / low_at thresholds — no duplicate
--     item lists). One inventory_shifts row per (branch, business_date,
--     shift in morning|evening). The OPEN step records opening_qty per
--     item; the CLOSE step records closing_qty + received_qty + the
--     Foodics-sold qty (foodics_qty) PER ITEM, and flips status to
--     'closed'. Counts live in inventory_shift_counts (one row per
--     shift+item); foodics_qty drives per-item variance (counted-consumed
--     vs POS-sold). inventory_shifts.foodics_total is kept as the cached
--     sum of per-item foodics_qty (for the daily Foodics chart/KPI).
--     Loaded on demand per branch+month (the series grows unbounded —
--     same perf discipline as daily_counts/attendance), never bulk-loaded.
--
--     New role 'branch_device': a SHARED per-branch iPad login that can
--     ONLY touch this inventory layer. It is added to the write roles
--     here and to daily_count_items SELECT (so the kiosk can read the
--     item catalogue). Floor (barista/head_barista) + operations + the
--     device write; destructive DELETE stays admin/head_barista.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_shifts (
  id              uuid primary key default gen_random_uuid(),
  branch          text not null,
  business_date   date not null,
  shift           text not null default 'morning',
  status          text not null default 'open',
  opened_by       uuid references public.employees(id),
  opened_by_name  text,
  opened_at       timestamptz,
  closed_by       uuid references public.employees(id),
  closed_by_name  text,
  closed_at       timestamptz,
  foodics_total   numeric(12,2),
  note            text,
  recorded_by     uuid default auth.uid(),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  CONSTRAINT inventory_shifts_shift_chk  CHECK (shift  IN ('morning','evening')),
  CONSTRAINT inventory_shifts_status_chk CHECK (status IN ('open','closed')),
  UNIQUE (branch, business_date, shift)
);
CREATE INDEX IF NOT EXISTS inventory_shifts_branch_date_idx ON public.inventory_shifts(branch, business_date);

CREATE TABLE IF NOT EXISTS public.inventory_shift_counts (
  id           uuid primary key default gen_random_uuid(),
  shift_id     uuid not null references public.inventory_shifts(id) ON DELETE CASCADE,
  item_id      uuid not null references public.daily_count_items(id) ON DELETE CASCADE,
  opening_qty  numeric(12,2),
  closing_qty  numeric(12,2),
  received_qty numeric(12,2),
  foodics_qty  numeric(12,2),
  UNIQUE (shift_id, item_id)
);
-- Idempotent guard: adds foodics_qty if an earlier version of this block
-- (without it) was already run.
ALTER TABLE public.inventory_shift_counts ADD COLUMN IF NOT EXISTS foodics_qty numeric(12,2);
CREATE INDEX IF NOT EXISTS inventory_shift_counts_shift_idx ON public.inventory_shift_counts(shift_id);

ALTER TABLE public.inventory_shifts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_shift_counts ENABLE ROW LEVEL SECURITY;

-- Idempotent: drop any existing policies on both tables before recreating.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public' AND tablename IN ('inventory_shifts','inventory_shift_counts')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "ish_select_floor_ops_device"
  ON public.inventory_shifts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "ish_insert_floor_ops_device"
  ON public.inventory_shifts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "ish_update_floor_ops_device"
  ON public.inventory_shifts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "ish_delete_admin_or_head_barista"
  ON public.inventory_shifts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

CREATE POLICY "isc_select_floor_ops_device"
  ON public.inventory_shift_counts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "isc_insert_floor_ops_device"
  ON public.inventory_shift_counts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "isc_update_floor_ops_device"
  ON public.inventory_shift_counts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "isc_delete_admin_or_head_barista"
  ON public.inventory_shift_counts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

-- Let the shared branch-device login read the item catalogue (the kiosk
-- needs item names/units/categories/low_at). Re-create the SELECT policy
-- idempotently with 'branch_device' added — no other change.
DROP POLICY IF EXISTS "dci_select_floor_or_ops" ON public.daily_count_items;
CREATE POLICY "dci_select_floor_or_ops"
  ON public.daily_count_items FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations','branch_device']));

-- Extend the system_role CHECK constraint with 'branch_device' so an admin
-- can actually assign the kiosk role in the employee editor (without this the
-- UPDATE fails the CHECK and surfaces as "Some fields are invalid").
ALTER TABLE public.employees
  DROP CONSTRAINT IF EXISTS employees_system_role_chk;
ALTER TABLE public.employees
  ADD CONSTRAINT employees_system_role_chk
  CHECK (system_role IS NULL OR system_role IN (
    'admin','hr','operations','barista','head_barista','roaster',
    'accounting','marketing','maintenance','bakery','employee','branch_device'
  ));

-- =============================================================
-- 70. INVENTORY BEAN CATALOG — align v60 + espresso to the branches' real list
--     Reuses daily_count_items (the inventory shift open/close form + Daily
--     count list active items per category; beans are entered in kg). Fully
--     idempotent & re-runnable, case-insensitive name match. Beans dropped
--     from the list are DEACTIVATED (active=false), never deleted, so any
--     past counts that reference them survive. The real lists (owner-given):
--       espresso (2): Colombia ESP, Guji ESP
--       v60 (10): Manos, Ethiopia, Brazil, Grape, Panama, Beni Suliman,
--                 Gadeb, Candy, Haraz, Peach
--     (retires V60 Chel-Chel + C.O.D-Oromio from the original seed.)
-- =============================================================
-- (a) The seed shipped Gadeb as 'Ethiopia Gadeb'; branches call it 'V60 Gadeb'.
--     Rename in place so its history carries over (no new item, no orphan).
UPDATE public.daily_count_items
   SET name = 'V60 Gadeb'
 WHERE category = 'v60' AND lower(name) = 'ethiopia gadeb';

-- (b) Insert any of the 10 desired V60 beans that don't exist yet (kg).
INSERT INTO public.daily_count_items (name, unit, category, tracks_waste, sort_order, active)
SELECT v.name, 'kg', 'v60', false, v.so, true
FROM (VALUES
  ('V60 Manos',162),('V60 Ethiopia',164),('V60 Brazil',166),('V60 Grape',168),
  ('V60 Panama',170),('V60 Beni Suliman',172),('V60 Gadeb',174),('V60 Candy',176),
  ('V60 Haraz',178),('V60 Peach',180)
) AS v(name, so)
WHERE NOT EXISTS (
  SELECT 1 FROM public.daily_count_items d
   WHERE d.category = 'v60' AND lower(d.name) = lower(v.name)
);

-- (c) Ensure the 10 are active, in kg, and cleanly ordered.
UPDATE public.daily_count_items SET active = true, unit = 'kg',
  sort_order = CASE lower(name)
    WHEN 'v60 manos' THEN 162 WHEN 'v60 ethiopia' THEN 164 WHEN 'v60 brazil' THEN 166
    WHEN 'v60 grape' THEN 168 WHEN 'v60 panama' THEN 170 WHEN 'v60 beni suliman' THEN 172
    WHEN 'v60 gadeb' THEN 174 WHEN 'v60 candy' THEN 176 WHEN 'v60 haraz' THEN 178
    WHEN 'v60 peach' THEN 180 ELSE sort_order END
 WHERE category = 'v60' AND lower(name) IN
   ('v60 manos','v60 ethiopia','v60 brazil','v60 grape','v60 panama',
    'v60 beni suliman','v60 gadeb','v60 candy','v60 haraz','v60 peach');

-- (d) Retire any other V60 beans (e.g. Chel-Chel, C.O.D-Oromio) — deactivate.
UPDATE public.daily_count_items SET active = false
 WHERE category = 'v60' AND lower(name) NOT IN
   ('v60 manos','v60 ethiopia','v60 brazil','v60 grape','v60 panama',
    'v60 beni suliman','v60 gadeb','v60 candy','v60 haraz','v60 peach');

-- (e) Espresso — ensure the 2 kinds (active, kg); retire any others.
INSERT INTO public.daily_count_items (name, unit, category, tracks_waste, sort_order, active)
SELECT v.name, 'kg', 'espresso', false, v.so, true
FROM (VALUES ('Colombia ESP',142),('Guji ESP',144)) AS v(name, so)
WHERE NOT EXISTS (
  SELECT 1 FROM public.daily_count_items d
   WHERE d.category = 'espresso' AND lower(d.name) = lower(v.name)
);
UPDATE public.daily_count_items SET active = true, unit = 'kg'
 WHERE category = 'espresso' AND lower(name) IN ('colombia esp','guji esp');
UPDATE public.daily_count_items SET active = false
 WHERE category = 'espresso' AND lower(name) NOT IN ('colombia esp','guji esp');

-- =============================================================
-- 71. BRANCH ROSTER — names-only staff list for one branch (kiosk picker)
--     A shared branch-device login can read only its OWN employee_extras row
--     (RLS), so it can't filter the "Who's on shift?" picker to its branch
--     client-side. This SECURITY DEFINER function returns ONLY id + names +
--     avatar colour for ACTIVE, non-device staff whose employee_extras.branch
--     matches p_branch — no salary / iqama / contact data crosses. Branch
--     match is case-insensitive (branch names are stored upper-case but be
--     defensive). EXECUTE granted to authenticated (names are low-sensitivity);
--     the frontend calls it via sb.rpc('branch_roster', { p_branch }).
-- =============================================================
CREATE OR REPLACE FUNCTION public.branch_roster(p_branch text)
RETURNS TABLE (id uuid, first_name text, last_name text, avatar_color text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT e.id, e.first_name, e.last_name, e.avatar_color
  FROM public.employees e
  JOIN public.employee_extras x ON x.employee_id = e.id
  WHERE e.status = 'active'
    AND COALESCE(e.system_role, 'employee') <> 'branch_device'
    AND upper(COALESCE(x.branch, '')) = upper(COALESCE(p_branch, ''))
  ORDER BY e.first_name, e.last_name;
$$;
REVOKE ALL ON FUNCTION public.branch_roster(text) FROM public;
GRANT EXECUTE ON FUNCTION public.branch_roster(text) TO authenticated;

-- =============================================================
-- 72. INVENTORY VARIANCE STANDARD — recipe dose, theoretical usage, waste log
--     Implements the standard coffee-cost-control method: compare ACTUAL
--     consumption (opening + received − closing, already captured) against
--     THEORETICAL usage (cups sold × standard dose), and log daily waste so
--     the gap is explained. Actual − Theoretical − Waste = true loss.
--   (a) Per-item standard dose in grams/serving (espresso shot, V60 cup).
--       Seeds the owner's recipe doses (20 g each); editable in Manage items.
--   (b) Daily waste log on the shift — the four standard reasons, in grams.
-- =============================================================
ALTER TABLE public.daily_count_items ADD COLUMN IF NOT EXISTS dose_g numeric(8,2);
UPDATE public.daily_count_items SET dose_g = 20 WHERE category = 'espresso' AND dose_g IS NULL;
UPDATE public.daily_count_items SET dose_g = 20 WHERE category = 'v60'      AND dose_g IS NULL;

ALTER TABLE public.inventory_shifts ADD COLUMN IF NOT EXISTS waste_dialin_g   numeric(10,2);
ALTER TABLE public.inventory_shifts ADD COLUMN IF NOT EXISTS waste_remakes_g  numeric(10,2);
ALTER TABLE public.inventory_shifts ADD COLUMN IF NOT EXISTS waste_training_g numeric(10,2);
ALTER TABLE public.inventory_shifts ADD COLUMN IF NOT EXISTS waste_spillage_g numeric(10,2);

-- =============================================================
-- 73. INVENTORY STAFF & CUSTOMER USAGE LOG — attributed non-sale consumption
--     Itemized log of coffee/sweets that left as STAFF consumption or a
--     CUSTOMER comp (calibration/remakes/training/spillage stay in the shift
--     waste log). One row per (shift, item, reason, optional employee, qty).
--     qty is in SERVINGS: for a bean, grams = qty × dose_g; for a pcs item
--     (sweets), qty = pieces. Loaded with the shift series per branch+month.
--     Write roles match inventory_shift_counts; DELETE is also floor/device
--     because saving a close REPLACES the shift's rows (delete-then-insert).
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_usage_log (
  id           uuid primary key default gen_random_uuid(),
  shift_id     uuid not null references public.inventory_shifts(id) ON DELETE CASCADE,
  item_id      uuid not null references public.daily_count_items(id) ON DELETE CASCADE,
  reason       text not null default 'staff_coffee',
  employee_id  uuid references public.employees(id),
  qty          numeric(10,2) not null default 0,
  note         text,
  recorded_by  uuid default auth.uid(),
  created_at   timestamptz not null default now(),
  CONSTRAINT inventory_usage_reason_chk CHECK (reason IN ('staff_coffee','staff_food','customer_comp','other'))
);
CREATE INDEX IF NOT EXISTS inventory_usage_log_shift_idx ON public.inventory_usage_log(shift_id);

ALTER TABLE public.inventory_usage_log ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='inventory_usage_log'
  LOOP EXECUTE format('DROP POLICY IF EXISTS %I ON public.inventory_usage_log', r.policyname); END LOOP;
END $$;

CREATE POLICY "iul_select_floor_ops_device" ON public.inventory_usage_log FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "iul_insert_floor_ops_device" ON public.inventory_usage_log FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "iul_update_floor_ops_device" ON public.inventory_usage_log FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "iul_delete_floor_ops_device" ON public.inventory_usage_log FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));

-- =============================================================
-- 74. INVENTORY DRINKS — staff/comp drink recipes (grams per drink)
--     A small bean-AGNOSTIC drink menu: each drink just carries grams_per
--     (the dose for that drink — single 20 g, double 40 g, etc.). When a
--     staff/comp coffee is logged you pick the DRINK (sets grams) AND the
--     BEAN (any of the 12), so "Manual Espresso → Guji" etc. all work.
--     inventory_usage_log.drink_id links the log row to the recipe; item_id
--     still records the actual bean used. SELECT to floor/ops/device;
--     manage (write) admin/head_barista.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_drinks (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  grams_per   numeric(8,2) not null default 20,
  category    text not null default 'espresso',  -- which beans the drink can use: espresso | v60 | any
  sort_order  int not null default 0,
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);
-- Idempotent guard if an earlier version of this block (without category) ran.
ALTER TABLE public.inventory_drinks ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'espresso';
-- Starter espresso menu (idempotent — only seeds when the table is empty).
-- Espresso drinks → bean pick is Colombia/Guji; "Manual Espresso" → any bean.
INSERT INTO public.inventory_drinks (name, grams_per, category, sort_order)
SELECT v.name, v.g, v.cat, v.so FROM (VALUES
  ('Manual Espresso',20,'any',     10),('Espresso',20,'espresso',20),('Double Espresso',40,'espresso',30),
  ('Americano',20,'espresso',40),('Latte',20,'espresso',50),('Cappuccino',20,'espresso',60),
  ('Flat White',40,'espresso',70),('Cortado',20,'espresso',80),('Macchiato',20,'espresso',90)
) AS v(name,g,cat,so)
WHERE NOT EXISTS (SELECT 1 FROM public.inventory_drinks);
-- If the menu was already seeded without categories, set Manual Espresso to 'any'.
UPDATE public.inventory_drinks SET category='any' WHERE lower(name)='manual espresso' AND category IS DISTINCT FROM 'any';

CREATE INDEX IF NOT EXISTS inventory_drinks_sort_idx ON public.inventory_drinks(sort_order);

ALTER TABLE public.inventory_drinks ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='inventory_drinks'
  LOOP EXECUTE format('DROP POLICY IF EXISTS %I ON public.inventory_drinks', r.policyname); END LOOP;
END $$;
CREATE POLICY "idr_select_floor_ops_device" ON public.inventory_drinks FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "idr_insert_admin_head" ON public.inventory_drinks FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "idr_update_admin_head" ON public.inventory_drinks FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "idr_delete_admin_head" ON public.inventory_drinks FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

ALTER TABLE public.inventory_usage_log ADD COLUMN IF NOT EXISTS drink_id uuid references public.inventory_drinks(id) ON DELETE SET NULL;

-- =============================================================
-- 75. INVENTORY USAGE — owner consumption reasons
--     Owners also take coffee/sweets — tracked but exempt from the staff
--     1+1 allowance. Widen the usage-log reason CHECK with owner_coffee /
--     owner_food (idempotent drop-then-add).
-- =============================================================
ALTER TABLE public.inventory_usage_log DROP CONSTRAINT IF EXISTS inventory_usage_reason_chk;
ALTER TABLE public.inventory_usage_log ADD CONSTRAINT inventory_usage_reason_chk
  CHECK (reason IN ('staff_coffee','staff_food','owner_coffee','owner_food','customer_comp','other'));

-- =============================================================
-- 76. INVENTORY OWNERS — a simple owners list for consumption logging
--     Owners aren't employees and have no app role. This is just a short
--     pick-list (seeded with the business owners; manage in-app). A usage row
--     for an owner sets owner_id; the dashboard's per-owner card reads it.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_owners (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  sort_order  int not null default 0,
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);
INSERT INTO public.inventory_owners (name, sort_order)
SELECT v.name, v.so FROM (VALUES ('Abdallah Alqatani',10),('Omar',20)) AS v(name,so)
WHERE NOT EXISTS (SELECT 1 FROM public.inventory_owners);

ALTER TABLE public.inventory_owners ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='inventory_owners'
  LOOP EXECUTE format('DROP POLICY IF EXISTS %I ON public.inventory_owners', r.policyname); END LOOP;
END $$;
CREATE POLICY "iow_select_floor_ops_device" ON public.inventory_owners FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "iow_insert_admin_head" ON public.inventory_owners FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "iow_update_admin_head" ON public.inventory_owners FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista']));
CREATE POLICY "iow_delete_admin_head" ON public.inventory_owners FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']));

ALTER TABLE public.inventory_usage_log ADD COLUMN IF NOT EXISTS owner_id uuid references public.inventory_owners(id) ON DELETE SET NULL;

-- =============================================================
-- 77. EMPLOYEE EXTRAS — per-employee daily working hours override
--     The overtime / hourly basis is salary ÷ 30 ÷ day-hours. Day-hours
--     defaulted by nationality (Saudi 8 / other 10); some staff work a
--     different day (e.g. 9h), which skewed their rate. This optional
--     per-employee override wins when set; blank falls back to the default.
-- =============================================================
ALTER TABLE public.employee_extras ADD COLUMN IF NOT EXISTS daily_hours numeric(4,1);

-- =============================================================
-- 78. INVENTORY DRINK SALES — the espresso side of the product mix
--     The product-mix screen records Foodics sales per product. Item sales
--     (V60 / sweets / 250g / premium) reuse inventory_shift_counts.foodics_qty
--     (one row per item). Espresso DRINKS (Latte, Cappuccino, …) aren't items,
--     so their sold quantities live here, one row per (shift, drink); the
--     dashboard rolls them up (qty × drink dose) into espresso theoretical.
--     Same write roles as the other shift tables; DELETE included (save
--     replaces the shift's rows).
-- =============================================================
CREATE TABLE IF NOT EXISTS public.inventory_drink_sales (
  id        uuid primary key default gen_random_uuid(),
  shift_id  uuid not null references public.inventory_shifts(id) ON DELETE CASCADE,
  drink_id  uuid not null references public.inventory_drinks(id) ON DELETE CASCADE,
  qty_sold  numeric(10,2) not null default 0,
  UNIQUE (shift_id, drink_id)
);
CREATE INDEX IF NOT EXISTS inventory_drink_sales_shift_idx ON public.inventory_drink_sales(shift_id);

ALTER TABLE public.inventory_drink_sales ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='inventory_drink_sales'
  LOOP EXECUTE format('DROP POLICY IF EXISTS %I ON public.inventory_drink_sales', r.policyname); END LOOP;
END $$;
CREATE POLICY "ids_select_floor_ops_device" ON public.inventory_drink_sales FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "ids_insert_floor_ops_device" ON public.inventory_drink_sales FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "ids_update_floor_ops_device" ON public.inventory_drink_sales FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));
CREATE POLICY "ids_delete_floor_ops_device" ON public.inventory_drink_sales FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']));

-- =============================================================
-- 79. INVENTORY DRINKS — serve tag (hot/iced/manual) + missing menu drinks
--     The product-mix entry screen mirrors the Foodics report sections:
--     HOT -> ICED -> MANUAL ESPRESSO. The drinks catalog had only hot drinks
--     and no way to split them. Add a `serve` column and seed the iced drinks,
--     Matcha (non-coffee, dose 0 so it never feeds espresso usage), Italian
--     Espresso, and the manual single-origin espressos. All espresso drinks
--     (any serve) already roll into espresso theoretical via drink sales x dose,
--     so no dashboard change is needed. Idempotent: column add guarded, seeds
--     skip any drink whose name already exists.
-- =============================================================
ALTER TABLE public.inventory_drinks ADD COLUMN IF NOT EXISTS serve text NOT NULL DEFAULT 'hot';

-- The single seeded "Latte" is the hot one; the report calls it "Hot Latte".
UPDATE public.inventory_drinks SET name='Hot Latte' WHERE lower(name)='latte';

INSERT INTO public.inventory_drinks (name, grams_per, category, serve, sort_order)
SELECT v.name, v.g, v.cat, v.serve, v.so
FROM (VALUES
  ('Italian Espresso',     20::numeric, 'espresso', 'hot',     35),
  ('Espresso Freddo',      20::numeric, 'espresso', 'iced',   110),
  ('Iced Americano',       20::numeric, 'espresso', 'iced',   120),
  ('Iced Latte',           20::numeric, 'espresso', 'iced',   130),
  ('Matcha Latte',          0::numeric, 'any',      'iced',   140),
  ('Brazil Fazinda ESP',   20::numeric, 'espresso', 'manual', 210),
  ('Columbia Manos ESP',   20::numeric, 'espresso', 'manual', 220),
  ('Columbia Narino ESP',  20::numeric, 'espresso', 'manual', 230),
  ('Ethiopia Guji ESP',    20::numeric, 'espresso', 'manual', 240)
) AS v(name, g, cat, serve, so)
WHERE NOT EXISTS (
  SELECT 1 FROM public.inventory_drinks d WHERE lower(d.name) = lower(v.name)
);

-- =============================================================
-- 80. EMPLOYEE DOCUMENTS TO SIGN ("Agreements")
--     HR drafts a free-text document (title + body) addressed to one
--     employee; the employee signs on their phone and HR/manager counter-
--     signs — the same two-party e-signature flow as warning letters
--     (block 65), stored as base64 PNG data-URLs on the row. The document
--     renders on the Hassad letterhead, printable/PDF. As with warnings,
--     signing goes through a SECURITY DEFINER RPC so an employee can set
--     ONLY their own signature (column-scoped, which plain RLS can't do).
-- =============================================================
CREATE TABLE IF NOT EXISTS public.signed_documents (
  id                 uuid primary key default gen_random_uuid(),
  employee_id        uuid not null references public.employees(id) ON DELETE CASCADE,
  title              text not null,
  body               text not null,
  created_by         uuid references public.employees(id),
  created_at         timestamptz not null default now(),
  employee_signature text,
  employee_signed_at timestamptz,
  manager_signature  text,
  manager_signed_at  timestamptz,
  manager_signed_by  uuid references public.employees(id)
);
CREATE INDEX IF NOT EXISTS signed_documents_emp_idx ON public.signed_documents(employee_id);

ALTER TABLE public.signed_documents ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='signed_documents'
  LOOP EXECUTE format('DROP POLICY IF EXISTS %I ON public.signed_documents', r.policyname); END LOOP;
END $$;
CREATE POLICY "sd_select_admin_hr_or_self" ON public.signed_documents FOR SELECT TO authenticated
  USING (
    public.has_role(ARRAY['admin','hr'])
    OR EXISTS (SELECT 1 FROM public.employees e WHERE e.id = signed_documents.employee_id AND e.user_id = auth.uid())
  );
CREATE POLICY "sd_insert_admin_hr" ON public.signed_documents FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "sd_update_admin_hr" ON public.signed_documents FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','hr'])) WITH CHECK (public.has_role(ARRAY['admin','hr']));
CREATE POLICY "sd_delete_admin" ON public.signed_documents FOR DELETE TO authenticated
  USING (public.is_admin());

CREATE OR REPLACE FUNCTION public.sign_document(p_id uuid, p_signature text, p_as text)
RETURNS public.signed_documents
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  d      public.signed_documents;
  my_emp uuid;
BEGIN
  IF p_signature IS NULL OR length(p_signature) < 50 THEN
    RAISE EXCEPTION 'Signature is empty';
  END IF;
  IF length(p_signature) > 400000 THEN
    RAISE EXCEPTION 'Signature image is too large';
  END IF;

  SELECT * INTO d FROM public.signed_documents WHERE id = p_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Document not found'; END IF;

  IF p_as = 'manager' THEN
    IF NOT public.has_role(ARRAY['admin','hr']) THEN
      RAISE EXCEPTION 'Only admin or HR can sign as the manager';
    END IF;
    SELECT id INTO my_emp FROM public.employees WHERE user_id = auth.uid();
    UPDATE public.signed_documents
       SET manager_signature = p_signature, manager_signed_at = now(), manager_signed_by = my_emp
     WHERE id = p_id
     RETURNING * INTO d;

  ELSIF p_as = 'employee' THEN
    SELECT id INTO my_emp FROM public.employees WHERE user_id = auth.uid();
    IF my_emp IS NULL OR my_emp <> d.employee_id THEN
      RAISE EXCEPTION 'You can only sign your own document';
    END IF;
    UPDATE public.signed_documents
       SET employee_signature = p_signature, employee_signed_at = now()
     WHERE id = p_id
     RETURNING * INTO d;

  ELSE
    RAISE EXCEPTION 'Invalid signer role: %', p_as;
  END IF;

  RETURN d;
END;
$$;
REVOKE ALL ON FUNCTION public.sign_document(uuid, text, text) FROM public;
GRANT EXECUTE ON FUNCTION public.sign_document(uuid, text, text) TO authenticated;

-- =============================================================
-- 81. INVENTORY DRINKS — full "Manual Espresso" single-origin set
--     Block 79 seeded only 4 manual single-origin espressos. The Foodics
--     "MANUAL ESPRESSO" menu category actually carries the full house
--     single-origin lineup, so the product-mix entry screen was missing
--     most of them. Seed the complete set (grams_per 20, category 'espresso',
--     serve 'manual') in Foodics list order. Three origins that are Inactive
--     in Foodics (Beni Suliman, Chel-Chele, Shakiso) are seeded active=false
--     so they stay off the entry screen but the catalog matches the console.
--     Idempotent: the INSERT skips any drink whose name already exists; the
--     reconcile UPDATE re-applies serve/category/sort_order/active by name so
--     the 4 pre-existing rows fall into the correct order too.
--     NOTE: each manual single-origin pulls from its OWN bean, but only
--     Colombia + Guji are tracked as espresso stock beans (daily_count_items),
--     so their cups still roll into the Colombia/Guji theoretical pool on the
--     variance dashboard — same behaviour block 79 already established for
--     Brazil Fazinda etc. Entry/reporting is unaffected; deep per-origin bean
--     variance would be a separate change.
-- =============================================================
INSERT INTO public.inventory_drinks (name, grams_per, category, serve, sort_order, active)
SELECT v.name, v.g, 'espresso', 'manual', v.so, v.active
FROM (VALUES
  ('Ethiopia Sidamo ESP',     20::numeric, 210, true),
  ('Yemen Haraz ESP',         20::numeric, 211, true),
  ('Ethiopia Gadeb ESP',      20::numeric, 212, true),
  ('Ethiopia Guji ESP',       20::numeric, 213, true),
  ('Columbia Manos ESP',      20::numeric, 214, true),
  ('Peach ESP',               20::numeric, 215, true),
  ('Candy ESP',               20::numeric, 216, true),
  ('Grape ESP',               20::numeric, 217, true),
  ('Panama ESP',              20::numeric, 218, true),
  ('Beni Suliman ESP',        20::numeric, 219, false),
  ('Ethiopia Chel-Chele ESP', 20::numeric, 220, false),
  ('Ethiopia Shakiso ESP',    20::numeric, 221, false),
  ('Ethiopia Oromio ESP',     20::numeric, 222, true),
  ('Columbia Narino ESP',     20::numeric, 223, true),
  ('Brazil Fazinda ESP',      20::numeric, 224, true)
) AS v(name, g, so, active)
WHERE NOT EXISTS (
  SELECT 1 FROM public.inventory_drinks d WHERE lower(d.name) = lower(v.name)
);

-- Reconcile ordering + serve + active for the whole manual set (also fixes the
-- 4 rows seeded by block 79 so they slot into Foodics order).
UPDATE public.inventory_drinks d SET
  serve      = 'manual',
  category   = 'espresso',
  sort_order = v.so,
  active     = v.active
FROM (VALUES
  ('Ethiopia Sidamo ESP',210,true),('Yemen Haraz ESP',211,true),
  ('Ethiopia Gadeb ESP',212,true),('Ethiopia Guji ESP',213,true),
  ('Columbia Manos ESP',214,true),('Peach ESP',215,true),
  ('Candy ESP',216,true),('Grape ESP',217,true),
  ('Panama ESP',218,true),('Beni Suliman ESP',219,false),
  ('Ethiopia Chel-Chele ESP',220,false),('Ethiopia Shakiso ESP',221,false),
  ('Ethiopia Oromio ESP',222,true),('Columbia Narino ESP',223,true),
  ('Brazil Fazinda ESP',224,true)
) AS v(name, so, active)
WHERE lower(d.name) = lower(v.name);

-- =============================================================
-- 82. INVENTORY DRINKS — drop generic espressos from the Product Mix
--     "Manual Espresso", "Espresso" and "Double Espresso" were seeded (block
--     78) with serve='hot', so they showed in the Product Mix → Hot section.
--     They aren't Foodics product-mix lines — they're generic espresso recipes
--     used only by the staff/customer usage log. Set serve='none' so they drop
--     out of every product-mix section (invDrinksByServe only renders
--     hot/iced/manual) while staying ACTIVE, so the staff usage-log drink
--     picker (invActiveDrinks, serve-agnostic) still lists them. Idempotent.
-- =============================================================
UPDATE public.inventory_drinks
   SET serve = 'none'
 WHERE lower(name) IN ('manual espresso','espresso','double espresso');

-- =============================================================
-- 83. ROAST BATCHES — per-batch traceability with sorting loss
--     After roasting, beans are hand-sorted and defects are excluded, so a
--     batch has THREE weights: green in → after roasting (moisture loss) →
--     after sorting (what actually reaches the shelf). Each batch gets a
--     sequential serial (displayed as RB-00042 in the app) so customer
--     complaints can be traced back to the exact roast. The batch row is the
--     analytical record; stock still moves through the two paired
--     inventory_movements (green out = green_in_kg, roasted in = sorted_kg),
--     stamped with the serial in their notes.
-- =============================================================
CREATE TABLE IF NOT EXISTS public.roast_batches (
  id              uuid primary key default gen_random_uuid(),
  serial_no       bigint generated by default as identity,
  green_item_id   uuid not null references public.inventory_items(id) on delete restrict,
  roasted_item_id uuid not null references public.inventory_items(id) on delete restrict,
  green_in_kg     numeric(12,2) not null CHECK (green_in_kg > 0),
  roasted_kg      numeric(12,2) not null CHECK (roasted_kg >= 0),
  sorted_kg       numeric(12,2) not null CHECK (sorted_kg >= 0),
  branch          text,
  roast_date      date not null default current_date,
  notes           text,
  recorded_by     uuid references public.employees(id),
  created_at      timestamptz not null default now(),
  CHECK (roasted_kg <= green_in_kg),
  CHECK (sorted_kg <= roasted_kg)
);
CREATE UNIQUE INDEX IF NOT EXISTS roast_batches_serial_idx ON public.roast_batches(serial_no);
CREATE INDEX IF NOT EXISTS roast_batches_date_idx ON public.roast_batches(roast_date DESC);

ALTER TABLE public.roast_batches ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'roast_batches'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- Same scopes as inventory_movements: whoever can see stock movement can
-- see batches; writes are roaster-shaped (admin, head barista, roaster).
CREATE POLICY "roast_batches_select_roles"
  ON public.roast_batches FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','hr','operations','head_barista','roaster']));
CREATE POLICY "roast_batches_insert_roles"
  ON public.roast_batches FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "roast_batches_update_roles"
  ON public.roast_batches FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','roaster']));
CREATE POLICY "roast_batches_delete_roles"
  ON public.roast_batches FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','roaster']));

-- =============================================================
-- 84. BEAN-CODED BATCH SERIALS — per-origin prefixes (EG-0001)
--     Each green bean can carry a short serial prefix (e.g. Ethiopia
--     Guji = EG, Panama = PN). Batches roasted from that bean are then
--     numbered per prefix (EG-0001, EG-0002, …) instead of the global
--     RB- sequence, so the bag label immediately identifies the origin.
--     The global serial_no identity column stays as the fallback for
--     beans without a prefix and for all pre-existing batches.
--     Numbering is assigned DB-side by a BEFORE INSERT trigger reading
--     an atomic per-prefix counter table, so two simultaneous inserts
--     can never mint the same number. The counter table has RLS enabled
--     with NO policies — only the SECURITY DEFINER trigger touches it.
-- =============================================================
ALTER TABLE public.inventory_items ADD COLUMN IF NOT EXISTS serial_prefix text;
ALTER TABLE public.roast_batches   ADD COLUMN IF NOT EXISTS serial_prefix text;
ALTER TABLE public.roast_batches   ADD COLUMN IF NOT EXISTS prefix_no bigint;

CREATE TABLE IF NOT EXISTS public.roast_serial_counters (
  prefix  text primary key,
  last_no bigint not null default 0
);
ALTER TABLE public.roast_serial_counters ENABLE ROW LEVEL SECURITY;
-- Deliberately no policies: clients never read or write counters directly.

CREATE UNIQUE INDEX IF NOT EXISTS roast_batches_prefix_serial_idx
  ON public.roast_batches(serial_prefix, prefix_no)
  WHERE serial_prefix IS NOT NULL;

CREATE OR REPLACE FUNCTION public.assign_roast_serial()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Normalize whatever the client sent; blank means "no prefix".
  NEW.serial_prefix := nullif(upper(btrim(coalesce(NEW.serial_prefix, ''))), '');
  -- Default to the green bean's configured prefix (stamped at roast
  -- time — renaming the bean's prefix later never rewrites history).
  IF NEW.serial_prefix IS NULL THEN
    SELECT nullif(upper(btrim(coalesce(i.serial_prefix, ''))), '')
      INTO NEW.serial_prefix
      FROM public.inventory_items i
     WHERE i.id = NEW.green_item_id;
  END IF;
  NEW.serial_prefix := left(NEW.serial_prefix, 6);
  IF NEW.serial_prefix IS NOT NULL AND NEW.prefix_no IS NULL THEN
    INSERT INTO public.roast_serial_counters AS c (prefix, last_no)
    VALUES (NEW.serial_prefix, 1)
    ON CONFLICT (prefix) DO UPDATE SET last_no = c.last_no + 1
    RETURNING last_no INTO NEW.prefix_no;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS assign_roast_serial_trigger ON public.roast_batches;
CREATE TRIGGER assign_roast_serial_trigger
  BEFORE INSERT ON public.roast_batches
  FOR EACH ROW EXECUTE FUNCTION public.assign_roast_serial();

-- =============================================================
-- 85. BRANCH-SCOPED INVENTORY RLS — enforce branch separation DB-side
--     Until now branch separation on the shift/count tables was app-layer
--     only (.eq('branch', invBranch())): RLS checked ROLE, so any
--     inventory-role login could read/write another branch's rows through
--     the API. This block binds branch-locked roles to their assigned
--     branch at the database:
--       · admin + operations stay cross-branch (they're the only roles the
--         app gives a branch picker — see invBranch() in index.html).
--       · head_barista, barista and branch_device are bound to their
--         employee_extras.branch.
--       · SAFETY VALVE: a user with NO branch assigned is unrestricted, so
--         running this migration can never lock staff out mid-shift —
--         binding starts when a branch is set on the profile.
--       · Rows with a NULL/blank branch (shared) stay visible to everyone.
--     Emergency revert (no data change): redefine branch_ok to
--       CREATE OR REPLACE FUNCTION public.branch_ok(text) RETURNS boolean
--         LANGUAGE sql STABLE AS $x$ SELECT true $x$;
--     Deliberately NOT scoped: inventory_items / inventory_movements /
--     incoming transfers (the roaster's stock + cross-branch transfers are
--     genuinely multi-branch), and the catalog tables (global by design).
-- =============================================================
CREATE OR REPLACE FUNCTION public.user_branch()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT NULLIF(TRIM(upper(x.branch)), '')
  FROM public.employees e
  JOIN public.employee_extras x ON x.employee_id = e.id
  WHERE e.user_id = auth.uid()
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION public.user_branch() FROM public;
GRANT EXECUTE ON FUNCTION public.user_branch() TO authenticated;

CREATE OR REPLACE FUNCTION public.branch_ok(p_branch text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public.has_role(ARRAY['admin','operations'])
      OR public.user_branch() IS NULL
      OR NULLIF(TRIM(upper(p_branch)), '') IS NULL
      OR NULLIF(TRIM(upper(p_branch)), '') = public.user_branch();
$$;
REVOKE ALL ON FUNCTION public.branch_ok(text) FROM public;
GRANT EXECUTE ON FUNCTION public.branch_ok(text) TO authenticated;

-- Child tables (shift counts / drink sales / usage log) carry no branch
-- column — they hang off inventory_shifts. SECURITY DEFINER so the lookup
-- doesn't recurse through inventory_shifts' own RLS.
CREATE OR REPLACE FUNCTION public.shift_branch_ok(p_shift uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(
    (SELECT public.branch_ok(s.branch) FROM public.inventory_shifts s WHERE s.id = p_shift),
    true);  -- no shift row: FK enforcement handles inserts; don't hide orphans
$$;
REVOKE ALL ON FUNCTION public.shift_branch_ok(uuid) FROM public;
GRANT EXECUTE ON FUNCTION public.shift_branch_ok(uuid) TO authenticated;

-- Recreate the policies on the seven branch-bound tables with the branch
-- condition ANDed in. Role arrays are unchanged from blocks 30/69/73/74.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname FROM pg_policies
           WHERE schemaname='public'
             AND tablename IN ('inventory_shifts','inventory_shift_counts',
                               'inventory_drink_sales','inventory_usage_log',
                               'daily_counts','weekly_counts','expiry_checks')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

CREATE POLICY "ish_select_floor_ops_device"
  ON public.inventory_shifts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.branch_ok(branch));
CREATE POLICY "ish_insert_floor_ops_device"
  ON public.inventory_shifts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.branch_ok(branch));
CREATE POLICY "ish_update_floor_ops_device"
  ON public.inventory_shifts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.branch_ok(branch))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.branch_ok(branch));
CREATE POLICY "ish_delete_admin_or_head_barista"
  ON public.inventory_shifts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']) AND public.branch_ok(branch));

CREATE POLICY "isc_select_floor_ops_device"
  ON public.inventory_shift_counts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "isc_insert_floor_ops_device"
  ON public.inventory_shift_counts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "isc_update_floor_ops_device"
  ON public.inventory_shift_counts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "isc_delete_admin_or_head_barista"
  ON public.inventory_shift_counts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']) AND public.shift_branch_ok(shift_id));

CREATE POLICY "ids_select_floor_ops_device" ON public.inventory_drink_sales FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "ids_insert_floor_ops_device" ON public.inventory_drink_sales FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "ids_update_floor_ops_device" ON public.inventory_drink_sales FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "ids_delete_floor_ops_device" ON public.inventory_drink_sales FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));

CREATE POLICY "iul_select_floor_ops_device" ON public.inventory_usage_log FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "iul_insert_floor_ops_device" ON public.inventory_usage_log FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "iul_update_floor_ops_device" ON public.inventory_usage_log FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id))
  WITH CHECK (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));
CREATE POLICY "iul_delete_floor_ops_device" ON public.inventory_usage_log FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','operations','head_barista','barista','branch_device']) AND public.shift_branch_ok(shift_id));

CREATE POLICY "dc_select_floor_or_ops"
  ON public.daily_counts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']) AND public.branch_ok(branch));
CREATE POLICY "dc_insert_floor"
  ON public.daily_counts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch));
CREATE POLICY "dc_update_floor"
  ON public.daily_counts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch));
CREATE POLICY "dc_delete_admin_or_head_barista"
  ON public.daily_counts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']) AND public.branch_ok(branch));

CREATE POLICY "wc_select_floor_or_ops"
  ON public.weekly_counts FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']) AND public.branch_ok(branch));
CREATE POLICY "wc_insert_floor"
  ON public.weekly_counts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch));
CREATE POLICY "wc_update_floor"
  ON public.weekly_counts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch));
CREATE POLICY "wc_delete_admin_or_head_barista"
  ON public.weekly_counts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']) AND public.branch_ok(branch));

CREATE POLICY "ec_select_floor_or_ops"
  ON public.expiry_checks FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista','operations']) AND public.branch_ok(branch));
CREATE POLICY "ec_insert_floor"
  ON public.expiry_checks FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch));
CREATE POLICY "ec_update_floor"
  ON public.expiry_checks FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch))
  WITH CHECK (public.has_role(ARRAY['admin','head_barista','barista']) AND public.branch_ok(branch));
CREATE POLICY "ec_delete_admin_or_head_barista"
  ON public.expiry_checks FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['admin','head_barista']) AND public.branch_ok(branch));

-- =============================================================
-- 86. B2B TAX INVOICES — ZATCA-style bilingual invoices for wholesale
--     customers. Sequential serial via identity (displayed INV-000001;
--     fresh sequence, owner-confirmed — the old INV-000115 series came
--     from an external tool). Line items live in a jsonb array
--     [{description, qty, unit, price}] with unit prices EXCLUDING VAT
--     (owner-confirmed); the app computes and stores the rounded
--     subtotal / VAT / total so stored history never shifts if rounding
--     rules ever change. Seller VAT number lives on companies.vat_number
--     (editable in Settings → letterhead, defaults to Hassad's).
-- =============================================================
ALTER TABLE public.companies ADD COLUMN IF NOT EXISTS vat_number text;

CREATE TABLE IF NOT EXISTS public.b2b_invoices (
  id               uuid primary key default gen_random_uuid(),
  invoice_no       bigint generated by default as identity,
  customer_name    text not null,
  customer_vat     text,
  customer_address text,
  invoice_date     date not null default current_date,
  due_terms        text not null default 'Immediate',
  items            jsonb not null default '[]',
  subtotal         numeric(14,2) not null default 0,
  vat_total        numeric(14,2) not null default 0,
  total            numeric(14,2) not null default 0,
  notes            text,
  created_by       uuid references public.employees(id),
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
CREATE UNIQUE INDEX IF NOT EXISTS b2b_invoices_no_idx   ON public.b2b_invoices(invoice_no);
CREATE INDEX IF NOT EXISTS b2b_invoices_date_idx        ON public.b2b_invoices(invoice_date DESC);

ALTER TABLE public.b2b_invoices ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies
           WHERE schemaname='public' AND tablename='b2b_invoices'
  LOOP EXECUTE format('DROP POLICY IF EXISTS %I ON public.b2b_invoices', r.policyname); END LOOP;
END $$;

CREATE POLICY "b2b_select_roles"
  ON public.b2b_invoices FOR SELECT TO authenticated
  USING (public.has_role(ARRAY['admin','accounting','operations']));
CREATE POLICY "b2b_insert_roles"
  ON public.b2b_invoices FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['admin','accounting','operations']));
CREATE POLICY "b2b_update_roles"
  ON public.b2b_invoices FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['admin','accounting','operations']))
  WITH CHECK (public.has_role(ARRAY['admin','accounting','operations']));
CREATE POLICY "b2b_delete_admin"
  ON public.b2b_invoices FOR DELETE TO authenticated
  USING (public.is_admin());

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
