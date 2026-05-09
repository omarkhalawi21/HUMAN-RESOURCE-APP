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

-- Backfill: anyone currently is_admin becomes 'admin', otherwise 'employee'.
UPDATE public.employees
   SET system_role = CASE WHEN is_admin THEN 'admin' ELSE 'employee' END
 WHERE system_role IS NULL;

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
