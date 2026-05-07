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
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  is_first boolean;
BEGIN
  SELECT NOT EXISTS (SELECT 1 FROM public.employees) INTO is_first;

  INSERT INTO public.employees (
    user_id, email, first_name, last_name,
    is_admin, status, job_title, department, hire_date, salary
  ) VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'first_name', ''),
    COALESCE(NEW.raw_user_meta_data->>'last_name', ''),
    is_first,
    'active',
    CASE WHEN is_first THEN 'Admin' ELSE 'Employee' END,
    CASE WHEN is_first THEN 'Management' ELSE 'General' END,
    CURRENT_DATE,
    0
  )
  ON CONFLICT (user_id) DO NOTHING;

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
