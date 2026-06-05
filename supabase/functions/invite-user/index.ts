// Supabase Edge Function: invite-user
//
// Sends a magic-link invitation email to an employee who's been pre-added
// to the directory but doesn't have an auth.users account yet. The link
// goes through our Custom SMTP (Resend → team@hasadco.sa). When the
// invited user clicks the link, sets a password, and lands in the app,
// the handle_new_user trigger auto-links them to their pre-existing
// employees row by matching email (block 62 made the link possible by
// relaxing user_id immutability to set-once semantics).
//
// Why an Edge Function:
// - Supabase's auth.admin.inviteUserByEmail() requires the service_role
//   key (full DB access). That key MUST NOT live in the browser bundle.
// - Edge Functions run on Supabase's Deno runtime with the service_role
//   available as an env var.
//
// Authorization model:
// - The caller's JWT is read from the Authorization header.
// - We verify the JWT against Supabase Auth (catches expired/tampered).
// - We look up the caller's employees row by user_id and check
//   system_role IN ('admin','hr') — matches canManagePeople() in app.
// - Only admin/hr can issue invites; everyone else gets 403.
//
// Required secrets (auto-provided by Supabase for Edge Functions):
//   SUPABASE_URL
//   SUPABASE_ANON_KEY
//   SUPABASE_SERVICE_ROLE_KEY
//
// Deploy: `supabase functions deploy invite-user`
// Or via Supabase Dashboard → Edge Functions → Deploy.

import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

// Roles allowed to invite. Mirrors canManagePeople() in index.html — if
// that ever broadens (e.g. to include 'operations'), update both sides.
const INVITER_ROLES = new Set(["admin", "hr"]);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return json({ error: "POST only" }, 405);
  }

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) {
    return json({ error: "Missing Authorization header" }, 401);
  }

  // 1. Verify caller's JWT
  const userClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authHeader } } }
  );

  const { data: { user }, error: userError } = await userClient.auth.getUser();
  if (userError || !user) {
    return json({ error: "Not authenticated" }, 401);
  }

  // 2. Confirm caller is admin or hr in OUR system. RLS on employees
  //    naturally lets a logged-in user read their own row.
  const { data: emp, error: empError } = await userClient
    .from("employees")
    .select("system_role")
    .eq("user_id", user.id)
    .maybeSingle();

  if (empError) {
    return json({ error: "Could not verify role: " + empError.message }, 500);
  }
  if (!emp) {
    return json({ error: "No employee profile found for caller" }, 403);
  }
  if (!INVITER_ROLES.has(emp.system_role)) {
    return json(
      { error: "Admin or HR access required to send invitations" },
      403
    );
  }

  // 3. Parse + validate request body
  let body: { email?: string; redirectTo?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const email = (body.email || "").trim().toLowerCase();
  if (!email) {
    return json({ error: "email is required" }, 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "Invalid email address" }, 400);
  }

  // 4. Call Supabase Admin invite API with service_role
  const adminClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );

  const { data, error } = await adminClient.auth.admin.inviteUserByEmail(
    email,
    body.redirectTo ? { redirectTo: body.redirectTo } : undefined
  );

  if (error) {
    // Common case: the email is already in auth.users (already invited
    // or already signed up). Bubble the message up so the UI can show it.
    return json({ error: error.message }, 400);
  }

  return json({ ok: true, user_id: data?.user?.id ?? null });
});
