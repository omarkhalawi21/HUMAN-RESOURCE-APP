// notify-push — sends a Web Push to the "person in charge" when a new
// maintenance or purchase request is created.
//
// Trigger: a Supabase Database Webhook on INSERT into maintenance_requests
// and purchase_requests calls this function with { type, table, record }.
//
// Deploy:
//   supabase functions deploy notify-push --no-verify-jwt
// Secrets (Project Settings → Edge Functions → Secrets, or `supabase secrets set`):
//   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY
// (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are injected automatically.)
import webpush from 'npm:web-push@3.6.7';
import { createClient } from 'npm:@supabase/supabase-js@2';

const SUPABASE_URL  = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const VAPID_PUBLIC  = Deno.env.get('VAPID_PUBLIC_KEY')!;
const VAPID_PRIVATE = Deno.env.get('VAPID_PRIVATE_KEY')!;

webpush.setVapidDetails('mailto:omarkhalawi21@gmail.com', VAPID_PUBLIC, VAPID_PRIVATE);
const sb = createClient(SUPABASE_URL, SERVICE_ROLE);

Deno.serve(async (req) => {
  let payload: any = {};
  try { payload = await req.json(); } catch { /* ignore */ }
  const { type, table, record } = payload;
  if (type !== 'INSERT' || !record) return new Response('ignored', { status: 200 });

  let title = '', body = '', url = '/', roles: string[] = [], exclude: string | null = null;
  if (table === 'maintenance_requests') {
    title = '🔧 New maintenance request'; body = record.title || '';
    url = '/#/maintenance'; roles = ['admin', 'maintenance']; exclude = record.reported_by;
  } else if (table === 'purchase_requests') {
    title = '🛒 New purchase request'; body = record.item || '';
    url = '/#/purchasing'; roles = ['admin', 'operations', 'maintenance']; exclude = record.requested_by;
  } else {
    return new Response('ignored', { status: 200 });
  }

  // Who's in charge → their employee ids (minus the person who submitted it).
  const { data: emps } = await sb.from('employees').select('id').in('system_role', roles);
  const ids = (emps ?? []).map((e: any) => e.id).filter((id: string) => id !== exclude);
  if (!ids.length) return new Response('no recipients', { status: 200 });

  const { data: subs } = await sb.from('push_subscriptions').select('*').in('employee_id', ids);
  const message = JSON.stringify({ title, body, url, tag: `${table}-${record.id}` });

  await Promise.all((subs ?? []).map(async (s: any) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        message,
      );
    } catch (err: any) {
      // 404/410 = the subscription is dead; prune it.
      const code = err?.statusCode;
      if (code === 404 || code === 410) {
        await sb.from('push_subscriptions').delete().eq('endpoint', s.endpoint);
      }
    }
  }));

  return new Response('ok', { status: 200 });
});
