// Hassad HR — push-only service worker.
// Deliberately has NO fetch handler: it never caches or intercepts requests,
// so it can't serve stale app code or break the single-file app. Its only job
// is to show a notification when a Web Push arrives and focus the app on tap.
self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) {
    data = { title: 'Hassad', body: event.data ? event.data.text() : '' };
  }
  const title = data.title || 'Hassad';
  const options = {
    body: data.body || '',
    icon: data.icon || '/logo.png',
    badge: '/logo.png',
    tag: data.tag || undefined,      // same tag replaces an earlier notification
    data: { url: data.url || '/' },
    requireInteraction: !!data.requireInteraction,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      // Focus an already-open app tab and route it to the target.
      if ('focus' in c) { try { await c.focus(); } catch (_) {} try { c.navigate(target); } catch (_) {} return; }
    }
    if (self.clients.openWindow) return self.clients.openWindow(target);
  })());
});
