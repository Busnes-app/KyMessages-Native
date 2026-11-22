const CACHE_NAME = 'ky-base-pwa-busnes-v4';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/manifest.json',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  const shell = url.pathname === '/' || url.pathname === '/index.html';
  // Allow public shell/assets only, never API, SCIM, SSO or future dynamic routes.
  if (!shell && url.pathname !== '/manifest.json' && !url.pathname.startsWith('/assets/')) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    // HTML must refresh online so a deploy can advance its hashed asset URLs.
    if (!shell) {
      const cached = await cache.match(event.request);
      if (cached) return cached;
    }
    let response;
    try {
      response = await fetch(event.request);
    } catch (error) {
      const cached = await cache.match(event.request);
      if (cached) return cached;
      throw error;
    }
    if (response.status === 200 && response.type === 'basic' && !response.redirected) {
      // Storage/quota failures must not hide a successful network response.
      try { await cache.put(event.request, response.clone()); } catch {}
    }
    return response;
  })());
});

function sanitizeRelativeUrl(raw) {
  if (typeof raw !== 'string') return '/';
  const trimmed = raw.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) return '/';
  return trimmed;
}

self.addEventListener('push', (event) => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json() || {};
    } catch {
      payload = { body: event.data.text() };
    }
  }
  const kind = payload.kind === 'call' ? 'call' : 'message';
  const roomId = typeof payload.room_id === 'string' ? payload.room_id : '';
  const title = typeof payload.title === 'string' && payload.title.trim() ? payload.title.trim() : 'KyMessages';
  const body = typeof payload.body === 'string' && payload.body.trim() ? payload.body.trim() : 'New message';
  const targetUrl = sanitizeRelativeUrl(payload.url || (roomId ? `/#room=${encodeURIComponent(roomId)}` : '/'));

  event.waitUntil((async () => {
    // Skip OS notifications for messages when the user is actively viewing that room.
    if (kind !== 'call' && roomId) {
      const openClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      const activeSameRoom = openClients.some((c) => {
        if (!c.focused || c.visibilityState !== 'visible') return false;
        try {
          const parsed = new URL(c.url);
          const hashMatch = parsed.hash === `#room=${encodeURIComponent(roomId)}` || parsed.hash === `#room=${roomId}`;
          const queryMatch = parsed.searchParams.get('room') === roomId;
          return hashMatch || queryMatch;
        } catch {
          return false;
        }
      });
      if (activeSameRoom) return;
    }

    await self.registration.showNotification(title, {
      body,
      icon: '/app-icon-192.png',
      badge: '/app-icon-192.png',
      tag: roomId ? `kymessages-${kind}-${roomId}` : `kymessages-${kind}`,
      renotify: true,
      requireInteraction: kind === 'call',
      data: {
        kind,
        roomId,
        url: targetUrl,
      },
    });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const roomId = typeof data.roomId === 'string' ? data.roomId : '';
  const safeUrl = sanitizeRelativeUrl(data.url || (roomId ? `/#room=${encodeURIComponent(roomId)}` : '/'));

  event.waitUntil((async () => {
    const windowClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windowClients) {
      try {
        const parsed = new URL(client.url);
        if (parsed.origin !== self.location.origin) continue;
        await client.focus();
        client.postMessage({ type: 'kymessages.navigate', roomId, url: safeUrl });
        return;
      } catch {
        // Ignore malformed client URLs.
      }
    }
    if (self.clients.openWindow) {
      await self.clients.openWindow(safeUrl);
    }
  })());
});
