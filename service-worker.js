/* Simple network-first for HTML, cache-first for versioned assets */
const APP_CACHE = 'app-cache-v1-20250910071128';
const ASSET_CACHE = 'asset-cache-v1-20250910071128';

// On install, just take control quickly
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// On activate, clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => (k.includes('app-cache-') || k.includes('asset-cache-')) && k !== APP_CACHE && k !== ASSET_CACHE ? caches.delete(k) : null));
    await self.clients.claim();
  })());
});

// Helper to decide if a request is an HTML navigation
function isHTMLRequest(request) {
  return request.mode === 'navigate' || (request.headers.get('accept') || '').includes('text/html');
}

// Fetch strategy
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Bypass for non-GET
  if (req.method !== 'GET') return;

  if (isHTMLRequest(req)) {
    // Network-first for HTML
    event.respondWith((async () => {
      try {
        const fresh = await fetch(req, { cache: 'no-store' });
        const cache = await caches.open(APP_CACHE);
        cache.put(req, fresh.clone());
        return fresh;
      } catch (e) {
        const cache = await caches.open(APP_CACHE);
        const cached = await cache.match(req);
        return cached || caches.match('/index.html');
      }
    })());
    return;
  }

  // For assets: if they look versioned (?v=... or filename hashes), use cache-first
  if (/[?&]v=|\.[a-f0-9]{6,}\./i.test(url.href)) {
    event.respondWith((async () => {
      const cache = await caches.open(ASSET_CACHE);
      const cached = await cache.match(req);
      if (cached) return cached;
      const res = await fetch(req);
      if (res.ok) cache.put(req, res.clone());
      return res;
    })());
    return;
  }

  // Default: network with fallback to cache
  event.respondWith((async () => {
    try {
      return await fetch(req);
    } catch (e) {
      const cache = await caches.open(ASSET_CACHE);
      const cached = await cache.match(req);
      return cached || new Response('', { status: 504, statusText: 'Gateway Timeout' });
    }
  })());
});
