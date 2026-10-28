// Cache para uso offline. Rede primeiro (pega atualizações), cópia local se estiver sem internet.
const CACHE = 'aebr-v1';
const SHELL = ['./', 'index.html', 'app.js', 'manifest.webmanifest', 'dados.bin',
  'icons/icon-180.png', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/maskable-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  const key = new URL(req.url); key.search = '';
  e.respondWith(fetch(req).then(r => {
    if (r.ok) { const cp = r.clone(); caches.open(CACHE).then(c => c.put(key.href, cp)); }
    return r;
  }).catch(() => caches.match(key.href, { ignoreSearch: true }).then(r => r || caches.match('index.html'))));
});
