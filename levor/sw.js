// Service Worker der Web-Testfassung: nur zum Offline-Laden der eigenen Dateien (gleicher Ursprung). Er holt beim
// Installieren die Dateien dieser Seite in den Zwischenspeicher und liefert sie danach von dort; inhalt.bin bleibt
// dabei verschlüsselt. Er fragt nie eine fremde Adresse an und schickt nichts weg.
// DATEIEN und STAND setzt tools/build_web.py aus dem, was wirklich im Paket liegt.
const STAND = 'levor-web-a5b5c0719392';
const DATEIEN = [
  './',
  'index.html',
  'inhalt.bin',
  'manifest.webmanifest',
  'symbol/levor-192.png',
  'symbol/levor-512.png',
  'zugang.css',
  'zugang.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(STAND).then((c) => c.addAll(DATEIEN.map((d) => new Request(d, { cache: 'reload' }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((n) => Promise.all(n.filter((x) => x !== STAND).map((x) => caches.delete(x))))
    .then(() => self.clients.claim()));
});

// Netz zuerst (damit eine neue Fassung ankommt), ohne Netz aus dem Zwischenspeicher.
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || e.request.method !== 'GET') return;
  e.respondWith(fetch(e.request).then((r) => {
    if (r.ok) { const kopie = r.clone(); caches.open(STAND).then((c) => c.put(e.request, kopie)).catch(() => {}); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true }).then((t) => t || caches.match('./'))));
});
