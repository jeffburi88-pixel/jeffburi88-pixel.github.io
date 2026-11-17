// Service Worker des verschlüsselten Pakets (tools/web_paket.py legt ihn als post/sw.js ab). Er fragt nie eine fremde
// Adresse an und schickt nichts weg.
// - Beim Installieren holt er nur die Sperrseite und ihre Dateien (gleicher Ursprung).
// - inhalt.bin (verschlüsselt): zuerst vom Server, sonst aus dem Zwischenspeicher (ohne Internet).
// - Alles andere liefert er aus dem Cache «buerokram-inhalt», den die Sperrseite nach dem Passwort füllt. Fehlt dort
//   die App (gesperrt, abgemeldet), führt jede Seite der App zurück zur Sperrseite.
const STAND = 'buerokram-zugang-6291699e09bb';
const INHALT = 'buerokram-inhalt';
const HUELLE = ['./', 'index.html', 'zugang.js', 'zugang.css', 'manifest.webmanifest', 'symbol/symbol-192.png', 'symbol/symbol-512.png'];

self.addEventListener('install', (ereignis) => {
  ereignis.waitUntil(caches.open(STAND).then((speicher) => speicher.addAll(HUELLE.map((d) => new Request(d, { cache: 'reload' }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (ereignis) => {
  // Alte Hüllen weg; der entschlüsselte Inhalt bleibt, bis «Abmelden» ihn löscht
  ereignis.waitUntil(caches.keys().then((namen) => Promise.all(namen.filter((n) => n !== STAND && n !== INHALT).map((n) => caches.delete(n))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (ereignis) => {
  const anfrage = ereignis.request;
  const url = new URL(anfrage.url);
  if (url.origin !== self.location.origin || anfrage.method !== 'GET') return;
  const basis = new URL('./', self.registration.scope).pathname;
  if (!url.pathname.startsWith(basis)) return;
  const pfad = url.pathname.slice(basis.length);

  if (pfad === 'inhalt.bin') {
    ereignis.respondWith(fetch(anfrage).then(async (antwort) => {
      if (antwort.ok && antwort.status === 200) (await caches.open(STAND)).put(new URL('inhalt.bin', self.registration.scope).href, antwort.clone());
      return antwort;
    }).catch(() => caches.match(new URL('inhalt.bin', self.registration.scope).href).then((t) => t || Response.error())));
    return;
  }
  if (pfad === '' || HUELLE.includes(pfad)) {
    // Die Sperrseite: zuerst frisch vom Server (neue Version), ohne Internet aus dem Zwischenspeicher
    ereignis.respondWith(fetch(anfrage).catch(() => caches.open(STAND).then((s) => s.match(anfrage, { ignoreSearch: true }))
      .then((t) => t || Response.error())));
    return;
  }
  ereignis.respondWith(caches.open(INHALT).then((s) => s.match(anfrage, { ignoreSearch: true })).then((treffer) => {
    if (treffer) return treffer;
    // Gesperrt: Die App liegt nicht auf dem Server. Seiten führen zur Sperrseite, alles andere gibt es nicht.
    if (anfrage.mode === 'navigate') return Response.redirect(new URL('./', self.registration.scope).href, 302);
    return new Response('', { status: 404 });
  }));
});
