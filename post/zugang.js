// Zugangssperre von «Bürokram im Browser» (Auftrag 17.11.2026). Übernommen aus Levor (web/zugang.js), angepasst:
// Bürokram besteht aus ES-Modulen, Workern und den Dateien der Texterkennung. Darum wird der Inhalt nicht als Blob
// gestartet, sondern nach dem Entschlüsseln in den Zwischenspeicher dieses Geräts gelegt (Cache «buerokram-inhalt»).
// Der Service Worker (sw.js) liefert die Dateien von dort unter ihren gewohnten Pfaden aus; die App selbst (start.html)
// ist unverändert.
//
// - Auf dem Server liegen nur diese Sperrseite und inhalt.bin: AES-256-GCM, Schlüssel aus dem Passwort mit
//   PBKDF2-SHA-256 abgeleitet, alles mit Web Crypto. Kein Konto, kein Dienst, keine Anfrage ausser an die eigenen Dateien.
// - Nach der richtigen Eingabe bleibt das Gerät entsperrt: Der abgeleitete Schlüssel liegt nicht auslesbar
//   (extractable: false) in IndexedDB («buerokram-zugang»), bis unter Mehr › Einstellungen «Abmelden» getippt wird.
//   Kommt eine neue Version, entschlüsselt die Seite sie mit diesem Schlüssel, ohne erneut zu fragen.
// - «Abmelden» löscht Schlüssel und entschlüsselte Dateien. Die Briefe (IndexedDB «buerokram») bleiben auf dem Gerät.
(function () {
  'use strict';
  const INHALT = 'buerokram-inhalt';
  const DB = 'buerokram-zugang';

  if ('serviceWorker' in navigator) {
    try { navigator.serviceWorker.register('sw.js').catch(() => {}); } catch (_) { /* ohne geht es auch */ }
  }

  const T = {
    zeigen: 'Passwort anzeigen', verbergen: 'Passwort verbergen', falsch: 'Das Passwort stimmt nicht. Versuch es noch einmal.',
    los: 'Öffnen', laedt: 'Einen Moment …', auspacken: 'Bürokram wird eingerichtet …',
    fehlt: 'Bürokram konnte nicht geladen werden. Öffne die Seite noch einmal, wenn du Internet hast.',
    alt: 'Dieser Browser ist zu alt für Bürokram. Nimm einen aktuellen Chrome.',
  };
  const AUGE_AUF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  const AUGE_ZU = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7c2.1 0 3.9.7 5.4 1.7M22 12s-3.6 7-10 7c-2.1 0-3.9-.7-5.4-1.7"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M3 3l18 18"/></svg>';

  // ---------------------------------------------------------------- Schlüssel merken (IndexedDB, nicht auslesbar)
  function db() {
    return new Promise((ok, nein) => {
      try {
        const r = indexedDB.open(DB, 1);
        r.onupgradeneeded = () => r.result.createObjectStore('schluessel');
        r.onsuccess = () => ok(r.result);
        r.onerror = () => nein(r.error);
      } catch (e) { nein(e); }
    });
  }
  async function merke(eintrag) {
    try {
      const d = await db();
      await new Promise((ok, nein) => { const tx = d.transaction('schluessel', 'readwrite'); tx.objectStore('schluessel').put(eintrag, 'k'); tx.oncomplete = ok; tx.onerror = () => nein(tx.error); });
    } catch (_) { /* ohne Speicher: entsperrt nur, solange die entschlüsselten Dateien da sind */ }
  }
  async function gemerkt() {
    try {
      const d = await db();
      return await new Promise((ok) => { const r = d.transaction('schluessel').objectStore('schluessel').get('k'); r.onsuccess = () => ok(r.result || null); r.onerror = () => ok(null); });
    } catch (_) { return null; }
  }
  async function vergiss() {
    try { await caches.delete(INHALT); } catch (_) { /* nichts da */ }
    try {
      const d = await db();
      await new Promise((ok) => { const tx = d.transaction('schluessel', 'readwrite'); tx.objectStore('schluessel').delete('k'); tx.oncomplete = ok; tx.onerror = ok; });
    } catch (_) { /* nichts gemerkt */ }
  }

  // ---------------------------------------------------------------- Entschlüsseln und auspacken
  const b64 = (u8) => btoa(String.fromCharCode.apply(null, Array.from(u8)));
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  function zerlege(buf) {
    const u8 = new Uint8Array(buf);
    if (String.fromCharCode.apply(null, Array.from(u8.slice(0, 6))) !== 'BKRAM1') throw new Error('Format');
    const runden = new DataView(buf).getUint32(6);
    return { runden, salz: u8.slice(10, 26), iv: u8.slice(26, 38), daten: u8.slice(38) };
  }
  async function schluesselAus(passwort, salz, runden) {
    const basis = await crypto.subtle.importKey('raw', new TextEncoder().encode(passwort), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salz, iterations: runden, hash: 'SHA-256' },
      basis, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function oeffne(schluessel, teile) {
    const gz = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: teile.iv }, schluessel, teile.daten);
    const strom = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(strom).arrayBuffer());
  }
  const TYPEN = { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8',
    css: 'text/css; charset=utf-8', json: 'application/json', webmanifest: 'application/manifest+json', wasm: 'application/wasm',
    png: 'image/png', jpg: 'image/jpeg', svg: 'image/svg+xml', woff2: 'font/woff2', txt: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8' };
  // Aufbau des Klartexts (tools/web_paket.py): "BKDAT1", Anzahl (4 Byte), je Datei Pfadlänge (2), Pfad (UTF-8), Grösse (4), Inhalt
  async function auspacken(roh) {
    const dv = new DataView(roh.buffer, roh.byteOffset, roh.byteLength);
    if (String.fromCharCode.apply(null, Array.from(roh.slice(0, 6))) !== 'BKDAT1') throw new Error('Format');
    const anzahl = dv.getUint32(6);
    let stelle = 10;
    await caches.delete(INHALT);
    const speicher = await caches.open(INHALT);
    const decoder = new TextDecoder();
    for (let i = 0; i < anzahl; i++) {
      const laenge = dv.getUint16(stelle); stelle += 2;
      const pfad = decoder.decode(roh.subarray(stelle, stelle + laenge)); stelle += laenge;
      const groesse = dv.getUint32(stelle); stelle += 4;
      const inhalt = roh.slice(stelle, stelle + groesse); stelle += groesse;
      const endung = pfad.split('.').pop().toLowerCase();
      await speicher.put(new Request(new URL(pfad, location.href).href),
        new Response(inhalt, { headers: { 'Content-Type': TYPEN[endung] || 'application/octet-stream' } }));
    }
  }

  // ---------------------------------------------------------------- Ablauf
  const $ = (id) => document.getElementById(id);
  const form = $('zugang-form'), feld = $('zugang-passwort'), auge = $('zugang-auge'), fehler = $('zugang-fehler'), los = $('zugang-los');
  const laedt = $('zugang-laedt');

  function verdecke() { feld.type = 'password'; auge.innerHTML = AUGE_AUF; auge.setAttribute('aria-label', T.zeigen); auge.setAttribute('aria-pressed', 'false'); }
  verdecke();
  // Auge: nimmt dem Feld den Fokus nicht (Tastatur bleibt offen)
  auge.addEventListener('pointerdown', (e) => e.preventDefault());
  auge.addEventListener('mousedown', (e) => e.preventDefault());
  auge.addEventListener('click', () => {
    const zeigen = feld.type === 'password';
    feld.type = zeigen ? 'text' : 'password';
    auge.innerHTML = zeigen ? AUGE_ZU : AUGE_AUF;
    auge.setAttribute('aria-label', zeigen ? T.verbergen : T.zeigen);
    auge.setAttribute('aria-pressed', String(zeigen));
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) verdecke(); });

  function zeigeForm(meldung) {
    laedt.hidden = true;
    $('zugang').hidden = false;
    if (meldung) { fehler.textContent = meldung; fehler.hidden = false; }
  }
  const weiter = () => location.replace(new URL('start.html', location.href).href);
  async function entpackt() {
    try { return !!(await (await caches.open(INHALT)).match(new URL('start.html', location.href).href)); } catch (_) { return false; }
  }

  let teile = null;
  async function lade() {
    const r = await fetch('inhalt.bin', { cache: 'no-cache' }).catch(() => null);
    if (r && r.ok) return zerlege(await r.arrayBuffer());
    const alt = await caches.match(new URL('inhalt.bin', location.href).href).catch(() => null);
    if (!alt) throw new Error('fehlt');
    return zerlege(await alt.arrayBuffer());
  }

  async function start() {
    if (!window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined' || !('caches' in window)) {
      zeigeForm(T.alt); los.disabled = true; return;
    }
    const alt = await gemerkt();
    try { teile = await lade(); } catch (_) {
      // Ohne Internet und ohne neue Version: Was schon entschlüsselt ist, gilt weiter
      if (alt && await entpackt()) { weiter(); return; }
      zeigeForm(T.fehlt); return;
    }
    const stand = hex(teile.iv);
    if (alt && alt.stand === stand && await entpackt()) { weiter(); return; }
    if (alt && alt.key && alt.salz === b64(teile.salz) && alt.runden === teile.runden) {
      // Neue Version, gleiches Passwort: ohne Frage einrichten
      laedt.textContent = T.auspacken;
      try { await auspacken(await oeffne(alt.key, teile)); await merke({ ...alt, stand }); weiter(); return; } catch (_) { await vergiss(); }
    }
    zeigeForm('');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!teile || !feld.value) return;
    fehler.hidden = true;
    los.disabled = true;
    los.textContent = T.laedt;
    let roh = null, key = null;
    try {
      key = await schluesselAus(feld.value, teile.salz, teile.runden);
      roh = await oeffne(key, teile);
    } catch (_) { roh = null; }
    verdecke();
    if (!roh) {
      los.disabled = false; los.textContent = T.los;
      fehler.textContent = T.falsch; fehler.hidden = false; feld.select(); return;
    }
    los.textContent = T.auspacken;
    try { await auspacken(roh); } catch (_) {
      los.disabled = false; los.textContent = T.los; fehler.textContent = T.fehlt; fehler.hidden = false; return;
    }
    await merke({ key, salz: b64(teile.salz), runden: teile.runden, stand: hex(teile.iv) });
    // Für den Passwort-Manager: Das Formular war erfolgreich (Navigation im selben Dokument, dann weiter)
    try { history.replaceState(null, '', location.pathname + '#'); history.replaceState(null, '', location.pathname); } catch (_) { /* egal */ }
    feld.value = '';
    feld.blur();
    setTimeout(weiter, 300);
  });

  start();
})();
