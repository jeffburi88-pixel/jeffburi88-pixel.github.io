// Zugangssperre der Web-Testfassung (Auftrag 16.11.2026, Punkte 8–10).
// Der ganze Inhalt (Stil, Skripte, Sprüche, alle Texte) liegt verschlüsselt in inhalt.bin: AES-256-GCM, Schlüssel aus
// dem Passwort mit PBKDF2-SHA-256 abgeleitet, alles mit Web Crypto im Browser. Kein Konto, kein Dienst, keine Anfrage
// ausser an die eigenen Dateien. Nach der richtigen Eingabe bleibt das Gerät entsperrt: Der abgeleitete Schlüssel liegt
// nicht auslesbar (extractable: false) in IndexedDB, bis „Abmelden“ getippt wird. Ohne IndexedDB gilt er nur, bis die
// Seite geschlossen wird.
(function () {
  'use strict';
  const modus = document.documentElement.dataset.modus;

  // Offline: Service Worker hält die eigenen Dateien bereit (auch inhalt.bin, verschlüsselt).
  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    try { navigator.serviceWorker.register('sw.js').catch(() => {}); } catch (_) { /* ohne geht es auch */ }
  }

  const TEXTE = {
    de: { hinweis: 'Testfassung. Bitte das Passwort eingeben.', name: 'Name', passwort: 'Passwort', los: 'Öffnen',
          zeigen: 'Passwort anzeigen', verbergen: 'Passwort verbergen', falsch: 'Das Passwort stimmt nicht.',
          laedt: 'Einen Moment …', fehlt: 'Die Testfassung konnte nicht geladen werden. Bitte mit Internet neu öffnen.',
          alt: 'Dieser Browser ist zu alt für die Testfassung.' },
    en: { hinweis: 'Test version. Please enter the password.', name: 'Name', passwort: 'Password', los: 'Open',
          zeigen: 'Show password', verbergen: 'Hide password', falsch: 'The password is not correct.',
          laedt: 'One moment …', fehlt: 'The test version could not be loaded. Please open it again with internet.',
          alt: 'This browser is too old for the test version.' },
    fr: { hinweis: 'Version de test. Saisis le mot de passe.', name: 'Nom', passwort: 'Mot de passe', los: 'Ouvrir',
          zeigen: 'Afficher le mot de passe', verbergen: 'Masquer le mot de passe', falsch: 'Le mot de passe n’est pas correct.',
          laedt: 'Un instant …', fehlt: 'Impossible de charger la version de test. Rouvre-la avec Internet.',
          alt: 'Ce navigateur est trop ancien pour la version de test.' },
    it: { hinweis: 'Versione di prova. Inserisci la password.', name: 'Nome', passwort: 'Password', los: 'Apri',
          zeigen: 'Mostra la password', verbergen: 'Nascondi la password', falsch: 'La password non è corretta.',
          laedt: 'Un momento …', fehlt: 'Non è stato possibile caricare la versione di prova. Riaprila con internet.',
          alt: 'Questo browser è troppo vecchio per la versione di prova.' },
  };
  const sprache = (() => {
    for (const l of navigator.languages || [navigator.language || 'de']) {
      const k = String(l).slice(0, 2).toLowerCase();
      if (TEXTE[k]) return k;
    }
    return 'de';
  })();
  const T = TEXTE[sprache];

  const AUGE_AUF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  const AUGE_ZU = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7c2.1 0 3.9.7 5.4 1.7M22 12s-3.6 7-10 7c-2.1 0-3.9-.7-5.4-1.7"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M3 3l18 18"/></svg>';

  // ---------------------------------------------------------------- Schlüssel merken (IndexedDB, nicht auslesbar)
  function db() {
    return new Promise((ok, nein) => {
      try {
        const r = indexedDB.open('levor-zugang', 1);
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
    } catch (_) { /* ohne Speicher: entsperrt nur bis zum Schliessen */ }
  }
  async function gemerkt() {
    try {
      const d = await db();
      return await new Promise((ok) => { const r = d.transaction('schluessel').objectStore('schluessel').get('k'); r.onsuccess = () => ok(r.result || null); r.onerror = () => ok(null); });
    } catch (_) { return null; }
  }
  async function vergiss() {
    try {
      const d = await db();
      await new Promise((ok) => { const tx = d.transaction('schluessel', 'readwrite'); tx.objectStore('schluessel').delete('k'); tx.oncomplete = ok; tx.onerror = ok; });
    } catch (_) { /* nichts gemerkt */ }
  }

  // ---------------------------------------------------------------- Entschlüsseln
  const b64 = (u8) => btoa(String.fromCharCode.apply(null, Array.from(u8)));
  function zerlege(buf) {
    const u8 = new Uint8Array(buf);
    const magie = String.fromCharCode.apply(null, Array.from(u8.slice(0, 6)));
    if (magie !== 'LEVOR1') throw new Error('Format');
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
    return JSON.parse(await new Response(strom).text());
  }
  async function starte(inhalt) {
    const css = URL.createObjectURL(new Blob([inhalt.css], { type: 'text/css' }));
    await new Promise((ok) => { const l = document.createElement('link'); l.rel = 'stylesheet'; l.href = css; l.onload = ok; l.onerror = ok; document.head.appendChild(l); });
    for (const code of inhalt.js) {
      const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
      await new Promise((ok, nein) => { const s = document.createElement('script'); s.src = url; s.onload = ok; s.onerror = nein; document.body.appendChild(s); });
    }
  }

  window.LEVOR_ZUGANG = {
    gesperrt: modus !== 'klar',
    async abmelden() {
      await vergiss();
      try { sessionStorage.clear(); } catch (_) { /* egal */ }
      location.replace(location.pathname);
    },
  };
  if (modus === 'klar') return;

  // ---------------------------------------------------------------- Ablauf
  const $ = (id) => document.getElementById(id);
  const form = $('zugang-form'), feld = $('zugang-passwort'), auge = $('zugang-auge'), fehler = $('zugang-fehler'), los = $('zugang-los');
  $('zugang-hinweis').textContent = T.hinweis;
  $('zugang-name-label').textContent = T.name;
  $('zugang-passwort-label').textContent = T.passwort;
  los.textContent = T.los;
  document.documentElement.lang = sprache;

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

  let teile = null;
  async function lade() {
    const r = await fetch('inhalt.bin', { cache: 'no-cache' }).catch(() => null) || await caches.match('inhalt.bin').catch(() => null);
    if (!r || !r.ok) throw new Error('fehlt');
    return zerlege(await r.arrayBuffer());
  }

  async function los_() {
    if (!window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined') {
      $('zugang').hidden = false; fehler.textContent = T.alt; fehler.hidden = false; los.disabled = true; return;
    }
    try { teile = await lade(); } catch (_) {
      $('zugang').hidden = false; fehler.textContent = T.fehlt; fehler.hidden = false; return;
    }
    const alt = await gemerkt();
    if (alt && alt.key && alt.salz === b64(teile.salz) && alt.runden === teile.runden) {
      try { await starte(await oeffne(alt.key, teile)); return; } catch (_) { await vergiss(); }
    }
    $('zugang').hidden = false;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!teile || !feld.value) return;
    fehler.hidden = true;
    los.disabled = true;
    los.textContent = T.laedt;
    let inhalt = null, key = null;
    try {
      key = await schluesselAus(feld.value, teile.salz, teile.runden);
      inhalt = await oeffne(key, teile);
    } catch (_) { inhalt = null; }
    los.disabled = false;
    los.textContent = T.los;
    verdecke();
    if (!inhalt) {
      fehler.textContent = T.falsch; fehler.hidden = false; feld.select(); return;
    }
    await merke({ key, salz: b64(teile.salz), runden: teile.runden });
    // Für den Passwort-Manager: Formular war erfolgreich (Navigation im selben Dokument, Formular verschwindet).
    try { history.replaceState(null, '', location.pathname + '#'); history.replaceState(null, '', location.pathname); } catch (_) { /* egal */ }
    feld.value = '';
    feld.blur();
    $('zugang').hidden = true;
    await starte(inhalt);
  });

  los_();
})();
