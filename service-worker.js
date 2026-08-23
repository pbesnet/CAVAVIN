// ═══════════════════════════════════════════════════════════════
// CAVAVIN — Service Worker (PWA installable + hors-ligne)
//
// Stratégie :
//   - Les appels API (/api/...) ne sont JAMAIS mis en cache : en ligne on
//     interroge le backend, hors ligne l'appli retombe sur son localStorage.
//   - Le "shell" de l'appli (index.html, icônes, polices) est mis en cache
//     pour que l'appli se LANCE même sans réseau.
//   - Navigation : réseau d'abord (pour avoir la dernière version), avec
//     repli sur le cache si hors ligne.
//
// ⚠️ Incrémente CACHE_VERSION à chaque déploiement de index.html pour forcer
//    la mise à jour du cache chez les utilisateurs.
// ═══════════════════════════════════════════════════════════════
const CACHE_VERSION = 'cavavin-v3';
const SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // 1) Ne jamais mettre en cache les appels au backend (données fraîches only)
  if (url.pathname.includes('/api/')) {
    return; // laisse passer normalement (réseau) ; hors ligne → l'appli gère via localStorage
  }

  // 2) Navigation (chargement de la page) : réseau d'abord, repli cache
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE_VERSION).then((c) => c.put('./index.html', copy));
        return res;
      }).catch(() => caches.match('./index.html'))
    );
    return;
  }

  // 3) Autres ressources (icônes, polices, css) : cache d'abord, sinon réseau
  event.respondWith(
    caches.match(req).then((cached) => cached || fetch(req).then((res) => {
      // met en cache les ressources statiques réussies (même origine)
      if (res.ok && url.origin === self.location.origin) {
        const copy = res.clone();
        caches.open(CACHE_VERSION).then((c) => c.put(req, copy));
      }
      return res;
    }).catch(() => cached))
  );
});
