const CACHE='bafang-scheduler-v13';
const ASSETS=['./','index.html','styles.css?v=12','app.js?v=11','manifest.json?v=13','icon-192.png?v=13','icon-512.png?v=13','apple-touch-icon.png?v=13'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS))));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))));
self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;if(e.request.mode==='navigate'){e.respondWith(fetch(e.request).then(resp=>{const copy=resp.clone();caches.open(CACHE).then(c=>c.put('index.html',copy));return resp}).catch(()=>caches.match('index.html')));return}e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(resp=>{const copy=resp.clone();caches.open(CACHE).then(c=>c.put(e.request,copy));return resp}))) });
