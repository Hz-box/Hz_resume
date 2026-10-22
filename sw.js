/* 사이트 복호화 서비스워커.
 * 링크로 받은 키를 이 브라우저에만 저장해 두고, 암호화된 파일(x/*.bin)을
 * 복호화해서 원래 주소(index.html, assets/...)로 돌려준다.
 * 키가 없거나 링크가 차단되면 아무것도 하지 않아 잠금 화면이 그대로 보인다. */
'use strict';

const SCOPE = new URL(self.registration.scope);
const DB = 'vault', STORE = 'kv';
let state = null;      // { key: CryptoKey, manifest, id, loadedAt }
let loading = null;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (e) => {
  const d = e.data || {};
  const port = e.ports && e.ports[0];
  const reply = (v) => port && port.postMessage(v);
  if (d.type === 'unlock') {
    e.waitUntil(open(d.id, d.secret)
      .then(async (st) => { await idb('put', { id: d.id, secret: d.secret }); state = st; reply({ ok: true }); })
      .catch((err) => reply({ ok: false, error: String(err && err.message || err) })));
  } else if (d.type === 'lock') {
    state = null;
    e.waitUntil(idb('delete').then(() => reply({ ok: true })));
  }
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== SCOPE.origin || !url.pathname.startsWith(SCOPE.pathname)) return;
  let rel = url.pathname.slice(SCOPE.pathname.length);
  try { rel = decodeURIComponent(rel); } catch (_) { return; }
  if (rel === 'sw.js' || rel.startsWith('x/')) return;
  e.respondWith(handle(req, rel));
});

async function handle(req, rel) {
  let st;
  try { st = await getState(req.mode === 'navigate'); } catch (_) { st = null; }
  if (!st) return fetch(req);
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  const f = st.manifest.files[rel];
  if (!f) return fetch(req);
  try {
    const r = await fetch(new URL('x/' + f.id + '.bin', SCOPE), { cache: 'no-cache' });
    if (!r.ok) return fetch(req);
    const body = await decrypt(st.key, await r.arrayBuffer());
    const headers = { 'content-type': f.type, 'cache-control': 'no-store' };
    if (f.type.startsWith('text/html')) {
      headers['content-security-policy'] = "frame-ancestors 'self'";
      headers['x-frame-options'] = 'SAMEORIGIN';
    }
    return new Response(body, { status: 200, headers });
  } catch (_) {
    return fetch(req);
  }
}

// 페이지 이동 때마다 목록을 새로 받아 수정된 내용과 링크 차단을 바로 반영한다.
async function getState(refresh) {
  if (state && !refresh) return state;
  if (!loading) {
    loading = (async () => {
      const cred = await idb('get');
      if (!cred) { state = null; return null; }
      try {
        state = await open(cred.id, cred.secret);
      } catch (err) {
        if (err && err.revoked) { await idb('delete'); state = null; }
        // 네트워크 오류면 기존 상태를 유지한다.
      }
      return state;
    })().finally(() => { loading = null; });
  }
  return loading;
}

async function open(id, secret) {
  const kr = await fetch(new URL('x/k/' + id + '.bin', SCOPE), { cache: 'no-store' });
  if (kr.status === 404) { const e = new Error('revoked'); e.revoked = true; throw e; }
  if (!kr.ok) throw new Error('key fetch failed');
  const linkKey = await crypto.subtle.importKey('raw', b64u(secret), 'AES-GCM', false, ['decrypt']);
  let raw;
  try { raw = await decrypt(linkKey, await kr.arrayBuffer()); }
  catch (_) { const e = new Error('bad link'); e.revoked = true; throw e; }
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const mr = await fetch(new URL('x/m.bin', SCOPE), { cache: 'no-cache' });
  if (!mr.ok) throw new Error('manifest fetch failed');
  const manifest = JSON.parse(new TextDecoder().decode(await decrypt(key, await mr.arrayBuffer())));
  return { key, manifest, id, loadedAt: Date.now() };
}

async function decrypt(key, buf) {
  const u = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
}

function b64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function idb(op, value) {
  return new Promise((resolve, reject) => {
    const rq = indexedDB.open(DB, 1);
    rq.onupgradeneeded = () => rq.result.createObjectStore(STORE);
    rq.onerror = () => reject(rq.error);
    rq.onsuccess = () => {
      const tx = rq.result.transaction(STORE, op === 'get' ? 'readonly' : 'readwrite');
      const s = tx.objectStore(STORE);
      const r = op === 'get' ? s.get('cred') : op === 'put' ? s.put(value, 'cred') : s.delete('cred');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    };
  });
}
