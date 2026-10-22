/* 잠금 화면 스크립트. 주소에 #k=… 키가 있으면 확인한 뒤 서비스워커에 넘기고 페이지를 다시 연다. */
(function () {
  'use strict';
  var me = document.currentScript;
  var base = new URL(me.getAttribute('data-base') || './', location.href);
  var title = document.getElementById('t'), msg = document.getElementById('m');
  function show(t, m) { title.textContent = t; msg.textContent = m; document.body.className = ''; }
  function clean() { history.replaceState(null, '', location.pathname + location.search); }

  var hit = /^#k=([0-9a-f]{16})\.([A-Za-z0-9_-]{43})$/.exec(location.hash);
  if (!hit) { show('비공개 페이지예요', '전달받은 링크로 접속해 주세요.'); return; }
  clean();

  if (!('serviceWorker' in navigator) || !(window.crypto && crypto.subtle) || !window.indexedDB) {
    show('이 브라우저에서는 열 수 없어요', 'Chrome, Safari, Edge의 일반 창(시크릿 모드 아님)에서 링크를 다시 열어 주세요.');
    return;
  }
  show('여는 중…', '잠시만 기다려 주세요.');

  var id = hit[1], secret = hit[2];
  navigator.serviceWorker.register(new URL('sw.js', base).href, { scope: base.pathname })
    .then(function (reg) { return ready(reg); })
    .then(function (sw) {
      return new Promise(function (resolve, reject) {
        var ch = new MessageChannel();
        var timer = setTimeout(function () { reject(new Error('timeout')); }, 15000);
        ch.port1.onmessage = function (e) { clearTimeout(timer); e.data && e.data.ok ? resolve() : reject(new Error(e.data && e.data.error)); };
        sw.postMessage({ type: 'unlock', id: id, secret: secret }, [ch.port2]);
      });
    })
    .then(function () { location.replace(location.pathname + location.search); })
    .catch(function (err) {
      var m = String(err && err.message || err);
      if (/revoked|bad link/.test(m)) show('링크가 만료되었어요', '새 링크를 요청해 주세요.');
      else show('열지 못했어요', '네트워크를 확인한 뒤 링크를 다시 열어 주세요. 시크릿 모드에서는 열리지 않을 수 있어요.');
    });

  function ready(reg) {
    return new Promise(function (resolve) {
      if (reg.active) return resolve(reg.active);
      var w = reg.installing || reg.waiting;
      w.addEventListener('statechange', function () { if (w.state === 'activated') resolve(w); });
    });
  }
})();
