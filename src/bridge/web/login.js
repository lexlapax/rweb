'use strict';
// The token form (token mode: an SSH tunnel). An address with `?token=` stays in the browser's
// history and goes to its sync and suggestion services; a token typed here goes only in a request
// header, once, to this origin. The bridge answers a right token with a redirect to the page's
// address (`/s/<id>/`) and sets the cookie the page uses from then on.
// The token is never put in an address, in storage or on the console, and the field is cleared as
// soon as it is read.
// Loaded as a plain script by login.html, and as a CommonJS module in tests (the pure helpers).
(function (root) {
  // rweb's tokens are letters, digits, `-` and `_` (the --token-file rules). Spaces around a pasted
  // token are dropped. Returns {token} or {msg} (and nothing is sent).
  function cleanToken(value) {
    const t = String(value || '').trim();
    if (!t) return {msg: 'Enter the token'};
    if (!/^[A-Za-z0-9_-]+$/.test(t)) return {msg: 'Wrong token: a token is letters, digits, - and _'};
    return {token: t};
  }

  // The page's address, from the final response of the token request (redirects followed): this
  // origin, path `/s/<id>/`, status 200. Anything else is not followed.
  const PAGE_PATH = /^\/s\/[A-Za-z0-9_-]+\/$/;
  function pageAddress(url, origin) {
    let u;
    try { u = new URL(String(url)); } catch { return null; }
    if (u.origin !== origin || !PAGE_PATH.test(u.pathname)) return null;
    return u.origin + u.pathname;
  }

  // What the form does with the answer: {go: address} or {msg: text to show}.
  function loginResult(status, url, origin) {
    if (status === 403) return {msg: 'Wrong token'};
    if (status === 429) return {msg: 'Too many attempts; wait a minute'};
    if (status === 200) {
      const go = pageAddress(url, origin);
      if (go) return {go};
      return {msg: 'The token was not accepted'};
    }
    return {msg: `Could not open rweb (HTTP ${status})`};
  }

  const api = {cleanToken, pageAddress, loginResult};
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; return; }
  root.RwebLogin = api;

  const form = document.getElementById('login');
  if (!form) return;
  const input = document.getElementById('token'), msg = document.getElementById('login-msg');
  const button = form.querySelector('button[type="submit"]');
  const say = text => { if (msg) msg.textContent = text; };
  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    const c = cleanToken(input.value);
    input.value = '';
    if (c.msg) { say(c.msg); input.focus(); return; }
    if (button) button.disabled = true;
    say('Checking…');
    let res;
    try {
      res = await fetch('/', {headers: {'rweb-token': c.token}, redirect: 'follow', credentials: 'same-origin', cache: 'no-store'});
    } catch {
      say('Could not reach rweb'); if (button) button.disabled = false; input.focus(); return;
    }
    const r = loginResult(res.status, res.url, location.origin);
    if (r.go) { location.replace(r.go); return; }
    say(r.msg); if (button) button.disabled = false; input.focus();
  });
})(typeof window !== 'undefined' ? window : globalThis);
