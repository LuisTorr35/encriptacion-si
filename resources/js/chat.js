/**
 * chat.js — Logica de la app de chat (lado cliente).
 *
 * Toda la criptografia ocurre AQUI. El servidor solo recibe/entrega sobres
 * cifrados y nunca ve texto plano ni claves privadas.
 *
 *  - Clave privada RSA: se genera en el navegador y vive en localStorage.
 *  - Clave publica RSA: se sube al servidor para que otros nos cifren.
 *  - Mensajes: cifrado hibrido KEM/DEM (ver cripto-core.js).
 */

import CriptoCore from './crypto/cripto-core.js';

// Expuesto en consola para la prueba de aceptacion (round-trip):
window.CriptoCore = CriptoCore;

const CFG = window.__CHAT__;
const PRIV_LS = `e2e.priv.${CFG.me.id}`;
const PUB_LS = `e2e.pub.${CFG.me.id}`;
const PW_SS = 'e2e.pw';   // contrasena capturada en el login (solo en este navegador)
const POLL_MS = 2500;

const el = (sel) => document.querySelector(sel);

const state = {
  myPriv: null,
  myPub: null,
  myPubJson: null,
  users: [],
  active: null,        // { id, other, otherPub }
  lastId: 0,
  pollTimer: null,
  cache: new Map(),    // messageId -> { plaintext, integrity, verified }
};

/* --------------------------------------------------------------------- *
 *  Cliente HTTP (sesion Breeze: cookie + CSRF)
 * --------------------------------------------------------------------- */

// Lee el token CSRF vigente desde la cookie XSRF-TOKEN (Laravel la renueva en
// cada respuesta). Asi evitamos el "CSRF token mismatch" cuando la sesion rota.
function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : CFG.csrf;
}

async function api(method, url, body) {
  const headers = { Accept: 'application/json' };
  const opts = { method, headers, credentials: 'same-origin' };
  if (method !== 'GET') headers['X-XSRF-TOKEN'] = csrfToken();
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    if (res.status === 419) msg = 'Sesion expirada. Recarga la pagina (F5) e inicia sesion de nuevo.';
    try { const j = await res.json(); if (j.message) msg = j.message; } catch (_) { /* noop */ }
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

/* --------------------------------------------------------------------- *
 *  Gestion de claves
 * --------------------------------------------------------------------- */

// Contrasena capturada en el formulario de login/registro (sessionStorage).
function storedPassword() {
  try { return sessionStorage.getItem(PW_SS); } catch (_) { return null; }
}

// Sube la clave publica y el blob cifrado de la privada (derivado de la contrasena).
async function uploadKeys(pubJson, privJson, password) {
  const wrapped = CriptoCore.wrapPrivateKey(privJson, password);
  const wrappedJson = JSON.stringify(wrapped);
  await api('POST', '/api/keys', { public_key: pubJson, wrapped_private_key: wrappedJson });
  CFG.me.public_key = pubJson;
  CFG.me.wrapped_private_key = wrappedJson;
}

// Descifra el blob de la clave privada con la contrasena; reintenta si es incorrecta.
function recoverPrivateKey(blob) {
  let pw = storedPassword();
  for (;;) {
    if (!pw) {
      pw = window.prompt('Escribe tu contrasena para recuperar tu clave de cifrado en este dispositivo:');
      if (!pw) throw new Error('Recuperacion de clave cancelada.');
      try { sessionStorage.setItem(PW_SS, pw); } catch (_) { /* noop */ }
    }
    try {
      return CriptoCore.unwrapPrivateKey(blob, pw);
    } catch (_) {
      try { sessionStorage.removeItem(PW_SS); } catch (_) { /* noop */ }
      pw = null;
      window.alert('Contrasena incorrecta. Intentalo de nuevo.');
    }
  }
}

async function ensureKeys() {
  let privJson = localStorage.getItem(PRIV_LS);
  let pubJson = localStorage.getItem(PUB_LS);
  const serverWrapped = CFG.me.wrapped_private_key
    ? JSON.parse(CFG.me.wrapped_private_key)
    : null;

  if (!privJson || !pubJson) {
    if (serverWrapped && CFG.me.public_key) {
      // Otro dispositivo ya genero la clave: recuperarla con la contrasena de login.
      setStatus('Recuperando tu clave de cifrado en este dispositivo…', true);
      await new Promise((r) => setTimeout(r, 30));
      privJson = recoverPrivateKey(serverWrapped);
      pubJson = CFG.me.public_key;
    } else {
      // Primera vez en cualquier dispositivo: generar el par RSA.
      setStatus('Generando tu par de claves RSA-2048 (solo la primera vez)…', true);
      await new Promise((r) => setTimeout(r, 30));
      const kp = CriptoCore.generateRsaKeyPair(2048);
      privJson = CriptoCore.exportPrivateKey(kp.privateKey);
      pubJson = CriptoCore.exportPublicKey(kp.publicKey);
    }
    localStorage.setItem(PRIV_LS, privJson);
    localStorage.setItem(PUB_LS, pubJson);
  }

  state.myPriv = CriptoCore.importPrivateKey(privJson);
  state.myPub = CriptoCore.importPublicKey(pubJson);
  state.myPubJson = pubJson;

  // Sincronizar con el servidor lo que falte: la clave publica y/o el blob cifrado
  // de la privada (para que otros dispositivos puedan recuperarla).
  const needsPub = CFG.me.public_key !== pubJson;
  const needsWrapped = !CFG.me.wrapped_private_key;
  if (needsPub || needsWrapped) {
    const pw = storedPassword();
    if (pw) {
      await uploadKeys(pubJson, privJson, pw);
    } else if (needsPub) {
      // Sin contrasena disponible: al menos publicar la clave publica.
      await api('POST', '/api/keys', { public_key: pubJson });
      CFG.me.public_key = pubJson;
    }
  }

  setStatus('Cifrado E2E activo · tu clave esta cifrada en el servidor y disponible en tus dispositivos.');
}

/* --------------------------------------------------------------------- *
 *  Sidebar: usuarios / conversaciones
 * --------------------------------------------------------------------- */

async function loadContacts() {
  const { users } = await api('GET', '/api/users');
  state.users = users;
  renderContacts();
}

function renderContacts() {
  const list = el('#contacts');
  list.innerHTML = '';
  if (state.users.length === 0) {
    list.innerHTML = '<p class="px-4 py-6 text-sm text-gray-400">No hay otros usuarios todavia.</p>';
    return;
  }
  for (const u of state.users) {
    const item = document.createElement('button');
    item.type = 'button';
    item.dataset.userId = u.id;
    item.className =
      'w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-100 transition ' +
      (state.active && state.active.other.id === u.id ? 'bg-gray-100' : '');

    const avatar = document.createElement('div');
    avatar.className = 'flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-sky-500 text-sm font-semibold text-white';
    avatar.textContent = (u.name || '?').trim().charAt(0).toUpperCase();

    const meta = document.createElement('div');
    meta.className = 'min-w-0 flex-1';
    const nameRow = document.createElement('div');
    nameRow.className = 'truncate font-medium text-gray-900';
    nameRow.textContent = u.name;
    const sub = document.createElement('div');
    sub.className = 'truncate text-xs text-gray-500';
    sub.textContent = u.has_key ? u.email : 'sin clave aun';
    meta.append(nameRow, sub);

    item.append(avatar, meta);
    item.addEventListener('click', () => openConversation(u));
    list.appendChild(item);
  }
}

/* --------------------------------------------------------------------- *
 *  Abrir conversacion
 * --------------------------------------------------------------------- */

async function openConversation(user) {
  stopPolling();
  el('#empty-state').classList.add('hidden');
  el('#chat-panel').classList.remove('hidden');
  el('#chat-panel').classList.add('flex');
  el('#thread').innerHTML = '';
  state.cache.clear();
  state.lastId = 0;

  try {
    const { conversation } = await api('POST', '/api/conversations', { user_id: user.id });
    state.active = {
      id: conversation.id,
      other: conversation.other,
      otherPub: conversation.other.public_key
        ? CriptoCore.importPublicKey(conversation.other.public_key)
        : null,
    };
  } catch (e) {
    setStatus('Error al abrir la conversacion: ' + e.message, false, true);
    return;
  }

  renderHeader();
  renderContacts();
  updateComposerAvailability();

  await fetchNew();
  startPolling();
  el('#composer-input').focus();
}

function renderHeader() {
  const o = state.active.other;
  el('#thread-name').textContent = o.name;
  el('#thread-sub').textContent = o.has_key
    ? 'cifrado de extremo a extremo'
    : 'este contacto aun no tiene clave publica';
  const av = el('#thread-avatar');
  av.textContent = (o.name || '?').trim().charAt(0).toUpperCase();
}

function updateComposerAvailability() {
  const ok = !!state.active.otherPub;
  el('#composer-input').disabled = !ok;
  el('#composer-send').disabled = !ok;
  el('#composer-input').placeholder = ok
    ? 'Escribe un mensaje cifrado…'
    : 'El contacto debe iniciar sesion para generar su clave.';
}

/* --------------------------------------------------------------------- *
 *  Enviar (cifrar)
 * --------------------------------------------------------------------- */

async function sendMessage() {
  const input = el('#composer-input');
  const text = input.value;
  if (!text.trim() || !state.active || !state.active.otherPub) return;

  input.value = '';
  input.style.height = 'auto';

  let envelope;
  try {
    envelope = CriptoCore.encryptMessage(text, state.myPub, state.active.otherPub, state.myPriv);
  } catch (e) {
    setStatus('Error al cifrar: ' + e.message, false, true);
    input.value = text;
    return;
  }

  const payload = {
    v: envelope.v,
    enc_key_sender: envelope.encKeySender,
    enc_key_recipient: envelope.encKeyRecipient,
    ciphertext: envelope.ciphertext,
    mac: envelope.mac,
    nonce: envelope.nonce,
    signature: envelope.signature,
  };

  try {
    const { message } = await api('POST', `/api/conversations/${state.active.id}/messages`, payload);
    appendMessage(message);
    state.lastId = Math.max(state.lastId, message.id);
    scrollToBottom(true);
  } catch (e) {
    setStatus('Error al enviar: ' + e.message, false, true);
    input.value = text;
  }
}

/* --------------------------------------------------------------------- *
 *  Recibir (descifrar) — polling
 * --------------------------------------------------------------------- */

async function fetchNew() {
  if (!state.active) return;
  let data;
  try {
    data = await api('GET', `/api/conversations/${state.active.id}/messages?after=${state.lastId}`);
  } catch (_) {
    return; // reintento en el siguiente ciclo
  }
  if (!data || !data.messages.length) return;

  const nearBottom = isNearBottom();
  for (const m of data.messages) {
    appendMessage(m);
    state.lastId = Math.max(state.lastId, m.id);
  }
  scrollToBottom(nearBottom);
}

function decryptMessage(m) {
  if (state.cache.has(m.id)) return state.cache.get(m.id);
  const isSender = m.mine;
  const senderPub = isSender ? state.myPub : state.active.otherPub;
  const env = {
    v: m.v,
    encKeySender: m.enc_key_sender,
    encKeyRecipient: m.enc_key_recipient,
    ciphertext: m.ciphertext,
    mac: m.mac,
    nonce: m.nonce,
    signature: m.signature,
  };
  let result;
  try {
    result = CriptoCore.decryptMessage(env, state.myPriv, isSender, senderPub);
  } catch (e) {
    result = { plaintext: null, integrity: false, verified: null, error: e.message };
  }
  state.cache.set(m.id, result);
  return result;
}

/* --------------------------------------------------------------------- *
 *  Render de mensajes
 * --------------------------------------------------------------------- */

function appendMessage(m) {
  const r = decryptMessage(m);
  const thread = el('#thread');

  const row = document.createElement('div');
  row.className = 'flex ' + (m.mine ? 'justify-end' : 'justify-start');

  const bubble = document.createElement('div');
  bubble.className =
    'max-w-[75%] rounded-2xl px-3.5 py-2 shadow-sm break-words whitespace-pre-wrap ' +
    (m.mine ? 'bg-sky-500 text-white rounded-br-md' : 'bg-white text-gray-900 rounded-bl-md border border-gray-100');

  const textNode = document.createElement('div');
  textNode.className = 'text-[15px] leading-snug';
  if (r.integrity && r.plaintext !== null) {
    textNode.textContent = r.plaintext;                 // textContent: a prueba de XSS
  } else {
    textNode.className += ' italic ' + (m.mine ? 'text-sky-100' : 'text-red-500');
    textNode.textContent = '⚠ ' + (r.error || 'No se pudo verificar/descifrar este mensaje');
  }

  const foot = document.createElement('div');
  foot.className = 'mt-1 flex items-center gap-1 text-[11px] ' + (m.mine ? 'text-sky-100 justify-end' : 'text-gray-400');
  const time = document.createElement('span');
  time.textContent = formatTime(m.created_at);
  foot.appendChild(time);

  if (r.integrity && r.verified === true) {
    const badge = document.createElement('span');
    badge.title = 'Firma de origen verificada (RSA-PSS)';
    badge.textContent = '✓ firmado';
    foot.appendChild(badge);
  } else if (r.integrity && r.verified === false) {
    const badge = document.createElement('span');
    badge.className = m.mine ? 'text-amber-200' : 'text-amber-500';
    badge.title = 'La firma no pudo verificarse';
    badge.textContent = '⚠ firma';
    foot.appendChild(badge);
  }

  bubble.append(textNode, foot);
  row.appendChild(bubble);
  thread.appendChild(row);
}

/* --------------------------------------------------------------------- *
 *  Utilidades de UI
 * --------------------------------------------------------------------- */

function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function isNearBottom() {
  const t = el('#thread-scroll');
  return t.scrollHeight - t.scrollTop - t.clientHeight < 120;
}

function scrollToBottom(force) {
  if (!force) return;
  const t = el('#thread-scroll');
  t.scrollTop = t.scrollHeight;
}

function setStatus(text, busy = false, error = false) {
  const s = el('#status');
  s.textContent = text;
  s.className =
    'text-xs ' +
    (error ? 'text-red-600' : busy ? 'text-amber-600' : 'text-emerald-600');
}

function startPolling() {
  stopPolling();
  state.pollTimer = setInterval(fetchNew, POLL_MS);
}

function stopPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = null;
}

/* --------------------------------------------------------------------- *
 *  Arranque
 * --------------------------------------------------------------------- */

function wireComposer() {
  const form = el('#composer');
  const input = el('#composer-input');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    sendMessage();
  });

  // Enter para enviar, Shift+Enter para salto de linea.
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // auto-resize del textarea
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 160) + 'px';
  });
}

async function boot() {
  wireComposer();
  try {
    await ensureKeys();
    await loadContacts();
  } catch (e) {
    setStatus('Error de inicializacion: ' + e.message, false, true);
    console.error(e);
  }
}

document.addEventListener('DOMContentLoaded', boot);
