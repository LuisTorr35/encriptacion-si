/**
 * cripto-core.js — Núcleo criptográfico E2E usando la **Web Crypto API** (auditada).
 *
 * Sustituye la implementación "desde cero" por las primitivas nativas del navegador/Node,
 * mantenidas y auditadas por los fabricantes (estándar W3C). Mismo diseño KEM/DEM:
 *
 *   - RSA-OAEP (SHA-256)  → encapsular la clave de sesión para cada participante (KEM)
 *   - AES-256-GCM         → cifrar el mensaje CON integridad incorporada (DEM/AEAD)
 *   - RSA-PSS  (SHA-256)  → firma de origen (opcional)
 *   - PBKDF2-HMAC-SHA256  → derivar clave desde la contraseña (envoltura multi-dispositivo)
 *
 * Notas:
 *   - Todas las operaciones criptográficas son ASÍNCRONAS (devuelven Promesas).
 *   - AES-GCM es un cifrado autenticado (AEAD): ya no hace falta HMAC aparte. El "tag" de
 *     autenticación de 16 bytes se guarda en el campo `mac` del sobre (mismo esquema en BD).
 *   - Las claves públicas se serializan como **JWK** (incluye `n` y `e`, compatible con el
 *     backend que valida esos campos).
 *
 * Única dependencia del entorno: globalThis.crypto (Web Crypto) y TextEncoder/TextDecoder.
 */

/* ===================================================================== *
 *  Utilidades de bytes / codificación (no son criptografía)
 * ===================================================================== */

const _enc = new TextEncoder();
const _dec = new TextDecoder('utf-8', { fatal: false });

function _crypto() {
  const c = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto : null;
  if (!c || !c.subtle || !c.getRandomValues) {
    throw new Error('Web Crypto API (crypto.subtle) no disponible en este entorno.');
  }
  return c;
}
function _subtle() { return _crypto().subtle; }

function randomBytes(n) {
  const out = new Uint8Array(n);
  _crypto().getRandomValues(out);
  return out;
}

function utf8Encode(str) { return _enc.encode(str); }
function utf8Decode(bytes) {
  return _dec.decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* ---- Base64 (sin dependencias) ---- */

const _B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const _B64INV = (() => {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < _B64.length; i++) t[_B64.charCodeAt(i)] = i;
  t['='.charCodeAt(0)] = -2;
  return t;
})();

function bytesToBase64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += _B64[(n >> 18) & 63] + _B64[(n >> 12) & 63] + _B64[(n >> 6) & 63] + _B64[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += _B64[(n >> 18) & 63] + _B64[(n >> 12) & 63] + '==';
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += _B64[(n >> 18) & 63] + _B64[(n >> 12) & 63] + _B64[(n >> 6) & 63] + '=';
  }
  return out;
}

function base64ToBytes(str) {
  const clean = String(str).replace(/[\r\n\s]/g, '');
  const out = [];
  let buffer = 0, bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const v = _B64INV[clean.charCodeAt(i)];
    if (v === -2) break;
    if (v === -1) throw new Error('Base64 invalido');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

/* ===================================================================== *
 *  Parámetros
 * ===================================================================== */

const RSA_BITS = 2048;
const PBKDF2_ITERATIONS = 150000;
const GCM_TAG_BYTES = 16;   // AES-GCM produce un tag de autenticación de 128 bits
const GCM_IV_BYTES = 12;    // IV recomendado para GCM

/** Quita campos del JWK que atarían la clave a un solo algoritmo (alg/use/key_ops),
 *  para poder reimportarla tanto como RSA-OAEP (cifrar) como RSA-PSS (firmar). */
function _cleanJwk(jwk) {
  const { alg, key_ops, use, ext, ...rest } = jwk; // eslint-disable-line no-unused-vars
  return rest; // conserva kty, n, e, d, p, q, dp, dq, qi
}

/* ===================================================================== *
 *  Claves RSA (generación / serialización JWK)
 * ===================================================================== */

/** Genera un par RSA. El material sirve tanto para OAEP (cifrar) como para PSS (firmar). */
async function generateRsaKeyPair(bits = RSA_BITS) {
  const kp = await _subtle().generateKey(
    { name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

async function exportPublicKey(pub) {
  return JSON.stringify(_cleanJwk(await _subtle().exportKey('jwk', pub)));
}

async function exportPrivateKey(priv) {
  return JSON.stringify(_cleanJwk(await _subtle().exportKey('jwk', priv)));
}

/** Importa una clave PÚBLICA y devuelve manejadores para cifrar (OAEP) y verificar (PSS). */
async function importPublicKey(json) {
  const jwk = _cleanJwk(typeof json === 'string' ? JSON.parse(json) : json);
  const s = _subtle();
  const [oaep, pss] = await Promise.all([
    s.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']),
    s.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']),
  ]);
  return { oaep, pss, n: jwk.n, e: jwk.e };
}

/** Importa una clave PRIVADA y devuelve manejadores para descifrar (OAEP) y firmar (PSS). */
async function importPrivateKey(json) {
  const jwk = _cleanJwk(typeof json === 'string' ? JSON.parse(json) : json);
  const s = _subtle();
  const [oaep, pss] = await Promise.all([
    s.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']),
    s.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']),
  ]);
  return { oaep, pss };
}

/* ===================================================================== *
 *  Cifrar / descifrar un mensaje (KEM/DEM con AES-256-GCM)
 * ===================================================================== */

/**
 * Cifra `plaintext` para emisor y receptor (multi-destinatario estilo PGP).
 * @returns {Promise<object>} sobre con campos en Base64.
 */
async function encryptMessage(plaintext, pubSender, pubRecipient, privSenderForSign = null) {
  const s = _subtle();

  // DEM: clave de sesión simétrica + AES-256-GCM (cifra y autentica a la vez)
  const kRaw = randomBytes(32);
  const aesKey = await s.importKey('raw', kRaw, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = randomBytes(GCM_IV_BYTES);
  const ctTag = new Uint8Array(await s.encrypt({ name: 'AES-GCM', iv }, aesKey, utf8Encode(plaintext)));
  const ciphertext = ctTag.slice(0, ctTag.length - GCM_TAG_BYTES);
  const tag = ctTag.slice(ctTag.length - GCM_TAG_BYTES); // tag de autenticación GCM

  // KEM: envolver la clave de sesión con la pública de cada participante (RSA-OAEP)
  const [encKS, encKR] = await Promise.all([
    s.encrypt({ name: 'RSA-OAEP' }, pubSender.oaep, kRaw),
    s.encrypt({ name: 'RSA-OAEP' }, pubRecipient.oaep, kRaw),
  ]);

  // Firma de origen opcional (RSA-PSS) sobre iv ‖ ciphertext ‖ tag
  let signature = null;
  if (privSenderForSign) {
    const sig = await s.sign({ name: 'RSA-PSS', saltLength: 32 }, privSenderForSign.pss, concatBytes(iv, ciphertext, tag));
    signature = bytesToBase64(new Uint8Array(sig));
  }

  return {
    v: 2,
    encKeySender: bytesToBase64(new Uint8Array(encKS)),
    encKeyRecipient: bytesToBase64(new Uint8Array(encKR)),
    ciphertext: bytesToBase64(ciphertext),
    mac: bytesToBase64(tag),   // el "mac" ahora es el tag GCM (integridad)
    nonce: bytesToBase64(iv),
    signature,
  };
}

/**
 * Descifra un sobre.
 * @returns {Promise<{plaintext:string|null, integrity:boolean, verified:(boolean|null)}>}
 */
async function decryptMessage(envelope, privKey, isSender, pubSenderForVerify = null) {
  const s = _subtle();
  const wrapped = base64ToBytes(isSender ? envelope.encKeySender : envelope.encKeyRecipient);
  const iv = base64ToBytes(envelope.nonce);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const tag = base64ToBytes(envelope.mac);

  // 1) Recuperar la clave de sesión (cada quien abre SU copia)
  let kRaw;
  try {
    kRaw = new Uint8Array(await s.decrypt({ name: 'RSA-OAEP' }, privKey.oaep, wrapped));
  } catch (err) {
    return { plaintext: null, integrity: false, verified: null, error: 'No se pudo desencapsular la clave (OAEP)' };
  }

  // 2) Descifrar + verificar integridad (AES-GCM falla si el ciphertext/tag fue alterado)
  let plaintext;
  try {
    const aesKey = await s.importKey('raw', kRaw, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await s.decrypt({ name: 'AES-GCM', iv }, aesKey, concatBytes(ciphertext, tag));
    plaintext = utf8Decode(new Uint8Array(pt));
  } catch (err) {
    return { plaintext: null, integrity: false, verified: null, error: 'Autenticacion GCM fallida (mensaje alterado)' };
  }

  // 3) Verificar firma de origen (opcional)
  let verified = null;
  if (envelope.signature && pubSenderForVerify) {
    try {
      verified = await s.verify(
        { name: 'RSA-PSS', saltLength: 32 },
        pubSenderForVerify.pss,
        base64ToBytes(envelope.signature),
        concatBytes(iv, ciphertext, tag),
      );
    } catch (_) { verified = false; }
  }

  return { plaintext, integrity: true, verified };
}

/* ===================================================================== *
 *  Envoltura de la clave privada con la contraseña (multi-dispositivo)
 *  PBKDF2-HMAC-SHA256 → AES-256-GCM (el tag GCM verifica la contraseña)
 * ===================================================================== */

async function _deriveWrapKey(password, salt, iterations, usage) {
  const s = _subtle();
  const base = await s.importKey('raw', utf8Encode(String(password)), { name: 'PBKDF2' }, false, ['deriveKey']);
  return s.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

/** Envuelve (cifra) el JSON de la clave privada con la contraseña. */
async function wrapPrivateKey(privateKeyJson, password, iterations = PBKDF2_ITERATIONS) {
  const s = _subtle();
  const salt = randomBytes(16);
  const iv = randomBytes(GCM_IV_BYTES);
  const key = await _deriveWrapKey(password, salt, iterations, 'encrypt');
  const ctTag = new Uint8Array(await s.encrypt({ name: 'AES-GCM', iv }, key, utf8Encode(privateKeyJson)));
  const ciphertext = ctTag.slice(0, ctTag.length - GCM_TAG_BYTES);
  const tag = ctTag.slice(ctTag.length - GCM_TAG_BYTES);

  return {
    v: 2,
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations,
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
    mac: bytesToBase64(tag),
  };
}

/** Abre (descifra) el blob con la contraseña. Lanza si la contraseña es incorrecta. */
async function unwrapPrivateKey(blob, password) {
  const s = _subtle();
  const salt = base64ToBytes(blob.salt);
  const iv = base64ToBytes(blob.nonce);
  const ciphertext = base64ToBytes(blob.ciphertext);
  const tag = base64ToBytes(blob.mac);
  const iterations = blob.iterations || PBKDF2_ITERATIONS;

  const key = await _deriveWrapKey(password, salt, iterations, 'decrypt');
  try {
    const pt = await s.decrypt({ name: 'AES-GCM', iv }, key, concatBytes(ciphertext, tag));
    return utf8Decode(new Uint8Array(pt));
  } catch (_) {
    throw new Error('Contrasena incorrecta o clave corrupta.');
  }
}

/* ===================================================================== *
 *  Auto-prueba (round-trip) — útil para consola / Node
 * ===================================================================== */

async function selfTest(bits = RSA_BITS) {
  const A = await generateRsaKeyPair(bits);
  const B = await generateRsaKeyPair(bits);

  const aPub = await importPublicKey(await exportPublicKey(A.publicKey));
  const aPriv = await importPrivateKey(await exportPrivateKey(A.privateKey));
  const bPub = await importPublicKey(await exportPublicKey(B.publicKey));
  const bPriv = await importPrivateKey(await exportPrivateKey(B.privateKey));

  const msg = 'Hola 你好 مرحبا 😀🔐🇵🇪 <>&"\'`  áéíóú — prueba KEM/DEM (Web Crypto)';
  const env = await encryptMessage(msg, aPub, bPub, aPriv);

  const recv = await decryptMessage(env, bPriv, false, aPub); // receptor B
  const back = await decryptMessage(env, aPriv, true, aPub);  // emisor A relee

  // integridad: alterar 1 byte del ciphertext
  const tampered = { ...env, ciphertext: bytesToBase64((() => { const b = base64ToBytes(env.ciphertext); b[0] ^= 1; return b; })()) };
  const tamperRes = await decryptMessage(tampered, bPriv, false, aPub);

  const result = {
    bits,
    recipientOk: recv.plaintext === msg,
    senderOk: back.plaintext === msg,
    signatureVerified: recv.verified === true,
    tamperRejected: tamperRes.integrity === false,
    recovered: recv.plaintext,
  };
  result.pass = result.recipientOk && result.senderOk && result.signatureVerified && result.tamperRejected;
  return result;
}

/* ===================================================================== *
 *  Export
 * ===================================================================== */

const CriptoCore = {
  // bytes / codificación
  utf8Encode, utf8Decode, bytesToBase64, base64ToBytes, randomBytes, concatBytes, bytesEqual,
  // claves
  generateRsaKeyPair, exportPublicKey, importPublicKey, exportPrivateKey, importPrivateKey,
  // alto nivel
  encryptMessage, decryptMessage,
  // envoltura de clave privada (multi-dispositivo)
  wrapPrivateKey, unwrapPrivateKey,
  // utilidades
  selfTest,
};

if (typeof window !== 'undefined') {
  window.CriptoCore = CriptoCore;
}

export default CriptoCore;
export {
  generateRsaKeyPair, exportPublicKey, importPublicKey, exportPrivateKey, importPrivateKey,
  encryptMessage, decryptMessage, wrapPrivateKey, unwrapPrivateKey, selfTest,
  bytesToBase64, base64ToBytes, utf8Encode, utf8Decode, concatBytes, randomBytes, bytesEqual,
};
