/**
 * cripto-core.js — Nucleo criptografico KEM/DEM implementado desde cero.
 *
 * Primitivas (sin librerias de cifrado de terceros):
 *   - SHA-256                  (hash)
 *   - HMAC-SHA256              (autenticacion)
 *   - HKDF-SHA256              (derivacion de subclaves)
 *   - AES-256-CTR              (cifrado simetrico de flujo)
 *   - RSA (BigInt)             (generacion de claves, modexp, Miller-Rabin)
 *   - RSA-OAEP (SHA-256)       (encapsulado de clave / KEM multi-destinatario)
 *   - RSA-PSS  (SHA-256)       (firma de origen, opcional)
 *   - UTF-8 + Base64           (transporte universal de caracteres)
 *
 * Unica dependencia del entorno: crypto.getRandomValues (CSPRNG del navegador/Node)
 * y TextEncoder/TextDecoder para UTF-8.
 *
 * Patron KEM/DEM multi-destinatario (estilo PGP):
 *   1. K  <- 32 bytes aleatorios               (clave de sesion)
 *   2. k_enc, k_mac <- HKDF-SHA256(K)
 *   3. C  <- AES-256-CTR(k_enc, UTF8(M))
 *   4. T  <- HMAC-SHA256(k_mac, nonce || C)     (Encrypt-then-MAC)
 *   5. encK_U <- RSA-OAEP(pk_U, K)  para cada participante U
 */

/* ===================================================================== *
 *  Utilidades de bytes / codificacion
 * ===================================================================== */

const _enc = new TextEncoder();
const _dec = new TextDecoder('utf-8', { fatal: false });

function getRandom() {
  // crypto global: navegador y Node >= 19 lo exponen.
  const c = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto : null;
  if (!c || !c.getRandomValues) {
    throw new Error('CSPRNG (crypto.getRandomValues) no disponible en este entorno.');
  }
  return c;
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  getRandom().getRandomValues(out);
  return out;
}

function utf8Encode(str) {
  return _enc.encode(str);
}

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
  // comparacion en tiempo constante (para MAC/OAEP)
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
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
  const clean = str.replace(/[\r\n\s]/g, '');
  const out = [];
  let buffer = 0, bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const v = _B64INV[clean.charCodeAt(i)];
    if (v === -2) break;       // padding
    if (v === -1) throw new Error('Base64 invalido');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/* ---- Hex <-> BigInt / bytes ---- */

function bytesToBigInt(bytes) {
  let r = 0n;
  for (let i = 0; i < bytes.length; i++) r = (r << 8n) | BigInt(bytes[i]);
  return r;
}

function bigIntToBytes(num, length) {
  // big-endian, rellenado con ceros a `length` bytes
  const out = new Uint8Array(length);
  let n = num;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error('bigIntToBytes: numero no cabe en la longitud dada');
  return out;
}

function bigIntToHex(num) {
  let h = num.toString(16);
  if (h.length % 2) h = '0' + h;
  return h;
}

function hexToBigInt(hex) {
  return BigInt('0x' + hex);
}

function bitLength(num) {
  return num.toString(2).length;
}

/* ===================================================================== *
 *  SHA-256
 * ===================================================================== */

const _K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function _rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function sha256(msg) {
  const m = msg instanceof Uint8Array ? msg : utf8Encode(String(msg));
  const len = m.length;
  const bitLen = len * 8;

  // padding
  const withPad = ((len + 8) >> 6) + 1; // bloques de 64 bytes
  const total = withPad * 64;
  const buf = new Uint8Array(total);
  buf.set(m);
  buf[len] = 0x80;
  // longitud en bits, big-endian, ultimos 8 bytes (usamos 32 bits altos = 0 para mensajes < 512MB)
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 4, bitLen >>> 0, false);
  dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000), false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + _K256[i] + w[i]) >>> 0;
      const S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((hh, i) => odv.setUint32(i * 4, hh, false));
  return out;
}

const SHA256_LEN = 32;

/* ===================================================================== *
 *  HMAC-SHA256
 * ===================================================================== */

function hmacSha256(key, message) {
  const blockSize = 64;
  let k = key instanceof Uint8Array ? key : utf8Encode(String(key));
  if (k.length > blockSize) k = sha256(k);
  const padded = new Uint8Array(blockSize);
  padded.set(k);

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = padded[i] ^ 0x36;
    opad[i] = padded[i] ^ 0x5c;
  }
  const inner = sha256(concatBytes(ipad, message));
  return sha256(concatBytes(opad, inner));
}

/* ===================================================================== *
 *  HKDF-SHA256 (RFC 5869)
 * ===================================================================== */

function hkdf(ikm, length, { salt = new Uint8Array(0), info = new Uint8Array(0) } = {}) {
  // Extract
  const prk = hmacSha256(salt.length ? salt : new Uint8Array(SHA256_LEN), ikm);
  // Expand
  const n = Math.ceil(length / SHA256_LEN);
  let t = new Uint8Array(0);
  const okm = new Uint8Array(n * SHA256_LEN);
  const infoB = info instanceof Uint8Array ? info : utf8Encode(String(info));
  for (let i = 0; i < n; i++) {
    t = hmacSha256(prk, concatBytes(t, infoB, new Uint8Array([i + 1])));
    okm.set(t, i * SHA256_LEN);
  }
  return okm.slice(0, length);
}

/** Deriva subclaves de la clave de sesion K. */
function deriveSubkeys(K) {
  const okm = hkdf(K, 64, { info: utf8Encode('chat-e2e/kem-dem/v1') });
  return { kEnc: okm.slice(0, 32), kMac: okm.slice(32, 64) };
}

/* ===================================================================== *
 *  AES-256 (cifrado de bloque) + modo CTR
 * ===================================================================== */

const _SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const _RCON = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]);

function _xtime(a) {
  return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}
function _mul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

/** Expansion de clave AES-256 -> 15 round keys (60 words). */
function _aes256KeyExpansion(key) {
  const Nk = 8, Nr = 14;
  const w = new Array(4 * (Nr + 1));
  for (let i = 0; i < Nk; i++) {
    w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
  }
  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    let temp = w[i - 1].slice();
    if (i % Nk === 0) {
      temp = [temp[1], temp[2], temp[3], temp[0]];            // RotWord
      temp = temp.map((b) => _SBOX[b]);                        // SubWord
      temp[0] ^= _RCON[i / Nk - 1];
    } else if (i % Nk === 4) {
      temp = temp.map((b) => _SBOX[b]);                        // SubWord (AES-256 extra)
    }
    w[i] = [
      w[i - Nk][0] ^ temp[0], w[i - Nk][1] ^ temp[1],
      w[i - Nk][2] ^ temp[2], w[i - Nk][3] ^ temp[3],
    ];
  }
  return w;
}

/** Cifra un unico bloque de 16 bytes con AES-256. */
function _aesEncryptBlock(block, roundKeys) {
  const Nr = 14;
  // estado en orden de columnas: s[r][c]
  let s = [[], [], [], []];
  for (let i = 0; i < 16; i++) s[i % 4][(i / 4) | 0] = block[i];

  const addRoundKey = (round) => {
    for (let c = 0; c < 4; c++) {
      const wk = roundKeys[round * 4 + c];
      for (let r = 0; r < 4; r++) s[r][c] ^= wk[r];
    }
  };
  const subBytes = () => { for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) s[r][c] = _SBOX[s[r][c]]; };
  const shiftRows = () => {
    for (let r = 1; r < 4; r++) {
      const row = [s[r][0], s[r][1], s[r][2], s[r][3]];
      for (let c = 0; c < 4; c++) s[r][c] = row[(c + r) % 4];
    }
  };
  const mixColumns = () => {
    for (let c = 0; c < 4; c++) {
      const a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
      s[0][c] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3;
      s[1][c] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3;
      s[2][c] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3);
      s[3][c] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2);
    }
  };

  addRoundKey(0);
  for (let round = 1; round < Nr; round++) {
    subBytes(); shiftRows(); mixColumns(); addRoundKey(round);
  }
  subBytes(); shiftRows(); addRoundKey(Nr);

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = s[i % 4][(i / 4) | 0];
  return out;
}

function _incrementCounter(counter) {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) break;
  }
}

/** AES-256-CTR. El mismo procedimiento cifra y descifra. */
function aes256ctr(key, nonce, data) {
  if (key.length !== 32) throw new Error('AES-256 requiere clave de 32 bytes');
  if (nonce.length !== 16) throw new Error('CTR requiere nonce/contador de 16 bytes');
  const roundKeys = _aes256KeyExpansion(key);
  const counter = nonce.slice();
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 16) {
    const ks = _aesEncryptBlock(counter, roundKeys);
    const end = Math.min(16, data.length - off);
    for (let i = 0; i < end; i++) out[off + i] = data[off + i] ^ ks[i];
    _incrementCounter(counter);
  }
  return out;
}

/* ===================================================================== *
 *  Aritmetica modular / RSA
 * ===================================================================== */

function modpow(base, exp, mod) {
  base %= mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function egcd(a, b) {
  let old_r = a, r = b;
  let old_s = 1n, s = 0n;
  let old_t = 0n, t = 1n;
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
    [old_t, t] = [t, old_t - q * t];
  }
  return { g: old_r, x: old_s, y: old_t };
}

function modinv(a, m) {
  const { g, x } = egcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error('Sin inverso modular (no coprimos)');
  return ((x % m) + m) % m;
}

function gcd(a, b) {
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

// Primos pequenos para criba por division de prueba.
const _SMALL_PRIMES = (() => {
  const limit = 2000, sieve = new Uint8Array(limit).fill(1), primes = [];
  for (let i = 2; i < limit; i++) {
    if (sieve[i]) {
      primes.push(BigInt(i));
      for (let j = i * i; j < limit; j += i) sieve[j] = 0;
    }
  }
  return primes;
})();

function _randomBigIntBits(bits) {
  const bytes = Math.ceil(bits / 8);
  const arr = randomBytes(bytes);
  // recortar bits sobrantes del byte mas alto
  const excess = bytes * 8 - bits;
  if (excess) arr[0] &= (0xff >> excess);
  return bytesToBigInt(arr);
}

function _millerRabin(n, rounds) {
  if (n < 2n) return false;
  for (const p of _SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  // n-1 = d * 2^r
  let d = n - 1n, r = 0n;
  while ((d & 1n) === 0n) { d >>= 1n; r++; }
  const nBits = bitLength(n);
  WitnessLoop: for (let i = 0; i < rounds; i++) {
    // base aleatoria en [2, n-2]
    let a;
    do { a = _randomBigIntBits(nBits) % (n - 3n); } while (a < 0n);
    a += 2n;
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let j = 1n; j < r; j++) {
      x = (x * x) % n;
      if (x === n - 1n) continue WitnessLoop;
    }
    return false;
  }
  return true;
}

function _generatePrime(bits, e) {
  while (true) {
    const bytes = Math.ceil(bits / 8);
    const arr = randomBytes(bytes);
    arr[0] |= 0xc0;              // dos bits altos en 1 -> garantiza longitud del producto
    arr[bytes - 1] |= 0x01;      // impar
    const candidate = bytesToBigInt(arr);
    // descarte rapido por division de prueba
    let small = false;
    for (const p of _SMALL_PRIMES) { if (candidate % p === 0n) { small = true; break; } }
    if (small) continue;
    if (gcd(e, candidate - 1n) !== 1n) continue; // e debe ser coprimo con p-1
    if (_millerRabin(candidate, 24)) return candidate;
  }
}

/** Genera un par de claves RSA. bits = tamano del modulo (2048 por defecto). */
function generateRsaKeyPair(bits = 2048) {
  const e = 65537n;
  const half = bits >> 1;
  let p, q, n;
  do {
    p = _generatePrime(half, e);
    q = _generatePrime(bits - half, e);
    if (p === q) continue;
    n = p * q;
  } while (bitLength(n) !== bits);

  if (p < q) [p, q] = [q, p];
  const phi = (p - 1n) * (q - 1n);
  const d = modinv(e, phi);
  // parametros CRT (aceleran el descifrado)
  const dp = d % (p - 1n);
  const dq = d % (q - 1n);
  const qinv = modinv(q, p);

  return {
    publicKey: { n, e, bits },
    privateKey: { n, e, d, p, q, dp, dq, qinv, bits },
  };
}

function _rsaPublic(pub, m) {
  return modpow(m, pub.e, pub.n);
}

function _rsaPrivate(priv, c) {
  if (priv.p && priv.q) {
    // Descifrado por CRT
    const m1 = modpow(c % priv.p, priv.dp, priv.p);
    const m2 = modpow(c % priv.q, priv.dq, priv.q);
    let h = (priv.qinv * (m1 - m2)) % priv.p;
    if (h < 0n) h += priv.p;
    return m2 + h * priv.q;
  }
  return modpow(c, priv.d, priv.n);
}

/* ---- MGF1-SHA256 ---- */

function mgf1(seed, length) {
  let out = new Uint8Array(0);
  let counter = 0;
  const blocks = [];
  let produced = 0;
  while (produced < length) {
    const cbytes = new Uint8Array(4);
    new DataView(cbytes.buffer).setUint32(0, counter, false);
    const block = sha256(concatBytes(seed, cbytes));
    blocks.push(block);
    produced += block.length;
    counter++;
  }
  out = concatBytes(...blocks);
  return out.slice(0, length);
}

/* ---- RSA-OAEP (SHA-256, etiqueta vacia) ---- */

const _LHASH_EMPTY = sha256(new Uint8Array(0)); // SHA-256("")

function rsaOaepEncrypt(pub, message) {
  const k = Math.ceil(bitLength(pub.n) / 8);
  const hLen = SHA256_LEN;
  if (message.length > k - 2 * hLen - 2) throw new Error('Mensaje OAEP demasiado largo');

  const ps = new Uint8Array(k - message.length - 2 * hLen - 2); // ceros
  const db = concatBytes(_LHASH_EMPTY, ps, new Uint8Array([0x01]), message); // len k-hLen-1
  const seed = randomBytes(hLen);
  const dbMask = mgf1(seed, k - hLen - 1);
  const maskedDB = xorBytes(db, dbMask);
  const seedMask = mgf1(maskedDB, hLen);
  const maskedSeed = xorBytes(seed, seedMask);
  const em = concatBytes(new Uint8Array([0x00]), maskedSeed, maskedDB); // len k

  const c = _rsaPublic(pub, bytesToBigInt(em));
  return bigIntToBytes(c, k);
}

function rsaOaepDecrypt(priv, ciphertext) {
  const k = Math.ceil(bitLength(priv.n) / 8);
  const hLen = SHA256_LEN;
  if (ciphertext.length !== k || k < 2 * hLen + 2) throw new Error('OAEP: longitud invalida');

  const m = _rsaPrivate(priv, bytesToBigInt(ciphertext));
  const em = bigIntToBytes(m, k);

  const y = em[0];
  const maskedSeed = em.slice(1, 1 + hLen);
  const maskedDB = em.slice(1 + hLen);
  const seedMask = mgf1(maskedDB, hLen);
  const seed = xorBytes(maskedSeed, seedMask);
  const dbMask = mgf1(seed, k - hLen - 1);
  const db = xorBytes(maskedDB, dbMask);

  const lHash = db.slice(0, hLen);
  let ok = (y === 0x00) && bytesEqual(lHash, _LHASH_EMPTY);

  // buscar separador 0x01 tras los ceros del padding
  let idx = hLen;
  while (idx < db.length && db[idx] === 0x00) idx++;
  if (idx >= db.length || db[idx] !== 0x01) ok = false;
  if (!ok) throw new Error('OAEP: descifrado invalido');
  return db.slice(idx + 1);
}

/* ---- RSA-PSS (SHA-256) — firma de origen opcional ---- */

function rsaPssSign(priv, message) {
  const emBits = bitLength(priv.n) - 1;
  const emLen = Math.ceil(emBits / 8);
  const hLen = SHA256_LEN;
  const sLen = hLen;
  const mHash = sha256(message);
  if (emLen < hLen + sLen + 2) throw new Error('PSS: clave demasiado pequena');

  const salt = randomBytes(sLen);
  const mPrime = concatBytes(new Uint8Array(8), mHash, salt);
  const H = sha256(mPrime);
  const ps = new Uint8Array(emLen - sLen - hLen - 2);
  const db = concatBytes(ps, new Uint8Array([0x01]), salt); // len emLen-hLen-1
  const dbMask = mgf1(H, emLen - hLen - 1);
  const maskedDB = xorBytes(db, dbMask);
  // poner a cero los bits sobrantes de la izquierda
  const zeroBits = 8 * emLen - emBits;
  if (zeroBits) maskedDB[0] &= (0xff >> zeroBits);
  const em = concatBytes(maskedDB, H, new Uint8Array([0xbc]));

  const k = Math.ceil(bitLength(priv.n) / 8);
  const s = _rsaPrivate(priv, bytesToBigInt(em));
  return bigIntToBytes(s, k);
}

function rsaPssVerify(pub, message, signature) {
  try {
    const emBits = bitLength(pub.n) - 1;
    const emLen = Math.ceil(emBits / 8);
    const hLen = SHA256_LEN;
    const sLen = hLen;
    const k = Math.ceil(bitLength(pub.n) / 8);
    if (signature.length !== k) return false;

    const m = _rsaPublic(pub, bytesToBigInt(signature));
    let em = bigIntToBytes(m, emLen);

    if (em[em.length - 1] !== 0xbc) return false;
    const maskedDB = em.slice(0, emLen - hLen - 1);
    const H = em.slice(emLen - hLen - 1, emLen - 1);
    const zeroBits = 8 * emLen - emBits;
    if (zeroBits && (maskedDB[0] & (0xff << (8 - zeroBits)) & 0xff)) return false;

    const dbMask = mgf1(H, emLen - hLen - 1);
    const db = xorBytes(maskedDB, dbMask);
    if (zeroBits) db[0] &= (0xff >> zeroBits);

    let i = 0;
    while (i < db.length - sLen - 1 && db[i] === 0x00) i++;
    if (db[i] !== 0x01) return false;
    const salt = db.slice(db.length - sLen);

    const mHash = sha256(message);
    const mPrime = concatBytes(new Uint8Array(8), mHash, salt);
    const Hp = sha256(mPrime);
    return bytesEqual(H, Hp);
  } catch (_) {
    return false;
  }
}

/* ===================================================================== *
 *  Serializacion de claves (JSON con campos hex)
 * ===================================================================== */

function exportPublicKey(pub) {
  return JSON.stringify({ n: bigIntToHex(pub.n), e: bigIntToHex(pub.e), bits: pub.bits });
}

function importPublicKey(json) {
  const o = typeof json === 'string' ? JSON.parse(json) : json;
  return { n: hexToBigInt(o.n), e: hexToBigInt(o.e), bits: o.bits || bitLength(hexToBigInt(o.n)) };
}

function exportPrivateKey(priv) {
  return JSON.stringify({
    n: bigIntToHex(priv.n), e: bigIntToHex(priv.e), d: bigIntToHex(priv.d),
    p: bigIntToHex(priv.p), q: bigIntToHex(priv.q),
    dp: bigIntToHex(priv.dp), dq: bigIntToHex(priv.dq), qinv: bigIntToHex(priv.qinv),
    bits: priv.bits,
  });
}

function importPrivateKey(json) {
  const o = typeof json === 'string' ? JSON.parse(json) : json;
  return {
    n: hexToBigInt(o.n), e: hexToBigInt(o.e), d: hexToBigInt(o.d),
    p: hexToBigInt(o.p), q: hexToBigInt(o.q),
    dp: hexToBigInt(o.dp), dq: hexToBigInt(o.dq), qinv: hexToBigInt(o.qinv),
    bits: o.bits || bitLength(hexToBigInt(o.n)),
  };
}

/* ===================================================================== *
 *  API de alto nivel: cifrar / descifrar un mensaje (sobre KEM/DEM)
 * ===================================================================== */

/**
 * Cifra el texto `plaintext` para el emisor y el receptor.
 * @param {string} plaintext
 * @param {object} pubSender    clave publica del emisor (importada)
 * @param {object} pubRecipient clave publica del receptor (importada)
 * @param {object|null} privSenderForSign  si se pasa, firma el sobre (RSA-PSS)
 * @returns {object} sobre con campos en Base64
 */
function encryptMessage(plaintext, pubSender, pubRecipient, privSenderForSign = null) {
  const K = randomBytes(32);
  const { kEnc, kMac } = deriveSubkeys(K);
  const nonce = randomBytes(16);
  const ciphertext = aes256ctr(kEnc, nonce, utf8Encode(plaintext));
  const mac = hmacSha256(kMac, concatBytes(nonce, ciphertext));

  const encKeySender = rsaOaepEncrypt(pubSender, K);
  const encKeyRecipient = rsaOaepEncrypt(pubRecipient, K);

  let signature = null;
  if (privSenderForSign) {
    // se firma el material publico del sobre (autenticidad de origen)
    signature = rsaPssSign(privSenderForSign, concatBytes(nonce, ciphertext, mac));
  }

  return {
    v: 1,
    encKeySender: bytesToBase64(encKeySender),
    encKeyRecipient: bytesToBase64(encKeyRecipient),
    ciphertext: bytesToBase64(ciphertext),
    mac: bytesToBase64(mac),
    nonce: bytesToBase64(nonce),
    signature: signature ? bytesToBase64(signature) : null,
  };
}

/**
 * Descifra un sobre.
 * @param {object} envelope  sobre (campos Base64)
 * @param {object} privKey   clave privada del usuario actual (importada)
 * @param {boolean} isSender true si el usuario actual fue el emisor (usa encKeySender)
 * @param {object|null} pubSenderForVerify  clave publica del emisor para verificar firma
 * @returns {{plaintext:string|null, integrity:boolean, verified:(boolean|null)}}
 */
function decryptMessage(envelope, privKey, isSender, pubSenderForVerify = null) {
  const wrapped = base64ToBytes(isSender ? envelope.encKeySender : envelope.encKeyRecipient);
  const nonce = base64ToBytes(envelope.nonce);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const macStored = base64ToBytes(envelope.mac);

  let K;
  try {
    K = rsaOaepDecrypt(privKey, wrapped);
  } catch (err) {
    return { plaintext: null, integrity: false, verified: null, error: 'No se pudo desencapsular la clave (OAEP)' };
  }

  const { kEnc, kMac } = deriveSubkeys(K);
  const macCalc = hmacSha256(kMac, concatBytes(nonce, ciphertext));
  const integrity = bytesEqual(macCalc, macStored);
  if (!integrity) {
    return { plaintext: null, integrity: false, verified: null, error: 'HMAC no coincide (mensaje alterado)' };
  }

  const plaintext = utf8Decode(aes256ctr(kEnc, nonce, ciphertext));

  let verified = null;
  if (envelope.signature && pubSenderForVerify) {
    verified = rsaPssVerify(
      pubSenderForVerify,
      concatBytes(nonce, ciphertext, macStored),
      base64ToBytes(envelope.signature),
    );
  }

  return { plaintext, integrity: true, verified };
}

/* ===================================================================== *
 *  Auto-prueba (round-trip) — util para consola / Node
 * ===================================================================== */

function selfTest(bits = 2048) {
  const t0 = Date.now();
  const A = generateRsaKeyPair(bits);
  const B = generateRsaKeyPair(bits);
  const tKeys = Date.now() - t0;

  const msg = 'Hola 你好 مرحبا 😀🔐🇵🇪 <>&"\'`  áéíóú — prueba KEM/DEM';
  const env = encryptMessage(msg, A.publicKey, B.publicKey, A.privateKey);

  const recv = decryptMessage(env, B.privateKey, false, A.publicKey);   // receptor B
  const back = decryptMessage(env, A.privateKey, true, A.publicKey);    // emisor A relee

  // prueba de integridad: alterar ciphertext
  const tampered = { ...env, ciphertext: bytesToBase64((() => { const b = base64ToBytes(env.ciphertext); b[0] ^= 1; return b; })()) };
  const tamperRes = decryptMessage(tampered, B.privateKey, false, A.publicKey);

  const result = {
    bits,
    keygenMs: tKeys,
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
  // bytes / codificacion
  utf8Encode, utf8Decode, bytesToBase64, base64ToBytes, randomBytes, concatBytes, bytesEqual,
  // hash / mac / kdf
  sha256, hmacSha256, hkdf, deriveSubkeys, mgf1,
  // simetrico
  aes256ctr,
  // rsa
  generateRsaKeyPair, rsaOaepEncrypt, rsaOaepDecrypt, rsaPssSign, rsaPssVerify, modpow, modinv,
  // claves
  exportPublicKey, importPublicKey, exportPrivateKey, importPrivateKey,
  // alto nivel
  encryptMessage, decryptMessage,
  // utilidades
  selfTest,
};

if (typeof window !== 'undefined') {
  window.CriptoCore = CriptoCore;
}

export default CriptoCore;
export {
  sha256, hmacSha256, hkdf, deriveSubkeys, aes256ctr,
  generateRsaKeyPair, rsaOaepEncrypt, rsaOaepDecrypt, rsaPssSign, rsaPssVerify,
  exportPublicKey, importPublicKey, exportPrivateKey, importPrivateKey,
  encryptMessage, decryptMessage, selfTest,
  bytesToBase64, base64ToBytes, utf8Encode, utf8Decode,
};
