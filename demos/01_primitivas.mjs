/**
 * DEMO 1 — Primitivas de la Web Crypto API contra vectores OFICIALES.
 *
 * Ahora el cifrado usa la **Web Crypto API** (auditada por los fabricantes). Esta demo
 * comprueba que esas primitivas nativas coinciden con los vectores de los estándares:
 *   - SHA-256        (FIPS 180-4)
 *   - HMAC-SHA256    (RFC 4231)
 *   - HKDF-SHA256    (RFC 5869)
 *   - PBKDF2-SHA256  (RFC 7914)
 *   - AES-256-GCM    (vector "Test Case 13" de McGrew & Viega)
 *
 * Ejecutar:  node demos/01_primitivas.mjs   (o:  npm run demo:primitivas)
 */

import { banner, eq, hex, fromHex, bytesOf, summary, resetFails, isMain } from './_util.mjs';

const subtle = globalThis.crypto.subtle;

async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}
async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
async function pbkdf2(pw, salt, iterations, dkBytes) {
  const base = await subtle.importKey('raw', pw, { name: 'PBKDF2' }, false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, dkBytes * 8));
}
async function hkdf(ikm, salt, info, dkBytes) {
  const base = await subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, dkBytes * 8));
}
async function aesGcm(key, iv, pt) {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, k, pt));
}

export async function demo() {
  resetFails();
  banner('DEMO 1 · Primitivas Web Crypto vs. vectores oficiales');

  // SHA-256 (FIPS 180-4)
  eq('SHA-256("abc")',
     hex(await sha256(bytesOf('abc'))),
     'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  // HMAC-SHA256 (RFC 4231, Test Case 2)
  eq('HMAC-SHA256 (RFC 4231 #2)',
     hex(await hmac(bytesOf('Jefe'), bytesOf('what do ya want for nothing?'))),
     '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');

  // HKDF-SHA256 (RFC 5869, Test Case 1)
  const ikm = new Uint8Array(22).fill(0x0b);
  const salt = fromHex('000102030405060708090a0b0c');
  const info = fromHex('f0f1f2f3f4f5f6f7f8f9');
  eq('HKDF-SHA256 (RFC 5869 #1), 42 bytes',
     hex(await hkdf(ikm, salt, info, 42)),
     '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

  // PBKDF2-HMAC-SHA256 (RFC 7914)
  eq('PBKDF2-SHA256 c=1 (RFC 7914)',
     hex(await pbkdf2(bytesOf('password'), bytesOf('salt'), 1, 32)),
     '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
  eq('PBKDF2-SHA256 c=4096 (RFC 7914)',
     hex(await pbkdf2(bytesOf('password'), bytesOf('salt'), 4096, 32)),
     'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');

  // AES-256-GCM (McGrew & Viega, Test Case 13: clave/IV en cero, texto vacío → solo el tag)
  const tag = await aesGcm(new Uint8Array(32), new Uint8Array(12), new Uint8Array(0));
  eq('AES-256-GCM tag (Test Case 13)',
     hex(tag),
     '530f8afbc74536b9a963b4f1c4cb738b');

  return summary('DEMO 1');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
