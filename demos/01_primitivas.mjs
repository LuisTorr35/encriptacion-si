/**
 * DEMO 1 — Primitivas criptograficas contra vectores OFICIALES.
 *
 * Demuestra que cada bloque del nucleo (implementado desde cero, sin librerias)
 * produce exactamente la salida de los estandares:
 *   - SHA-256        (FIPS 180-4)
 *   - HMAC-SHA256    (RFC 4231)
 *   - HKDF-SHA256    (RFC 5869)
 *   - AES-256-CTR    (NIST SP 800-38A)
 *   - PBKDF2-SHA256  (RFC 7914)
 *
 * Ejecutar:  node demos/01_primitivas.mjs   (o:  npm run demo:primitivas)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, eq, hex, fromHex, bytesOf, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 1 · Primitivas vs. vectores oficiales');

  // --- SHA-256 (FIPS 180-4) ---
  eq('SHA-256("abc")',
     hex(CC.sha256(bytesOf('abc'))),
     'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  eq('SHA-256("") cadena vacia',
     hex(CC.sha256(bytesOf(''))),
     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

  // --- HMAC-SHA256 (RFC 4231, Test Case 2) ---
  eq('HMAC-SHA256 (RFC 4231 #2)',
     hex(CC.hmacSha256(bytesOf('Jefe'), bytesOf('what do ya want for nothing?'))),
     '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');

  // --- HKDF-SHA256 (RFC 5869, Test Case 1) ---
  const ikm = new Uint8Array(22).fill(0x0b);
  const salt = fromHex('000102030405060708090a0b0c');
  const inf = fromHex('f0f1f2f3f4f5f6f7f8f9');
  eq('HKDF-SHA256 (RFC 5869 #1), 42 bytes',
     hex(CC.hkdf(ikm, 42, { salt, info: inf })),
     '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

  // --- AES-256-CTR (NIST SP 800-38A, F.5.5) — 4 bloques ---
  const aesKey = fromHex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
  const ctr0 = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  const pt = fromHex(
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710');
  const expectedCt =
    '601ec313775789a5b7a7f504bbf3d228' +
    'f443e3ca4d62b59aca84e990cacaf5c5' +
    '2b0930daa23de94ce87017ba2d84988d' +
    'dfc9c58db67aada613c2dd08457941a6';
  eq('AES-256-CTR (NIST SP 800-38A F.5.5), 4 bloques',
     hex(CC.aes256ctr(aesKey, ctr0, pt)), expectedCt);
  // y descifra de vuelta (CTR es su propio inverso)
  eq('AES-256-CTR descifra al original',
     hex(CC.aes256ctr(aesKey, ctr0, fromHex(expectedCt))), hex(pt));

  // --- PBKDF2-HMAC-SHA256 (RFC 7914) ---
  eq('PBKDF2-SHA256 c=1 (RFC 7914)',
     hex(CC.pbkdf2Sha256(bytesOf('password'), bytesOf('salt'), 1, 32)),
     '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
  eq('PBKDF2-SHA256 c=4096 (RFC 7914)',
     hex(CC.pbkdf2Sha256(bytesOf('password'), bytesOf('salt'), 4096, 32)),
     'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');

  return summary('DEMO 1');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
