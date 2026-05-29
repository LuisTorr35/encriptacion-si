/**
 * DEMO 3 — Integridad (anti-manipulación) y soporte universal de caracteres.
 *
 *   - Alterar 1 byte del ciphertext => AES-256-GCM RECHAZA al descifrar (autenticación AEAD).
 *   - Round-trip de caracteres: emojis, chino, árabe, acentos, símbolos peligrosos.
 *   - Cadena muy larga cifrada/descifrada sin error.
 *
 * Ejecutar:  node demos/03_integridad_caracteres.mjs   (o:  npm run demo:integridad)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 3 · Integridad y caracteres (Web Crypto)');

  step('Preparando claves de Ana y Beto…');
  const ana = await CC.generateRsaKeyPair(2048);
  const beto = await CC.generateRsaKeyPair(2048);
  const anaPub = await CC.importPublicKey(await CC.exportPublicKey(ana.publicKey));
  const anaPriv = await CC.importPrivateKey(await CC.exportPrivateKey(ana.privateKey));
  const betoPub = await CC.importPublicKey(await CC.exportPublicKey(beto.publicKey));
  const betoPriv = await CC.importPrivateKey(await CC.exportPrivateKey(beto.privateKey));

  // --- 1) Anti-manipulación ---
  step('Integridad: el "servidor" altera 1 byte del ciphertext en la BD…');
  const sobre = await CC.encryptMessage('transferir 100 a la cuenta correcta', anaPub, betoPub, anaPriv);
  const ct = CC.base64ToBytes(sobre.ciphertext);
  ct[0] ^= 0x01;
  const alterado = { ...sobre, ciphertext: CC.bytesToBase64(ct) };
  const res = await CC.decryptMessage(alterado, betoPriv, false, anaPub);
  check('mensaje alterado => RECHAZADO (AES-GCM)', res.integrity === false && res.plaintext === null);
  info('motivo', res.error || '(sin error)');

  const ok = await CC.decryptMessage(sobre, betoPriv, false, anaPub);
  check('mensaje intacto => ACEPTADO', ok.integrity === true);

  // --- 2) Caracteres variados (UTF-8) ---
  step('Round-trip de caracteres dificiles:');
  const casos = [
    'áéíóú ñ Ñ ¿¡',
    '你好世界 (chino)',
    'مرحبا بالعالم (arabe)',
    '😀🔐🇵🇪👨‍👩‍👧‍👦 (emojis + ZWJ)',
    '<script>alert("xss")</script> & "comillas" \'simples\' `backticks`',
    'Tab\ty saltos\nde\nlinea',
  ];
  for (const c of casos) {
    const e = await CC.encryptMessage(c, anaPub, betoPub, anaPriv);
    const d = await CC.decryptMessage(e, betoPriv, false, anaPub);
    eq('llega identico: ' + trunc(c, 32), d.plaintext, c);
  }

  // --- 3) Cadena muy larga ---
  step('Cadena larga (50 000 caracteres):');
  const larga = '🔒'.repeat(25000);
  const eL = await CC.encryptMessage(larga, anaPub, betoPub, anaPriv);
  const dL = await CC.decryptMessage(eL, betoPriv, false, anaPub);
  check(`cadena larga round-trip (${larga.length} chars, ${CC.base64ToBytes(eL.ciphertext).length} bytes cifrados)`,
        dL.plaintext === larga);

  return summary('DEMO 3');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
