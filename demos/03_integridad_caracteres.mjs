/**
 * DEMO 3 — Integridad (anti-manipulacion) y soporte universal de caracteres.
 *
 * Cubre las pruebas de la seccion 12 del plan:
 *   - Alterar 1 bit del ciphertext => el receptor RECHAZA (HMAC, Encrypt-then-MAC).
 *   - Round-trip de caracteres: emojis, chino, arabe, acentos, simbolos peligrosos.
 *   - Cadena muy larga (100 000 caracteres) cifrada/descifrada sin error.
 *
 * Ejecutar:  node demos/03_integridad_caracteres.mjs   (o:  npm run demo:integridad)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 3 · Integridad y caracteres');

  step('Preparando claves de Ana y Beto…');
  const ana = CC.generateRsaKeyPair(2048);
  const beto = CC.generateRsaKeyPair(2048);

  // --- 1) Anti-manipulacion ---
  step('Integridad: el "servidor" altera 1 byte del ciphertext en la BD…');
  const sobre = CC.encryptMessage('transferir 100 a la cuenta correcta', ana.publicKey, beto.publicKey, ana.privateKey);
  const ctBytes = CC.base64ToBytes(sobre.ciphertext);
  ctBytes[0] ^= 0x01; // flip de 1 bit
  const sobreAlterado = { ...sobre, ciphertext: CC.bytesToBase64(ctBytes) };
  const res = CC.decryptMessage(sobreAlterado, beto.privateKey, false, ana.publicKey);
  check('mensaje alterado => RECHAZADO (HMAC no coincide)', res.integrity === false && res.plaintext === null);
  info('motivo', res.error || '(sin error)');

  const sobreOk = CC.decryptMessage(sobre, beto.privateKey, false, ana.publicKey);
  check('mensaje intacto => ACEPTADO', sobreOk.integrity === true);

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
    const e = CC.encryptMessage(c, ana.publicKey, beto.publicKey, ana.privateKey);
    const d = CC.decryptMessage(e, beto.privateKey, false, ana.publicKey);
    eq('llega identico: ' + trunc(c, 32), d.plaintext, c);
  }

  // --- 3) Cadena muy larga ---
  step('Cadena larga (100 000 caracteres):');
  const larga = '🔒'.repeat(25000); // cada emoji = varios bytes UTF-8
  const eL = CC.encryptMessage(larga, ana.publicKey, beto.publicKey, ana.privateKey);
  const dL = CC.decryptMessage(eL, beto.privateKey, false, ana.publicKey);
  check(`cadena larga round-trip (${larga.length} chars, ${CC.base64ToBytes(eL.ciphertext).length} bytes cifrados)`,
        dL.plaintext === larga);

  return summary('DEMO 3');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
