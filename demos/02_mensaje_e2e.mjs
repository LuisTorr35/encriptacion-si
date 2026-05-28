/**
 * DEMO 2 — Mensaje con cifrado de extremo a extremo (KEM/DEM multi-destinatario).
 *
 * Reproduce, en consola, exactamente lo que hace el navegador:
 *   1. Ana y Beto generan su par RSA-2048.
 *   2. Ana cifra un mensaje UNA vez y encapsula la clave de sesion K para AMBOS
 *      (patron PGP), ademas de firmar el sobre (RSA-PSS).
 *   3. El "servidor" solo ve el sobre en Base64 (ilegible).
 *   4. Beto (receptor) y Ana (emisora) descifran su propia copia y verifican la firma.
 *
 * Ejecutar:  node demos/02_mensaje_e2e.mjs   (o:  npm run demo:mensaje)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 2 · Mensaje E2E entre Ana y Beto');

  step('Generando pares de claves RSA-2048 (en el navegador real ocurre igual)…');
  const t0 = Date.now();
  const ana = CC.generateRsaKeyPair(2048);
  const beto = CC.generateRsaKeyPair(2048);
  info('tiempo de generacion', `${Date.now() - t0} ms (2 claves)`);

  // En la app, las claves se serializan (JSON hex) para guardarlas/transportarlas.
  const anaPub = CC.importPublicKey(CC.exportPublicKey(ana.publicKey));
  const betoPub = CC.importPublicKey(CC.exportPublicKey(beto.publicKey));

  const M = 'Hola Beto 👋 esto es secreto: la reunion es a las 3pm 🔐';
  step('Ana cifra el mensaje para {Ana, Beto} y lo firma (RSA-PSS):');
  info('texto plano', M);
  const sobre = CC.encryptMessage(M, anaPub, betoPub, ana.privateKey);

  step('Sobre cifrado (esto es lo UNICO que ve el servidor / MySQL):');
  info('v', sobre.v);
  info('encKeySender   ', trunc(sobre.encKeySender, 56));
  info('encKeyRecipient', trunc(sobre.encKeyRecipient, 56));
  info('ciphertext     ', trunc(sobre.ciphertext, 56));
  info('mac            ', sobre.mac);
  info('nonce          ', sobre.nonce);
  info('signature      ', trunc(sobre.signature, 56));

  check('el sobre NO contiene el texto plano',
        !JSON.stringify(sobre).includes('reunion') && !JSON.stringify(sobre).includes('Hola Beto'));

  step('Beto (receptor) descifra con SU clave privada y verifica la firma de Ana:');
  const recvBeto = CC.decryptMessage(sobre, beto.privateKey, false, anaPub);
  info('texto recuperado', recvBeto.plaintext);
  eq('Beto recupera el mensaje original', recvBeto.plaintext, M);
  check('Beto: integridad (HMAC) OK', recvBeto.integrity === true);
  check('Beto: firma de Ana verificada (RSA-PSS)', recvBeto.verified === true);

  step('Ana (emisora) relee su propia copia del historial:');
  const recvAna = CC.decryptMessage(sobre, ana.privateKey, true, anaPub);
  eq('Ana relee el mismo mensaje', recvAna.plaintext, M);
  check('Ana: integridad (HMAC) OK', recvAna.integrity === true);

  step('Un tercero (clave distinta) NO puede descifrar:');
  const mallory = CC.generateRsaKeyPair(2048);
  const intruso = CC.decryptMessage(sobre, mallory.privateKey, false, anaPub);
  check('intruso rechazado (no desencapsula K)', intruso.plaintext === null && intruso.integrity === false);

  return summary('DEMO 2');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
