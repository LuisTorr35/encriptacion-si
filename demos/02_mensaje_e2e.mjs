/**
 * DEMO 2 — Mensaje con cifrado de extremo a extremo (KEM/DEM con Web Crypto).
 *
 *   1. Ana y Beto generan su par RSA-2048 (Web Crypto).
 *   2. Ana cifra el mensaje con AES-256-GCM y encapsula la clave de sesión para AMBOS
 *      (RSA-OAEP), además de firmar el sobre (RSA-PSS).
 *   3. El "servidor" solo ve el sobre en Base64 (ilegible).
 *   4. Beto (receptor) y Ana (emisora) descifran su copia y verifican la firma.
 *
 * Ejecutar:  node demos/02_mensaje_e2e.mjs   (o:  npm run demo:mensaje)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 2 · Mensaje E2E entre Ana y Beto (Web Crypto)');

  step('Generando pares de claves RSA-2048 (Web Crypto, igual que en el navegador)…');
  const t0 = Date.now();
  const ana = await CC.generateRsaKeyPair(2048);
  const beto = await CC.generateRsaKeyPair(2048);
  info('tiempo de generacion', `${Date.now() - t0} ms (2 claves)`);

  // Se serializan a JWK y se reimportan (como hace la app)
  const anaPub = await CC.importPublicKey(await CC.exportPublicKey(ana.publicKey));
  const anaPriv = await CC.importPrivateKey(await CC.exportPrivateKey(ana.privateKey));
  const betoPub = await CC.importPublicKey(await CC.exportPublicKey(beto.publicKey));
  const betoPriv = await CC.importPrivateKey(await CC.exportPrivateKey(beto.privateKey));

  const M = 'Hola Beto 👋 esto es secreto: la reunion es a las 3pm 🔐';
  step('Ana cifra para {Ana, Beto} y firma (RSA-PSS):');
  info('texto plano', M);
  const sobre = await CC.encryptMessage(M, anaPub, betoPub, anaPriv);

  step('Sobre cifrado (lo UNICO que ve el servidor / MySQL):');
  info('v', sobre.v);
  info('encKeySender   ', trunc(sobre.encKeySender, 56));
  info('encKeyRecipient', trunc(sobre.encKeyRecipient, 56));
  info('ciphertext     ', trunc(sobre.ciphertext, 56));
  info('mac (tag GCM)  ', sobre.mac);
  info('nonce (IV)     ', sobre.nonce);
  info('signature      ', trunc(sobre.signature, 56));

  check('el sobre NO contiene el texto plano',
        !JSON.stringify(sobre).includes('reunion') && !JSON.stringify(sobre).includes('Hola Beto'));

  step('Beto (receptor) descifra con SU clave privada y verifica la firma de Ana:');
  const recvBeto = await CC.decryptMessage(sobre, betoPriv, false, anaPub);
  info('texto recuperado', recvBeto.plaintext);
  eq('Beto recupera el mensaje original', recvBeto.plaintext, M);
  check('Beto: integridad (AES-GCM) OK', recvBeto.integrity === true);
  check('Beto: firma de Ana verificada (RSA-PSS)', recvBeto.verified === true);

  step('Ana (emisora) relee su propia copia del historial:');
  const recvAna = await CC.decryptMessage(sobre, anaPriv, true, anaPub);
  eq('Ana relee el mismo mensaje', recvAna.plaintext, M);

  step('Un tercero (clave distinta) NO puede descifrar:');
  const mallory = await CC.generateRsaKeyPair(2048);
  const malloryPriv = await CC.importPrivateKey(await CC.exportPrivateKey(mallory.privateKey));
  const intruso = await CC.decryptMessage(sobre, malloryPriv, false, anaPub);
  check('intruso rechazado (no desencapsula K)', intruso.plaintext === null && intruso.integrity === false);

  return summary('DEMO 2');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
