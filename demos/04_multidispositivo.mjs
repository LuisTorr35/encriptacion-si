/**
 * DEMO 4 — Multi-dispositivo: clave privada envuelta con la contraseña (Web Crypto).
 *
 *   1. DISPOSITIVO 1: Ana genera su par RSA y "envuelve" su clave privada con su contraseña
 *      (PBKDF2-HMAC-SHA256 → AES-256-GCM).
 *   2. El SERVIDOR guarda SOLO ese blob: ni la clave privada ni la contraseña.
 *   3. DISPOSITIVO 2: con el blob + la contraseña, Ana RECUPERA su clave idéntica.
 *   4. Una contraseña incorrecta es RECHAZADA (la autenticación GCM falla).
 *   5. La clave recuperada SIRVE: descifra un mensaje que le mandaron a Ana.
 *
 * Ejecutar:  node demos/04_multidispositivo.mjs   (o:  npm run demo:multidispositivo)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 4 · Multi-dispositivo (envoltura con contraseña, Web Crypto)');

  const PASSWORD = 'mi-contrasena-de-login';

  step('DISPOSITIVO 1 — Ana genera su par RSA-2048 y exporta su clave privada (JWK):');
  const ana = await CC.generateRsaKeyPair(2048);
  const privJson = await CC.exportPrivateKey(ana.privateKey);
  info('clave privada (JWK)', trunc(privJson, 60));

  step('Ana envuelve su clave privada con su contraseña (PBKDF2 150k iter):');
  const t0 = Date.now();
  const blob = await CC.wrapPrivateKey(privJson, PASSWORD);
  info('tiempo de envoltura', `${Date.now() - t0} ms`);

  step('Esto es lo UNICO que se sube al servidor (blob cifrado):');
  info('kdf       ', blob.kdf);
  info('iterations', blob.iterations);
  info('salt      ', blob.salt);
  info('nonce (IV)', blob.nonce);
  info('ciphertext', trunc(blob.ciphertext, 56));
  info('mac (tag) ', blob.mac);

  const blobStr = JSON.stringify(blob);
  check('el blob NO contiene la clave privada en claro',
        !blobStr.includes(privJson) && !blobStr.includes(JSON.parse(privJson).d.slice(0, 32)));
  check('el blob NO contiene la contraseña', !blobStr.includes(PASSWORD));

  step('DISPOSITIVO 2 — Ana inicia sesion en otro navegador. Solo tiene el blob + su contraseña:');
  const t1 = Date.now();
  const recuperada = await CC.unwrapPrivateKey(blob, PASSWORD);
  info('tiempo de recuperacion', `${Date.now() - t1} ms`);
  check('la clave recuperada es IDENTICA a la original', recuperada === privJson);

  step('Si la contraseña es incorrecta, se RECHAZA (no se filtra nada):');
  let rechazada = false; let motivo = '';
  try { await CC.unwrapPrivateKey(blob, 'contrasena-equivocada'); }
  catch (e) { rechazada = true; motivo = e.message; }
  check('contraseña incorrecta => rechazada', rechazada);
  info('motivo', motivo);

  step('Prueba final: la clave recuperada SIRVE para descifrar mensajes de Ana:');
  const beto = await CC.generateRsaKeyPair(2048);
  const betoPub = await CC.importPublicKey(await CC.exportPublicKey(beto.publicKey));
  const betoPriv = await CC.importPrivateKey(await CC.exportPrivateKey(beto.privateKey));
  const anaPub = await CC.importPublicKey(await CC.exportPublicKey(ana.publicKey));
  const M = 'Mensaje para Ana, legible en cualquier dispositivo 📱💻';
  const sobre = await CC.encryptMessage(M, betoPub, anaPub, betoPriv); // Beto -> Ana
  const privRecuperada = await CC.importPrivateKey(recuperada);        // la del "dispositivo 2"
  const leido = await CC.decryptMessage(sobre, privRecuperada, false, betoPub);
  eq('Ana lee el mensaje en el dispositivo 2', leido.plaintext, M);

  return summary('DEMO 4');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
