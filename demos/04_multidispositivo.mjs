/**
 * DEMO 4 — Multi-dispositivo: clave privada envuelta con la contrasena.
 *
 * Demuestra la funcionalidad nueva (rama `multi-dispositivo`):
 *   1. DISPOSITIVO 1: Ana genera su par RSA y "envuelve" su clave privada con su
 *      contrasena -> blob (PBKDF2-HMAC-SHA256 -> AES-256-CTR + HMAC).
 *   2. El SERVIDOR guarda SOLO ese blob: ni la clave privada ni la contrasena.
 *   3. DISPOSITIVO 2: con el blob + la contrasena, Ana RECUPERA su clave identica.
 *   4. Una contrasena incorrecta es RECHAZADA (HMAC).
 *   5. La clave recuperada SIRVE: descifra un mensaje que le mandaron a Ana.
 *
 * Ejecutar:  node demos/04_multidispositivo.mjs   (o:  npm run demo:multidispositivo)
 */

import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, summary, resetFails, isMain } from './_util.mjs';

export async function demo() {
  resetFails();
  banner('DEMO 4 · Multi-dispositivo (envoltura con contrasena)');

  const PASSWORD = 'mi-contrasena-de-login';

  step('DISPOSITIVO 1 — Ana genera su par RSA-2048 y exporta su clave privada:');
  const ana = CC.generateRsaKeyPair(2048);
  const privJson = CC.exportPrivateKey(ana.privateKey);
  info('clave privada (JSON)', trunc(privJson, 60));

  step('Ana envuelve su clave privada con su contrasena (PBKDF2 150k iter):');
  const t0 = Date.now();
  const blob = CC.wrapPrivateKey(privJson, PASSWORD);
  info('tiempo de envoltura', `${Date.now() - t0} ms`);

  step('Esto es lo UNICO que se sube al servidor (blob cifrado):');
  info('kdf       ', blob.kdf);
  info('iterations', blob.iterations);
  info('salt      ', blob.salt);
  info('nonce     ', blob.nonce);
  info('ciphertext', trunc(blob.ciphertext, 56));
  info('mac       ', blob.mac);

  const blobStr = JSON.stringify(blob);
  check('el blob NO contiene la clave privada en claro',
        !blobStr.includes(privJson) && !blobStr.includes(JSON.parse(privJson).d.slice(0, 32)));
  check('el blob NO contiene la contrasena', !blobStr.includes(PASSWORD));

  step('DISPOSITIVO 2 — Ana inicia sesion en otro navegador. Solo tiene el blob + su contrasena:');
  const t1 = Date.now();
  const recuperada = CC.unwrapPrivateKey(blob, PASSWORD);
  info('tiempo de recuperacion', `${Date.now() - t1} ms`);
  check('la clave recuperada es IDENTICA a la original', recuperada === privJson);

  step('Si la contrasena es incorrecta, se RECHAZA (no se filtra nada):');
  let rechazada = false;
  let motivo = '';
  try { CC.unwrapPrivateKey(blob, 'contrasena-equivocada'); }
  catch (e) { rechazada = true; motivo = e.message; }
  check('contrasena incorrecta => rechazada', rechazada);
  info('motivo', motivo);

  step('Prueba final: la clave recuperada SIRVE para descifrar mensajes de Ana:');
  const beto = CC.generateRsaKeyPair(2048);
  const M = 'Mensaje para Ana, legible en cualquier dispositivo 📱💻';
  const sobre = CC.encryptMessage(M, beto.publicKey, ana.publicKey, beto.privateKey); // Beto -> Ana
  const privRecuperada = CC.importPrivateKey(recuperada); // la del "dispositivo 2"
  const leido = CC.decryptMessage(sobre, privRecuperada, false, beto.publicKey);      // Ana = receptora
  eq('Ana lee el mensaje en el dispositivo 2', leido.plaintext, M);

  return summary('DEMO 4');
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
