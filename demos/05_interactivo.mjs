/**
 * DEMO 5 — INTERACTIVA: escribe TU propio texto y mira cómo se cifra y descifra.
 *
 *   1. Genera los pares RSA-2048 de Ana (emisora) y Beto (receptor).
 *   2. Te pide un mensaje y, por cada uno: Ana cifra → Beto descifra → Ana relee.
 *   3. El esquema completo (qué clave se usa y por qué) se explica UNA vez al inicio.
 *
 * Ejecutar:  node demos/05_interactivo.mjs   (o:  npm run demo:interactivo)
 */

import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import CC from '../resources/js/crypto/cripto-core.js';
import { banner, step, info, check, eq, trunc, isMain } from './_util.mjs';

const utf8Len = (s) => new TextEncoder().encode(s).length;

/** "Huella" corta de un par RSA (los últimos 4 chars del módulo `n`). Pública y
 *  privada del mismo par comparten huella. */
function huella(jwkStr) {
  const n = JSON.parse(jwkStr).n;
  return '#' + n.replace(/[^a-zA-Z0-9]/g, '').slice(-4).toLowerCase();
}

export async function demo() {
  banner('DEMO 5 · Interactiva — cifra tu propio texto (Web Crypto)');

  // --- Preparación (una sola vez) ---
  const ana = await CC.generateRsaKeyPair(2048);
  const beto = await CC.generateRsaKeyPair(2048);
  const anaPubJson = await CC.exportPublicKey(ana.publicKey);
  const betoPubJson = await CC.exportPublicKey(beto.publicKey);
  const anaPub = await CC.importPublicKey(anaPubJson);
  const anaPriv = await CC.importPrivateKey(await CC.exportPrivateKey(ana.privateKey));
  const betoPub = await CC.importPublicKey(betoPubJson);
  const betoPriv = await CC.importPrivateKey(await CC.exportPrivateKey(beto.privateKey));
  const fAna = huella(anaPubJson);
  const fBeto = huella(betoPubJson);

  // --- Explicación del esquema (una sola vez) ---
  step(`Claves: Ana ${fAna} (emisora) y Beto ${fBeto} (receptor). Cada par RSA tiene una huella;`);
  info('', 'su pública y su privada la comparten. Lo que cifra una pública solo lo abre su privada.');
  info('Cifrar (Ana) ', `AES-256-GCM con clave K nueva → ciphertext; K se envuelve con RSA-OAEP para ambos; firma RSA-PSS.`);
  info('Descifrar    ', `cada uno abre SU copia de K con su privada (Beto: encKeyRecipient, Ana: encKeySender).`);

  const rl = readline.createInterface({ input, output });
  console.log('\n(Escribe un mensaje y pulsa Enter. Enter vacío o "salir" para terminar.)');

  let n = 0;
  while (true) {
    let texto;
    try {
      texto = await rl.question('\n📝 Tu mensaje > ');
    } catch {
      break;
    }
    if (!texto.trim() || texto.trim().toLowerCase() === 'salir') break;
    n++;

    banner(`Mensaje #${n}`);
    info('texto plano', `${texto}   (${[...texto].length} chars · ${utf8Len(texto)} bytes)`);

    // CIFRAR (Ana)
    const sobre = await CC.encryptMessage(texto, anaPub, betoPub, anaPriv);
    step('Cifrado → sobre (lo único que viaja al servidor, en Base64):');
    info('ciphertext', `${trunc(sobre.ciphertext, 48)}  ·  mac ${sobre.mac.slice(0, 12)}…  ·  nonce ${sobre.nonce.slice(0, 12)}…`);
    check('el sobre NO contiene tu texto en claro', !JSON.stringify(sobre).includes(texto));

    // DESCIFRAR (Beto, receptor)
    const recv = await CC.decryptMessage(sobre, betoPriv, false, anaPub);
    step('Descifrado por Beto (receptor):');
    info('texto recuperado', recv.plaintext);
    eq('Beto recupera tu mensaje exacto', recv.plaintext, texto);
    check('integridad (AES-GCM) y firma de Ana (RSA-PSS) OK', recv.integrity === true && recv.verified === true);

    // Ana relee su copia
    const recvAna = await CC.decryptMessage(sobre, anaPriv, true, anaPub);
    check('Ana relee su propia copia (encKeySender + su privada)', recvAna.plaintext === texto);
  }

  rl.close();
  console.log('\n👋 Listo. Cifraste ' + n + ' mensaje(s).\n');
  return 0;
}

if (await isMain(import.meta.url)) process.exit((await demo()) ? 1 : 0);
