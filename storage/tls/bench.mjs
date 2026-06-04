// Benchmark de los algoritmos del chat usando la Web Crypto API nativa.
// Mide los mismos parametros que usa el proyecto (RSA-2048, AES-256-GCM,
// PBKDF2 150k, etc.). Node usa OpenSSL; el navegador usa BoringSSL/NSS:
// implementaciones nativas equivalentes, asi que los tiempos son representativos.
const s = globalThis.crypto.subtle;
const enc = new TextEncoder();

function now() { return Number(process.hrtime.bigint()) / 1e6; } // ms

async function bench(label, iters, fn) {
  // calentamiento
  for (let i = 0; i < Math.min(3, iters); i++) await fn();
  const t0 = now();
  for (let i = 0; i < iters; i++) await fn();
  const total = now() - t0;
  const per = total / iters;
  console.log(`${label.padEnd(38)} ${per.toFixed(3).padStart(9)} ms/op   (${iters} ops, ${(1000/per).toFixed(0)} ops/s)`);
  return per;
}

// --- preparar material ---
const kp = await s.generateKey(
  { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
  true, ['encrypt','decrypt']);
const jwk = await s.exportKey('jwk', kp.privateKey);
const pubJwk = await s.exportKey('jwk', kp.publicKey);
delete jwk.key_ops; delete jwk.alg; delete pubJwk.key_ops; delete pubJwk.alg;

const pubOAEP = await s.importKey('jwk', pubJwk, { name:'RSA-OAEP', hash:'SHA-256' }, false, ['encrypt']);
const privOAEP = await s.importKey('jwk', jwk, { name:'RSA-OAEP', hash:'SHA-256' }, false, ['decrypt']);
const privPSS = await s.importKey('jwk', jwk, { name:'RSA-PSS', hash:'SHA-256' }, false, ['sign']);
const pubPSS = await s.importKey('jwk', pubJwk, { name:'RSA-PSS', hash:'SHA-256' }, false, ['verify']);

const kRaw = crypto.getRandomValues(new Uint8Array(32));
const aesKey = await s.importKey('raw', kRaw, { name:'AES-GCM' }, false, ['encrypt','decrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12));
const msg = enc.encode('Hola, este es un mensaje de chat de prueba tipico para medir AES-GCM 🔐');
const ctTag = await s.encrypt({ name:'AES-GCM', iv }, aesKey, msg);
const encK = await s.encrypt({ name:'RSA-OAEP' }, pubOAEP, kRaw);
const sig = await s.sign({ name:'RSA-PSS', saltLength:32 }, privPSS, new Uint8Array(ctTag));
const pwBase = await s.importKey('raw', enc.encode('password'), { name:'PBKDF2' }, false, ['deriveKey']);
const salt = crypto.getRandomValues(new Uint8Array(16));

console.log('\n=== Benchmark Web Crypto (nativo) — mismos parametros del proyecto ===\n');

await bench('RSA-2048 generar par de claves', 20, async () =>
  s.generateKey({ name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['encrypt','decrypt']));

await bench('AES-256-GCM cifrar mensaje', 20000, async () =>
  s.encrypt({ name:'AES-GCM', iv }, aesKey, msg));

await bench('AES-256-GCM descifrar mensaje', 20000, async () =>
  s.decrypt({ name:'AES-GCM', iv }, aesKey, ctTag));

await bench('RSA-OAEP encapsular K (cifrar)', 2000, async () =>
  s.encrypt({ name:'RSA-OAEP' }, pubOAEP, kRaw));

await bench('RSA-OAEP abrir K (descifrar)', 2000, async () =>
  s.decrypt({ name:'RSA-OAEP' }, privOAEP, encK));

await bench('RSA-PSS firmar', 2000, async () =>
  s.sign({ name:'RSA-PSS', saltLength:32 }, privPSS, new Uint8Array(ctTag)));

await bench('RSA-PSS verificar', 5000, async () =>
  s.verify({ name:'RSA-PSS', saltLength:32 }, pubPSS, sig, new Uint8Array(ctTag)));

await bench('PBKDF2-HMAC-SHA256 (150k iter)', 30, async () =>
  s.deriveKey({ name:'PBKDF2', salt, iterations:150000, hash:'SHA-256' }, pwBase, { name:'AES-GCM', length:256 }, false, ['encrypt']));

console.log('\n--- Costo total de ENVIAR un mensaje (AES + 2x RSA-OAEP + RSA-PSS) ---');
const t0 = now();
const N = 1000;
for (let i = 0; i < N; i++) {
  await s.encrypt({ name:'AES-GCM', iv }, aesKey, msg);
  await s.encrypt({ name:'RSA-OAEP' }, pubOAEP, kRaw);
  await s.encrypt({ name:'RSA-OAEP' }, pubOAEP, kRaw);
  await s.sign({ name:'RSA-PSS', saltLength:32 }, privPSS, new Uint8Array(ctTag));
}
console.log(`Enviar 1 mensaje completo: ${((now()-t0)/N).toFixed(3)} ms\n`);
