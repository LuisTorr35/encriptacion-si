// ── BENCHMARK DE CIFRADO (pegar en la consola del navegador, F12) ──
// Mide los tiempos de cada algoritmo del chat con la Web Crypto nativa.
(async () => {
  const s = crypto.subtle, enc = new TextEncoder();
  const t = () => performance.now();
  const row = (l, p, n) => console.log(
    `${l.padEnd(36)} ${p.toFixed(3).padStart(9)} ms/op  (${(1000/p).toFixed(0)} ops/s)`);
  async function bench(l, iters, fn) {
    for (let i = 0; i < 3; i++) await fn();
    const t0 = t(); for (let i = 0; i < iters; i++) await fn();
    row(l, (t() - t0) / iters, iters);
  }

  // preparar material
  const kp = await s.generateKey({ name:'RSA-OAEP', modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['encrypt','decrypt']);
  const jwk = await s.exportKey('jwk', kp.privateKey);
  const pj  = await s.exportKey('jwk', kp.publicKey);
  for (const k of [jwk, pj]) { delete k.key_ops; delete k.alg; }
  const pubO  = await s.importKey('jwk', pj,  { name:'RSA-OAEP', hash:'SHA-256' }, false, ['encrypt']);
  const privO = await s.importKey('jwk', jwk, { name:'RSA-OAEP', hash:'SHA-256' }, false, ['decrypt']);
  const privP = await s.importKey('jwk', jwk, { name:'RSA-PSS',  hash:'SHA-256' }, false, ['sign']);
  const pubP  = await s.importKey('jwk', pj,  { name:'RSA-PSS',  hash:'SHA-256' }, false, ['verify']);
  const kRaw  = crypto.getRandomValues(new Uint8Array(32));
  const aes   = await s.importKey('raw', kRaw, { name:'AES-GCM' }, false, ['encrypt','decrypt']);
  const iv    = crypto.getRandomValues(new Uint8Array(12));
  const msg   = enc.encode('Mensaje de chat tipico para medir AES-GCM 🔐');
  const ct    = await s.encrypt({ name:'AES-GCM', iv }, aes, msg);
  const eK    = await s.encrypt({ name:'RSA-OAEP' }, pubO, kRaw);
  const sig   = await s.sign({ name:'RSA-PSS', saltLength:32 }, privP, new Uint8Array(ct));
  const pw    = await s.importKey('raw', enc.encode('password'), { name:'PBKDF2' }, false, ['deriveKey']);
  const salt  = crypto.getRandomValues(new Uint8Array(16));

  console.log('%c=== Tiempos de cifrado (Web Crypto nativa del navegador) ===', 'font-weight:bold');
  await bench('RSA-2048 generar par',        20,    () => s.generateKey({ name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['encrypt','decrypt']));
  await bench('AES-256-GCM cifrar',          20000, () => s.encrypt({ name:'AES-GCM', iv }, aes, msg));
  await bench('AES-256-GCM descifrar',       20000, () => s.decrypt({ name:'AES-GCM', iv }, aes, ct));
  await bench('RSA-OAEP cifrar K',           2000,  () => s.encrypt({ name:'RSA-OAEP' }, pubO, kRaw));
  await bench('RSA-OAEP descifrar K',        2000,  () => s.decrypt({ name:'RSA-OAEP' }, privO, eK));
  await bench('RSA-PSS firmar',              2000,  () => s.sign({ name:'RSA-PSS', saltLength:32 }, privP, new Uint8Array(ct)));
  await bench('RSA-PSS verificar',           5000,  () => s.verify({ name:'RSA-PSS', saltLength:32 }, pubP, sig, new Uint8Array(ct)));
  await bench('PBKDF2-HMAC-SHA256 (150k)',   30,    () => s.deriveKey({ name:'PBKDF2', salt, iterations:150000, hash:'SHA-256' }, pw, { name:'AES-GCM', length:256 }, false, ['encrypt']));
  console.log('%c✓ Benchmark completado', 'color:green;font-weight:bold');
})();
