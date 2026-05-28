import CC from './resources/js/crypto/cripto-core.js';
const hex = (u) => [...u].map(b => b.toString(16).padStart(2, '0')).join('');
const enc = (s) => new TextEncoder().encode(s);
let fails = 0;
const ck = (n, g, w) => { const ok = g === w; if (!ok) fails++; console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${ok ? '' : `\n  got=${g}\n want=${w}`}`); };

// Vectores conocidos PBKDF2-HMAC-SHA256
ck('c=1',    hex(CC.pbkdf2Sha256(enc('password'), enc('salt'), 1, 32)),    '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
ck('c=2',    hex(CC.pbkdf2Sha256(enc('password'), enc('salt'), 2, 32)),    'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');
ck('c=4096', hex(CC.pbkdf2Sha256(enc('password'), enc('salt'), 4096, 32)), 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
ck('long',   hex(CC.pbkdf2Sha256(enc('passwordPASSWORDpassword'), enc('saltSALTsaltSALTsaltSALTsaltSALTsalt'), 4096, 40)),
             '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9');

// wrap/unwrap round-trip
const kp = CC.generateRsaKeyPair(2048);
const privJson = CC.exportPrivateKey(kp.privateKey);
const t0 = Date.now();
const blob = CC.wrapPrivateKey(privJson, 'mi-contrasena-secreta');
const wrapMs = Date.now() - t0;
const t1 = Date.now();
const back = CC.unwrapPrivateKey(blob, 'mi-contrasena-secreta');
const unwrapMs = Date.now() - t1;
ck('wrap/unwrap round-trip', back === privJson, true);

// contrasena incorrecta debe fallar
let rejected = false;
try { CC.unwrapPrivateKey(blob, 'contrasena-mala'); } catch (_) { rejected = true; }
ck('contrasena incorrecta rechazada', rejected, true);

console.log(`\nTiempo wrap=${wrapMs}ms  unwrap=${unwrapMs}ms  (iteraciones=${blob.iterations})`);
console.log(fails === 0 ? '\n✅ PBKDF2 OK' : `\n❌ ${fails} fallo(s)`);
process.exit(fails ? 1 : 0);
