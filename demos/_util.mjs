/**
 * Utilidades compartidas para las demos de consola.
 * Sin dependencias externas: solo Node (>= 18) y el nucleo criptografico propio.
 */

export const enc = new TextEncoder();
export const dec = new TextDecoder();

export const bytesOf = (s) => enc.encode(s);
export const hex = (u) => [...u].map((b) => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (s) => new Uint8Array(s.match(/.{1,2}/g).map((b) => parseInt(b, 16)));

let _fails = 0;

export function resetFails() { _fails = 0; }
export function fails() { return _fails; }

/** Marca una comprobacion booleana. */
export function check(name, ok, detail = '') {
  if (ok) {
    console.log(`  ✓ ${name}`);
  } else {
    _fails++;
    console.log(`  ✗ ${name}${detail ? '\n      ' + detail : ''}`);
  }
  return ok;
}

/** Comprueba igualdad estricta y muestra ambos valores si falla. */
export function eq(name, got, want) {
  return check(name, got === want, `obtenido = ${got}\n      esperado = ${want}`);
}

/** Encabezado de seccion. */
export function banner(title) {
  const line = '='.repeat(Math.max(8, title.length + 6));
  console.log('\n' + line);
  console.log('  ' + title);
  console.log(line);
}

export function step(text) {
  console.log('\n• ' + text);
}

export function info(label, value) {
  console.log(`    ${label}: ${value}`);
}

/** Recorta un texto largo para mostrarlo en consola. */
export function trunc(s, n = 64) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + `… (${s.length} chars)` : s;
}

/** Resumen final de la demo. */
export function summary(label) {
  if (_fails === 0) {
    console.log(`\n✅ ${label}: TODO OK\n`);
  } else {
    console.log(`\n❌ ${label}: ${_fails} fallo(s)\n`);
  }
  return _fails;
}

/** Devuelve true si este modulo se ejecuto directamente (no importado). */
export async function isMain(metaUrl) {
  if (!process.argv[1]) return false;
  const { pathToFileURL } = await import('node:url');
  return metaUrl === pathToFileURL(process.argv[1]).href;
}
