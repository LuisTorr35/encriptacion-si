/**
 * Ejecuta TODAS las demos de consola en orden y muestra un resumen global.
 *
 * Ejecutar:  node demos/run_todo.mjs   (o:  npm run demo)
 */

import { demo as d1 } from './01_primitivas.mjs';
import { demo as d2 } from './02_mensaje_e2e.mjs';
import { demo as d3 } from './03_integridad_caracteres.mjs';
import { demo as d4 } from './04_multidispositivo.mjs';

const demos = [
  ['1 · Primitivas vs. vectores oficiales', d1],
  ['2 · Mensaje E2E (KEM/DEM)', d2],
  ['3 · Integridad y caracteres', d3],
  ['4 · Multi-dispositivo', d4],
];

let totalFails = 0;
for (const [nombre, fn] of demos) {
  totalFails += await fn();
}

console.log('\n' + '#'.repeat(50));
if (totalFails === 0) {
  console.log('  ✅ TODAS LAS DEMOS PASARON');
} else {
  console.log(`  ❌ HUBO ${totalFails} FALLO(S) EN TOTAL`);
}
console.log('#'.repeat(50) + '\n');

process.exit(totalFails ? 1 : 0);
