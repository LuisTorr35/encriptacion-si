# Demos de consola — Cifrado E2E (KEM/DEM)

Programas en **Node.js** (sin navegador) que demuestran, paso a paso, todo el
funcionamiento del núcleo criptográfico (`resources/js/crypto/cripto-core.js`),
incluido el **multi-dispositivo**. Útiles para presentar/defender el proyecto.

> Requisito: **Node.js ≥ 18** (usa la Web Crypto global para los bytes aleatorios).
> No necesitan ni base de datos ni el servidor Laravel.

## Cómo ejecutar

```bash
npm run demo                    # ejecuta las 4 demos en orden + resumen global

# o una por una:
npm run demo:primitivas         # 1) primitivas vs. vectores oficiales
npm run demo:mensaje            # 2) mensaje E2E entre Ana y Beto
npm run demo:integridad         # 3) anti-manipulación + caracteres + cadena larga
npm run demo:multidispositivo   # 4) recuperar la clave con la contraseña

# equivalente sin npm:
node demos/01_primitivas.mjs
```

Cada demo termina con `✅ ... TODO OK` o `❌ ... N fallo(s)` y un código de salida
distinto de cero si algo falla (sirve para CI).

## Qué demuestra cada una

| Demo | Archivo | Qué prueba |
|---|---|---|
| 1 | `01_primitivas.mjs` | SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231), HKDF (RFC 5869), AES-256-CTR (NIST SP 800-38A), PBKDF2 (RFC 7914) — todo contra los **vectores oficiales**. |
| 2 | `02_mensaje_e2e.mjs` | Flujo completo KEM/DEM: Ana cifra para `{Ana, Beto}`, firma (RSA-PSS); el sobre es ilegible; Beto y Ana descifran su copia; un tercero no puede. |
| 3 | `03_integridad_caracteres.mjs` | Alterar 1 bit del ciphertext ⇒ se rechaza (HMAC, Encrypt-then-MAC); round-trip de emojis/chino/árabe/símbolos; cadena de 100 000 caracteres. |
| 4 | `04_multidispositivo.mjs` | La clave privada se envuelve con la contraseña (PBKDF2→AES+HMAC); el servidor solo ve el blob; otro dispositivo la recupera idéntica; contraseña incorrecta rechazada; la clave recuperada **sí descifra**. |

## Relación con la app real

Estas demos llaman a **las mismas funciones** que usa el navegador en
`resources/js/chat.js`:

- `encryptMessage` / `decryptMessage` → enviar/recibir mensajes.
- `wrapPrivateKey` / `unwrapPrivateKey` → guardar/recuperar la clave entre dispositivos.

Es decir, lo que ves pasar en consola es exactamente lo que ocurre en producción
(la diferencia es que el navegador, además, habla con la API de Laravel).
