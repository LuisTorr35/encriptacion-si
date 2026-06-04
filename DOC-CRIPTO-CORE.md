# Documentación de `cripto-core.js`

Referencia técnica del módulo **`resources/js/crypto/cripto-core.js`**: el motor
criptográfico E2E del chat. Documenta cada función (firma, parámetros, retorno, qué hace
y línea), las constantes y las decisiones de diseño.

> Para el flujo completo y cómo lo usa la interfaz, ver `MAPEO-CIFRADO.md`.

---

## Índice

1. [Propósito y dependencias](#1-propósito-y-dependencias)
2. [Constantes / parámetros](#2-constantes--parámetros)
3. [Utilidades internas (bytes y codificación)](#3-utilidades-internas-bytes-y-codificación)
4. [API de claves RSA](#4-api-de-claves-rsa)
5. [API de cifrado de mensajes](#5-api-de-cifrado-de-mensajes)
6. [API de envoltura de la clave privada](#6-api-de-envoltura-de-la-clave-privada)
7. [Auto-prueba](#7-auto-prueba)
8. [Exportaciones](#8-exportaciones)
9. [Glosario](#9-glosario)

---

## 1. Propósito y dependencias

**Qué es:** una biblioteca sin estado (*stateless*) que envuelve la **Web Crypto API**
nativa del navegador/Node y expone funciones de alto nivel para cifrado de extremo a
extremo. No guarda nada por su cuenta: recibe datos, opera y devuelve; quien decide dónde
persistir (localStorage, servidor) es `chat.js`.

**Esquema:** híbrido **KEM/DEM** (estilo PGP, multi-destinatario).
- KEM (asimétrico): **RSA-OAEP** SHA-256, 2048 bits → envuelve la clave de sesión.
- DEM (simétrico): **AES-256-GCM** (AEAD) → cifra el mensaje con integridad.
- Firma (asimétrico): **RSA-PSS** SHA-256, salt 32 → origen del mensaje (opcional).
- KDF: **PBKDF2-HMAC-SHA256**, 150.000 iteraciones → protege la privada con contraseña.

**Única dependencia del entorno** (`cripto-core.js:19`): `globalThis.crypto`
(Web Crypto) y `TextEncoder`/`TextDecoder`. Funciona igual en navegador y en Node.

**Característica transversal:** todas las operaciones criptográficas son **asíncronas**
(devuelven `Promise`), porque la Web Crypto API (`crypto.subtle`) es asíncrona.

---

## 2. Constantes / parámetros

Definidas en `cripto-core.js:108-115`:

| Constante | Valor | Línea | Significado |
|-----------|-------|-------|-------------|
| `RSA_BITS` | `2048` | `112` | tamaño del módulo RSA |
| `PBKDF2_ITERATIONS` | `150000` | `113` | iteraciones de PBKDF2 (coste anti-fuerza bruta) |
| `GCM_TAG_BYTES` | `16` | `114` | tamaño del tag de autenticación GCM (128 bits) |
| `GCM_IV_BYTES` | `12` | `115` | tamaño del IV/nonce recomendado para GCM |

---

## 3. Utilidades internas (bytes y codificación)

No son criptografía; son apoyo. Definidas en `cripto-core.js:22-106`.

### `_crypto()` / `_subtle()` — `29-36`
Obtienen el objeto `crypto` y `crypto.subtle`. Lanzan un `Error` claro si el entorno no
soporta Web Crypto. Toda función cripto pasa por aquí.

### `randomBytes(n)` — `38-42`
- **Parámetros:** `n` (número de bytes).
- **Retorna:** `Uint8Array` de `n` bytes aleatorios **criptográficamente seguros**
  (`crypto.getRandomValues`).
- **Uso:** generar la clave de sesión `K`, IVs y salts. Es la base de la
  [aleatorización / cifrado probabilístico](MAPEO-CIFRADO.md).

### `utf8Encode(str)` / `utf8Decode(bytes)` — `44-47`
Conversión texto ⇄ bytes UTF-8. El decoder es **no estricto** (`fatal: false`) para no
romper si llegan bytes inválidos.

### `concatBytes(...arrays)` — `49-56`
Concatena varios `Uint8Array`. Se usa para construir lo que se firma/verifica:
`iv ‖ ciphertext ‖ tag`.

### `bytesEqual(a, b)` — `58-63`
Comparación de bytes en **tiempo (casi) constante** (acumula diferencias con XOR en vez
de cortar al primer byte distinto), para no filtrar información por temporización.

### `bytesToBase64(bytes)` / `base64ToBytes(str)` — `75` / `93`
Implementación propia de Base64 (sin dependencias) para serializar bytes en JSON.
`base64ToBytes` limpia espacios/saltos y lanza `Error` ante un carácter inválido.

---

## 4. API de claves RSA

### `_cleanJwk(jwk)` — `119-122` *(interna)*
Quita del JWK los campos `alg`, `key_ops`, `use`, `ext`. Esto **desata** la clave de un
único algoritmo, permitiendo reimportar el mismo material como **RSA-OAEP** (cifrar) y
como **RSA-PSS** (firmar). Conserva `kty, n, e, d, p, q, dp, dq, qi`.

---

### `generateRsaKeyPair(bits = 2048)` — `129-136`
Genera un par de claves RSA (asimétrico).
- **Parámetros:** `bits` (por defecto `RSA_BITS = 2048`).
- **Retorna:** `Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }>`.
- **Detalles:** algoritmo `RSA-OAEP`, exponente público `65537` (`0x010001`), hash
  `SHA-256`, `extractable: true` (para poder exportar la privada), usos
  `['encrypt', 'decrypt']`.

### `exportPublicKey(pub)` — `138-140`
- **Parámetros:** `pub` (`CryptoKey` pública).
- **Retorna:** `Promise<string>` — JWK serializado (ya `_cleanJwk`).

### `exportPrivateKey(priv)` — `142-144`
- **Parámetros:** `priv` (`CryptoKey` privada).
- **Retorna:** `Promise<string>` — JWK serializado (incluye los componentes privados).

### `importPublicKey(json)` — `147-155`
- **Parámetros:** `json` — JWK como string u objeto.
- **Retorna:** `Promise<{ oaep, pss, n, e }>`:
  - `oaep`: `CryptoKey` para **cifrar** (uso `['encrypt']`, no extraíble).
  - `pss`: `CryptoKey` para **verificar firma** (uso `['verify']`, no extraíble).
  - `n`, `e`: componentes del módulo (los valida el backend).
- **Nota:** importa la **misma** clave dos veces (en paralelo) con algoritmos distintos.

### `importPrivateKey(json)` — `158-166`
- **Parámetros:** `json` — JWK como string u objeto.
- **Retorna:** `Promise<{ oaep, pss }>`:
  - `oaep`: `CryptoKey` para **descifrar** (uso `['decrypt']`).
  - `pss`: `CryptoKey` para **firmar** (uso `['sign']`).

---

## 5. API de cifrado de mensajes

### `encryptMessage(plaintext, pubSender, pubRecipient, privSenderForSign = null)` — `176-209`
Cifra un mensaje para emisor y receptor (multi-destinatario).
- **Parámetros:**
  - `plaintext` (string): el mensaje en claro.
  - `pubSender` (objeto de `importPublicKey`): pública del emisor.
  - `pubRecipient` (objeto de `importPublicKey`): pública del receptor.
  - `privSenderForSign` (objeto de `importPrivateKey`, opcional): si se pasa, firma el
    mensaje (RSA-PSS); si es `null`, no hay firma.
- **Retorna:** `Promise<object>` — el **sobre**:
  ```js
  {
    v: 2,
    encKeySender,     // K cifrada con la pública del emisor (RSA-OAEP), Base64
    encKeyRecipient,  // K cifrada con la pública del receptor (RSA-OAEP), Base64
    ciphertext,       // mensaje cifrado (AES-256-GCM), Base64
    mac,              // tag GCM de 16 bytes (integridad), Base64
    nonce,            // IV de 12 bytes, Base64
    signature,        // firma RSA-PSS o null, Base64
  }
  ```
- **Algoritmo interno:**
  1. `K = randomBytes(32)` — clave AES-256 simétrica, nueva por mensaje (`180`).
  2. `iv = randomBytes(12)` (`182`).
  3. AES-256-GCM cifra → separa `ciphertext` y `tag` de 16 bytes (`183-185`).
  4. RSA-OAEP envuelve `K` con la pública del emisor y del receptor, en paralelo (`188-191`).
  5. Si hay privada, RSA-PSS firma `iv‖ciphertext‖tag` (`195-198`).
- **Errores:** propaga cualquier fallo de Web Crypto (entrada inválida, clave incorrecta).

### `decryptMessage(envelope, privKey, isSender, pubSenderForVerify = null)` — `215-254`
Descifra un sobre y verifica integridad y (opcionalmente) la firma.
- **Parámetros:**
  - `envelope` (objeto): el sobre con los campos en Base64.
  - `privKey` (objeto de `importPrivateKey`): mi privada.
  - `isSender` (bool): `true` si soy quien lo envió (usa `encKeySender`); `false` si soy
    el receptor (usa `encKeyRecipient`).
  - `pubSenderForVerify` (objeto de `importPublicKey`, opcional): pública del emisor, para
    verificar la firma.
- **Retorna:** `Promise<{ plaintext, integrity, verified, error? }>`:
  - `plaintext` (string|null): el texto, o `null` si falló.
  - `integrity` (bool): `true` si se desencapsuló y descifró/autenticó correctamente.
  - `verified` (bool|null): `true`/`false` si había firma; `null` si no había firma o
    pública con que verificar.
  - `error` (string, solo en fallo): motivo legible.
- **No lanza excepciones**: captura los fallos y los devuelve como objeto de resultado
  (`226-228`, `236-238`), para que la UI los muestre sin romperse.
- **Algoritmo interno:**
  1. Elige la copia de `K` según `isSender` y la desencapsula con RSA-OAEP (`217-228`).
  2. AES-256-GCM descifra `ciphertext‖tag`; si fue alterado, GCM falla → `integrity:false`
     (`231-238`).
  3. Si hay firma + pública, RSA-PSS verifica → `verified` (`240-251`).

---

## 6. API de envoltura de la clave privada

Permite usar la misma clave privada en varios dispositivos cifrándola con la contraseña
del usuario (el servidor solo ve el blob cifrado).

### `_deriveWrapKey(password, salt, iterations, usage)` — `261-271` *(interna)*
Deriva una clave AES-256 a partir de la contraseña con **PBKDF2-HMAC-SHA256**.
- **Parámetros:** `password` (string), `salt` (`Uint8Array`), `iterations` (número),
  `usage` (`'encrypt'` o `'decrypt'`).
- **Retorna:** `Promise<CryptoKey>` — clave AES-GCM no extraíble (uso `['deriveKey']` en
  la base, derivada a AES-256).

### `wrapPrivateKey(privateKeyJson, password, iterations = 150000)` — `274-292`
Cifra el JWK de la clave privada con la contraseña.
- **Parámetros:** `privateKeyJson` (string), `password` (string), `iterations` (opcional).
- **Retorna:** `Promise<object>` — el blob:
  ```js
  {
    v: 2,
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations,
    salt,        // 16 bytes, Base64
    nonce,       // IV 12 bytes, Base64
    ciphertext,  // privada cifrada, Base64
    mac,         // tag GCM, Base64
  }
  ```
- **Interno:** `salt` y `iv` nuevos cada vez (`276-277`) → dos envolturas de la misma
  clave dan blobs distintos. Cifra con AES-256-GCM (`279`).

### `unwrapPrivateKey(blob, password)` — `295-310`
Descifra el blob para recuperar el JWK de la privada.
- **Parámetros:** `blob` (objeto de `wrapPrivateKey`), `password` (string).
- **Retorna:** `Promise<string>` — el JWK de la privada.
- **Errores:** si la contraseña es incorrecta, el tag GCM no cuadra y **lanza**
  `Error('Contrasena incorrecta o clave corrupta.')` (`307-308`). Así sirve de validador
  de contraseña.

---

## 7. Auto-prueba

### `selfTest(bits = 2048)` — `316-345`
Prueba de aceptación de extremo a extremo (round-trip), útil desde la consola del
navegador: `window.CriptoCore.selfTest()`.
- Genera dos usuarios A y B, cifra de A para B, B descifra, A relee, y comprueba que
  **alterar 1 byte del ciphertext se rechaza** (integridad).
- **Retorna:** `Promise<object>` con banderas `recipientOk`, `senderOk`,
  `signatureVerified`, `tamperRejected`, `recovered` y un `pass` global.

---

## 8. Exportaciones

`cripto-core.js:347-373`:
- Objeto por defecto `CriptoCore` con todas las funciones públicas.
- Se asigna a `window.CriptoCore` si hay `window` (para pruebas en consola, `364-366`).
- `export default CriptoCore` + exportaciones nombradas de cada función (`369-373`),
  para que `chat.js` las importe como módulo ES.

**Superficie pública** (lo que usa `chat.js`):
`generateRsaKeyPair`, `exportPublicKey`, `importPublicKey`, `exportPrivateKey`,
`importPrivateKey`, `encryptMessage`, `decryptMessage`, `wrapPrivateKey`,
`unwrapPrivateKey`, `selfTest`, más las utilidades de bytes/Base64.

---

## 9. Glosario

| Término | Significado |
|---------|-------------|
| **E2E** | Cifrado de extremo a extremo: solo emisor y receptor pueden leer. |
| **KEM** | *Key Encapsulation Mechanism*: cifrar la clave de sesión con asimétrico (RSA-OAEP). |
| **DEM** | *Data Encapsulation Mechanism*: cifrar el dato con simétrico (AES-GCM). |
| **Asimétrico** | Dos claves (pública/privada). RSA. Lento, datos pequeños. |
| **Simétrico** | Una sola clave compartida. AES. Rápido, cualquier tamaño. |
| **AEAD** | Cifrado autenticado: cifra **y** detecta manipulación (AES-GCM). |
| **Tag / MAC** | Sello de 16 bytes de GCM que garantiza integridad (campo `mac`). |
| **IV / nonce** | Vector de inicialización: valor aleatorio único por mensaje (campo `nonce`). |
| **Cifrado probabilístico** | Que dos mensajes iguales den cifrados distintos. Garantía: seguridad semántica / IND-CPA. |
| **KDF** | *Key Derivation Function*: deriva una clave desde una contraseña (PBKDF2). |
| **Salt** | Valor aleatorio que se añade antes de derivar/firmar para que el resultado no se repita. |
| **JWK** | *JSON Web Key*: formato JSON estándar para serializar claves. |
| **`extractable`** | Flag de una `CryptoKey`: si se puede exportar a JWK o no. |
| **`keyUsages`** | Flags que limitan qué puede hacer una clave (`encrypt`, `decrypt`, `sign`, `verify`, `deriveKey`). |
