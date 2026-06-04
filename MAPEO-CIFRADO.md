# Mapeo del cifrado E2E

Documento de referencia: **dónde** ocurre cada operación de cifrado, **qué método**
se llama, **desde qué parte de la interfaz**, **qué datos recibe/devuelve** y **cómo
funciona** internamente.

> Regla general del proyecto: **todo el cifrado ocurre en el navegador (frontend).**
> El backend Laravel **nunca cifra ni descifra** — solo valida la forma de los datos,
> los guarda en Base64 y los reparte.

---

## 0. Arquitectura en una imagen

```
NAVEGADOR (emisor)                  SERVIDOR (Laravel)             NAVEGADOR (receptor)
─────────────────                   ──────────────────             ───────────────────
texto plano
   │
   │ encryptMessage()               guarda el sobre                 decryptMessage()
   ▼   (cripto-core.js)             SIN descifrar (Base64)             ▲
 sobre cifrado  ───POST──►  MessageController::store  ──GET──►  sobre cifrado
                                                                       │
                                                                  texto plano
```

- **Frontend:** `resources/js/crypto/cripto-core.js` (motor) + `resources/js/chat.js` (orquestador / interfaz).
- **Backend:** `app/Http/Controllers/Api/MessageController.php` y `KeyController.php` (solo almacenamiento).

---

## 0.1. Dónde vive cada dato (memoria)

Es clave entender en **qué tipo de memoria** reside cada pieza, porque determina su
persistencia y su exposición:

| Dato | Memoria | Persistencia | Dónde (código) |
|------|---------|--------------|----------------|
| Clave privada RSA en JWK (texto) | **localStorage del navegador** (disco) | persiste tras cerrar el navegador | `chat.js:19` (`e2e.priv2.<id>`) |
| Clave pública RSA en JWK (texto) | **localStorage del navegador** (disco) | persiste | `chat.js:20` (`e2e.pub2.<id>`) |
| Claves importadas `state.myPriv` / `state.myPub` (`CryptoKey`) | **RAM** (memoria JS de la pestaña) | se borra al recargar/cerrar | `chat.js:140-141`, objeto `state` (`chat.js:27`) |
| Pública del contacto `state.active.otherPub` (`CryptoKey`) | **RAM** | se borra al cerrar la conversación/pestaña | `chat.js:224` |
| Contraseña del usuario | **sessionStorage del navegador** (disco, por pestaña) | se borra al cerrar la pestaña | `chat.js:21-22` (`e2e.pw.<id>`) |
| Clave de sesión AES `K` (32 bytes) | **RAM, efímera** | existe solo durante el cifrado/descifrado de UN mensaje; nunca se guarda | `cripto-core.js:180` (`randomBytes(32)`) |
| Mensajes ya descifrados (texto plano) | **RAM** (caché en memoria) | se borra al recargar/cambiar de chat | `chat.js:35` (`state.cache`, un `Map`) |
| Sobre cifrado + pública + blob de la privada cifrada | **Base de datos del servidor** (disco) | persistente en el servidor | `MessageController` / `KeyController` |

**Resumen de memoria:**
- En **disco del navegador** (sobrevive al cierre): claves RSA en JWK (`localStorage`) y
  la contraseña por sesión de pestaña (`sessionStorage`).
- En **RAM** (volátil, desaparece al recargar): las claves ya importadas como `CryptoKey`,
  la clave de sesión AES `K`, y los mensajes descifrados.
- En **disco del servidor** (BD): solo datos **cifrados** (Base64). El servidor nunca
  tiene en memoria ni la clave privada en claro ni la contraseña.

---

## 0.2. Los dos archivos del frontend: motor vs orquestador

Toda la lógica del cliente se reparte en **dos archivos con responsabilidades separadas**:

| | `cripto-core.js` (motor) | `chat.js` (orquestador) |
|---|--------------------------|--------------------------|
| **Rol** | la "caja de herramientas" criptográfica | la lógica de la aplicación |
| **Qué hace** | envuelve la Web Crypto API en funciones de alto nivel | decide **cuándo** y **con qué** llamarlas |
| **Sabe de cripto** | sí, **todas** las decisiones (algoritmos, tamaños, sobre) | no — solo invoca |
| **Sabe de la app** | no (no toca DOM, servidor ni almacenamiento) | sí (UI, eventos, localStorage, fetch) |
| **Estado** | **sin estado** (recibe → opera → devuelve) | mantiene `state` (claves, conversación, caché) |

```
Web Crypto API (cruda)          cripto-core.js (envuelta)        chat.js (la usa)
──────────────────────          ─────────────────────────        ────────────────
crypto.subtle.generateKey  ──►  generateRsaKeyPair()        ──►  ensureKeys()
crypto.subtle.encrypt ×N   ──►  encryptMessage()            ──►  sendMessage()
crypto.subtle.decrypt ×N   ──►  decryptMessage()            ──►  decryptMessage()
crypto.subtle.deriveKey    ──►  wrapPrivateKey()/unwrap...  ──►  uploadKeys()/recover...
```

- **`cripto-core` = el QUÉ y el CÓMO** de la criptografía (las herramientas).
- **`chat` = el CUÁNDO y el DÓNDE** de la aplicación (quien las usa).

`chat.js` importa el motor **una sola vez** (`chat.js:12`:
`import CriptoCore from './crypto/cripto-core.js'`) y lo reutiliza en todos los puntos.

**Ventaja de separarlos:** el motor es reutilizable, auditable y testeable de forma
aislada (por eso tiene `selfTest()`); cambiar la UI no puede romper la criptografía.

---

## 1. Esquema criptográfico (qué algoritmos y por qué)

Cifrado **híbrido KEM/DEM** (mismo diseño que PGP, multi-destinatario):

| Rol | Primitiva | Tipo de cifrado | Definido en |
|-----|-----------|-----------------|-------------|
| **KEM** — envolver la clave de sesión | RSA-OAEP (SHA-256), 2048 bits | **asimétrico** (clave pública/privada) | `cripto-core.js` |
| **DEM** — cifrar el mensaje + integridad | AES-256-GCM, AEAD | **simétrico** (una sola clave compartida) | `cripto-core.js` |
| **Firma** — origen del mensaje (opcional) | RSA-PSS (SHA-256, salt 32) | **asimétrico** (firma con privada, verifica con pública) | `cripto-core.js` |
| **KDF** — proteger la clave privada con la contraseña | PBKDF2-HMAC-SHA256, 150.000 iter | **derivación** (contraseña → clave simétrica) | `cripto-core.js` |

- **RSA (asimétrico):** dos claves distintas. Lo que cifra la pública solo lo abre la
  privada. Lento, solo para datos pequeños (aquí, la clave AES de 32 bytes).
- **AES (simétrico):** una única clave secreta cifra y descifra. Rápido, para cualquier
  tamaño (aquí, el mensaje completo).

**Por qué híbrido:** RSA es lento y solo cifra datos muy pequeños. Por eso AES (rápido,
cualquier tamaño) cifra el mensaje, y RSA solo cifra la clave AES de 32 bytes.

**Por qué AES-GCM:** es un cifrado *autenticado* (AEAD). Además de cifrar, produce un
"tag" de 16 bytes que detecta cualquier manipulación: si cambian un byte del mensaje,
el descifrado **falla** en lugar de devolver basura. Ese tag se guarda en el campo `mac`.

---

## 2. El "sobre" cifrado

Cada mensaje viaja como un objeto con estos campos (todos en Base64):

| Campo (frontend) | Campo (backend/BD) | Contenido |
|------------------|--------------------|-----------|
| `v` | `v` | versión del esquema (2 = Web Crypto) |
| `encKeySender` | `enc_key_sender` | clave de sesión AES (simétrica) cifrada con la **pública del emisor** (RSA-OAEP, asimétrico) |
| `encKeyRecipient` | `enc_key_recipient` | clave de sesión AES (simétrica) cifrada con la **pública del receptor** (RSA-OAEP, asimétrico) |
| `ciphertext` | `ciphertext` | mensaje cifrado con AES-256-GCM (simétrico) |
| `mac` | `mac` | tag de autenticación GCM (16 bytes) |
| `nonce` | `nonce` | IV de 12 bytes usado por GCM |
| `signature` | `signature` | firma RSA-PSS (asimétrico) sobre `iv‖ciphertext‖tag` (opcional) |

La clave de sesión se envuelve **dos veces** (emisor y receptor) para que **ambos**
puedan abrir el mensaje (tú puedes releer lo que enviaste).

---

## 2.1. Aleatorización: cifrado probabilístico (por qué dos mensajes iguales NO producen el mismo cifrado)

Si escribes **"hola"** dos veces, el texto cifrado que viaja al servidor es **distinto
cada vez**. Esto es deliberado: evita que un observador (o el servidor) deduzca que dos
mensajes son iguales, detecte repeticiones o arme un "diccionario" de cifrados conocidos.

### El nombre correcto: distingue el MÉTODO del RESULTADO

Son dos conceptos distintos y conviene no confundirlos:

- **Vector de inicialización (IV / nonce)** → es el **MÉTODO / mecanismo**. El valor
  aleatorio (junto con la clave de sesión `K` y los salts) que se mete en cada cifrado.
  Es la *causa*.
- **Cifrado probabilístico** (o *no determinista*) → es el **RESULTADO / la propiedad**:
  "dos mensajes iguales producen cifrados distintos". La garantía de seguridad formal que
  esto otorga se llama **seguridad semántica** o **IND-CPA** (*indistinguishability under
  chosen-plaintext attack*). Es el *efecto*.

```
IV / vector de inicialización  ──── MÉTODO ────►  Cifrado probabilístico
(+ clave K aleatoria, salts)      (la causa)       (la propiedad resultante;
                                                    garantía: seguridad semántica / IND-CPA)
```

> En resumen: **el IV no es el nombre de la propiedad; es el ingrediente que la provoca.**
> El IV viaja en claro en el campo `nonce` del sobre — no es secreto, solo debe ser
> **único por mensaje** (regla de oro de AES-GCM: nunca repetir nonce con la misma clave).

Lo consiguen **cuatro fuentes de aleatoriedad**, todas generadas con `randomBytes`
(`cripto-core.js:38`, que usa `crypto.getRandomValues`, un generador seguro):

| Pieza aleatoria | Tamaño | Dónde se genera | Qué varía |
|-----------------|--------|-----------------|-----------|
| **Clave de sesión `K`** (AES) | 32 bytes | `cripto-core.js:180` | clave simétrica **nueva por cada mensaje** → todo el `ciphertext` cambia |
| **IV / `nonce`** (AES-GCM) | 12 bytes | `cripto-core.js:182` | aunque `K` se repitiera, el IV distinto hace que el `ciphertext` y el `tag` cambien |
| **Salt de RSA-OAEP** (interno) | — | dentro de `s.encrypt` RSA-OAEP (`189-190`) | el relleno aleatorio de OAEP hace que cifrar la **misma** `K` dé `encKey*` distintos |
| **Salt de RSA-PSS** (firma) | 32 bytes | `cripto-core.js:196` (`saltLength: 32`) | la firma del **mismo** contenido es distinta cada vez |

**Efecto en el sobre:** como `K`, el `nonce` y el relleno de OAEP cambian en cada envío,
**todos** los campos variables del sobre (`encKeySender`, `encKeyRecipient`,
`ciphertext`, `mac`, `nonce`, `signature`) son diferentes entre dos mensajes idénticos.
Lo único que se mantiene constante es `v` (la versión).

**Importante:** estos valores aleatorios **no son secretos**. El `nonce` viaja en claro
dentro del sobre porque el receptor lo necesita para descifrar; lo que importa es que
sea **único por mensaje**, no oculto. `K` sí es secreta, pero nunca viaja en claro: solo
viaja envuelta con RSA (en `encKeySender`/`encKeyRecipient`).

> Misma idea en la envoltura de la clave privada: `wrapPrivateKey` (`cripto-core.js:274`)
> genera un **salt** (16 bytes, `:276`) y un **IV** (12 bytes, `:277`) nuevos cada vez,
> así que envolver la misma clave con la misma contraseña dos veces da blobs distintos.

---

## 3. Mapeo de métodos: definición ↔ uso

Todos los métodos se **definen** en `resources/js/crypto/cripto-core.js` y se **invocan**
desde `resources/js/chat.js` a través del objeto `CriptoCore`
(importado en `chat.js:12`).

| Método | Def. (`cripto-core.js`) | Uso (`chat.js`) | Función que lo llama |
|--------|-------------------------|-----------------|----------------------|
| `generateRsaKeyPair` | `129` | `132` | `ensureKeys` |
| `exportPrivateKey` | `142` | `133` | `ensureKeys` |
| `exportPublicKey` | `138` | `134` | `ensureKeys` |
| `importPrivateKey` | `158` | `140` | `ensureKeys` |
| `importPublicKey` (mía) | `147` | `141` | `ensureKeys` |
| `importPublicKey` (contacto) | `147` | `224` | `openConversation` |
| `wrapPrivateKey` | `274` | `88` | `uploadKeys` |
| `unwrapPrivateKey` | `295` | `105` | `recoverPrivateKey` |
| `encryptMessage` | `176` | `278` | `sendMessage` |
| `decryptMessage` | `215` | `343` | `decryptMessage` |

---

## 3.1. Flags de las claves (`extractable` y `keyUsages`)

La Web Crypto API marca cada `CryptoKey` con **flags** que limitan lo que puede hacer.
Es un principio de *mínimo privilegio*: la propia API **rechaza** una operación si no
coincide con el flag declarado. Hay dos tipos.

### `extractable` (booleano) — ¿se puede exportar la clave?

| Clave | Línea | `extractable` | Por qué |
|-------|-------|---------------|---------|
| par RSA generado | `cripto-core.js:132` | `true` | hay que exportar la privada a JWK para guardarla en localStorage |
| cualquier clave importada | `cripto-core.js:151,152,162,163,181,233,…` | `false` | una vez en uso, ya no se puede volver a sacar (vive opaca en RAM) |

### `keyUsages` (array) — ¿qué puede hacer la clave?

| Clave | Línea | Flags de uso |
|-------|-------|--------------|
| par RSA generado | `133` | `['encrypt', 'decrypt']` |
| pública → OAEP | `151` | `['encrypt']` (solo cifrar) |
| pública → PSS | `152` | `['verify']` (solo verificar firma) |
| privada → OAEP | `162` | `['decrypt']` (solo descifrar) |
| privada → PSS | `163` | `['sign']` (solo firmar) |
| AES de sesión (cifrar) | `181` | `['encrypt']` |
| AES de sesión (descifrar) | `233` | `['decrypt']` |
| base PBKDF2 | `263` | `['deriveKey']` |

Por estos flags, `importPublicKey`/`importPrivateKey` importan la **misma** clave RSA
**dos veces** (`150-153`, `161-164`): una para OAEP (cifrar/descifrar) y otra para PSS
(firmar/verificar). Una sola importación no podría hacer ambas cosas.

> Relacionado: `_cleanJwk` (`cripto-core.js:119`) borra del JWK los campos
> `alg`/`use`/`key_ops` precisamente para poder reimportar el mismo material con flags
> distintos (OAEP por un lado, PSS por otro) sin conflicto.

---

## 4. Frontend — flujo y código exacto

### 4.0. Arranque: cómo se inicia todo (`boot → ensureKeys`)

El punto de entrada es el evento de carga del DOM (`chat.js:487`):
```js
document.addEventListener('DOMContentLoaded', boot);   // chat.js:487
```

Eso dispara **`boot`** (`chat.js:476-485`), el coordinador del arranque:
```js
async function boot() {
  wireComposer();          // 1. conecta los eventos del compositor (Enter / botón Enviar)
  try {
    await ensureKeys();    // 2. ← INICIALIZA LAS CLAVES (primero; sin claves no hay chat)
    await loadContacts();  // 3. carga la lista de usuarios
  } catch (e) {
    setStatus('Error de inicializacion: ' + e.message, false, true);
  }
}
```

Cadena completa:
```
DOMContentLoaded (chat.js:487)
        ▼
   boot()  (chat.js:476)
        ├──► wireComposer()   conecta Enter / botón Enviar
        ├──► ensureKeys()     ← INICIALIZA LAS CLAVES (chat.js:114)
        └──► loadContacts()   carga usuarios
```

**El método que inicializa las claves es `ensureKeys`** (`chat.js:114`), detallado abajo.

### 4.1. Gestión de claves

#### `ensureKeys` — `chat.js:114-160`  (el método que inicializa las claves)
Garantiza que el usuario tenga su par RSA disponible en este dispositivo. Decide entre
**tres escenarios**:

| Escenario | Condición | Qué hace | Método del core |
|-----------|-----------|----------|-----------------|
| **A — Primera vez** (cualquier dispositivo) | no hay clave ni local ni en servidor | **genera** par RSA nuevo | `generateRsaKeyPair(2048)` (`:132`) |
| **B — Dispositivo nuevo** (ya existía) | no hay local, pero sí en servidor | **recupera** con la contraseña | `recoverPrivateKey` → `unwrapPrivateKey` (`:105`) |
| **C — Dispositivo conocido** | ya hay clave en localStorage | **reutiliza** la local | (solo importa) |

En los tres casos termina igual: importando a RAM (`:140-141`) y sincronizando con el
servidor lo que falte.

**El mismo flujo, en código:**

- **Primera vez (cualquier dispositivo):** genera el par y lo exporta a JWK.
  ```js
  const kp = await CriptoCore.generateRsaKeyPair(2048);         // chat.js:132
  privJson = await CriptoCore.exportPrivateKey(kp.privateKey);  // chat.js:133
  pubJson  = await CriptoCore.exportPublicKey(kp.publicKey);    // chat.js:134
  ```
- **Otro dispositivo (ya hay clave en el servidor):** la recupera con la contraseña.
  ```js
  privJson = await recoverPrivateKey(serverWrapped);  // chat.js:126 → usa unwrapPrivateKey
  ```
- **Siempre:** importa ambas claves a manejadores en memoria.
  ```js
  state.myPriv = await CriptoCore.importPrivateKey(privJson);  // chat.js:140 → {oaep, pss}
  state.myPub  = await CriptoCore.importPublicKey(pubJson);    // chat.js:141 → {oaep, pss, n, e}
  ```
- **Sincroniza con el servidor** lo que falte (pública y/o blob de la privada).

> Almacenamiento: la privada y la pública en JWK viven en `localStorage`
> (`e2e.priv2.<id>` / `e2e.pub2.<id>`, definidas en `chat.js:19-20`).

#### `uploadKeys` — `chat.js:87-93`  (CIFRA la clave privada)
Sube la pública y el blob CIFRADO de la privada.
```js
const wrapped = await CriptoCore.wrapPrivateKey(privJson, password);  // chat.js:88
const wrappedJson = JSON.stringify(wrapped);
await api('POST', '/api/keys', { public_key: pubJson, wrapped_private_key: wrappedJson });
```
- **Recibe:** JWK de la privada (string) + contraseña del login.
- **Produce:** blob `{v, kdf, iterations, salt, nonce, ciphertext, mac}` → se sube cifrado.

#### `recoverPrivateKey` — `chat.js:96-112`  (DESCIFRA la clave privada)
Recupera la privada en un dispositivo nuevo pidiendo la contraseña; reintenta si falla.
```js
return await CriptoCore.unwrapPrivateKey(blob, pw);  // chat.js:105
```
- **Recibe:** blob del servidor + contraseña.
- **Produce:** JWK de la privada (string). Si la contraseña es incorrecta, lanza error
  (lo detecta porque el tag GCM no cuadra) y vuelve a preguntar.

### 4.2. Abrir conversación

#### `openConversation` — `chat.js:211-243`
Pide la conversación e importa la **clave pública del contacto** para poder cifrarle.
```js
const otherPub = conversation.other.public_key
  ? await CriptoCore.importPublicKey(conversation.other.public_key)  // chat.js:224
  : null;
state.active = { id: conversation.id, other: conversation.other, otherPub };
```
- Si el contacto aún no tiene clave pública, el compositor se deshabilita
  (`updateComposerAvailability`, `chat.js:255-262`).

### 4.3. Enviar (CIFRAR mensaje)

#### Cadena de eventos: del Enter / botón "Enviar" hasta el cifrado

El usuario tiene **dos formas** de disparar el envío, y ambas terminan llamando a la
misma función `sendMessage`, que es donde se cifra. El "cableado" se hace una sola vez
en `wireComposer` (`chat.js:447-474`):

**(A) Botón "Enviar"** — el `<button id="composer-send" type="submit">`
(vista `resources/views/chat/index.blade.php:73`) está dentro del
`<form id="composer">` (`index.blade.php:69`). Al pulsarlo se dispara el `submit` del
formulario:
```js
form.addEventListener('submit', (e) => {   // chat.js:451
  e.preventDefault();                      // evita que el navegador recargue la página
  sendMessage();                           // ← aquí empieza el cifrado
});
```

**(B) Tecla Enter** — en el `<textarea id="composer-input">`. Enter envía;
Shift+Enter hace salto de línea:
```js
input.addEventListener('keydown', (e) => {              // chat.js:457
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();                                 // no inserta el salto de línea
    sendMessage();                                      // ← aquí empieza el cifrado
  }
});
```

**Flujo completo del disparo:**
```
[Enter sin Shift]  ─┐
                    ├─►  sendMessage()  ──►  CriptoCore.encryptMessage(...)  ──►  POST al backend
[clic en "Enviar"] ─┘     (chat.js:268)         (chat.js:278, CIFRA)            (chat.js:296)
```

> Nota: el cifrado **no** ocurre mientras escribes. Solo se dispara en el instante del
> Enter/clic, dentro de `sendMessage`, justo antes de mandar el mensaje al servidor.

#### `sendMessage` — `chat.js:268-304`

Lo primero que hace es leer y validar el texto; si está vacío o no hay clave del
contacto, **no** cifra ni envía:
```js
const input = el('#composer-input');
const text = input.value;
if (!text.trim() || !state.active || !state.active.otherPub) return;  // chat.js:271

input.value = '';            // limpia el campo de inmediato (feedback al usuario)
input.style.height = 'auto';
```

Y a continuación cifra:
```js
envelope = await CriptoCore.encryptMessage(
  text,                    // texto plano del input
  state.myPub,             // mi pública  → copia de la clave para mí
  state.active.otherPub,   // pública del contacto → copia para él
  state.myPriv,            // mi privada  → para firmar (RSA-PSS)
);                                                              // chat.js:278

const payload = {                       // mapea el sobre al formato del backend
  v: envelope.v,
  enc_key_sender:    envelope.encKeySender,
  enc_key_recipient: envelope.encKeyRecipient,
  ciphertext: envelope.ciphertext,
  mac:  envelope.mac,
  nonce: envelope.nonce,
  signature: envelope.signature,
};                                                             // chat.js:285-293

await api('POST', `/api/conversations/${state.active.id}/messages`, payload);  // chat.js:296
```
- **Entrada:** texto del `#composer-input`.
- **Salida:** el sobre cifrado se envía por POST. El texto plano **nunca** sale del navegador.

### 4.4. Recibir (DESCIFRAR mensaje)

#### `fetchNew` — `chat.js:310-326`
Polling cada `POLL_MS` (2500 ms, `chat.js:23`): `GET .../messages?after=<lastId>`.
Cada mensaje recibido pasa por `decryptMessage`.

#### `decryptMessage` — `chat.js:328-349`
```js
const isSender = m.mine;
const senderPub = isSender ? state.myPub : state.active.otherPub;  // de quién verificar la firma
const env = {                          // reconstruye el sobre desde la respuesta del backend
  v: m.v,
  encKeySender:    m.enc_key_sender,
  encKeyRecipient: m.enc_key_recipient,
  ciphertext: m.ciphertext,
  mac: m.mac, nonce: m.nonce, signature: m.signature,
};
result = await CriptoCore.decryptMessage(env, state.myPriv, isSender, senderPub);  // chat.js:343
state.cache.set(m.id, result);         // cachea para no descifrar dos veces
```
- **Devuelve:** `{ plaintext, integrity, verified }`.
- El render (`appendMessage`, `chat.js:355-400`) muestra:
  - `plaintext` con `textContent` (a prueba de XSS) si `integrity` es `true`.
  - Un aviso ⚠ si falló el descifrado o la integridad.
  - Una insignia "✓ firmado" / "⚠ firma" según `verified`.

---

## 5. Cómo funciona internamente cada método (cripto-core.js)

### 5.1. `encryptMessage(plaintext, pubSender, pubRecipient, privSenderForSign)` — `176-209`
```
1. K  = randomBytes(32)            // clave AES-256 (SIMÉTRICA), nueva por mensaje, vive solo en RAM  (180)
2. IV = randomBytes(12)                                                            (182)
3. ctTag = AES-256-GCM(K, IV, plaintext)        // cifrado SIMÉTRICO               (183)
   ciphertext = ctTag[:-16]   ;   tag = ctTag[-16:]   // separa mensaje y sello    (184-185)
4. encKS = RSA-OAEP(pubSender,    K)   // ASIMÉTRICO: envuelve K para el emisor    (189)
   encKR = RSA-OAEP(pubRecipient, K)   // ASIMÉTRICO: envuelve K para el receptor  (190)
5. signature = RSA-PSS(privSender, IV ‖ ciphertext ‖ tag)   // ASIMÉTRICO, opcional (196)
6. return { v:2, encKeySender, encKeyRecipient, ciphertext, mac:tag, nonce:IV, signature }
   // K se descarta: nunca se guarda en disco, desaparece de la RAM al terminar
```

### 5.2. `decryptMessage(envelope, privKey, isSender, pubSenderForVerify)` — `215-254`
```
1. wrapped = isSender ? encKeySender : encKeyRecipient   // elige mi copia          (217)
   K = RSA-OAEP-decrypt(privKey, wrapped)   // ASIMÉTRICO: recupera K en RAM        (225)
       └─ si falla → { integrity:false, error:'OAEP' }                              (226-228)
2. plaintext = AES-256-GCM-decrypt(K, IV, ciphertext ‖ tag)   // SIMÉTRICO          (234)
       └─ si el mensaje fue alterado, GCM lanza → { integrity:false }               (236-238)
3. si hay signature y pública del emisor:
   verified = RSA-PSS-verify(pubSender, signature, IV ‖ ciphertext ‖ tag)  // ASIMÉTRICO (244-249)
4. return { plaintext, integrity:true, verified }   // plaintext queda en RAM (state.cache)
```

### 5.3. `wrapPrivateKey(privateKeyJson, password, iterations=150000)` — `274-292`
```
1. salt = randomBytes(16)  ;  IV = randomBytes(12)                                  (276-277)
2. key  = PBKDF2-HMAC-SHA256(password, salt, 150000) → clave AES-256 (SIMÉTRICA, en RAM)  (278 → _deriveWrapKey:261)
3. ctTag = AES-256-GCM(key, IV, privateKeyJson)   // SIMÉTRICO: cifra la privada RSA (279)
4. return { v:2, kdf, iterations, salt, nonce:IV, ciphertext, mac:tag }   // este blob va a la BD del servidor
```

### 5.4. `unwrapPrivateKey(blob, password)` — `295-310`
```
1. key = PBKDF2-HMAC-SHA256(password, blob.salt, blob.iterations)   // clave SIMÉTRICA en RAM (303)
2. privateKeyJson = AES-256-GCM-decrypt(key, blob.nonce, blob.ciphertext ‖ blob.mac)  // SIMÉTRICO (305)
       └─ si la contraseña es incorrecta, el tag no cuadra → lanza error            (307-308)
   // el JWK recuperado se guarda luego en localStorage (chat.js:136)
```

### 5.5. Generación / serialización de claves (RSA, asimétrico)
- `generateRsaKeyPair(bits=2048)` — `129-136`: genera el par RSA (asimétrico) OAEP,
  exponente 65537, `extractable:true`. Resultado: `CryptoKey` en **RAM**.
- `exportPublicKey` / `exportPrivateKey` — `138` / `142`: `CryptoKey` (RAM) → JWK string
  (que luego se persiste en **localStorage** y/o, cifrado, en la **BD**).
- `importPublicKey` — `147-155`: JWK → `{oaep (cifrar), pss (verificar), n, e}` en **RAM**.
- `importPrivateKey` — `158-166`: JWK → `{oaep (descifrar), pss (firmar)}` en **RAM**.
- `_cleanJwk` — `119-122`: quita `alg`/`use`/`key_ops` para reusar la **misma** clave RSA
  tanto en OAEP (cifrar) como en PSS (firmar).

---

## 6. Backend — solo almacena (NO cifra)

### `MessageController::store` — `MessageController.php:31-57`
Recibe el sobre cifrado, valida su forma y lo guarda **sin descifrar**.
```php
$data = $request->validate([
    'v' => ['nullable', 'integer'],
    'enc_key_sender'    => ['required', 'string', 'max:20000'],
    'enc_key_recipient' => ['required', 'string', 'max:20000'],
    'ciphertext' => ['required', 'string'],
    'mac'       => ['required', 'string', 'max:200'],
    'nonce'     => ['required', 'string', 'max:200'],
    'signature' => ['nullable', 'string', 'max:20000'],
]);
$message = $conversation->messages()->create([... $data ...]);  // persiste tal cual
```
- `index` (`MessageController.php:14-28`): devuelve los mensajes posteriores a `?after=`
  (polling), sin tocar el contenido cifrado.

### `KeyController::store` — `KeyController.php:17-46`
Guarda la pública (texto, no secreta) y el blob de la privada YA cifrado.
```php
$user->public_key = $data['public_key'];                  // valida que sea JWK con n y e
$user->wrapped_private_key = $data['wrapped_private_key']; // blob PBKDF2+AES (cifrado)
```
- Solo valida **forma**: que la pública tenga `n` y `e`; que el blob tenga
  `salt`/`nonce`/`ciphertext`/`mac`. Nunca descifra.
- `show` (`KeyController.php:49-59`): entrega la pública de un usuario para poder cifrarle.

---

## 7. Resumen de archivos

| Archivo | Rol en el cifrado |
|---------|-------------------|
| `resources/js/crypto/cripto-core.js` | **Motor**: define todas las primitivas (cifrar, descifrar, claves, KDF). |
| `resources/js/chat.js` | **Orquestador / interfaz**: llama a los métodos según la acción del usuario. |
| `app/Http/Controllers/Api/MessageController.php` | Almacena y entrega los sobres cifrados. **No cifra.** |
| `app/Http/Controllers/Api/KeyController.php` | Almacena y entrega las claves públicas y el blob cifrado de la privada. **No cifra.** |

**Conclusión:** el cifrado vive por completo en el frontend (`cripto-core.js`, invocado
desde `chat.js`). El backend es un buzón que guarda y reparte Base64 ilegible — el
servidor nunca tiene las claves privadas en claro ni la contraseña, así que no puede
leer los mensajes. Eso es lo que hace que el sistema sea de extremo a extremo (E2E).

---

## 8. Apéndice: las DOS operaciones de cifrado (chat ↔ core)

En toda la app solo se **cifra** (no descifrar) en dos sitios. Esta tabla los empareja:

| | **CIFRADO 1 — Mensaje** | **CIFRADO 2 — Clave privada** |
|---|--------------------------|-------------------------------|
| **Cuándo** | al enviar un mensaje | al subir/sincronizar claves (multi-dispositivo) |
| **Disparador en `chat.js`** | `sendMessage` (`:268`) | `uploadKeys` (`:87`) |
| **Llamada que cifra (`chat.js`)** | `encryptMessage(...)` (`:278`) | `wrapPrivateKey(...)` (`:88`) |
| **Método del core** | `encryptMessage` (`cripto-core.js:176`) | `wrapPrivateKey` (`cripto-core.js:274`) |
| **Qué cifra** | el texto del mensaje | el JWK de la clave privada |
| **Clave simétrica (AES)** | aleatoria `K = randomBytes(32)` | derivada de la contraseña (PBKDF2) |
| **Protección de esa clave** | RSA-OAEP la envuelve (×2: emisor y receptor) | la propia contraseña (al reescribirla en otro dispositivo) |
| **Cifrado del dato** | AES-256-GCM | AES-256-GCM |
| **Resultado** | el **sobre** → POST a `.../messages` | el **blob** → POST a `/api/keys` |

**El patrón compartido:** en ambos casos `chat.js` decide *cuándo* cifrar y entrega los
datos; `cripto-core.js` hace el cifrado real con Web Crypto. La diferencia está en **de
dónde sale la clave AES**:
- **Mensaje:** la clave nace **aleatoria** y se protege con **RSA** (asimétrico) → el
  receptor la abre con su clave privada.
- **Clave privada:** la clave nace **de tu contraseña** (PBKDF2) y se protege con esa
  misma contraseña → tú la abres reescribiéndola en otro dispositivo.

> Descifrar ocurre en otros dos sitios simétricos: `decryptMessage` (`chat.js:343` →
> `cripto-core.js:215`) al recibir, y `recoverPrivateKey` (`chat.js:105` →
> `unwrapPrivateKey`, `cripto-core.js:295`) al recuperar la clave en un dispositivo nuevo.
