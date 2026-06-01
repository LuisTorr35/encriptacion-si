# Chat E2E — Mensajería con cifrado de extremo a extremo

Aplicación web de mensajería 1-a-1 estilo Telegram con **cifrado de extremo a extremo (E2E)**
usando un criptosistema híbrido **KEM/DEM (RSA-OAEP + AES-256-GCM)** sobre la **Web Crypto API**
(criptografía nativa y auditada del navegador/Node). Las conversaciones se guardan **cifradas** en
MySQL: el servidor nunca ve el texto plano ni las claves privadas.

> Proyecto académico/demostrativo de Seguridad Informática.

---

## 1. Cómo funciona (conocimiento cero)

```
Navegador A  ──(sobre cifrado)──►  Laravel + MySQL  ──(sobre cifrado)──►  Navegador B
  cifra/descifra aquí               guarda cifrado, sin claves              cifra/descifra aquí
```

- La **clave privada RSA** se genera en el navegador y vive en `localStorage`. **Nunca** sale del cliente en claro.
- Para **multi-dispositivo**, la clave privada también se guarda en el servidor **cifrada** con una
  clave derivada de tu contraseña (PBKDF2-HMAC-SHA256 → AES-256-GCM). El servidor solo ve el
  blob cifrado: jamás la clave en claro ni la contraseña. Al iniciar sesión en otro dispositivo, la
  clave se **recupera y descifra localmente** con tu contraseña.
- La **clave pública RSA** sí se sube al servidor, para que otros puedan cifrarte mensajes.
- Cada mensaje usa una **clave de sesión aleatoria `K`** que se **encapsula para ambos
  participantes** (emisor y receptor) con RSA-OAEP, de modo que los dos puedan leer el historial
  (patrón multi-destinatario estilo PGP).

### Algoritmo de cada mensaje (KEM/DEM)

```
1. K               <- clave de sesión AES-256 aleatoria
2. C, tag          <- AES-256-GCM(K, iv, UTF8(mensaje))    (cifra + autentica en uno)
3. encK_A          <- RSA-OAEP(pub_A, K)                   (envuelta para el emisor)
4. encK_B          <- RSA-OAEP(pub_B, K)                   (envuelta para el receptor)
5. firma           <- RSA-PSS(priv_emisor, iv||C||tag)     (autenticidad de origen)
```

Para descifrar, el usuario desencapsula `K` con su clave privada y descifra con **AES-256-GCM**,
que **verifica la integridad** automáticamente (si el mensaje fue alterado, falla y se rechaza).

Todas las operaciones usan la **Web Crypto API** (`crypto.subtle`) en
[`resources/js/crypto/cripto-core.js`](resources/js/crypto/cripto-core.js):
RSA-OAEP (SHA-256), AES-256-GCM, RSA-PSS y PBKDF2-HMAC-SHA256. Es criptografía nativa, auditada
por los fabricantes del navegador (estándar W3C); no se incluye ninguna librería de cifrado de
terceros. El `tag` de autenticación de AES-GCM se guarda en el campo `mac` del sobre.

---

## 2. Stack

| Capa | Tecnología |
|---|---|
| Backend | Laravel 11 (PHP 8.2+) |
| Auth + UI base | Laravel Breeze (Blade + Tailwind) |
| Base de datos | MySQL / MariaDB (XAMPP) |
| Criptografía | KEM/DEM sobre la **Web Crypto API**, **del lado del cliente** |
| Tiempo real | Polling cada 2.5 s vía `fetch` |

---

## 3. Requisitos (XAMPP)

- **XAMPP** con **Apache** y **MySQL** en ejecución.
- **PHP ≥ 8.2** con las extensiones `pdo_mysql`, `mbstring`, `openssl`, `fileinfo`
  (el PHP que trae XAMPP ya las incluye).
- **Composer**.
- **Node.js ≥ 18** y **npm** (para compilar los assets).
- Navegador moderno con **Web Crypto API** (`crypto.subtle`, `crypto.getRandomValues`, `TextEncoder`).

---

## 4. Ejecución

```bash
# 1. Iniciar Apache y MySQL desde el panel de XAMPP.

# 2. Instalar dependencias
composer install
npm install

# 3. Configurar entorno (si .env no existe)
cp .env.example .env
php artisan key:generate
#   .env ya viene apuntando a:  DB_DATABASE=chat_e2e  DB_USERNAME=root  DB_PASSWORD=

# 4. Crear la base de datos y poblarla con los usuarios de prueba
#    (crea la BD 'chat_e2e' en phpMyAdmin, o deja que migrate la use)
php artisan migrate:fresh --seed

# 5. Compilar assets de frontend
npm run build        # (o `npm run dev` durante el desarrollo)

# 6. Levantar el servidor
php artisan serve    # http://127.0.0.1:8000
```

> **Nota (Windows / XAMPP):** si tu `php` del PATH no es el de XAMPP y le faltan extensiones,
> usa el de XAMPP explícitamente, p. ej.:
> `C:\xampp\php\php.exe artisan serve`

---

## 5. Probar el chat E2E entre dos usuarios

Usuarios de prueba precargados por el seeder (contraseña `password` en ambos):

| Nombre | Email |
|---|---|
| Ana | `ana@test.com` |
| Beto | `beto@test.com` |

Para chatear necesitas **dos sesiones distintas** (Ana y Beto a la vez), por lo que usa un
**navegador o perfil distinto** para cada uno:

1. Abre `http://127.0.0.1:8000` en una ventana normal e inicia sesión como **Ana**.
2. Abre otra ventana **de incógnito** (o un navegador distinto) e inicia sesión como **Beto**.
3. La primera vez que cada uno entra, el navegador genera su par de claves RSA-2048
   (un par de segundos), sube la pública y guarda la privada **cifrada** en el servidor.
   Cada usuario verá al otro en la lista de **Contactos**.
4. Haz clic en el contacto y empieza a chatear. Los mensajes aparecen en el otro lado en ~2.5 s.

### Multi-dispositivo

Como la clave privada se guarda **cifrada con tu contraseña** en el servidor, puedes iniciar sesión
con el **mismo usuario en otro dispositivo o navegador** y recuperar tu clave (y por tanto leer y
seguir tu historial cifrado):

1. Inicia sesión con el mismo usuario en el nuevo dispositivo.
2. El navegador descarga el blob cifrado, lo descifra **localmente** con tu contraseña y restaura tu
   clave privada en ese `localStorage`. El servidor nunca recibe la clave ni la contraseña.
3. Si el navegador no recuerda la contraseña (p. ej. tras cerrar sesión), te la pedirá una vez para
   recuperar la clave.

---

## 6. Verificaciones de seguridad

- **Conocimiento cero:** abre la tabla `messages` en phpMyAdmin → solo verás Base64 cifrado,
  ningún texto legible.
- **Integridad:** altera a mano un `ciphertext` en la BD → el receptor mostrará el mensaje como
  no verificado (la autenticación AES-GCM falla).
- **Caracteres y longitud:** envía emojis, chino, árabe, acentos y símbolos `<>&"'` y textos muy
  largos → deben llegar idénticos.
- **Round-trip en consola del navegador:** en `/chat`, abre la consola y ejecuta
  `await CriptoCore.selfTest()` → debe devolver `{ ..., pass: true }`. Genera dos pares de claves,
  cifra/descifra, verifica la firma y comprueba que un mensaje alterado se rechaza. (Es asíncrono.)
- **Demos de consola (Node, sin navegador):** `npm run demo` ejecuta una suite que valida las
  primitivas contra vectores oficiales (FIPS/RFC/NIST) y demuestra el flujo E2E, la integridad,
  los caracteres y el multi-dispositivo. Ver [`demos/README.md`](demos/README.md).

---

## 7. Estructura clave

```
app/Http/Controllers/Api/   KeyController, UserController, ConversationController, MessageController
app/Http/Controllers/       ChatController
app/Models/                 User, Conversation, Message
database/migrations/        public_key, conversations, conversation_user, messages
database/seeders/           TestUsersSeeder (Ana y Beto)
resources/js/crypto/        cripto-core.js   (núcleo KEM/DEM sobre Web Crypto API)
resources/js/               chat.js          (claves, cifrar/descifrar, polling, render)
resources/views/chat/       index.blade.php  (UI estilo Telegram)
routes/web.php              rutas web + API (auth de sesión Breeze, CSRF)
```

### Endpoints (todos bajo sesión autenticada)

| Método | Ruta | Función |
|---|---|---|
| POST | `/api/keys` | Subir la clave pública del usuario |
| GET | `/api/users` | Listar otros usuarios |
| GET | `/api/users/{id}/key` | Clave pública de un usuario |
| POST | `/api/conversations` | Crear/obtener conversación 1-a-1 |
| GET | `/api/conversations` | Mis conversaciones |
| GET | `/api/conversations/{id}/messages?after={id}` | Mensajes (polling) |
| POST | `/api/conversations/{id}/messages` | Enviar sobre cifrado |

El servidor valida la pertenencia a la conversación, pero **jamás descifra** el contenido.

---

## 8. Notas de alcance

Proyecto **académico**, diseñado desde el inicio sobre la **Web Crypto API** (primitivas nativas
y auditadas del navegador/Node). Mejoras posibles para un entorno real: claves
RSA ≥ 3072 bits (o migrar a curvas X25519/Ed25519), *forward secrecy* (estilo Signal), verificación
de identidad entre usuarios (huellas) y Argon2id en lugar de PBKDF2.

La portabilidad **multi-dispositivo** ya está implementada: la clave privada se envuelve con una
clave derivada de la contraseña (PBKDF2-HMAC-SHA256, 150 000 iteraciones) y se guarda cifrada en el
servidor, sin exponerla en claro. La contraseña se captura solo en el navegador (`sessionStorage`)
para derivar la clave; nunca se envía al servidor. Limitación conocida: si el usuario cambia su
contraseña, debe regenerarse el blob cifrado (no se re-envuelve automáticamente).
