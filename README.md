# 2FA (TOTP) desde cero + Step-Up Auth observable con Prefect
# Ya se califico en Clase

Prueba de concepto del laboratorio de **Patrones Arquitectónicos Avanzados**:

- **`mobile-authenticator/`**: app Authenticator propia (Expo / React Native) que calcula códigos TOTP de 6 dígitos cada 30 s **sin conexión**. El algoritmo (RFC 6238 / RFC 4226) está implementado a mano; solo se usa una librería para el HMAC-SHA1.
- **`backend-prefect/`**: API FastAPI con autenticación escalonada (Step-Up), máquina de estados de aprovisionamiento, patrón Strategy para el segundo factor y protección anti-replay. Cada login y verificación ejecuta un `@flow` de Prefect cuyas `@task` se ven en vivo en el dashboard. Incluye la web de login (HTML + JS, servida por FastAPI).
- **Supabase (Postgres)** guarda usuarios, configuración 2FA y códigos de respaldo.

```
                        (sin red: modo avión)
┌────────────────────┐   escanea el QR una vez    ┌──────────────────────────────┐
│  App móvil (Expo)  │ ◀───────────────────────── │  Web (index/enroll/verify/   │
│  HMAC-SHA1(secreto,│                            │       vault .html)           │
│   unix_time // 30) │   el usuario teclea el     └──────────────┬───────────────┘
└────────────────────┘   código de 6 dígitos ───────────────────▶│ HTTP
                                                                  ▼
                                   ┌───────────────────────────────────────────────┐
                                   │ FastAPI  /auth/login  /auth/verify-2fa  ...   │
                                   │   └─ invoca @flow de Prefect por petición     │
                                   └───────┬─────────────────────────┬─────────────┘
                                           │                         │ estados y logs
                                           ▼                         ▼
                                   Supabase (Postgres)       Prefect server :4200
```

---

## Requisitos

| Herramienta | Versión probada |
|---|---|
| Python | 3.12 |
| Node.js | 22 |
| Proyecto de Supabase | plan gratuito |
| iPhone o Android con **Expo Go** (opcional) | Expo SDK 58 |

---

## 1. Configurar Supabase (una sola vez)

1. En el **SQL Editor** de Supabase ejecutar [`backend-prefect/sql/schema.sql`](backend-prefect/sql/schema.sql).
   Crea las tablas `users`, `mfa_configs` (con el secreto TOTP cifrado) y `backup_codes`, el enum `mfa_status` y activa Row Level Security.
2. Copiar la cadena de conexión de **Connect → Session pooler** (no "Direct connection": en el plan gratuito esa solo funciona por IPv6).
3. Crear el `.env`:

   ```bash
   cd backend-prefect
   cp .env.example .env
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"                           # pegar como JWT_SECRET
   python3 -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"  # pegar como MFA_ENCRYPTION_KEY
   ```

   y completar `DATABASE_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres`.
   Si la contraseña tiene `@ # / : %`, debe ir URL-encoded (`@` → `%40`).

   `MFA_ENCRYPTION_KEY` cifra los secretos TOTP en la base de datos (ver sección 7). Si se pierde, los usuarios deben volver a activar el 2FA.

> **Base de datos creada con una versión anterior** (columna `secret_base32` en texto plano): después de configurar `MFA_ENCRYPTION_KEY`, ejecutar
> `.venv/bin/python scripts/encrypt_existing_secrets.py --dry-run` y luego sin `--dry-run`. Renombra la columna, cifra los secretos existentes y agrega la restricción que impide guardar texto plano. Los usuarios conservan sus códigos: el secreto no cambia, solo cómo se guarda.

## 2. Instalar el backend

```bash
cd backend-prefect
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## 3. Levantar todo (3 terminales)

**Terminal 1: servidor de Prefect**

```bash
cd backend-prefect
.venv/bin/prefect server start
```

Dashboard en http://127.0.0.1:4200

**Terminal 2: API + web**

```bash
cd backend-prefect
.venv/bin/uvicorn app.main:app --reload
```

- Web: http://127.0.0.1:8000
- Documentación interactiva de la API: http://127.0.0.1:8000/docs

El backend lee `PREFECT_API_URL` del `.env`, así que los flows aparecen en el servidor de la terminal 1.
Usar **un solo proceso** de uvicorn: la caché anti-replay y el límite de intentos viven en memoria.

**Terminal 3: app móvil**

```bash
cd mobile-authenticator
npm install
npx expo start          # luego "w" para abrir en el navegador, o escanear el QR con el iPhone
```

- **En el PC (Expo web):** `npx expo start --web`. Sin cámara: usar "Ingresar clave manualmente" y pegar la clave que muestra la web.
- **En el teléfono:** instalar **Expo Go** y escanear el QR de la terminal con la cámara. El teléfono y el PC deben estar en la misma red Wi-Fi. Si no conecta: `npx expo start --tunnel`.

---

## 4. Uso

1. En http://127.0.0.1:8000 crear una cuenta e iniciar sesión. Se recibe un `pre_auth_token` (no da acceso a nada protegido).
2. Como el 2FA está `DISABLED`, la web lleva a **Activar 2FA**: muestra un QR y la clave en Base32. El estado pasa a `PENDING_VERIFICATION`.
3. En la app: **Agregar cuenta** → escanear el QR o pegar la clave.
4. Escribir en la web el código que muestra la app. El estado pasa a `ACTIVE`; se muestran **10 códigos de respaldo** (una sola vez) y se entra a la bóveda.
5. Desde ahora, cada login pide el código: `/auth/login` → `pre_auth_token` → `/auth/verify-2fa` → `access_token` con `mfa_verified: true` → `GET /api/boveda-secreta`.

---

## 5. Guion de las pruebas de aceptación

Tener abiertos: la web, la app y el **Prefect UI → Runs**.

### Prueba 1: Paridad estándar

1. Iniciar sesión con un usuario nuevo y llegar a la página **Activar 2FA**.
2. Escanear el **mismo QR** con la app del equipo y con Google/Microsoft Authenticator.
3. Ambas muestran **el mismo código al mismo tiempo**, y cambian juntas al terminar la ventana de 30 s.

Por qué funciona: la app implementa RFC 6238 tal cual. Los tests verifican los vectores oficiales de RFC 4226 y RFC 6238, y que la app y el backend en Python generan el mismo código.

### Prueba 2: Modo avión

1. Con la app abierta, activar **modo avión** en el teléfono.
2. Esperar a que la barra llegue a 0 y el código cambie: la app no necesita red, solo el reloj.
3. En la web (PC): iniciar sesión y escribir el código. Se abre `GET /api/boveda-secreta`.

> Con Expo Go el código JS se descarga desde el PC al abrir la app: abrirla **antes** de activar el modo avión y no recargarla. Después funciona sin conexión.

### Prueba 3: Ataque de repetición (anti-replay)

1. Iniciar sesión y verificar con un código: entra a la bóveda.
2. **Cerrar sesión, iniciar sesión otra vez y enviar el mismo código** antes de que cambie.
3. La web muestra *"Este código ya fue usado: ataque de repetición bloqueado"* (HTTP **409**).
4. En Prefect: el flow `verify-2fa-totp` aparece **Failed** (rojo); `validate_pre_auth_state` está Completed y **`check_anti_replay_cache` está Failed**, con el log `REPLAY ATTACK: code ****NN was already used...`.

### Prueba 4: Desfase de reloj o código de respaldo

**Ventana TOTP:** abrir en Prefect el último `verify-2fa-totp` y ver el log de `execute_mfa_strategy`:

```
code matched window C-1 (counter 59762072)
TOTP window C-1: phone clock is behind the server, or the code was sent right after it rolled over
```

Para forzar `C-1`: copiar el código cuando a la barra le quedan ~3 s y enviarlo justo después del cambio. La bóveda también muestra la ventana usada.

**Código de respaldo:** en la página de verificación elegir *Código de respaldo* y escribir uno de los 10 códigos (`K7QX2-MNP4R`, con o sin guion). El log muestra `BackupCodeStrategy` y cuántos códigos quedan. Reusar el mismo código falla.

---

## 6. Patrones implementados

| Patrón | Dónde | Cómo |
|---|---|---|
| **Máquina de estados / Process Manager** | [`app/mfa/state.py`](backend-prefect/app/mfa/state.py), [`flows/provisioning_flow.py`](backend-prefect/app/flows/provisioning_flow.py) | `DISABLED → PENDING_VERIFICATION → ACTIVE`. Solo el primer código válido de la app activa el 2FA; si el usuario nunca escanea el QR sigue en `PENDING` y puede volver a intentarlo sin quedar bloqueado. Las transiciones se validan en código y otra vez en el `UPDATE ... WHERE status = ...` de la base de datos. |
| **Step-Up Authentication** | [`security/tokens.py`](backend-prefect/app/security/tokens.py), [`deps.py`](backend-prefect/app/deps.py) | `pre_auth_token` (scope `pre_auth`, 5 min) solo sirve para `/auth/verify-2fa` y `/2fa/*`. El `access_token` (scope `access`, `mfa_verified: true`) es el único aceptado por `/api/boveda-secreta`. |
| **Strategy** | [`mfa/strategies/`](backend-prefect/app/mfa/strategies/) | `SecondFactorStrategy` con `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (un solo uso). Una factory elige según `method: "totp" \| "backup"`. |
| **Anti-replay / idempotencia** | [`mfa/replay_cache.py`](backend-prefect/app/mfa/replay_cache.py) | Caché en memoria de `(user_id, código)` por 90 s (3 ventanas × 30 s). |

### Flows y tasks de Prefect

| Flow | Tasks |
|---|---|
| `login` | `verify_credentials` → `issue_pre_auth_token` |
| `enroll-2fa` | `validate_pre_auth_state` → `start_enrollment` |
| `activate-2fa` | `validate_pre_auth_state` → `check_anti_replay_cache` → `verify_enrollment_code` → `activate_mfa` → `issue_elevated_session` |
| `verify-2fa` | `validate_pre_auth_state` → `check_anti_replay_cache` → `execute_mfa_strategy` → `issue_elevated_session` |

Contraseñas, códigos y tokens se pasan como `SecretStr`: en el Prefect UI los parámetros aparecen como `**********` y los logs solo muestran los 2 últimos dígitos del código. Las tasks no guardan resultados ni caché.

### Endpoints

| Método y ruta | Autenticación | Respuesta |
|---|---|---|
| `POST /auth/register` | — | 201 · 409 si el usuario existe |
| `POST /auth/login` | — | `pre_auth_token`, `next_step` (`enroll-2fa` / `verify-2fa`) |
| `POST /2fa/enroll` | Bearer `pre_auth_token` | `otpauth_uri`, `secret`, `qr_svg` |
| `POST /2fa/activate` | Bearer `pre_auth_token` | `access_token`, `backup_codes`, `window` |
| `POST /auth/verify-2fa` | Bearer `pre_auth_token` | `access_token`, `mfa_method`, `window` |
| `GET /api/boveda-secreta` | Bearer `access_token` | recurso protegido |

Errores: `{"error": "...", "detail": "..."}`. **401** credenciales, token o código inválidos · **409** replay detectado · **429** demasiados intentos.

---

## 7. Decisiones de seguridad (más allá de la guía)

### El secreto TOTP se cifra, no se hashea

| Dato | Cómo se guarda | Por qué |
|---|---|---|
| Contraseña | Hash bcrypt | El servidor solo necesita compararla |
| Códigos de respaldo | Hash SHA-256 | El servidor solo necesita compararlos |
| Secreto TOTP | **Cifrado AES-256-GCM** | El servidor necesita el secreto original para calcular `HMAC-SHA1(secreto, hora // 30)`; un hash no se puede revertir y haría imposible verificar códigos |

- En `mfa_configs.secret_encrypted` solo se guarda `v1:<nonce>:<texto cifrado>`. La llave (`MFA_ENCRYPTION_KEY`) está en el `.env` del backend, nunca en la base de datos ni en Git.
- El secreto se descifra solo en memoria, en [`repositories.py`](backend-prefect/app/repositories.py), en el momento de verificar un código; no aparece en logs, en Prefect ni en respuestas HTTP.
- Cada cifrado usa un nonce aleatorio (dos usuarios con el mismo secreto no se ven iguales) y el `user_id` como dato asociado: copiar el secreto cifrado de un usuario a otra fila hace fallar el descifrado. GCM también detecta cualquier modificación del texto cifrado.
- La restricción `secret_is_encrypted` de Postgres rechaza cualquier valor que no tenga el formato cifrado, aunque el código tuviera un error.
- **Qué protege:** una filtración solo de la base de datos (backup, inyección SQL, acceso indebido a Supabase). **Qué no protege:** un atacante con control total del servidor (base de datos + `.env`). En producción la llave iría en un servicio como AWS KMS o HashiCorp Vault. La única forma de no tener ningún secreto compartido en el servidor es usar otra tecnología (WebAuthn / passkeys), que no es TOTP.

### Otras decisiones

- **Límite de intentos:** tras 5 códigos fallidos (incorrectos o repetidos) con el mismo `pre_auth_token`, se responde 429 y hay que volver a ingresar la contraseña. Sin esto, 5 minutos de fuerza bruta contra 3 de 10⁶ códigos serían un riesgo real.
- **`pre_auth_token` de un solo uso:** una vez canjeado por un `access_token` no sirve de nuevo.
- **Carrera en el anti-replay:** la guía revisa la caché en la Task 2 y marca el código en la Task 4. Si dos peticiones con el mismo código pasan la Task 2 a la vez, `issue_elevated_session` vuelve a comprobar de forma atómica y rechaza la segunda.
- **Clave de la caché:** se usa `(user_id, código)` como pide la guía. Una alternativa algo más fuerte es `(user_id, contador que hizo match)`, que impide reutilizar la misma ventana aunque el código fuera distinto.
- **Códigos de respaldo:** se guardan con SHA-256 (son aleatorios de 50 bits; bcrypt solo hace falta para contraseñas elegidas por personas) y se consumen con un `UPDATE ... WHERE used_at IS NULL RETURNING`, seguro ante peticiones simultáneas.
- **Login:** un usuario inexistente tarda lo mismo que una contraseña incorrecta, para no revelar qué usuarios existen.
- **Supabase:** RLS activado sin políticas, para que la API REST pública (anon key) no exponga hashes ni secretos. El backend se conecta como `postgres` y no se ve afectado.
- **App móvil:** los secretos se guardan en `expo-secure-store` (Keychain / Keystore). En web, en `localStorage`, solo para desarrollo.

### Limitaciones conocidas (aceptables en un laboratorio)

- La caché anti-replay y el límite de intentos están en memoria: se pierden al reiniciar y no se comparten entre procesos. En producción irían en Redis.
- La llave de cifrado está en el `.env`, no en un gestor de llaves (KMS / Vault), y no hay rotación automática (el prefijo `v1:` deja preparado el formato para hacerla).
- No hay flujo para desactivar o rotar el 2FA una vez `ACTIVE`.

---

## 8. Tests

```bash
# Backend: TOTP, strategies, estados, tokens, flows (con un servidor Prefect temporal) y API (~2.5 min)
cd backend-prefect && .venv/bin/pytest

# Backend contra Supabase real (crea y borra un usuario temporal)
cd backend-prefect && RUN_DB_TESTS=1 .venv/bin/pytest tests/test_repositories_integration.py

# App móvil: Base32, HOTP, TOTP, parser otpauth://
cd mobile-authenticator && npm test && npm run typecheck && npm run lint
```

---

## 9. Problemas comunes

| Síntoma | Causa / solución |
|---|---|
| `missing "=" after ... in connection info string` | A `DATABASE_URL` le falta el prefijo `postgresql://`. |
| `MFA_ENCRYPTION_KEY must be 32 random bytes in base64` | Falta la llave en el `.env` o no tiene el formato correcto; generarla con el comando de la sección 1. |
| `column "secret_encrypted" does not exist` | La base de datos es de una versión anterior: ejecutar `scripts/encrypt_existing_secrets.py`. |
| `TOTP secret could not be decrypted` | La llave del `.env` no es la misma con la que se cifraron los secretos. |
| No aparecen runs en Prefect | El servidor de la terminal 1 no está corriendo, o `PREFECT_API_URL` no está en el `.env`. |
| El código de la app nunca es aceptado | Se volvió a generar el QR (re-enrolamiento) después de escanearlo: escanear el nuevo; la app reemplaza la clave de la cuenta con el mismo nombre. |
| Siempre `C-1` o `C+1` | El reloj del teléfono o del PC está desfasado; activar la hora automática. |
| Expo Go no conecta al PC | Misma red Wi-Fi; revisar el firewall (puerto 8081) o usar `npx expo start --tunnel`. |
| `Este código ya fue usado` en el primer intento | El mismo código se usó al activar el 2FA; esperar al siguiente. |
