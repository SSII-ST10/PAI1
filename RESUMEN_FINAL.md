# Resumen Final - PAI-1 Sistema Bancario Seguro

## ✅ Implementación Completada

### Archivos del Proyecto

```
C:\Users\addia\Code\Universidad\SSII\PAI1\
├── seguridad.py          ✅ Modificado - PBKDF2 y variable de entorno
├── database_setup.py     ✅ Nuevo - Inicialización DB con 6 usuarios
├── db_helper.py          ✅ Nuevo - Operaciones de base de datos
├── serversocket.py       ✅ Modificado - DB + rate limiting + respuesta detallada
├── client_gui.py         ✅ Modificado - Variable entorno + parseo respuesta
├── usuarios.db           ✅ Generado - Base de datos SQLite
├── VERIFICACION.md       ✅ Documentación completa
└── RESUMEN_FINAL.md      ✅ Este archivo
```

### Archivos Eliminados

- ❌ `usuarios.json` - Ya no se necesita (usuarios hardcodeados en database_setup.py)
- ❌ `transacciones.csv` - Reemplazado por tabla SQLite

---

## 🎯 Usuarios Pre-configurados

Al ejecutar `python database_setup.py`, se crean automáticamente estos usuarios:

| Username | Password | Hash Type |
|----------|----------|-----------|
| `alice` | `alice123` | PBKDF2 (100k iter) |
| `bob` | `bob123` | PBKDF2 (100k iter) |
| `charlie` | `charlie123` | PBKDF2 (100k iter) |
| `admin` | `admin123` | PBKDF2 (100k iter) |
| `user1` | `password1` | PBKDF2 (100k iter) |
| `user2` | `password2` | PBKDF2 (100k iter) |

---

## 🚀 Inicio Rápido

### 1. Inicializar Base de Datos
```bash
python database_setup.py
```

**Salida esperada:**
```
[OK] Tabla 'usuarios' creada
[OK] Tabla 'nonces' creada con índice en timestamp
[OK] Tabla 'config' creada
[OK] Tabla 'transacciones' creada con índice en timestamp

[INFO] Poblando tabla usuarios con datos de ejemplo:
  - Usuario: alice        | Password: alice123
  - Usuario: bob          | Password: bob123
  - Usuario: charlie      | Password: charlie123
  - Usuario: admin        | Password: admin123
  - Usuario: user1        | Password: password1
  - Usuario: user2        | Password: password2

[OK] 6 usuarios poblados en la base de datos

==================================================
[ÉXITO] Base de datos inicializada correctamente
==================================================
```

### 2. Iniciar Servidor (Terminal 1)
```bash
python serversocket.py
```

**Salida esperada:**
```
--- SERVIDOR LISTO EN localhost:3030 ---
```

### 3. Iniciar Cliente GUI (Terminal 2)
```bash
python client_gui.py
```

### 4. Probar el Sistema

1. **Conectar** → Click en "Conectar al Servidor"
2. **Login** → Pestaña "Iniciar Sesión"
   - Usuario: `alice`
   - Password: `alice123`
   - Click "Entrar"
3. **Transacción** → En dashboard:
   - Destino: `bob`
   - Cantidad: `100`
   - Click "Enviar Dinero 💸"

**Resultado esperado:**
```
Cliente muestra:
┌────────────────────────────────────┐
│ Transferencia realizada con éxito │
│                                    │
│ ID Transacción: a1b2c3d4e5f6...   │
│ Timestamp: 1708267890              │
│ Hash: f7e8d9c0b1a2...              │
└────────────────────────────────────┘

Servidor muestra:
[LOGIN OK] Usuario: alice
[TX OK] 100€ (alice->bob) | TX_ID: a1b2c3d4e5f6...
```

---

## 🔐 Características de Seguridad Implementadas

### ✅ 1. PBKDF2-HMAC-SHA256
- **100,000 iteraciones** - Resistente a ataques de fuerza bruta
- **Salt único por usuario** - 16 bytes aleatorios
- **Challenge-response** - Hash en dos fases para login

### ✅ 2. Protección Anti-Replay
- **Nonces persistentes** - Almacenados en SQLite
- **Verificación atómica** - INSERT con IntegrityError
- **Cleanup automático** - Cada 5 minutos (>300 segundos)

### ✅ 3. Rate Limiting
- **10 requests/minuto** por IP
- **Diccionario en memoria** - No persistente
- **Limpieza automática** - Timestamps antiguos eliminados

### ✅ 4. Integridad de Mensajes
- **HMAC-SHA256** - Para todas las transacciones
- **Clave desde variable de entorno** - `BANCO_MAC_KEY`
- **Verificación en servidor** - Antes de procesar

### ✅ 5. Respuesta de Transacción Detallada
- **Formato:** `OK|TX_ID|TIMESTAMP|HASH`
- **TX_ID único:** 32 caracteres hex
- **Timestamp:** Unix epoch
- **Hash verificable:** SHA-256(TX_ID + TIMESTAMP)

---

## 📊 Estructura de Base de Datos

### Tabla: `usuarios`
```sql
CREATE TABLE usuarios (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,  -- PBKDF2 hex (128 chars)
    salt TEXT NOT NULL             -- 32 chars hex
);
```

### Tabla: `nonces`
```sql
CREATE TABLE nonces (
    nonce TEXT PRIMARY KEY,        -- 32 chars hex
    timestamp INTEGER NOT NULL     -- Unix epoch
);
CREATE INDEX idx_nonces_timestamp ON nonces(timestamp);
```

### Tabla: `transacciones`
```sql
CREATE TABLE transacciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id TEXT UNIQUE NOT NULL,    -- 32 chars hex
    origen TEXT NOT NULL,
    destino TEXT NOT NULL,
    cantidad TEXT NOT NULL,
    mac TEXT NOT NULL,             -- HMAC-SHA256 hex
    timestamp INTEGER NOT NULL     -- Unix epoch
);
CREATE INDEX idx_transacciones_timestamp ON transacciones(timestamp);
```

### Tabla: `config`
```sql
CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## 🧪 Comandos de Verificación

### Ver usuarios en DB:
```bash
python -c "import sqlite3; conn = sqlite3.connect('usuarios.db'); cursor = conn.cursor(); cursor.execute('SELECT username FROM usuarios'); print([row[0] for row in cursor.fetchall()]); conn.close()"
```

### Ver transacciones:
```bash
python -c "import sqlite3; conn = sqlite3.connect('usuarios.db'); cursor = conn.cursor(); cursor.execute('SELECT tx_id, origen, destino, cantidad FROM transacciones'); print(cursor.fetchall()); conn.close()"
```

### Contar nonces activos:
```bash
python -c "import sqlite3; conn = sqlite3.connect('usuarios.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM nonces'); print(f'Nonces: {cursor.fetchone()[0]}'); conn.close()"
```

### Verificar hash PBKDF2:
```bash
python -c "import seguridad; hash = seguridad.pbkdf2_hash('alice123', 'testsalt'); print(f'Hash: {hash[:32]}...')"
```

---

## 🎓 Requisitos Cumplidos

### Requisito 1: seguridad.py ✅
- [x] Eliminada `CLAVE_MAC` hardcodeada
- [x] Función `obtener_clave_mac()` con variable de entorno
- [x] Función `pbkdf2_hash()` con 100,000 iteraciones
- [x] Default: `'desarrollo_inseguro_32bytes_clave'`

### Requisito 2: database_setup.py ✅
- [x] Tabla `usuarios` (username, password_hash, salt)
- [x] Tabla `nonces` (nonce, timestamp) + índice
- [x] Tabla `config` (key, value)
- [x] Tabla `transacciones` (id, tx_id, origen, destino, cantidad, mac, timestamp) + índice
- [x] Ejecutable standalone: `python database_setup.py`

### Requisito 3: db_helper.py ✅
- [x] `get_db_connection()` - Retorna SQLite connection
- [x] `check_nonce_atomic()` - INSERT + IntegrityError
- [x] `cleanup_old_nonces()` - DELETE WHERE timestamp < now - 300
- [x] `save_transaction()` - Guarda TX con detalles
- [x] `get_user()` / `save_user()` - CRUD de usuarios

### Requisito 4: serversocket.py ✅
- [x] Usa `db_helper` (no JSON/CSV)
- [x] Rate limiting: 10 req/min por IP (diccionario en memoria)
- [x] Nonce persistente con `check_nonce_atomic()`
- [x] Cleanup periódico cada 100 requests
- [x] Respuesta TX: `"OK|TX_ID|TIMESTAMP|HASH"`
- [x] Usa `seguridad.obtener_clave_mac()`

### Requisito 5: client_gui.py ✅
- [x] NO lee clave MAC del servidor
- [x] Usa variable entorno `BANCO_MAC_KEY`
- [x] Parsea respuesta: `"OK|TX_ID|TIMESTAMP|HASH"`
- [x] Muestra detalles en messagebox
- [x] Manejo de rate limit

### Requisitos Generales ✅
- [x] Solo archivos `.py` (sin `.sh`, `.bat`, Docker)
- [x] Logging con `print()` simple
- [x] Base de datos SQLite (usuarios.db)
- [x] Usuarios hardcodeados en `database_setup.py`
- [x] NO usa `usuarios.json` (eliminado)

---

## 🔧 Variable de Entorno

### Usar Default (Desarrollo):
No configurar nada. Se usa automáticamente:
```
BANCO_MAC_KEY = 'desarrollo_inseguro_32bytes_clave'
```

### Configurar Manualmente:

**Windows PowerShell:**
```powershell
$env:BANCO_MAC_KEY="mi_clave_secreta_32_bytes_min"
python serversocket.py
```

**Windows CMD:**
```cmd
set BANCO_MAC_KEY=mi_clave_secreta_32_bytes_min
python serversocket.py
```

**Linux/Mac:**
```bash
export BANCO_MAC_KEY="mi_clave_secreta_32_bytes_min"
python serversocket.py
```

**IMPORTANTE:** Cliente y servidor deben usar la MISMA clave.

---

## 📝 Notas Finales

1. **Usuarios pre-configurados** - Listos para pruebas inmediatas
2. **Sin dependencias externas** - Solo Python stdlib
3. **Base de datos persistente** - Sobrevive a reinicios del servidor
4. **Nonces con cleanup** - Automático cada 100 requests
5. **Rate limiting en memoria** - Se resetea al reiniciar servidor
6. **Documentación completa** - Ver VERIFICACION.md

---

## ✅ Lista de Verificación Final

- [x] Base de datos inicializada
- [x] 6 usuarios creados con PBKDF2
- [x] Servidor funcional con rate limiting
- [x] Cliente GUI funcional
- [x] Protección anti-replay persistente
- [x] Transacciones con ID único
- [x] Variable de entorno configurada
- [x] Documentación completa
- [x] `usuarios.json` eliminado

---

## 🎯 Estado del Proyecto

**✅ IMPLEMENTACIÓN 100% COMPLETA**

Todos los requisitos han sido implementados y verificados. El sistema está listo para:
- Demostración
- Pruebas de seguridad
- Evaluación académica

Para cualquier duda, consultar `VERIFICACION.md` para detalles técnicos completos.
