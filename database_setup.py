import sqlite3
import os
import secrets

DB_FILE = "sistema.db"


def crear_base_datos():
    """Crea todas las tablas necesarias para el sistema bancario"""

    # Eliminar DB existente si existe (fresh start)
    if os.path.exists(DB_FILE):
        print(f"[INFO] Base de datos existente encontrada: {DB_FILE}")
        respuesta = input("¿Desea eliminarla y crear una nueva? (s/n): ")
        if respuesta.lower() == "s":
            os.remove(DB_FILE)
            print("[OK] Base de datos anterior eliminada")
        else:
            print("[INFO] Manteniendo base de datos existente")
            return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Tabla usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    print("[OK] Tabla 'usuarios' creada")

    # Tabla nonces (con índice en timestamp para cleanup eficiente)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_nonces_timestamp 
        ON nonces(timestamp)
    """)
    print("[OK] Tabla 'nonces' creada con índice en timestamp")

    # Tabla config (para almacenar configuraciones del sistema)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    print("[OK] Tabla 'config' creada")

    # Tabla transacciones
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transacciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_id TEXT UNIQUE NOT NULL,
            origen TEXT NOT NULL,
            destino TEXT NOT NULL,
            cantidad TEXT NOT NULL,
            mac TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_transacciones_timestamp 
        ON transacciones(timestamp)
    """)
    print("[OK] Tabla 'transacciones' creada con índice en timestamp")

    conn.commit()

    # Poblar tabla usuarios con datos de ejemplo
    poblar_usuarios(cursor)

    conn.commit()
    conn.close()

    print("\n" + "=" * 50)
    print("[ÉXITO] Base de datos inicializada correctamente")
    print(f"Archivo: {DB_FILE}")
    print("=" * 50)
    print("\nPuede iniciar el servidor con: python serversocket.py")


def poblar_usuarios(cursor):
    """
    Pobla la tabla usuarios con datos de ejemplo usando PBKDF2
    """
    # Importar seguridad para usar PBKDF2
    try:
        import seguridad
    except ImportError:
        print(
            "[ADVERTENCIA] No se pudo importar seguridad.py, saltando población de usuarios"
        )
        return

    # Lista de usuarios de ejemplo para pruebas
    usuarios_ejemplo = [
        ("alice", "alice123"),
        ("bob", "bob123"),
        ("charlie", "charlie123"),
        ("admin", "admin123"),
        ("user1", "password1"),
        ("user2", "password2"),
    ]

    usuarios_creados = []

    for username, password in usuarios_ejemplo:
        salt = secrets.token_hex(16)
        password_hash = seguridad.pbkdf2_hash(password, salt)

        usuarios_creados.append(
            {
                "username": username,
                "password": password,
                "salt": salt,
                "hash": password_hash,
            }
        )

    # Insertar usuarios en la base de datos
    print("\n[INFO] Poblando tabla usuarios con datos de ejemplo:")
    for usuario in usuarios_creados:
        try:
            cursor.execute(
                "INSERT INTO usuarios (username, password_hash, salt) VALUES (?, ?, ?)",
                (usuario["username"], usuario["hash"], usuario["salt"]),
            )
            print(
                f"  - Usuario: {usuario['username']:12} | Password: {usuario['password']}"
            )
        except sqlite3.IntegrityError:
            print(f"  - Usuario {usuario['username']} ya existe, saltando...")

    print(f"\n[OK] {len(usuarios_creados)} usuarios poblados en la base de datos")


if __name__ == "__main__":
    crear_base_datos()
