import sqlite3
import time

DB_FILE = "sistema.db"


def get_db_connection():
    """
    Retorna conexión a la base de datos SQLite
    Returns:
        sqlite3.Connection
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Permite acceso por nombre de columna
    return conn


def check_nonce_atomic(nonce):
    """
    Verifica e inserta nonce de forma atómica
    Usa INSERT con try/except para detectar duplicados

    Args:
        nonce: str - nonce a verificar

    Returns:
        bool - True si el nonce es NUEVO (insertado correctamente)
               False si el nonce YA EXISTE (posible replay attack)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = int(time.time())

    try:
        cursor.execute(
            "INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (nonce, timestamp)
        )
        conn.commit()
        conn.close()
        return True  # Nonce nuevo, insertado correctamente
    except sqlite3.IntegrityError:
        # Nonce duplicado - PRIMARY KEY violation
        conn.close()
        return False  # Replay attack detectado


def cleanup_old_nonces():
    """
    Elimina nonces con más de 300 segundos (5 minutos)
    Debe ejecutarse periódicamente para evitar crecimiento infinito
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    limite = int(time.time()) - 300

    cursor.execute("DELETE FROM nonces WHERE timestamp < ?", (limite,))
    eliminados = cursor.rowcount
    conn.commit()
    conn.close()

    if eliminados > 0:
        print(f"[CLEANUP] {eliminados} nonces antiguos eliminados")

    return eliminados


def save_transaction(tx_id, origen, destino, cantidad, mac):
    """
    Guarda transacción en la base de datos

    Args:
        tx_id: str - ID único de la transacción
        origen: str - usuario origen
        destino: str - usuario destino
        cantidad: str - cantidad transferida
        mac: str - MAC de verificación
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = int(time.time())

    cursor.execute(
        "INSERT INTO transacciones (tx_id, origen, destino, cantidad, mac, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (tx_id, origen, destino, cantidad, mac, timestamp),
    )
    conn.commit()
    conn.close()


def get_user(username):
    """
    Obtiene datos de un usuario

    Args:
        username: str

    Returns:
        dict con keys 'password_hash' y 'salt', o None si no existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash, salt FROM usuarios WHERE username = ?", (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"password_hash": row["password_hash"], "salt": row["salt"]}
    return None


def save_user(username, password_hash, salt):
    """
    Guarda nuevo usuario en la base de datos

    Args:
        username: str
        password_hash: str
        salt: str

    Returns:
        bool - True si se guardó correctamente, False si ya existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO usuarios (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # Usuario ya existe
        conn.close()
        return False
