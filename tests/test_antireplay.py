"""
Tests anti-replay mediante verificación de nonces en base de datos.

Vulnerabilidad cubierta: ataques de repetición (replay attacks).
Un atacante que capture un mensaje válido (registro o transacción) no puede
reenviarlo porque el nonce único que incluye ya fue registrado en la BD.
La unicidad se garantiza con PRIMARY KEY + INSERT atómico.

Los tests usan una base de datos SQLite en memoria para no afectar
el archivo sistema.db de producción.

Ejecución:
    python tests/test_antireplay.py -v
"""

import os
import sqlite3
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import db_helper
import seguridad


class _ConexionPersistente:
    """
    Wrapper sobre sqlite3.Connection que convierte close() en un no-op.

    db_helper abre y cierra la conexión dentro de cada función. Para tests
    con BD en memoria, cerrar la conexión destruiría los datos. Este wrapper
    delega todo en la conexión real excepto close(), que no hace nada.
    sqlite3.Connection no permite asignar atributos directamente en CPython,
    por lo que se usa composición en lugar de monkey-patching.
    """

    def __init__(self, conn):
        self._conn = conn

    def close(self):
        pass  # no-op: mantener la BD en memoria entre llamadas

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def cerrar_real(self):
        """Cierra la conexión real subyacente (llamar en tearDown)."""
        self._conn.close()


def _crear_bd_en_memoria():
    """
    Crea una conexión SQLite en memoria con el esquema mínimo necesario
    (tabla nonces) para testear db_helper sin tocar sistema.db.
    Devuelve un _ConexionPersistente que no se destruye al llamar a close().
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE nonces (
            nonce     TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    return _ConexionPersistente(conn)


class TestAntiReplay(unittest.TestCase):
    """Tests de protección anti-replay basada en nonces únicos."""

    def setUp(self):
        """
        Crea una BD en memoria nueva antes de cada test.
        Se parchea get_db_connection para que devuelva siempre esta conexión
        sin cerrarla (close() se convierte en no-op para mantener los datos
        entre las múltiples aperturas que hace cada función de db_helper).
        """
        self._conn = _crear_bd_en_memoria()

        self._patcher = patch("db_helper.get_db_connection", return_value=self._conn)
        self._patcher.start()

    def tearDown(self):
        """Para el patcher y cierra la conexión real al finalizar cada test."""
        self._patcher.stop()
        self._conn.cerrar_real()

    # ------------------------------------------------------------------
    # test_nonce_valido
    # ------------------------------------------------------------------
    def test_nonce_valido(self):
        """
        Un nonce nuevo (nunca visto) debe ser aceptado.

        Comportamiento esperado: check_nonce_atomic() inserta el nonce en BD
        y retorna True, permitiendo que la operación continúe.
        """
        nonce_nuevo = seguridad.generar_nonce()

        resultado = db_helper.check_nonce_atomic(nonce_nuevo)

        self.assertTrue(
            resultado,
            f"Un nonce nuevo '{nonce_nuevo[:8]}...' debe ser aceptado (True).",
        )

    # ------------------------------------------------------------------
    # test_nonce_repetido_inmediato
    # ------------------------------------------------------------------
    def test_nonce_repetido_inmediato(self):
        """
        Reusar el mismo nonce de forma inmediata debe ser rechazado.

        Vulnerabilidad probada: replay attack. El atacante captura el
        mensaje legítimo y lo reenvía sin modificarlo. El servidor detecta
        que el nonce ya está registrado y rechaza la segunda petición.
        """
        nonce = seguridad.generar_nonce()

        # Primera vez: debe ser aceptado
        primera = db_helper.check_nonce_atomic(nonce)
        self.assertTrue(primera, "La primera inserción del nonce debe ser True.")

        # Segunda vez (inmediata): debe ser rechazado
        segunda = db_helper.check_nonce_atomic(nonce)

        self.assertFalse(
            segunda,
            f"El nonce '{nonce[:8]}...' ya existe; debe ser rechazado (False).",
        )

    # ------------------------------------------------------------------
    # test_nonce_persistencia
    # ------------------------------------------------------------------
    def test_nonce_persistencia(self):
        """
        El nonce debe estar físicamente persistido en la BD después de insertarlo.

        Verifica que check_nonce_atomic() realmente escribe en la tabla
        y no solo mantiene el estado en memoria.
        """
        nonce = seguridad.generar_nonce()
        db_helper.check_nonce_atomic(nonce)

        # Consulta directa a la BD en memoria para verificar persistencia
        cursor = self._conn.execute(
            "SELECT nonce FROM nonces WHERE nonce = ?", (nonce,)
        )
        fila = cursor.fetchone()

        self.assertIsNotNone(
            fila,
            f"El nonce '{nonce[:8]}...' debe estar persistido en la tabla nonces.",
        )
        self.assertEqual(
            fila["nonce"],
            nonce,
            "El nonce almacenado debe coincidir exactamente con el nonce insertado.",
        )

    # ------------------------------------------------------------------
    # test_cleanup_nonces
    # ------------------------------------------------------------------
    def test_cleanup_nonces(self):
        """
        Los nonces con más de 300 segundos deben eliminarse en el cleanup.

        Verifica que cleanup_old_nonces() borra nonces caducados pero
        preserva los recientes. Esto evita el crecimiento infinito de la
        tabla sin abrir una ventana de replay.
        """
        ahora = int(time.time())
        nonce_antiguo = "nonce_antiguo_caducado_" + seguridad.generar_nonce()
        nonce_reciente = seguridad.generar_nonce()

        # Insertar nonce con timestamp hace 400 segundos (debe eliminarse)
        self._conn.execute(
            "INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)",
            (nonce_antiguo, ahora - 400),
        )
        # Insertar nonce reciente (debe conservarse)
        self._conn.execute(
            "INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)",
            (nonce_reciente, ahora),
        )
        self._conn.commit()

        eliminados = db_helper.cleanup_old_nonces()

        self.assertGreaterEqual(
            eliminados,
            1,
            "cleanup_old_nonces() debe eliminar al menos 1 nonce antiguo (>300s).",
        )

        # El nonce reciente debe seguir existiendo
        cursor = self._conn.execute(
            "SELECT nonce FROM nonces WHERE nonce = ?", (nonce_reciente,)
        )
        self.assertIsNotNone(
            cursor.fetchone(),
            "El nonce reciente no debe ser eliminado por el cleanup.",
        )

        # El nonce antiguo debe haber sido eliminado
        cursor = self._conn.execute(
            "SELECT nonce FROM nonces WHERE nonce = ?", (nonce_antiguo,)
        )
        self.assertIsNone(
            cursor.fetchone(),
            "El nonce antiguo (>300s) debe haber sido eliminado por el cleanup.",
        )

    # ------------------------------------------------------------------
    # Test adicional: múltiples nonces distintos son todos aceptados
    # ------------------------------------------------------------------
    def test_nonces_distintos_son_aceptados(self):
        """
        Múltiples nonces distintos deben ser aceptados individualmente.

        Confirma que el mecanismo no bloquea por volumen, solo por
        reutilización del mismo nonce (identificador único de mensaje).
        """
        nonces = [seguridad.generar_nonce() for _ in range(5)]
        resultados = [db_helper.check_nonce_atomic(n) for n in nonces]

        self.assertTrue(
            all(resultados),
            "Cada nonce único debe ser aceptado independientemente.",
        )


if __name__ == "__main__":
    unittest.main()
