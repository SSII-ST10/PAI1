"""
Tests de autenticación mediante PBKDF2 y protocolo Challenge-Response.

Vulnerabilidades cubiertas:
  - Contraseñas débiles: PBKDF2 con 100.000 iteraciones hace inviable
    la fuerza bruta incluso si el hash es robado.
  - Transmisión de contraseña en claro: el protocolo Challenge-Response
    nunca envía la contraseña; solo un HMAC que no puede revertirse.
  - Reutilización de respuestas: cada sesión usa un nonce único del servidor,
    por lo que la misma contraseña produce respuestas distintas.

Ejecución:
    python tests/test_autenticacion.py -v
"""

import hmac
import os
import sqlite3
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import db_helper
import seguridad


class _ConexionPersistente:
    """
    Wrapper sobre sqlite3.Connection que convierte close() en un no-op.
    sqlite3.Connection no permite asignar atributos en CPython, de modo que
    se usa composición para interceptar close() sin tocar el objeto real.
    """

    def __init__(self, conn):
        self._conn = conn

    def close(self):
        pass  # no-op: mantener la BD en memoria entre llamadas

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def cerrar_real(self):
        self._conn.close()


def _crear_bd_en_memoria():
    """BD SQLite en memoria con el esquema mínimo (tabla nonces)."""
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


class TestAutenticacion(unittest.TestCase):
    """Tests del protocolo de autenticación PBKDF2 + Challenge-Response."""

    def setUp(self):
        """Prepara credenciales fijas para simular un usuario registrado."""
        self.username = "alice"
        self.password_correcto = "alice123"
        self.password_incorrecto = "wrongpassword"

        # Simular el registro: salt aleatorio + hash PBKDF2 almacenado en BD
        self.salt = seguridad.generar_nonce(16)  # salt hexadecimal de 32 chars
        self.stored_hash = seguridad.pbkdf2_hash(self.password_correcto, self.salt)

        # Nonce que el servidor generaría para el challenge
        self.nonce_server = seguridad.generar_nonce()

        # BD en memoria y patcher para test_respuesta_challenge_reutilizada
        self._conn = _crear_bd_en_memoria()
        self._patcher = patch("db_helper.get_db_connection", return_value=self._conn)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        self._conn.cerrar_real()

    # ------------------------------------------------------------------
    # test_login_correcto
    # ------------------------------------------------------------------
    def test_login_correcto(self):
        """
        Con credenciales válidas, la respuesta del cliente debe coincidir
        con la verificación del servidor.

        Flujo simulado:
          Cliente: calcular_respuesta_challenge(password, salt, nonce_server)
          Servidor: verificar_respuesta_challenge(stored_hash, nonce_server)
          → ambas deben producir el mismo valor hexadecimal.
        """
        # Lado cliente: tiene la contraseña en texto plano
        respuesta_cliente = seguridad.calcular_respuesta_challenge(
            self.password_correcto, self.salt, self.nonce_server
        )

        # Lado servidor: solo tiene el hash almacenado en BD
        respuesta_esperada = seguridad.verificar_respuesta_challenge(
            self.stored_hash, self.nonce_server
        )

        self.assertTrue(
            hmac.compare_digest(respuesta_cliente, respuesta_esperada),
            "Con credenciales correctas, cliente y servidor deben coincidir.",
        )

    # ------------------------------------------------------------------
    # test_password_incorrecto
    # ------------------------------------------------------------------
    def test_password_incorrecto(self):
        """
        Con contraseña errónea, la respuesta del cliente no debe coincidir
        con la verificación del servidor.

        Vulnerabilidad probada: protección contra credenciales inválidas.
        Un atacante que intente autenticarse con una contraseña distinta
        obtendrá un PBKDF2 diferente → HMAC diferente → autenticación falla.
        """
        # El atacante usa una contraseña incorrecta
        respuesta_cliente_mala = seguridad.calcular_respuesta_challenge(
            self.password_incorrecto, self.salt, self.nonce_server
        )

        respuesta_esperada = seguridad.verificar_respuesta_challenge(
            self.stored_hash, self.nonce_server
        )

        self.assertFalse(
            hmac.compare_digest(respuesta_cliente_mala, respuesta_esperada),
            "Con contraseña incorrecta, la respuesta no debe coincidir con la esperada.",
        )

    # ------------------------------------------------------------------
    # test_challenge_response
    # ------------------------------------------------------------------
    def test_challenge_response(self):
        """
        Verifica la estructura matemática del protocolo Challenge-Response.

        El protocolo implementa dos pasos bien definidos:
          Paso 1: hash_base = PBKDF2-HMAC-SHA256(password, salt, 100.000 iter)
          Paso 2: respuesta = HMAC-SHA256(hash_base, nonce_server)

        Este test verifica que ambas funciones (cliente y servidor) siguen
        exactamente esta estructura y que son simétricas.
        """
        # Verificar la estructura paso a paso manualmente
        import hashlib
        from hashlib import pbkdf2_hmac

        # Paso 1: calcular hash_base como lo hace el cliente
        hash_base_manual = pbkdf2_hmac(
            "sha256",
            self.password_correcto.encode(),
            self.salt.encode(),
            100000,
        ).hex()

        # Paso 2: calcular HMAC como lo hace el cliente
        respuesta_manual = hmac.new(
            hash_base_manual.encode(),
            self.nonce_server.encode(),
            hashlib.sha256,
        ).hexdigest()

        # Comparar con la función de la librería
        respuesta_libreria = seguridad.calcular_respuesta_challenge(
            self.password_correcto, self.salt, self.nonce_server
        )

        self.assertEqual(
            respuesta_manual,
            respuesta_libreria,
            "calcular_respuesta_challenge() debe implementar HMAC(PBKDF2(pwd,salt), nonce).",
        )

        # El servidor aplica solo el Paso 2 (ya tiene el hash almacenado)
        respuesta_servidor = seguridad.verificar_respuesta_challenge(
            self.stored_hash, self.nonce_server
        )

        self.assertEqual(
            respuesta_manual,
            respuesta_servidor,
            "verificar_respuesta_challenge() debe producir el mismo resultado.",
        )

    # ------------------------------------------------------------------
    # test_salt_unico
    # ------------------------------------------------------------------
    def test_salt_unico(self):
        """
        La misma contraseña con salts distintos produce hashes diferentes.

        Vulnerabilidad probada: ataques de diccionario / rainbow tables.
        Si todos los usuarios con la misma contraseña tuviesen el mismo hash,
        romper uno equivaldría a romper todos. El salt único por usuario lo evita.
        """
        salt1 = seguridad.generar_nonce(16)
        salt2 = seguridad.generar_nonce(16)

        # Los salts son distintos (altamente improbable que colisionen)
        self.assertNotEqual(salt1, salt2, "generar_nonce() debe producir salts únicos.")

        hash1 = seguridad.pbkdf2_hash(self.password_correcto, salt1)
        hash2 = seguridad.pbkdf2_hash(self.password_correcto, salt2)

        self.assertNotEqual(
            hash1,
            hash2,
            "La misma contraseña con salts distintos debe producir hashes diferentes.",
        )

    # ------------------------------------------------------------------
    # test_respuesta_challenge_reutilizada
    # ------------------------------------------------------------------
    def test_respuesta_challenge_reutilizada(self):
        """
        Reutilizar la respuesta de un challenge anterior debe ser rechazado.

        Vulnerabilidad probada: replay del challenge-response.
        Aunque el atacante capture la respuesta válida de una sesión,
        no puede usarla en otra sesión porque el nonce_server es diferente.

        Este test usa la BD en memoria para verificar que el nonce del
        servidor no puede reutilizarse en un segundo intento de login.
        """
        nonce_sesion_1 = seguridad.generar_nonce()
        nonce_sesion_2 = seguridad.generar_nonce()

        # Respuesta capturada de la sesión 1
        respuesta_sesion_1 = seguridad.calcular_respuesta_challenge(
            self.password_correcto, self.salt, nonce_sesion_1
        )

        # El atacante intenta reutilizar esa respuesta en la sesión 2
        # (que tiene un nonce diferente)
        respuesta_esperada_sesion_2 = seguridad.verificar_respuesta_challenge(
            self.stored_hash, nonce_sesion_2
        )

        self.assertFalse(
            hmac.compare_digest(respuesta_sesion_1, respuesta_esperada_sesion_2),
            "La respuesta de la sesión 1 no debe ser válida para la sesión 2 "
            "(nonces distintos producen respuestas distintas).",
        )

        # Adicionalmente: el nonce del servidor no puede repetirse en la BD
        # (si se usase como nonce de operación)
        primera = db_helper.check_nonce_atomic(nonce_sesion_1)
        segunda = db_helper.check_nonce_atomic(nonce_sesion_1)

        self.assertTrue(primera, "El primer uso del nonce debe ser aceptado.")
        self.assertFalse(
            segunda,
            "El segundo uso del mismo nonce de sesión debe ser rechazado.",
        )


if __name__ == "__main__":
    unittest.main()
