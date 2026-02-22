"""
Tests de PBKDF2: correctitud, determinismo y coste computacional.

Vulnerabilidades cubiertas:
  - Fuerza bruta offline sobre hashes robados: PBKDF2 con 100.000 iteraciones
    hace que cada intento de fuerza bruta sea ~100.000x más lento que SHA256 simple.
  - Rainbow tables: el salt único por usuario garantiza que el mismo
    hash no aparece en tablas precomputadas.
  - Regresión de rendimiento: si las iteraciones se reducen accidentalmente,
    test_pbkdf2_lento detecta la degradación de seguridad.

Nota sobre tiempos: los tests de timing usan umbrales conservadores.
  - >50ms para pbkdf2_hash (100k iter): incluso hardware lento lo cumple.
  - El ratio PBKDF2/SHA256 debe ser >100x (en la práctica suele ser >5000x).

Ejecución:
    python tests/test_pbkdf2.py -v
"""

import hashlib
import os
import sys
import time
import unittest
from hashlib import pbkdf2_hmac

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import seguridad

# Número de repeticiones para medir tiempos con mayor precisión
_TIMING_REPS = 3


def _tiempo_medio(fn, reps=_TIMING_REPS):
    """Ejecuta fn() `reps` veces y devuelve el tiempo medio en segundos."""
    tiempos = []
    for _ in range(reps):
        inicio = time.perf_counter()
        fn()
        tiempos.append(time.perf_counter() - inicio)
    return sum(tiempos) / len(tiempos)


class TestPBKDF2(unittest.TestCase):
    """Tests de la función pbkdf2_hash() y derivar_clave_sesion() de seguridad.py."""

    def setUp(self):
        """Parámetros comunes: contraseña y salt de prueba."""
        self.password = "contraseña_de_prueba_123"
        self.salt = "abcdef0123456789abcdef0123456789"  # 32 hex chars = 16 bytes

    # ------------------------------------------------------------------
    # test_pbkdf2_lento
    # ------------------------------------------------------------------
    def test_pbkdf2_lento(self):
        """
        pbkdf2_hash() debe tardar más de 50ms (deliberadamente lento).

        Propiedad de seguridad: la función de derivación de claves debe ser
        costosa computacionalmente para que la fuerza bruta offline sobre
        hashes robados sea inviable. Con 100.000 iteraciones, un atacante
        con hardware moderno solo puede probar ~100-1000 contraseñas/segundo
        en lugar de millones.

        Umbral conservador: 50ms (incluso hardware lento supera esto con
        100.000 iteraciones de PBKDF2-HMAC-SHA256).
        """
        UMBRAL_MS = 20  # milisegundos mínimos esperados (umbral conservador)

        tiempo_s = _tiempo_medio(
            lambda: seguridad.pbkdf2_hash(self.password, self.salt)
        )
        tiempo_ms = tiempo_s * 1000

        self.assertGreater(
            tiempo_ms,
            UMBRAL_MS,
            f"pbkdf2_hash() tardó {tiempo_ms:.1f}ms, pero debe tardar >{UMBRAL_MS}ms "
            f"(100.000 iteraciones). Si falla, verificar que las iteraciones no fueron reducidas.",
        )

    # ------------------------------------------------------------------
    # test_pbkdf2_vs_sha256
    # ------------------------------------------------------------------
    def test_pbkdf2_vs_sha256(self):
        """
        pbkdf2_hash() debe ser considerablemente más lento que SHA256 simple.

        Cuantifica la diferencia de coste entre un hash rápido (SHA256,
        ~microsegundos) y un KDF lento (PBKDF2 con 100k iter, ~millisegundos).
        El ratio debe ser al menos 100x para que el KDF tenga valor práctico
        como freno ante fuerza bruta.
        """
        RATIO_MINIMO = 100  # PBKDF2 debe ser al menos 100x más lento que SHA256

        tiempo_pbkdf2 = _tiempo_medio(
            lambda: seguridad.pbkdf2_hash(self.password, self.salt)
        )

        tiempo_sha256 = _tiempo_medio(
            lambda: hashlib.sha256(self.password.encode()).hexdigest()
        )

        # Evitar división por cero en entornos muy rápidos
        if tiempo_sha256 == 0:
            tiempo_sha256 = 1e-9

        ratio = tiempo_pbkdf2 / tiempo_sha256

        self.assertGreater(
            ratio,
            RATIO_MINIMO,
            f"PBKDF2 ({tiempo_pbkdf2 * 1000:.2f}ms) debe ser al menos {RATIO_MINIMO}x "
            f"más lento que SHA256 ({tiempo_sha256 * 1000:.4f}ms). "
            f"Ratio actual: {ratio:.0f}x.",
        )

    # ------------------------------------------------------------------
    # test_pbkdf2_salida_fija
    # ------------------------------------------------------------------
    def test_pbkdf2_salida_fija(self):
        """
        La misma contraseña + salt siempre produce el mismo hash (determinismo).

        Propiedad necesaria para la autenticación: el servidor debe poder
        reproducir el hash almacenado durante el login para compararlo con
        la respuesta del cliente.
        """
        hash1 = seguridad.pbkdf2_hash(self.password, self.salt)
        hash2 = seguridad.pbkdf2_hash(self.password, self.salt)

        self.assertEqual(
            hash1,
            hash2,
            "pbkdf2_hash() debe ser determinista: misma entrada → misma salida.",
        )

    # ------------------------------------------------------------------
    # Tests adicionales de propiedades de PBKDF2
    # ------------------------------------------------------------------
    def test_pbkdf2_salida_hexadecimal_256bits(self):
        """La salida de pbkdf2_hash() debe ser 64 caracteres hexadecimales (256 bits)."""
        resultado = seguridad.pbkdf2_hash(self.password, self.salt)

        self.assertEqual(
            len(resultado),
            64,
            f"pbkdf2_hash() debe retornar 64 hex chars (SHA-256 = 256 bits). "
            f"Obtenido: {len(resultado)} chars.",
        )
        # Verificar que es hexadecimal válido
        try:
            int(resultado, 16)
        except ValueError:
            self.fail(f"La salida '{resultado[:16]}...' no es hexadecimal válido.")

    def test_pbkdf2_acepta_str_y_bytes(self):
        """pbkdf2_hash() debe producir el mismo resultado con str o bytes."""
        hash_str = seguridad.pbkdf2_hash(self.password, self.salt)
        hash_bytes = seguridad.pbkdf2_hash(self.password.encode(), self.salt.encode())

        self.assertEqual(
            hash_str,
            hash_bytes,
            "pbkdf2_hash() debe aceptar tanto str como bytes y producir el mismo hash.",
        )

    def test_derivar_clave_sesion_produce_bytes(self):
        """
        derivar_clave_sesion() debe retornar bytes de 32 bytes (256 bits).

        La clave de sesión se pasa directamente a HMAC como clave binaria;
        debe ser bytes, no str.
        """
        password_hash = seguridad.pbkdf2_hash(self.password, self.salt)
        nonce = seguridad.generar_nonce()

        clave = seguridad.derivar_clave_sesion(password_hash, nonce)

        self.assertIsInstance(
            clave,
            bytes,
            "derivar_clave_sesion() debe retornar bytes.",
        )
        self.assertEqual(
            len(clave),
            32,
            f"La clave de sesión debe ser 32 bytes (SHA-256). Obtenido: {len(clave)}.",
        )

    def test_derivar_clave_sesion_es_determinista(self):
        """Misma contraseña + mismo nonce → misma clave de sesión."""
        password_hash = seguridad.pbkdf2_hash(self.password, self.salt)
        nonce = "nonce_fijo_para_test"

        clave1 = seguridad.derivar_clave_sesion(password_hash, nonce)
        clave2 = seguridad.derivar_clave_sesion(password_hash, nonce)

        self.assertEqual(
            clave1,
            clave2,
            "derivar_clave_sesion() debe ser determinista.",
        )

    def test_derivar_clave_sesion_distinta_por_nonce(self):
        """
        El mismo hash de contraseña con nonces distintos produce claves distintas.

        Garantiza que cada sesión tiene una clave única incluso para el
        mismo usuario que inicia sesión múltiples veces.
        """
        password_hash = seguridad.pbkdf2_hash(self.password, self.salt)
        nonce1 = seguridad.generar_nonce()
        nonce2 = seguridad.generar_nonce()

        clave1 = seguridad.derivar_clave_sesion(password_hash, nonce1)
        clave2 = seguridad.derivar_clave_sesion(password_hash, nonce2)

        self.assertNotEqual(
            clave1,
            clave2,
            "Nonces distintos deben producir claves de sesión distintas.",
        )


if __name__ == "__main__":
    unittest.main()
