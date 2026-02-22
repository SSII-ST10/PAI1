"""
Tests de rate limiting (limitación de tasa de peticiones por IP).

Vulnerabilidad cubierta: ataques de fuerza bruta y denegación de servicio.
El servidor limita a 10 peticiones por minuto por dirección IP.
Las peticiones 1-10 son aceptadas; la 11ª y siguientes son rechazadas
hasta que transcurran 60 segundos desde las primeras peticiones.

Estrategia: se prueban directamente las funciones de serversocket sin
arrancar el servidor TCP real, reseteando el estado global entre tests.

Ejecución:
    python tests/test_rate_limiting.py -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import serversocket


TEST_IP = "192.168.1.100"


class TestRateLimiting(unittest.TestCase):
    """Tests de la función check_rate_limit() de serversocket."""

    def setUp(self):
        """
        Limpia el estado global de rate_limit_tracker antes de cada test.
        Esto garantiza que cada test parte de 0 peticiones para TEST_IP.
        """
        serversocket.rate_limit_tracker.clear()

    def tearDown(self):
        """Limpia el estado al finalizar para no afectar otros tests."""
        serversocket.rate_limit_tracker.clear()

    # ------------------------------------------------------------------
    # test_rate_limit_9_peticiones
    # ------------------------------------------------------------------
    def test_rate_limit_9_peticiones(self):
        """
        Las primeras 9 peticiones deben ser aceptadas sin restricción.

        El umbral es 10 peticiones/minuto, por lo que cualquier cantidad
        menor o igual a 10 debe ser permitida.
        """
        resultados = [serversocket.check_rate_limit(TEST_IP) for _ in range(9)]

        self.assertTrue(
            all(resultados),
            f"Las primeras 9 peticiones deben ser aceptadas. "
            f"Fallidas en posiciones: {[i for i, r in enumerate(resultados) if not r]}.",
        )

    # ------------------------------------------------------------------
    # test_rate_limit_10_peticiones
    # ------------------------------------------------------------------
    def test_rate_limit_10_peticiones(self):
        """
        La décima petición (exactamente en el límite) debe ser aceptada.

        El límite es 10 req/min. La implementación bloquea cuando ya hay
        >= 10 timestamps registrados (antes de añadir el actual), por lo que
        la petición número 10 es la última permitida.
        """
        # Peticiones 1-9
        for _ in range(9):
            serversocket.check_rate_limit(TEST_IP)

        # Petición 10: debe ser aceptada
        resultado_10 = serversocket.check_rate_limit(TEST_IP)

        self.assertTrue(
            resultado_10,
            "La décima petición (en el límite exacto) debe ser aceptada.",
        )

    # ------------------------------------------------------------------
    # test_rate_limit_11_peticiones
    # ------------------------------------------------------------------
    def test_rate_limit_11_peticiones(self):
        """
        La undécima petición debe ser rechazada (límite superado).

        Vulnerabilidad probada: sin rate limiting, un atacante podría
        lanzar miles de intentos de login por segundo para fuerza bruta.
        Con el límite de 10/min, el espacio de ataque se reduce drásticamente.
        """
        # Consumir las 10 peticiones permitidas
        for _ in range(10):
            serversocket.check_rate_limit(TEST_IP)

        # Petición 11: debe ser rechazada
        resultado_11 = serversocket.check_rate_limit(TEST_IP)

        self.assertFalse(
            resultado_11,
            "La undécima petición debe ser rechazada (rate limit excedido).",
        )

    # ------------------------------------------------------------------
    # test_rate_limit_reset_60s
    # ------------------------------------------------------------------
    def test_rate_limit_reset_60s(self):
        """
        Después de 60 segundos los timestamps caducan y el contador se resetea.

        Simula que las 10 peticiones anteriores ocurrieron hace >60 segundos
        inyectando timestamps artificialmente en el pasado. La siguiente
        petición debe ser aceptada porque la ventana deslizante ya expiró.
        """
        ahora = time.time()

        # Simular 10 peticiones ocurridas hace 61 segundos (ya expiradas)
        serversocket.rate_limit_tracker[TEST_IP] = [ahora - 61] * 10

        # La siguiente petición debe ser aceptada (ventana limpia)
        resultado = serversocket.check_rate_limit(TEST_IP)

        self.assertTrue(
            resultado,
            "Después de 60 segundos, el rate limit debe resetearse y aceptar peticiones.",
        )

    # ------------------------------------------------------------------
    # Tests adicionales de comportamiento del rate limiter
    # ------------------------------------------------------------------
    def test_ips_independientes(self):
        """
        El rate limit de una IP no afecta a otras IPs.

        Cada cliente es limitado de forma independiente. Saturar el límite
        de una IP no debe bloquear a usuarios legítimos de otras IPs.
        """
        ip_atacante = "10.0.0.1"
        ip_legítima = "10.0.0.2"

        # El atacante agota su límite
        for _ in range(10):
            serversocket.check_rate_limit(ip_atacante)
        resultado_atacante = serversocket.check_rate_limit(ip_atacante)

        # El usuario legítimo no debe verse afectado
        resultado_legitimo = serversocket.check_rate_limit(ip_legítima)

        self.assertFalse(
            resultado_atacante,
            "La IP del atacante debe estar bloqueada.",
        )
        self.assertTrue(
            resultado_legitimo,
            "Otras IPs no deben verse afectadas por el rate limit de otra IP.",
        )

    def test_ventana_deslizante(self):
        """
        El rate limit usa una ventana deslizante de 60s, no una ventana fija.

        Las peticiones antiguas (>60s) se descartan al evaluar el límite,
        permitiendo que el tráfico fluya de forma continua dentro del umbral.
        """
        ahora = time.time()

        # 8 peticiones hace 30 segundos (recientes, dentro de ventana)
        serversocket.rate_limit_tracker[TEST_IP] = [ahora - 30] * 8

        # Las siguientes 2 peticiones deben ser aceptadas (8 + 1 = 9, 8 + 2 = 10)
        primera = serversocket.check_rate_limit(TEST_IP)
        segunda = serversocket.check_rate_limit(TEST_IP)
        # La tercera debe ser rechazada (8 + 3 = 11 > 10)
        tercera = serversocket.check_rate_limit(TEST_IP)

        self.assertTrue(primera, "La novena petición total debe ser aceptada.")
        self.assertTrue(segunda, "La décima petición total debe ser aceptada.")
        self.assertFalse(tercera, "La undécima petición total debe ser rechazada.")


if __name__ == "__main__":
    unittest.main()
