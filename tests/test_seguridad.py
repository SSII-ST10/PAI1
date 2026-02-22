"""
Suite de tests de seguridad del PAI-1 Sistema Bancario.
Archivo maestro que agrupa y ejecuta todos los módulos de tests.

CÓMO EJECUTAR:
    # Todos los tests (verbose):
    python tests/test_seguridad.py -v

    # Un módulo individual:
    python tests/test_integridad.py -v
    python tests/test_antireplay.py -v
    python tests/test_autenticacion.py -v
    python tests/test_rate_limiting.py -v
    python tests/test_sesiones.py -v
    python tests/test_pbkdf2.py -v

    # Desde el directorio raíz con el runner de unittest:
    python -m unittest discover -s tests -p "test_*.py" -v

MÓDULOS DE TESTS:
    test_integridad    → MAC/HMAC: manipulación de mensajes en tránsito
    test_antireplay    → Nonces: ataques de repetición (replay attacks)
    test_autenticacion → PBKDF2 + Challenge-Response: autenticación segura
    test_rate_limiting → Rate limit: fuerza bruta y DDoS
    test_sesiones      → Gestión de sesiones: acceso no autorizado
    test_pbkdf2        → PBKDF2: coste computacional y correctitud

ARCHIVOS TESTEADOS:
    seguridad.py    → funciones criptográficas (mac, pbkdf2_hash, challenge-response)
    db_helper.py    → acceso a BD (nonces atómicos, cleanup, usuarios)
    serversocket.py → lógica del servidor (rate limiting, sesiones activas)

NOTA: Los tests de integración en test_sesiones.py están marcados con
@unittest.skip y requieren un servidor TCP arrancado en localhost:3030.
"""

import os
import sys
import unittest

# Garantizar que el directorio raíz está en el path para que los submódulos
# puedan importar seguridad, db_helper y serversocket.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# -----------------------------------------------------------------------
# Importar todas las suites de tests
# -----------------------------------------------------------------------
from test_antireplay import TestAntiReplay
from test_autenticacion import TestAutenticacion
from test_integridad import TestIntegridad
from test_pbkdf2 import TestPBKDF2
from test_rate_limiting import TestRateLimiting
from test_sesiones import TestSesiones, TestSesionesIntegracion


def suite_completa():
    """
    Construye una TestSuite que agrupa todos los tests de seguridad.
    El orden refleja la pila de seguridad: del nivel más bajo (cripto)
    al más alto (integración de sesiones).
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 1. Primitivas criptográficas
    suite.addTests(loader.loadTestsFromTestCase(TestPBKDF2))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegridad))

    # 2. Protección de mensajes
    suite.addTests(loader.loadTestsFromTestCase(TestAntiReplay))

    # 3. Autenticación
    suite.addTests(loader.loadTestsFromTestCase(TestAutenticacion))

    # 4. Control de acceso en servidor
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiting))
    suite.addTests(loader.loadTestsFromTestCase(TestSesiones))

    # 5. Integración (skipped por defecto: requieren servidor arrancado)
    suite.addTests(loader.loadTestsFromTestCase(TestSesionesIntegracion))

    return suite


if __name__ == "__main__":
    # Cambiar al directorio de tests para que los imports relativos funcionen
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    runner = unittest.TextTestRunner(verbosity=2)
    resultado = runner.run(suite_completa())

    # Código de salida no-cero si algún test falló (útil para CI)
    sys.exit(0 if resultado.wasSuccessful() else 1)
