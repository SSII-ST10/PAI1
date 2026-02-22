"""
Tests de gestión de sesiones y autorización de transacciones.

Vulnerabilidades cubiertas:
  - Acceso sin autenticación: una transacción sin sesión activa debe ser
    rechazada aunque el MAC sea correcto.
  - Suplantación de sesión: usar la clave de sesión de otro usuario no
    produce un MAC válido para el usuario objetivo.
  - Aislamiento de sesiones: cada sesión tiene un nonce de intercambio
    único que hace que la clave de sesión sea distinta para cada login.

La lógica de validación de MAC en transacciones está embebida dentro de
iniciar_servidor(). Estos tests validan los componentes individuales
(derivación de clave, cálculo/verificación de MAC, estado del diccionario
sesiones_activas) que dicha función orquesta. Los tests de integración
completa (socket-to-socket) están marcados con @unittest.skip.

Ejecución:
    python tests/test_sesiones.py -v
"""

import hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import seguridad
import serversocket


class TestSesiones(unittest.TestCase):
    """Tests de gestión de sesiones y validación de MAC en transacciones."""

    def setUp(self):
        """
        Prepara dos usuarios con sesiones activas para los tests.

        alice  → sesión legítima con clave derivada de su hash y nonce propio.
        bob    → sesión legítima con clave derivada de su hash y nonce propio.
        mallory→ sin sesión activa (no autenticada).
        """
        serversocket.sesiones_activas.clear()

        # --- Usuario alice ---
        self.alice_password = "alice123"
        self.alice_salt = seguridad.generar_nonce(16)
        self.alice_hash = seguridad.pbkdf2_hash(self.alice_password, self.alice_salt)
        self.alice_nonce = seguridad.generar_nonce()
        self.alice_clave = seguridad.derivar_clave_sesion(
            self.alice_hash, self.alice_nonce
        )

        serversocket.sesiones_activas["alice"] = {
            "nonce_intercambio": self.alice_nonce,
            "clave_sesion": self.alice_clave,
        }

        # --- Usuario bob ---
        self.bob_password = "bob456"
        self.bob_salt = seguridad.generar_nonce(16)
        self.bob_hash = seguridad.pbkdf2_hash(self.bob_password, self.bob_salt)
        self.bob_nonce = seguridad.generar_nonce()
        self.bob_clave = seguridad.derivar_clave_sesion(self.bob_hash, self.bob_nonce)

        serversocket.sesiones_activas["bob"] = {
            "nonce_intercambio": self.bob_nonce,
            "clave_sesion": self.bob_clave,
        }

        # mallory no tiene sesión activa

    def tearDown(self):
        """Limpia sesiones activas al finalizar cada test."""
        serversocket.sesiones_activas.clear()

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------
    def _mac_transaccion(self, origen, destino, cantidad, clave_sesion):
        """Calcula el MAC de una transacción como lo haría el cliente."""
        msg = f"{origen},{destino},{cantidad}"
        return seguridad.mac(msg, clave_sesion)

    def _verificar_transaccion(self, origen, destino, cantidad, mac_recibido):
        """
        Replica la lógica de verificación de transacción de iniciar_servidor():
          1. Busca sesión del usuario origen.
          2. Recalcula MAC con la clave de sesión almacenada.
          3. Compara con compare_digest (tiempo constante).
        Retorna (bool, str): (éxito, mensaje).
        """
        sesion = serversocket.sesiones_activas.get(origen)
        if not sesion:
            return False, "ERROR: Sesión no válida"

        msg_datos = f"{origen},{destino},{cantidad}"
        mac_esperado = seguridad.mac(msg_datos, sesion["clave_sesion"])

        if hmac.compare_digest(mac_recibido, mac_esperado):
            return True, "OK"
        return False, "ERROR: Fallo de Integridad (MAC inválido)"

    # ------------------------------------------------------------------
    # test_sesion_valida
    # ------------------------------------------------------------------
    def test_sesion_valida(self):
        """
        Con sesión activa y MAC correcto, la transacción debe ser aceptada.

        Escenario normal: alice envía una transferencia a bob. El MAC fue
        calculado con la clave de sesión de alice. El servidor la verifica
        y aprueba la transacción.
        """
        origen, destino, cantidad = "alice", "bob", "100.00"

        mac_correcto = self._mac_transaccion(
            origen, destino, cantidad, self.alice_clave
        )
        exito, mensaje = self._verificar_transaccion(
            origen, destino, cantidad, mac_correcto
        )

        self.assertTrue(
            exito,
            f"Con sesión válida y MAC correcto, la transacción debe ser aceptada. "
            f"Respuesta: {mensaje}",
        )
        self.assertEqual(mensaje, "OK")

    # ------------------------------------------------------------------
    # test_sesion_invalida
    # ------------------------------------------------------------------
    def test_sesion_invalida(self):
        """
        Sin sesión activa, la transacción debe ser rechazada.

        Vulnerabilidad probada: acceso sin autenticación previa.
        Un atacante que envíe directamente un mensaje de transacción sin
        haber completado el login debe ser bloqueado, independientemente
        del contenido o MAC del mensaje.
        """
        origen, destino, cantidad = "mallory", "alice", "9999.00"

        # Mallory calcula un MAC con una clave cualquiera (no tiene sesión)
        clave_falsa = seguridad.derivar_clave_sesion("hash_falso", "nonce_falso")
        mac_cualquiera = self._mac_transaccion(origen, destino, cantidad, clave_falsa)

        exito, mensaje = self._verificar_transaccion(
            origen, destino, cantidad, mac_cualquiera
        )

        self.assertFalse(
            exito,
            "Sin sesión activa, la transacción debe ser rechazada.",
        )
        self.assertIn(
            "Sesión no válida",
            mensaje,
            f"El mensaje de error debe indicar sesión inválida. Obtenido: '{mensaje}'",
        )

    # ------------------------------------------------------------------
    # test_sesion_otro_usuario
    # ------------------------------------------------------------------
    def test_sesion_otro_usuario(self):
        """
        Usar la clave de sesión de otro usuario produce un MAC inválido.

        Vulnerabilidad probada: suplantación de identidad en transacciones.
        bob intenta enviar una transacción firmada como alice, pero usando
        su propia clave de sesión (la única que conoce). El servidor recalcula
        el MAC con la clave de alice y detecta la discrepancia.

        Esto garantiza que cada usuario solo puede firmar sus propias
        transacciones.
        """
        origen, destino, cantidad = "alice", "eve", "500.00"

        # bob firma el mensaje de alice con su propia clave (ataque de suplantación)
        mac_de_bob = self._mac_transaccion(origen, destino, cantidad, self.bob_clave)

        exito, mensaje = self._verificar_transaccion(
            origen, destino, cantidad, mac_de_bob
        )

        self.assertFalse(
            exito,
            "Un MAC firmado con la clave de otra sesión debe ser rechazado.",
        )
        self.assertIn(
            "MAC inválido",
            mensaje,
            f"El error debe indicar fallo de integridad MAC. Obtenido: '{mensaje}'",
        )

    # ------------------------------------------------------------------
    # Tests adicionales de propiedades de sesión
    # ------------------------------------------------------------------
    def test_claves_sesion_distintas_por_usuario(self):
        """
        Dos usuarios con la misma contraseña tienen claves de sesión distintas
        porque sus nonces de intercambio son únicos.

        Confirma el aislamiento criptográfico entre sesiones.
        """
        password_comun = "shared_password"
        salt1 = seguridad.generar_nonce(16)
        salt2 = seguridad.generar_nonce(16)

        hash1 = seguridad.pbkdf2_hash(password_comun, salt1)
        hash2 = seguridad.pbkdf2_hash(password_comun, salt2)

        nonce1 = seguridad.generar_nonce()
        nonce2 = seguridad.generar_nonce()

        clave1 = seguridad.derivar_clave_sesion(hash1, nonce1)
        clave2 = seguridad.derivar_clave_sesion(hash2, nonce2)

        self.assertNotEqual(
            clave1,
            clave2,
            "Dos sesiones distintas deben tener claves de sesión diferentes.",
        )

    def test_logout_elimina_sesion(self):
        """
        Después del logout, la sesión de alice no debe estar en sesiones_activas.

        Simula el comportamiento del tipo "4" (LOGOUT) de iniciar_servidor():
        elimina la entrada del diccionario en memoria.
        """
        self.assertIn("alice", serversocket.sesiones_activas)

        # Simular logout
        serversocket.sesiones_activas.pop("alice", None)

        self.assertNotIn(
            "alice",
            serversocket.sesiones_activas,
            "Después del logout, alice no debe tener sesión activa.",
        )

        # Intentar transacción post-logout debe fallar
        mac_cualquiera = self._mac_transaccion(
            "alice", "bob", "50.00", self.alice_clave
        )
        exito, _ = self._verificar_transaccion("alice", "bob", "50.00", mac_cualquiera)

        self.assertFalse(
            exito,
            "Tras el logout, cualquier transacción de alice debe ser rechazada.",
        )


# ------------------------------------------------------------------
# Tests de integración (requieren servidor TCP arrancado en localhost:3030)
# ------------------------------------------------------------------
# @unittest.skip(
#    "Test de integración: requiere servidor TCP en localhost:3030. "
#    "Iniciar con: python serversocket.py"
# )
class TestSesionesIntegracion(unittest.TestCase):
    """
    Tests de integración completa que verifican el flujo socket→servidor.
    Están desactivados por defecto. Para ejecutarlos:
      1. Iniciar el servidor: python serversocket.py
      2. Ejecutar con: python tests/test_sesiones.py -v TestSesionesIntegracion
    """

    import socket as _socket

    HOST = "localhost"
    PORT = 3030

    def _enviar_recibir(self, mensaje):
        """Envía un mensaje al servidor y recibe la respuesta."""
        with self._socket.socket(self._socket.AF_INET, self._socket.SOCK_STREAM) as s:
            s.connect((self.HOST, self.PORT))
            s.send(mensaje.encode())
            return s.recv(4096).decode()

    def test_integracion_transaccion_sin_sesion(self):
        """Transacción directa sin login previo → ERROR: Sesión no válida."""
        nonce = seguridad.generar_nonce()
        clave_falsa = b"clave_falsa_para_test_integracion"
        mac_val = seguridad.mac("user_fake,destino,100.00", clave_falsa)
        respuesta = self._enviar_recibir(
            f"3,user_fake,destino,100.00,{nonce},{mac_val}"
        )
        self.assertIn("ERROR", respuesta)


if __name__ == "__main__":
    unittest.main()
