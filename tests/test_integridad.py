"""
Tests de integridad de mensajes mediante MAC/HMAC.

Vulnerabilidad cubierta: manipulación de mensajes en tránsito.
Un atacante que intercepte un mensaje firmado con HMAC-SHA256 no puede:
  - Modificar el contenido sin invalidar el MAC.
  - Forjar un MAC válido sin conocer la clave secreta.
  - Reutilizar un MAC de otro mensaje.

Ejecución:
    python tests/test_integridad.py -v
"""

import hmac
import os
import sys
import unittest

# Añadir el directorio raíz del proyecto al path para poder importar los módulos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import seguridad


class TestIntegridad(unittest.TestCase):
    """Tests de integridad de mensajes (MAC/HMAC)."""

    def setUp(self):
        """Prepara datos comunes para todos los tests de esta clase."""
        # Clave de sesión de 32 bytes derivada con derivar_clave_sesion()
        password_hash = seguridad.pbkdf2_hash("password_test", "salt_test_hex")
        nonce_intercambio = "aabbccddeeff00112233445566778899"
        self.clave_sesion = seguridad.derivar_clave_sesion(
            password_hash, nonce_intercambio
        )

        # Mensaje de transacción de prueba
        self.mensaje = "alice,bob,250.00"

        # MAC correcto calculado con la clave de sesión
        self.mac_correcto = seguridad.mac(self.mensaje, self.clave_sesion)

    # ------------------------------------------------------------------
    # test_mac_valido
    # ------------------------------------------------------------------
    def test_mac_valido(self):
        """
        Verifica que un MAC calculado correctamente es aceptado.

        Escenario normal: el cliente envía mensaje + MAC calculado con la
        clave de sesión. El servidor recalcula el MAC y compara.
        Si la comparación tiene éxito, el mensaje no fue alterado.
        """
        mac_recalculado = seguridad.mac(self.mensaje, self.clave_sesion)

        resultado = hmac.compare_digest(self.mac_correcto, mac_recalculado)

        self.assertTrue(
            resultado,
            "El MAC válido debería ser aceptado: el mensaje no fue alterado.",
        )

    # ------------------------------------------------------------------
    # test_mac_modificado
    # ------------------------------------------------------------------
    def test_mac_modificado(self):
        """
        Verifica que alterar 1 solo carácter del MAC hace que la verificación falle.

        Vulnerabilidad probada: un atacante que intercepte el mensaje y
        cambie el MAC (o lo fabrique sin conocer la clave) debe ser detectado.
        Incluso un cambio mínimo en el digest hexadecimal debe causar rechazo.
        """
        # Flip del primer carácter del MAC hexadecimal
        primer_char = self.mac_correcto[0]
        char_distinto = "0" if primer_char != "0" else "1"
        mac_manipulado = char_distinto + self.mac_correcto[1:]

        resultado = hmac.compare_digest(mac_manipulado, self.mac_correcto)

        self.assertFalse(
            resultado,
            "Un MAC con 1 carácter modificado debe ser rechazado (fallo de integridad).",
        )

    # ------------------------------------------------------------------
    # test_datos_modificados
    # ------------------------------------------------------------------
    def test_datos_modificados(self):
        """
        Verifica que cambiar los datos manteniendo el MAC original falla.

        Vulnerabilidad probada: ataque de modificación de datos en tránsito.
        El atacante cambia el destinatario o la cantidad pero reutiliza el
        MAC original. El servidor debe detectar la discrepancia.
        """
        # El atacante cambia el destinatario: bob -> eve
        mensaje_alterado = "alice,eve,250.00"

        # El MAC original sigue siendo el de "alice,bob,250.00"
        mac_del_mensaje_alterado = seguridad.mac(mensaje_alterado, self.clave_sesion)

        resultado = hmac.compare_digest(self.mac_correcto, mac_del_mensaje_alterado)

        self.assertFalse(
            resultado,
            "El MAC del mensaje original no debe coincidir con el de un mensaje alterado.",
        )

    # ------------------------------------------------------------------
    # test_clave_sesion_incorrecta
    # ------------------------------------------------------------------
    def test_clave_sesion_incorrecta(self):
        """
        Verifica que usar una clave de sesión diferente produce un MAC distinto.

        Vulnerabilidad probada: si un atacante no conoce la clave de sesión
        (derivada de PBKDF2 + nonce de intercambio único), no puede generar
        un MAC válido para ningún mensaje, aunque conozca el contenido.
        """
        # Clave de sesión perteneciente a otra sesión (nonce distinto)
        password_hash_otro = seguridad.pbkdf2_hash("password_test", "salt_test_hex")
        clave_sesion_incorrecta = seguridad.derivar_clave_sesion(
            password_hash_otro, "nonce_de_otra_sesion_completamente_diferente"
        )

        mac_con_clave_incorrecta = seguridad.mac(self.mensaje, clave_sesion_incorrecta)

        resultado = hmac.compare_digest(self.mac_correcto, mac_con_clave_incorrecta)

        self.assertFalse(
            resultado,
            "Un MAC generado con una clave de sesión incorrecta debe ser rechazado.",
        )

    # ------------------------------------------------------------------
    # Tests adicionales de propiedades del MAC
    # ------------------------------------------------------------------
    def test_mac_es_determinista(self):
        """El mismo mensaje y clave siempre producen el mismo MAC (determinismo)."""
        mac1 = seguridad.mac(self.mensaje, self.clave_sesion)
        mac2 = seguridad.mac(self.mensaje, self.clave_sesion)
        self.assertEqual(
            mac1, mac2, "seguridad.mac() debe ser determinista para misma entrada."
        )

    def test_mac_longitud_fija(self):
        """El MAC HMAC-SHA256 siempre produce 64 caracteres hexadecimales (256 bits)."""
        self.assertEqual(
            len(self.mac_correcto),
            64,
            f"HMAC-SHA256 debe ser 64 hex chars, obtenido: {len(self.mac_correcto)}.",
        )

    def test_mac_acepta_bytes_y_str(self):
        """seguridad.mac() debe aceptar tanto str como bytes para mensaje y clave."""
        clave_bytes = (
            self.clave_sesion
            if isinstance(self.clave_sesion, bytes)
            else self.clave_sesion.encode()
        )
        mac_str = seguridad.mac(self.mensaje, self.clave_sesion)
        mac_bytes = seguridad.mac(self.mensaje.encode(), clave_bytes)
        self.assertEqual(
            mac_str,
            mac_bytes,
            "mac() debe producir el mismo resultado con str o bytes.",
        )


if __name__ == "__main__":
    unittest.main()
