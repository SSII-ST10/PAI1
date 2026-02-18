import secrets
import hashlib
import hmac
import os
from hashlib import pbkdf2_hmac


def obtener_clave_mac():
    """
    Obtiene clave MAC desde variable de entorno con default de desarrollo
    Returns:
        bytes - clave MAC para HMAC
    """
    clave = os.getenv("BANCO_MAC_KEY", "desarrollo_inseguro_32bytes_clave")
    return clave.encode() if isinstance(clave, str) else clave


def generar_nonce(length=16):
    """
    Genera un nonce aleatorio criptográficamente seguro
    Args:
        length: int - longitud en bytes (default 16)
    Returns:
        str - nonce en hexadecimal
    """
    return secrets.token_hex(length)


def pbkdf2_hash(password, salt):
    """
    Genera hash PBKDF2-HMAC-SHA256 con 100,000 iteraciones
    Args:
        password: str - contraseña en texto plano
        salt: str - salt en hexadecimal
    Returns:
        str - hash en hexadecimal
    """
    if isinstance(password, str):
        password = password.encode()
    if isinstance(salt, str):
        salt = salt.encode()
    return pbkdf2_hmac("sha256", password, salt, 100000).hex()


def mac(mensaje, key):
    """
    Genera HMAC-SHA256 de un mensaje
    Args:
        mensaje: str o bytes - mensaje a autenticar
        key: str o bytes - clave secreta
    Returns:
        str - MAC en hexadecimal
    """
    if isinstance(mensaje, str):
        mensaje = mensaje.encode()
    if isinstance(key, str):
        key = key.encode()
    return hmac.new(key, mensaje, hashlib.sha256).hexdigest()
