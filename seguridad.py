import hashlib
import hmac
import secrets
from hashlib import pbkdf2_hmac


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


def calcular_respuesta_challenge(password, salt, nonce_server):
    """
    Calcula la respuesta al challenge del servidor para autenticación.
    Paso 1: PBKDF2(password, salt) -> hash_base  (100,000 iteraciones)
    Paso 2: HMAC-SHA256(hash_base, nonce_server) -> respuesta final
    Uso: lado CLIENTE (tiene la contraseña en texto plano).
    Args:
        password: str - contraseña en texto plano
        salt: str - salt en hexadecimal (del servidor)
        nonce_server: str - nonce generado por el servidor
    Returns:
        str - respuesta en hexadecimal
    """
    hash_base = pbkdf2_hash(password, salt)
    if isinstance(nonce_server, str):
        nonce_server = nonce_server.encode()
    return hmac.new(hash_base.encode(), nonce_server, hashlib.sha256).hexdigest()


def verificar_respuesta_challenge(stored_hash, nonce_server):
    """
    Verifica la respuesta al challenge usando el hash almacenado en BD.
    Paso único: HMAC-SHA256(stored_hash, nonce_server) -> respuesta esperada
    Uso: lado SERVIDOR (tiene el hash PBKDF2 ya almacenado, no el password).
    Args:
        stored_hash: str - PBKDF2(password, salt) almacenado en BD
        nonce_server: str - nonce generado por el servidor
    Returns:
        str - respuesta esperada en hexadecimal
    """
    if isinstance(nonce_server, str):
        nonce_server = nonce_server.encode()
    return hmac.new(stored_hash.encode(), nonce_server, hashlib.sha256).hexdigest()


def derivar_clave_sesion(password_hash, nonce_intercambio):
    """
    Deriva clave de sesión única para MAC de transacciones
    A partir del hash de password y un nonce de intercambio
    """
    # PBKDF2 rapido (1000 iteraciones) para derivar clave por sesion
    if isinstance(password_hash, str):
        password_hash = password_hash.encode()
    if isinstance(nonce_intercambio, str):
        nonce_intercambio = nonce_intercambio.encode()
    return pbkdf2_hmac("sha256", password_hash, nonce_intercambio, 1000)
