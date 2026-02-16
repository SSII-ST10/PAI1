import secrets
import hashlib
import hmac

CLAVE_MAC = b'Clave_Secreta_Banco_2024'

def generar_nonce(length=16):
    """Genera un número aleatorio único (Nonce)"""
    return secrets.token_hex(length)

def generar_hash_password(password, salt):
    """Genera un hash SHA-256 de la contraseña + salt"""
    datos = password + salt
    return hashlib.sha256(datos.encode()).hexdigest()

def mac(mensaje, key):
    """Calcula el HMAC-SHA256 de un mensaje"""
    if isinstance(mensaje, str):
        mensaje = mensaje.encode()
    if isinstance(key, str):
        key = key.encode()
        
    return hmac.new(key, mensaje, hashlib.sha256).hexdigest()