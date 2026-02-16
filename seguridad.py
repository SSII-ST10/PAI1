import hmac, hashlib, secrets, json

CLAVE_SECRETA = b'ClaveSuperSecretaParaElPai_2026'

nonces_usudos = set()

def generar_nonce():
    return secrets.token_hex(16)

def calcular_mac(datos_str, nonce):
    mensaje_concatenado = datos_str + nonce
    mac = hmac.new(CLAVE_SECRETA, mensaje_concatenado.encode('utf-8'), hashlib.sha256).hexdigest()
    return mac

def validar_integridad(datos_str, nonce, mac_recibido):
    if nonce in nonces_usudos:
        return False
    mac_calculado = calcular_mac(datos_str, nonce)

    if secrets.compare_digest(mac_calculado, mac_recibido):
        return True, "OK"
    else:
        return False, "ERROR INTEGRIDAD: El MAC no coincide (mensaje modificado)"