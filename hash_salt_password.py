import json, hashlib, os, secrets

DB_FILE = "../usuarios.json"

def _cargar_datos():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE,'r',encoding='utf-8') as archivo:
            return json.load(archivo)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}
    
def _guardar_datos(data):
    with open(DB_FILE, 'w', encoding='utf-8') as archivo:
        json.dump(data, archivo, indent = 4)

    
def registrar_usuario(usuario, contraseña):
    data = _cargar_datos()

    if usuario in data:
        return False
    
    salt = secrets.token_hex(16)
    salted_password = salt + contraseña
    sha256_hash = hashlib.sha256(salted_password.encode()).hexdigest()

    data[usuario] = {"salt":salt, "password_hash":sha256_hash}
    _guardar_datos(data)

    return True

def verificar_contraseña(usuario, contraseña):
    data = _cargar_datos()

    if usuario not in data:
        return False
    
    stored_salt = data[usuario]["salt"]
    stored_hash = data[usuario]["password_hash"]

    check_salted = stored_salt + contraseña
    check_hash = hashlib.sha256(check_salted.encode()).hexdigest()

    return secrets.compare_digest(stored_hash, check_hash)