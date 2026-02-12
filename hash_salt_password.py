import json, hashlib, os, secrets

def hash_password_salt(usuario, contraseña):
    salt = secrets.token_hex(16)

    salted_password = salt + contraseña

    sha256_hash = hashlib.sha256(salted_password.encode()).hexdigest()

    try:
        with open("usuarios.json",'r',encoding='utf-8') as archivo:
            data = json.load(archivo)
        with open("usuarios.json",'w',encoding='utf-8') as archivo:
            data[usuario] = {"salt":salt,"password_hash":sha256_hash}
            json.dump(data,archivo, indent=4)
        print("Usuario guardado correctamente")
    except Exception as e:
        print("Error al guardar", e)

    return salt + sha256_hash

dicc = {}

usuario = input("Introduzca su nombre de usuario: ")
contraseña = input("Introduzca su contraseña: ")

hash_password_salt(usuario, contraseña)