import socket
import json
import hash_salt_password as hash  
import seguridad  

HOST = "127.0.0.1"
PORT = 3030  

def procesar_logica_negocio(datos_str):
    """
    Procesa el JSON interno (registro/login) una vez que sabemos que es seguro.
    """
    try:
        mensaje = json.loads(datos_str)
        accion = mensaje.get("accion")
        user = mensaje.get("usuario")
        pwd = mensaje.get("password")

        if accion == "registro":
            if hash.registrar_usuario(user, pwd):
                return "Usuario registrado correctamente"
            else:
                return "Error: El usuario ya existe"
        
        elif accion == "login":
            if hash.verificar_contraseña(user, pwd):
                return "Login correcto. Bienvenido!"
            else:
                return "Error: Credenciales incorrectas"
        
        else:
            return "Acción desconocida"
            
    except Exception as e:
        return f"Error procesando lógica: {e}"

def manejar_conexion(conn, addr):
    print(f"Conectado por {addr}")
    while True:
        try:
            data = conn.recv(2048)
            if not data:
                break 
            
            try:
                paquete = json.loads(data.decode())
            except json.JSONDecodeError:
                print(f">> Recibido algo que no es JSON de {addr}")
                continue

            datos_reales = paquete.get("datos") 
            nonce = paquete.get("nonce")
            mac_recibido = paquete.get("mac")

            if datos_reales is None or nonce is None or mac_recibido is None:
                print(f">> ALERTA: Mensaje inválido recibido de {addr}. Falta nonce o mac.")
                error_response = json.dumps({"status": "ERROR", "mensaje": "Formato incorrecto. Actualiza tu cliente."})
                conn.sendall(error_response.encode())
                continue

            print(f"\n--- Nuevo Mensaje Seguro de {addr} ---")
            print(f"Nonce: {nonce}")
            print(f"MAC: {mac_recibido}")
            
            es_valido, motivo = seguridad.validar_integridad(datos_reales, nonce, mac_recibido)
            
            if es_valido:
                print(">> SEGURIDAD OK. Integridad verificada.")
                respuesta_texto = procesar_logica_negocio(datos_reales)
                respuesta_final = json.dumps({"status": "OK", "mensaje": respuesta_texto})
            else:
                print(f">> ALERTA DE SEGURIDAD: {motivo}")
                respuesta_final = json.dumps({"status": "SECURITY_ERROR", "mensaje": motivo})
            
            conn.sendall(respuesta_final.encode())
            
        except ConnectionResetError:
            print(f"Cliente {addr} forzó el cierre de la conexión.")
            break
        except Exception as e:
            print(f"Error inesperado en conexión: {e}")
            break

print(f"--- Servidor SEGURO INICIADO en {HOST}:{PORT} ---")
print("Esperando clientes...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.bind((HOST, PORT))
        s.listen()
    except OSError as e:
        print(f"Error al iniciar servidor: {e}")
        print("Comprueba que no tengas otro servidor corriendo en este puerto.")
        exit()

    while True:
        try:
            conn, addr = s.accept()
            with conn:
                manejar_conexion(conn, addr)
            print(f"Cliente {addr} desconectado. Esperando siguiente...")
        except KeyboardInterrupt:
            print("\nServidor detenido por el usuario.")
            break