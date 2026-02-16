import socket
import json
import seguridad  

HOST = "127.0.0.1"
PORT = 3030 

def enviar_mensaje_seguro(socket_cliente, mensaje_dict):
    """
    Empaqueta el mensaje lógico (diccionario) dentro de un sobre seguro
    con Nonce y MAC (Integridad + Anti-Replay).
    """
    try:
        payload_str = json.dumps(mensaje_dict)
        
        nonce = seguridad.generar_nonce()
        
        mac = seguridad.calcular_mac(payload_str, nonce)
        
        paquete_seguro = {
            "datos": payload_str, 
            "nonce": nonce,
            "mac": mac
        }
        
        socket_cliente.sendall(json.dumps(paquete_seguro).encode())
        return True
    except Exception as e:
        print(f"Error al enviar mensaje seguro: {e}")
        return False

def main():
    print(f"--- INICIANDO CLIENTE SEGURO (Destino: {PORT}) ---")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(">> Conexión establecida con el servidor.")
            
            while True:
                print("\n--- MENÚ PRINCIPAL ---")
                print("1. Registrarse")
                print("2. Iniciar Sesión")
                print("3. Salir")
                opcion = input("Elige una opción: ")
                
                if opcion == "3":
                    print("Cerrando cliente...")
                    break

                usuario = input("Usuario: ")
                password = input("Contraseña: ")
                
                mensaje = {}
                if opcion == "1":
                    mensaje = {"accion": "registro", "usuario": usuario, "password": password}
                elif opcion == "2":
                    mensaje = {"accion": "login", "usuario": usuario, "password": password}
                else:
                    print("Opción no válida. Inténtalo de nuevo.")
                    continue
                
                if enviar_mensaje_seguro(s, mensaje):
                    print(">> Mensaje enviado de forma segura (con MAC y Nonce).")
                    
                    try:
                        data = s.recv(2048)
                        if not data:
                            print("El servidor cerró la conexión.")
                            break
                        
                        respuesta = json.loads(data.decode())
                        
                        print("\n=== RESPUESTA DEL SERVIDOR ===")
                        print(f"Estado: {respuesta.get('status')}")
                        print(f"Mensaje: {respuesta.get('mensaje')}")
                        print("==============================")
                        
                    except json.JSONDecodeError:
                        print("Error: La respuesta del servidor no es un JSON válido.")
                else:
                    print("No se pudo enviar el mensaje.")

    except ConnectionRefusedError:
        print(f"\nERROR CRÍTICO: No se puede conectar al puerto {PORT}.")
        print("Asegúrate de que 'serversocket.py' está ejecutándose primero.")
    except Exception as e:
        print(f"\nOcurrió un error inesperado: {e}")

if __name__ == "__main__":
    main()