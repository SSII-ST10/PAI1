import socket
import secrets
import sys
import seguridad 

HOST = 'localhost'
PORT = 3030

def main():
    while True:
        print("\n--- MENU CLIENTE ---")
        print("1. Iniciar Sesion")
        print("2. Registrarse")
        print("3. Transferencia")
        print("4. Salir")
        
        opcion = input("Elige: ")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((HOST, PORT))
        except:
            print("Error: No se puede conectar al servidor")
            continue

        try:
            if opcion == '1':
                user = input("Usuario: ")
                password = input("Contrasena: ")
                client_nonce = secrets.token_hex(16)
                
                msg = f"1,{user},{client_nonce}"
                s.send(msg.encode())
                
                respuesta = s.recv(1024).decode()
                
                if "ERROR" in respuesta:
                    print(respuesta)
                else:
                    datos = respuesta.split(',')
                    salt_rx = datos[0]
                    nonce_server_rx = datos[1]
                    
                    hash_base = seguridad.generar_hash_password(password, salt_rx)
                    
                    hash_final = seguridad.generar_hash_password(hash_base, nonce_server_rx)
                    
                    s.send(hash_final.encode())
                    
                    resultado = s.recv(1024).decode()
                    print("Servidor:", resultado)

            elif opcion == '2':
                user = input("Nuevo Usuario: ")
                password = input("Nueva Contrasena: ")
                nonce = secrets.token_hex(16)
                
                msg = f"2,{user},{password},{nonce}"
                s.send(msg.encode())
                print(s.recv(1024).decode())

            elif opcion == '3':
                org = input("Origen: ")
                dest = input("Destino: ")
                cant = input("Cantidad: ")
                nonce = secrets.token_hex(16)
                
                msg_datos = f"{org},{dest},{cant},{nonce}"
                
                mac_val = seguridad.mac(msg_datos, seguridad.CLAVE_MAC)
                
                msg_final = f"3,{org},{dest},{cant},{nonce},{mac_val}"
                s.send(msg_final.encode())
                print(s.recv(1024).decode())

            elif opcion == '4':
                s.send("4,BYE".encode())
                break

        except Exception as e:
            print(f"Error: {e}")
        finally:
            s.close()

if __name__ == "__main__":
    main()