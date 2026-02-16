import socket
import sys
import os
import json
import csv
import secrets
import traceback 
import seguridad 

# Configuración
HOST = 'localhost'
PORT = 3030 
ARCHIVO_USUARIOS = 'usuarios.json'
ARCHIVO_TRANSACCIONES = 'transacciones.csv'
nonces_usados = set()

def cargar_usuarios():
    # Si no existe, crea usuarios por defecto: usuario "1" con clave "1"
    if not os.path.exists(ARCHIVO_USUARIOS):
        datos_base = {"1": ["ab4fea0dbae12cb8e67a5c0d0a895c16e750c560b7702513e695cb7b494e1d99", "ea6fa87194b7ef911d726409d9168879"]}
        with open(ARCHIVO_USUARIOS, 'w') as f:
            json.dump(datos_base, f)
        return datos_base
    try:
        with open(ARCHIVO_USUARIOS, 'r') as f:
            return json.load(f)
    except:
        return {}

def guardar_usuario(usuario, password_hash, salt):
    usuarios = cargar_usuarios()
    usuarios[usuario] = [password_hash, salt]
    with open(ARCHIVO_USUARIOS, 'w') as f:
        json.dump(usuarios, f)

def registrar_transaccion(origen, destino, cantidad, mac):
    existe = os.path.exists(ARCHIVO_TRANSACCIONES)
    with open(ARCHIVO_TRANSACCIONES, 'a', newline='') as f:
        writer = csv.writer(f)
        if not existe:
            writer.writerow(["Origen", "Destino", "Cantidad", "MAC_Verificacion"])
        writer.writerow([origen, destino, cantidad, mac])

def iniciar_servidor():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST, PORT))
    except socket.error as e:
        print(f"Error puerto {PORT}: {e}")
        return

    s.listen(5)
    print(f"--- SERVIDOR COMPATIBLE CORRIENDO EN {HOST}:{PORT} ---")
    print("Esperando conexión del cliente gráfico...")

    while True:
        try:
            conn, addr = s.accept()
            print(f"\n[+] Conectado: {addr}")
            
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                
                try:
                    mensaje = data.decode()
                    print(f"Procesando: {mensaje}")
                    
                    # AQUÍ ESTÁ LA CLAVE: Usamos split(',') no json.loads()
                    partes = mensaje.split(',')
                    tipo = partes[0]

                    # --- 1. LOGIN ---
                    if tipo == '1': 
                        if len(partes) < 3: 
                            conn.send("ERROR: Faltan datos".encode())
                            continue
                        user, nonce = partes[1], partes[2]
                        
                        # Anti-Replay
                        if nonce in nonces_usados:
                            conn.send("ERROR: Replay detectado".encode())
                            continue
                        nonces_usados.add(nonce)
                        
                        usuarios = cargar_usuarios()
                        if user in usuarios:
                            # Enviar Salt
                            conn.send(usuarios[user][1].encode())
                            # Recibir Hash
                            pass_client = conn.recv(1024).decode()
                            
                            # Secure Compare
                            if secrets.compare_digest(pass_client, usuarios[user][0]):
                                conn.send("OK".encode())
                                print(f"Usuario {user} autenticado.")
                            else:
                                conn.send("ERROR: Password mal".encode())
                        else:
                            conn.send("ERROR: Usuario no existe".encode())

                    # --- 2. REGISTRO ---
                    elif tipo == '2': 
                        if len(partes) < 4: continue
                        u, p, n = partes[1], partes[2], partes[3]
                        
                        if n in nonces_usados:
                            conn.send("ERROR: Replay".encode())
                            continue
                        nonces_usados.add(n)
                        
                        # Generar credenciales seguras
                        salt = secrets.token_hex(16)
                        ph = seguridad.generar_hash_password(p, salt)
                        guardar_usuario(u, ph, salt)
                        conn.send("OK".encode())
                        print(f"Usuario {u} registrado.")

                    # --- 3. TRANSFERENCIA ---
                    elif tipo == '3': 
                        # Formato: 3,origen,destino,cantidad,nonce,mac
                        if len(partes) < 6: 
                            conn.send("ERROR: Datos incompletos".encode())
                            continue
                        
                        org, dest, cant, n, mac_rx = partes[1], partes[2], partes[3], partes[4], partes[5]
                        
                        # Anti-Replay
                        if n in nonces_usados:
                            conn.send("ERROR: Replay".encode())
                            continue
                        nonces_usados.add(n)
                        
                        # Verificar Integridad (MAC)
                        msg_datos = f"{org},{dest},{cant},{n}"
                        mac_calc = seguridad.mac(msg_datos, seguridad.CLAVE_MAC)
                        
                        if secrets.compare_digest(mac_rx, mac_calc):
                            registrar_transaccion(org, dest, cant, mac_rx)
                            conn.send("OK: Transferencia realizada con integridad".encode())
                            print(f"Transferencia OK: {cant} eur")
                        else:
                            print(f"ALERTA: MAC inválido. Esperado={mac_calc}, Recibido={mac_rx}")
                            conn.send("ERROR: Fallo de Integridad".encode())

                    # --- 4. SALIR ---
                    elif tipo == '4':
                        print("Cliente cerró sesión.")
                        conn.close()
                        break

                except Exception as e_interno:
                    print(f"Error procesando mensaje: {e_interno}")
                    traceback.print_exc()

        except Exception as e:
            print(f"Error general: {e}")
        finally:
            try: conn.close()
            except: pass

if __name__ == "__main__":
    iniciar_servidor()