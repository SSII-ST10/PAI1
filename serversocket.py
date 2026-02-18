import socket
import sys
import os
import secrets
import traceback
import time
import hashlib
import seguridad
import db_helper

HOST = "localhost"
PORT = 3030

# Rate limiting: diccionario en memoria {ip: [timestamp1, timestamp2, ...]}
rate_limit_tracker = {}
request_counter = 0  # Para triggear cleanup periódico


def check_rate_limit(ip):
    """
    Verifica rate limit de 10 req/min por IP
    Returns: True si permitido, False si excedido
    """
    global rate_limit_tracker
    now = time.time()

    if ip not in rate_limit_tracker:
        rate_limit_tracker[ip] = []

    # Limpiar timestamps antiguos (> 60 segundos)
    rate_limit_tracker[ip] = [t for t in rate_limit_tracker[ip] if now - t < 60]

    # Verificar límite
    if len(rate_limit_tracker[ip]) >= 10:
        return False  # Rate limit excedido

    # Añadir timestamp actual
    rate_limit_tracker[ip].append(now)
    return True


def generar_tx_response(tx_id):
    """
    Genera respuesta formateada para transacción exitosa
    Formato: OK|TX_ID|TIMESTAMP|HASH
    """
    timestamp = int(time.time())
    tx_hash = hashlib.sha256(f"{tx_id}{timestamp}".encode()).hexdigest()
    return f"OK|{tx_id}|{timestamp}|{tx_hash}"


def iniciar_servidor():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST, PORT))
    except socket.error as e:
        print(f"Error puerto {PORT}: {e}")
        return

    s.listen(5)
    print(f"--- SERVIDOR LISTO EN {HOST}:{PORT} ---")

    while True:
        conn = None
        try:
            conn, addr = s.accept()
            print(f"\n[+] Cliente conectado: {addr}")

            while True:
                data = conn.recv(1024)
                if not data:
                    break

                try:
                    # Obtener IP del cliente
                    client_ip = addr[0]

                    # Verificar rate limit
                    if not check_rate_limit(client_ip):
                        print(f"[RATE LIMIT] Bloqueado: {client_ip}")
                        conn.send("ERROR: Rate limit excedido (10 req/min)".encode())
                        continue

                    # Cleanup periódico de nonces (cada 100 requests)
                    global request_counter
                    request_counter += 1
                    if request_counter % 100 == 0:
                        db_helper.cleanup_old_nonces()

                    mensaje = data.decode()
                    partes = mensaje.split(",")
                    tipo = partes[0]

                    if tipo == "1":
                        # LOGIN
                        if len(partes) < 2:
                            conn.send("ERROR: Faltan datos".encode())
                            continue

                        user = partes[1]

                        # Obtener usuario de DB
                        user_data = db_helper.get_user(user)

                        if user_data:
                            stored_hash = user_data["password_hash"]
                            salt = user_data["salt"]

                            nonce_server = seguridad.generar_nonce()
                            conn.send(f"{salt},{nonce_server}".encode())

                            hash_recibido = conn.recv(1024).decode()

                            # Calcular hash esperado: PBKDF2(PBKDF2(password, salt), nonce_server)
                            calculo_local = seguridad.pbkdf2_hash(
                                stored_hash, nonce_server
                            )

                            if secrets.compare_digest(hash_recibido, calculo_local):
                                conn.send("OK".encode())
                                print(f"[LOGIN OK] Usuario: {user}")
                            else:
                                conn.send("ERROR: Contraseña incorrecta".encode())
                        else:
                            conn.send("ERROR: Usuario no encontrado".encode())

                    elif tipo == "2":
                        # REGISTRO
                        if len(partes) < 4:
                            conn.send("ERROR: Faltan datos".encode())
                            continue

                        u, p, n = partes[1], partes[2], partes[3]

                        # Verificar nonce (protección anti-replay)
                        if not db_helper.check_nonce_atomic(n):
                            conn.send("ERROR: Replay detectado".encode())
                            print(f"[REPLAY ATTACK] Registro - Nonce: {n[:8]}...")
                            continue

                        # Generar salt y hash con PBKDF2
                        salt = secrets.token_hex(16)
                        password_hash = seguridad.pbkdf2_hash(p, salt)

                        # Guardar en DB
                        if db_helper.save_user(u, password_hash, salt):
                            conn.send("OK".encode())
                            print(f"[REGISTRO OK] Usuario: {u}")
                        else:
                            conn.send("ERROR: Usuario ya registrado".encode())

                    elif tipo == "3":
                        # TRANSACCIÓN
                        if len(partes) < 6:
                            conn.send("ERROR: Datos incompletos".encode())
                            continue

                        org, dest, cant, n, mac_rx = (
                            partes[1],
                            partes[2],
                            partes[3],
                            partes[4],
                            partes[5],
                        )

                        # Verificar nonce (protección anti-replay)
                        if not db_helper.check_nonce_atomic(n):
                            conn.send("ERROR: Replay detectado".encode())
                            print(f"[REPLAY ATTACK] Transacción - Nonce: {n[:8]}...")
                            continue

                        # Verificar MAC
                        msg_datos = f"{org},{dest},{cant},{n}"
                        clave_mac = seguridad.obtener_clave_mac()
                        mac_calc = seguridad.mac(msg_datos, clave_mac)

                        if secrets.compare_digest(mac_rx, mac_calc):
                            # Generar ID de transacción único
                            tx_id = secrets.token_hex(16)

                            # Guardar en DB
                            db_helper.save_transaction(tx_id, org, dest, cant, mac_rx)

                            # Generar respuesta con detalles
                            response = generar_tx_response(tx_id)
                            conn.send(response.encode())
                            print(f"[TX OK] {cant}€ ({org}->{dest}) | TX_ID: {tx_id}")
                        else:
                            conn.send(
                                "ERROR: Fallo de Integridad (MAC inválido)".encode()
                            )
                            print(f"[MAC FAIL] Transacción rechazada")

                    elif tipo == "4":
                        # LOGOUT
                        conn.close()
                        break

                except Exception as e_interno:
                    print(f"Error procesando: {e_interno}")
                    traceback.print_exc()

        except Exception as e:
            print(f"Error general: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass


if __name__ == "__main__":
    iniciar_servidor()
