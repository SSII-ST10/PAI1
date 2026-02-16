import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import seguridad
import time
import json

HOST = 'localhost'
PORT = 3030

class BancoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Banco Seguro - Cliente PAI 1")
        self.root.geometry("900x600")
        
        self.sock = None
        self.username = None
        self.connected = False
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.left_frame = ttk.Frame(root, padding="20")
        self.left_frame.place(relx=0, rely=0, relwidth=0.6, relheight=1)
        
        self.right_frame = ttk.LabelFrame(root, text="Logs del Sistema (Evidencias)", padding="10")
        self.right_frame.place(relx=0.6, rely=0, relwidth=0.4, relheight=1)
        
        self.log_area = scrolledtext.ScrolledText(self.right_frame, state='disabled', font=("Consolas", 9))
        self.log_area.pack(fill="both", expand=True)
        
        self.mostrar_pantalla_conexion()

    def log(self, mensaje, tipo="INFO"):
        """Añade mensajes al panel de logs con timestamp"""
        self.log_area.config(state='normal')
        timestamp = time.strftime("%H:%M:%S")
        tag = "info"
        if tipo == "ERROR": tag = "error"
        elif tipo == "OK": tag = "success"
        elif tipo == "SEC": tag = "security"
        
        self.log_area.insert(tk.END, f"[{timestamp}] [{tipo}] {mensaje}\n", tag)
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')
        
        self.log_area.tag_config("error", foreground="red")
        self.log_area.tag_config("success", foreground="green")
        self.log_area.tag_config("security", foreground="blue")

    def limpiar_frame(self):
        for widget in self.left_frame.winfo_children():
            widget.destroy()
    
    def conectar(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            self.connected = True
            self.log(f"Conectado a {HOST}:{PORT}", "OK")
            self.mostrar_pantalla_login()
        except Exception as e:
            self.log(f"Error de conexión: {e}", "ERROR")
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")

    def enviar_recibir(self, mensaje):
        if not self.sock:
            return None
        try:
            self.sock.sendall(mensaje.encode())
            self.log(f"Enviado: {mensaje}", "INFO")
            respuesta = self.sock.recv(1024).decode()
            self.log(f"Recibido: {respuesta}", "INFO")
            return respuesta
        except Exception as e:
            self.log(f"Error socket: {e}", "ERROR")
            return None

    def mostrar_pantalla_conexion(self):
        self.limpiar_frame()
        
        ttk.Label(self.left_frame, text="🏦 Sistema Bancario Seguro", font=("Helvetica", 24)).pack(pady=40)
        ttk.Label(self.left_frame, text="PAI 1 - Integridad y Autenticación", font=("Helvetica", 12)).pack(pady=10)
        
        btn = ttk.Button(self.left_frame, text="Conectar al Servidor", command=self.conectar)
        btn.pack(pady=20, ipadx=20, ipady=10)

    def mostrar_pantalla_login(self):
        self.limpiar_frame()
        
        ttk.Label(self.left_frame, text="Identificación", font=("Helvetica", 18)).pack(pady=20)
        
        tab_control = ttk.Notebook(self.left_frame)
        tab1 = ttk.Frame(tab_control)
        tab2 = ttk.Frame(tab_control)
        tab_control.add(tab1, text='Iniciar Sesión')
        tab_control.add(tab2, text='Registrarse')
        tab_control.pack(expand=1, fill="both", padx=20)
        
        ttk.Label(tab1, text="Usuario:").pack(pady=5)
        user_entry = ttk.Entry(tab1)
        user_entry.pack(pady=5)
        
        ttk.Label(tab1, text="Contraseña:").pack(pady=5)
        pass_entry = ttk.Entry(tab1, show="*")
        pass_entry.pack(pady=5)
        
        def realizar_login():
            u = user_entry.get()
            p = pass_entry.get()
            if not u or not p:
                messagebox.showwarning("Aviso", "Rellene todos los campos")
                return
            
            nonce = seguridad.generar_nonce()
            msg = f"1,{u},{nonce}"
            resp = self.enviar_recibir(msg)
            
            if resp and not resp.startswith("ERROR") and "Datos incorrectos" not in resp:
                salt = resp
                pass_hash = seguridad.generar_hash_password(p, salt)
                self.log(f"Hash generado: {pass_hash[:10]}...", "SEC")
                
                resp_final = self.enviar_recibir(pass_hash)
                
                if "OK" in resp_final:
                    self.username = u
                    messagebox.showinfo("Éxito", "Login correcto")
                    self.mostrar_dashboard()
                else:
                    messagebox.showerror("Error", f"Login fallido: {resp_final}")
            else:
                messagebox.showerror("Error", f"Usuario no encontrado o error: {resp}")

        ttk.Button(tab1, text="Entrar", command=realizar_login).pack(pady=20)
        
        ttk.Label(tab2, text="Nuevo Usuario:").pack(pady=5)
        reg_user = ttk.Entry(tab2)
        reg_user.pack(pady=5)
        
        ttk.Label(tab2, text="Nueva Contraseña:").pack(pady=5)
        reg_pass = ttk.Entry(tab2, show="*")
        reg_pass.pack(pady=5)
        
        def realizar_registro():
            u = reg_user.get()
            p = reg_pass.get()
            if not u or not p: return
            
            nonce = seguridad.generar_nonce()
            msg = f"2,{u},{p},{nonce}"
            resp = self.enviar_recibir(msg)
            if resp and "OK" in resp:
                messagebox.showinfo("Éxito", "Usuario registrado. Por favor inicie sesión.")
            else:
                messagebox.showerror("Error", resp)
                
        ttk.Button(tab2, text="Registrar", command=realizar_registro).pack(pady=20)

    def mostrar_dashboard(self):
        self.limpiar_frame()
        
        header = ttk.Frame(self.left_frame)
        header.pack(fill="x", pady=10, padx=10)
        ttk.Label(header, text=f"Hola, {self.username}", font=("Helvetica", 16, "bold")).pack(side="left")
        ttk.Button(header, text="Cerrar Sesión", command=self.logout).pack(side="right")
        
        ttk.Separator(self.left_frame, orient='horizontal').pack(fill='x', pady=10)
        
        ttk.Label(self.left_frame, text="Realizar Transferencia", font=("Helvetica", 14)).pack(pady=10)
        
        form_frame = ttk.Frame(self.left_frame, padding=20, relief="groove")
        form_frame.pack(fill="x", padx=20)
        
        ttk.Label(form_frame, text="Cuenta Destino (Usuario):").grid(row=0, column=0, sticky="w", pady=5)
        dest_entry = ttk.Entry(form_frame)
        dest_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=5)
        
        ttk.Label(form_frame, text="Cantidad (€):").grid(row=1, column=0, sticky="w", pady=5)
        cant_entry = ttk.Entry(form_frame)
        cant_entry.grid(row=1, column=1, sticky="ew", pady=5, padx=5)
        
        form_frame.columnconfigure(1, weight=1)
        
        def enviar_transaccion():
            dest = dest_entry.get()
            cant = cant_entry.get()
            
            if not dest or not cant:
                messagebox.showwarning("Error", "Complete los campos")
                return
            
            nonce = seguridad.generar_nonce()
            
            mensaje_datos = f"{self.username},{dest},{cant},{nonce}"
            
            mac_calculado = seguridad.mac(mensaje_datos.encode(), seguridad.CLAVE_MAC)
            
            self.log(f"Calculando MAC para: {mensaje_datos}", "SEC")
            self.log(f"MAC: {mac_calculado}", "SEC")
            
            msg_final = f"3,{mensaje_datos},{mac_calculado}"
            
            resp = self.enviar_recibir(msg_final)
            
            if resp:
                if "OK" in resp:
                    messagebox.showinfo("Éxito", f"Transferencia realizada:\n{resp}")
                    self.log("Integridad verificada por el servidor.", "success")
                elif "Integridad" in resp:
                    messagebox.showerror("Error de Seguridad", "El servidor detectó un error de integridad (MAC inválido).")
                elif "Replay" in resp:
                    messagebox.showerror("Ataque Detectado", "El servidor detectó un ataque de Replay (Nonce repetido).")
                else:
                    messagebox.showerror("Error", resp)

        ttk.Button(form_frame, text="Enviar Dinero 💸", command=enviar_transaccion).grid(row=2, column=0, columnspan=2, pady=20)
        
        info_frame = ttk.LabelFrame(self.left_frame, text="Estado de Seguridad", padding=10)
        info_frame.pack(fill="x", padx=20, pady=20)
        ttk.Label(info_frame, text="🔒 Canal Cifrado (Simulado)").pack(anchor="w")
        ttk.Label(info_frame, text="🛡️ Protección Anti-Replay Activa").pack(anchor="w")
        ttk.Label(info_frame, text="✅ Verificación de Integridad (HMAC-SHA256)").pack(anchor="w")

    def logout(self):
        try:
            self.enviar_recibir("4")
            self.sock.close()
        except:
            pass
        self.sock = None
        self.connected = False
        self.username = None
        self.mostrar_pantalla_conexion()

if __name__ == "__main__":
    root = tk.Tk()
    app = BancoApp(root)
    root.mainloop()