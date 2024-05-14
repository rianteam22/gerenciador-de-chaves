#app.py
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from config import Config
import hashlib


Config.ensure_dir(Config.KEYS_DIR)
Config.ensure_dir(Config.ENCRYPTED_FILES_DIR)

from cripto import criptografar_com_chave_publica, descriptografar_com_chave_privada
from gestao_chaves import (
    apagar_chave, gerar_par_chaves, exportar_chave_publica, exportar_chave_privada,
    importar_chave_publica, importar_chave_privada, listar_chaves
)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Trabalho 01 – Sistema de Gerenciamento de Chaves Públicas e Criptografia")
        self.root.geometry("535x610")  # Slightly larger window for better layout
        self.keys_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'keys')        
        self.setup_ui()

    def setup_ui(self):
        """Setup the user interface with frames for better organization."""
        self.setup_key_management_ui()
        self.setup_search_ui()
        self.setup_text_input_ui()
        self.setup_cripto_ui()

    def setup_key_management_ui(self):
        frame = ttk.LabelFrame(self.root, text="Key Management", padding="10 10 10 10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)

        ttk.Button(frame, text="Generate and Show Keys", command=self.generate_and_show_keys).grid(row=0, column=0, padx=10, pady=5)
        ttk.Button(frame, text="Import Private Key", command=self.importar_chave_privada_interactive).grid(row=0, column=1, padx=10, pady=5)
        ttk.Button(frame, text="Import Public Key", command=self.importar_chave_publica_interactive).grid(row=0, column=2, padx=10, pady=5)


    def setup_search_ui(self):
        frame = ttk.LabelFrame(self.root, text="Search and List Keys", padding="10 10 10 10")
        frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        self.search_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.search_var).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10)
        ttk.Button(frame, text="Search Keys", command=self.pesquisar_chaves).grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(frame, text="List All Keys", command=lambda: self.listar_chaves(None)).grid(row=0, column=2, padx=10, pady=10)

    def pesquisar_chaves(self):
        termo_pesquisa = self.search_var.get()
        self.listar_chaves(termo_pesquisa)

    def listar_chaves(self, filtro=None):
        chaves = listar_chaves(self.keys_dir, filtro)
        if not chaves:
            self.show_message("No matching keys found.")
            return
        
        top = tk.Toplevel(self.root)
        top.title("Stored Keys")

        frame = ttk.Frame(top)
        frame.pack(pady=10)

        ttk.Label(frame, text="Select a key to delete or view details:").pack()

        # Function to delete a key and refresh the list
        def delete_and_refresh(chave):
            if apagar_chave(os.path.join(self.keys_dir, chave)):
                messagebox.showinfo("Success", f"Key {chave} successfully deleted.")
                top.destroy()
                self.listar_chaves(filtro)  # Refresh the list
            else:
                messagebox.showerror("Error", f"Failed to delete {chave}.")

        for chave in chaves:
            ttk.Button(frame, text=chave, command=lambda c=chave: delete_and_refresh(c)).pack()

    def ask_for_password(self, prompt):
        """Ask user for password with validation and hashing."""
        while True:
            password = simpledialog.askstring("Password", prompt, show='*')
            if not password:
                self.show_error("No password provided; operation cancelled.")
                return None
            if len(password) < 8:
                self.show_error("The password must be at least 8 characters long.")
                continue
            # Hashing the password before using it for encryption
            hashed_password = hashlib.sha256(password.encode()).digest()
            return hashed_password
    
    def generate_and_show_keys(self):
        senha = self.ask_for_password("Digite uma senha para encriptar a chave privada:")
        if senha is None:
            return  # Cancela a operação se nenhuma senha for fornecida
        try:
            priv_key, pub_key, salt = gerar_par_chaves(senha)  # Agora passa a senha para a função de geração
            self.show_keys_ui(priv_key, pub_key, salt)
        except Exception as e:
            self.show_error(f"Falha em gerar chaves: {str(e)}")

    def show_keys_ui(self, priv_key, pub_key, salt):
        key_window = tk.Toplevel(self.root)
        key_window.title("Chaves Geradas")
        key_window.geometry("700x820")

        txt_priv = tk.Text(key_window, height=25, width=80)
        txt_priv.insert(tk.END, priv_key.decode())  # Assuming priv_key is already a bytes object
        txt_priv.pack(pady=10)

        txt_pub = tk.Text(key_window, height=10, width=80)
        txt_pub.insert(tk.END, pub_key.decode())  # Assuming pub_key is already a bytes object
        txt_pub.pack(pady=10)

        ttk.Button(key_window, text="Exportar Chave Privada", command=lambda: self.export_key(priv_key, "private", salt)).pack(pady=5)
        ttk.Button(key_window, text="Exportar Chave Pública", command=lambda: self.export_key(pub_key, "public")).pack(pady=5)

    def export_key(self, key, key_type, salt=None):
        file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if file_path:
            if key_type == "private":
                exportar_chave_privada(key, file_path, salt)
            elif key_type == "public":
                exportar_chave_publica(key, file_path)
            messagebox.showinfo("Sucesso", f"{key_type.capitalize()} key exported successfully.")

    def importar_chave_privada_interactive(self):
        """Interactively import a private key with user-selected file and password."""
        private_key_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            senha = self.ask_for_password("Enter a password to decrypt the private key:")
            try:
                chave_privada = importar_chave_privada(private_key_path, senha)
                self.show_message("Private key imported successfully!")
            except Exception as e:
                self.show_error(f"Error importing private key: {str(e)}")

    def importar_chave_publica_interactive(self):
        """Interactively import a public key with user-selected file."""
        public_key_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            try:
                chave_publica = importar_chave_publica(public_key_path)
                self.show_message("Public key imported successfully!")
            except Exception as e:
                self.show_error(f"Error importing public key: {str(e)}")
     
    def setup_text_input_ui(self):
        frame = ttk.LabelFrame(self.root, text="Input Text", padding="10 10 10 10")
        frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        self.text_input = tk.Text(frame, height=10, width=40)
        self.text_input.grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(frame, text="Save Text", command=self.save_text).grid(row=1, column=0, padx=10)

    def save_text(self):
        text = self.text_input.get("1.0", tk.END)
        with open("temp_text.txt", "w") as file:
            file.write(text)
            
    def choose_key(self):
        keys = listar_chaves(self.keys_dir)
        if not keys:
            messagebox.showerror("Error", "No keys available.")
            return None
        key_file = filedialog.askopenfilename(initialdir=self.keys_dir, title="Select Key", filetypes=[("PEM files", "*.pem")])
        return key_file

    def salvar_arquivo(self, caminho, dados):
        with open(caminho, 'wb') as file:
            file.write(dados)
        messagebox.showinfo("Sucesso", "Arquivo salvo com sucesso!")

    def setup_cripto_ui(self):
        frame = ttk.LabelFrame(self.root, text="Criptografia / Descriptografia", padding="10 10 10 10")
        frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        ttk.Button(frame, text="Criptografar", command=self.executar_criptografia).grid(row=0, column=0, padx=10, pady=5)
        ttk.Button(frame, text="Descriptografar", command=self.executar_descriptografia).grid(row=0, column=1, padx=10, pady=5)

    def executar_criptografia(self):
        arquivo = 'temp_text.txt'  # O caminho do arquivo temporário com texto salvo
        chave = self.choose_key()  # Selecione a chave pública
        if chave:
            encrypted_data = criptografar_com_chave_publica(arquivo, chave)
            save_path = filedialog.asksaveasfilename(defaultextension=".enc", title="Salvar Arquivo Criptografado")
            print(f'Encripted data{encrypted_data}\n Save Path{save_path}')
            if save_path:
                self.salvar_arquivo(save_path, encrypted_data)

    def executar_descriptografia(self):
        arquivo = filedialog.askopenfilename(title="Selecionar Arquivo Criptografado")
        chave = self.choose_key()  # Selecione a chave privada
        if chave:
            senha = self.ask_for_password("Digite a senha para descriptografar a chave:")
            decrypted_data = descriptografar_com_chave_privada(arquivo, chave, senha)
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Salvar Arquivo Descriptografado")
            if save_path:
                self.salvar_arquivo(save_path, decrypted_data)

                
    def show_message(self, message):
        messagebox.showinfo("Message", message)

    def show_error(self, message):
        messagebox.showerror("Error", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
