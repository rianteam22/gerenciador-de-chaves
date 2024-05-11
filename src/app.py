import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from gestao_chaves import (
    apagar_chave, carregar_chave_privada, carregar_chave_publica,
    gerar_par_chaves, exportar_chave_publica, exportar_chave_privada,
    importar_chave_publica, importar_chave_privada, listar_chaves
)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Trabalho 01 – Sistema de Gerenciamento de Chaves Públicas e Criptografia")
        self.root.geometry("600x600")
        self.keys_dir = os.path.join(os.path.dirname(__file__), 'keys')  # Define o diretório das chaves
        
        self.setup_ui()

    def setup_ui(self):
        """Setup the user interface with buttons and labels."""
        frame = ttk.Frame(self.root, padding="10 10 10 10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(frame, text="Gerenciamento de Chaves").grid(column=1)
        self.search_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.search_var).grid(row=2, column=1, sticky=(tk.W, tk.E), padx=10)
        ttk.Button(frame, text="Pesquisar Chaves", command=self.pesquisar_chaves).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=10, pady=10)
        ttk.Button(frame, text="Listar Todas as Chaves", command=lambda: self.listar_chaves(None)).grid(row=1, column=2, sticky=(tk.W, tk.E), padx=10, pady=10)

        actions = [
            ("Gerar Par de Chaves", self.gerar_chaves),
            ("Exportar Chave Privada", self.exportar_chave_privada_interactive),
            ("Exportar Chave Pública", self.exportar_chave_publica_interactive),
            ("Importar Chave Privada", self.importar_chave_privada_interactive),
            ("Importar Chave Pública", self.importar_chave_publica_interactive)
        ]
        for i, (label, action) in enumerate(actions, start=1):
            ttk.Button(frame, text=label, command=action).grid(row=i, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)
        
            
    def pesquisar_chaves(self):
        """Mostrar uma lista de chaves armazenadas que correspondem ao termo de pesquisa."""
        termo_pesquisa = self.search_var.get()
        self.listar_chaves(termo_pesquisa)

    def listar_chaves(self, filtro=None):
        """Mostrar uma lista de chaves armazenadas ao usuário e opções para apagar, com opção de filtro."""
        chaves = listar_chaves(self.keys_dir, filtro)
        if not chaves:
            self.show_message("Nenhuma chave correspondente encontrada.")
            return
        
        top = tk.Toplevel(self.root)
        top.title("Chaves Armazenadas")
        ttk.Label(top, text="Selecione uma chave para apagar ou veja detalhes:").pack()

        for chave in chaves:
            ttk.Button(top, text=chave, command=lambda c=chave: self.apagar_chave(os.path.join(self.keys_dir, c))).pack()

    def apagar_chave(self, path):
        """Apagar a chave selecionada."""
        if messagebox.askokcancel("Confirmar", "Você realmente deseja apagar esta chave?"):
            if apagar_chave(path):
                self.show_message("Chave apagada com sucesso.")
            else:
                self.show_error("Falha ao apagar chave.")
 
    def ask_for_password(self, prompt):
        """Ask user for password with validation."""
        while True:
            senha = simpledialog.askstring("Senha", prompt, show='*')
            if not senha:
                self.show_error("Nenhuma senha foi fornecida; a operação foi cancelada.")
                return None
            if len(senha) < 8:
                self.show_error("A senha deve ter pelo menos 8 caracteres.")
                continue
            return senha

    def gerar_chaves(self):
        """Generate public and private keys with a password provided by the user."""
        senha = self.ask_for_password("Digite uma senha para encriptar a chave privada:")
        if senha is None:
            return
        try:
            gerar_par_chaves('minha_chave_privada.pem', 'minha_chave_publica.pem', senha)
            self.show_message("Chaves geradas com sucesso!")
        except Exception as e:
            self.show_error(f"Falha em gerar chaves: {str(e)}")

    # Example of a refactored export function
    def exportar_chave_privada_interactive(self):
        """Interactively export a private key with user-selected file and password."""
        senha = self.ask_for_password("Digite a senha para encriptar a chave privada:")
        if senha is None:
            return
        private_key_path = filedialog.askopenfilename(title="Selecionar chave privada para exportar", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            try:
                chave_privada = carregar_chave_privada(private_key_path, senha)
                local_para_salvar = filedialog.asksaveasfilename(title="Salvar chave privada como", filetypes=[("PEM files", "*.pem")])
                if local_para_salvar:
                    exportar_chave_privada(chave_privada, local_para_salvar, senha)
            except Exception as e:
                self.show_error(f"Erro ao exportar chave privada: {str(e)}")

    def exportar_chave_publica_interactive(self):
        """Interactively export a public key with user-selected file."""
        public_key_path = filedialog.askopenfilename(title="Selecionar chave pública para exportar", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            try:
                chave_publica = carregar_chave_publica(public_key_path)
                local_para_salvar = filedialog.asksaveasfilename(title="Salvar chave pública como", filetypes=[("PEM files", "*.pem")])
                if local_para_salvar:
                    exportar_chave_publica(chave_publica, local_para_salvar)
                    self.show_message("Chave pública exportada com sucesso!")
            except Exception as e:
                self.show_error(f"Erro ao exportar chave pública: {str(e)}")

    def importar_chave_privada_interactive(self):
        """Interactively import a private key with user-selected file and password."""
        private_key_path = filedialog.askopenfilename(title="Selecionar chave privada", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            password = simpledialog.askstring("Senha", "Digite a senha de sua chave privada:", show='*')
            try:
                importar_chave_privada(private_key_path, password)
                self.show_message("Chave privada importada com sucesso!")
            except Exception as e:
                self.show_error(f"Erro ao importar chave privada: {str(e)}")

    def importar_chave_publica_interactive(self):
        """Interactively import a public key with user-selected file."""
        public_key_path = filedialog.askopenfilename(title="Selecionar chave pública", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            try:
                importar_chave_publica(public_key_path)
                self.show_message("Chave pública importada com sucesso!")
            except Exception as e:
                self.show_error(f"Erro ao importar chave pública: {str(e)}")

    def show_message(self, message):
        """Display a message box with an informational message."""
        messagebox.showinfo("Mensagem", message)

    def show_error(self, message):
        """Display an error message box."""
        messagebox.showerror("Erro", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
