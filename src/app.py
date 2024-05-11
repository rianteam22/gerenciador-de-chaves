import tkinter as tk
from tkinter import filedialog
from gestao_chaves import gerar_par_chaves, exportar_chave_publica, exportar_chave_privada, importar_chave_publica, importar_chave_privada
from tkinter import ttk  # Importar ttk para estilos melhores

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Trabalho 01 – Sistema de Gerenciamento de Chaves Públicas e Criptografia")
        self.root.geometry("800x500")

        # Frame para Gerenciamento de Chaves
        frame_gerenciamento_chaves = ttk.Frame(root, padding="3 3 12 12")
        frame_gerenciamento_chaves.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(frame_gerenciamento_chaves, text="Gerenciamento de Chaves").grid(columnspan=3)
        
        ttk.Button(frame_gerenciamento_chaves, text="Gerar Par de Chaves", command=self.gerar_chaves).grid(row=1, column=0)
        ttk.Button(frame_gerenciamento_chaves, text="Exportar Chaves", command=self.exportar_chaves).grid(row=1, column=1)
        ttk.Button(frame_gerenciamento_chaves, text="Importar Chaves", command=self.importar_chaves).grid(row=1, column=2)



    def show_message(self, message):
        tk.messagebox.showinfo("Mensagem", message)

    def show_error(self, message):
        tk.messagebox.showerror("Erro", message)

    def gerar_chaves(self):
        try:
            gerar_par_chaves('minha_chave_privada.pem', 'minha_chave_publica.pem')
            self.show_message("Chaves geradas com sucesso!")
        except Exception as e:
            self.show_error(f"Falha em gerar chaves: {str(e)}")
    def exportar_chaves(self):
        private_key_path = filedialog.asksaveasfilename(title="Salvar chave privada como", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            exportar_chave_privada('minha_chave_privada.pem', private_key_path, 'sua_senha')
        
        public_key_path = filedialog.asksaveasfilename(title="Salvar chave pública como", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            exportar_chave_publica('minha_chave_publica.pem', public_key_path)
        self.show_message("Chaves exportadas com sucesso!")
        
    def importar_chaves(self):
        public_key_path = filedialog.askopenfilename(title="Selecionar chave pública", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            importar_chave_publica(public_key_path)
        
        private_key_path = filedialog.askopenfilename(title="Selecione chave privada", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            password = tk.simpledialog.askstring("Senha", "Digite a senha de sua chave privada:", show='*')
            importar_chave_privada(private_key_path, password)
        self.show_message("As chaves foram importadas com sucesso!")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
