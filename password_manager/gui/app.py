import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import ttk
from gui.views.init_view import InitView
from gui.views.vault_view import VaultView
from gui.views.export_view import ExportView

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Password Manager")
        self.geometry("800x600")
        self.minsize(800, 600)
        
        self.container = ttk.Frame(self)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        
        for F in (InitView, VaultView, ExportView):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
            
        self.show_frame("InitView")

    def show_frame(self, page_name, **kwargs):
        frame = self.frames[page_name]
        if hasattr(frame, "on_show"):
            frame.on_show(**kwargs)
        frame.tkraise()

if __name__ == "__main__":
    app = App()
    app.mainloop()