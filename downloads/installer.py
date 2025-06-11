import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

class InstallerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AGIS Defence System Installer")
        self.root.geometry("600x400")
        
        # Center window
        self.center_window()
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Welcome message
        ttk.Label(
            main_frame,
            text="Welcome to AGIS Defence System",
            font=("Helvetica", 16, "bold")
        ).grid(row=0, column=0, pady=20)
        
        ttk.Label(
            main_frame,
            text="This wizard will guide you through the installation process.",
            wraplength=500
        ).grid(row=1, column=0, pady=10)
        
        # Installation path
        ttk.Label(
            main_frame,
            text="Installation Directory:"
        ).grid(row=2, column=0, pady=5, sticky=tk.W)
        
        self.install_path = tk.StringVar(value=os.path.expanduser("~\\AGIS Defence"))
        ttk.Entry(
            main_frame,
            textvariable=self.install_path,
            width=50
        ).grid(row=3, column=0, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            main_frame,
            orient="horizontal",
            length=400,
            mode="determinate"
        )
        self.progress.grid(row=4, column=0, pady=20)
        
        # Install button
        self.install_btn = ttk.Button(
            main_frame,
            text="Install",
            command=self.install
        )
        self.install_btn.grid(row=5, column=0, pady=10)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to install")
        ttk.Label(
            main_frame,
            textvariable=self.status_var
        ).grid(row=6, column=0, pady=5)

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def install(self):
        try:
            install_dir = Path(self.install_path.get())
            
            # Create installation directory
            self.update_status("Creating installation directory...", 10)
            install_dir.mkdir(parents=True, exist_ok=True)
            
            # Create virtual environment
            self.update_status("Creating virtual environment...", 30)
            subprocess.run([sys.executable, "-m", "venv", str(install_dir / "venv")], check=True)
            
            # Install requirements
            self.update_status("Installing dependencies...", 50)
            pip_path = str(install_dir / "venv" / "Scripts" / "pip.exe")
            subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
            
            # Copy application files
            self.update_status("Copying application files...", 70)
            # Add file copying logic here
            
            # Create desktop shortcut
            self.update_status("Creating shortcuts...", 90)
            # Add shortcut creation logic here
            
            self.update_status("Installation complete!", 100)
            messagebox.showinfo(
                "Installation Complete",
                "AGIS Defence System has been successfully installed!"
            )
            
            self.root.quit()
            
        except Exception as e:
            messagebox.showerror("Installation Error", str(e))
            self.status_var.set("Installation failed")
            self.progress["value"] = 0

    def update_status(self, message, progress):
        self.status_var.set(message)
        self.progress["value"] = progress
        self.root.update()

def main():
    root = tk.Tk()
    app = InstallerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 