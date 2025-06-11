import sys
import os
import ctypes
import winreg
import subprocess
import json
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import requests
from pathlib import Path

class AGISInstaller(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("AGIS Defence System Installer")
        self.geometry("600x700")
        
        # Center window
        self.center_window()
        
        # Initialize UI
        self.create_ui()
        
        # Initialize permissions
        self.permissions = {
            "system_monitor": False,
            "network_access": False,
            "firewall_config": False,
            "logs_access": False,
            "data_backup": False
        }
        
    def center_window(self):
        """Center the window on the screen."""
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = 600
        window_height = 700
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
    def create_ui(self):
        """Create the installer UI."""
        # Main frame
        main_frame = ttk.Frame(self, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Welcome message
        ttk.Label(main_frame, text="Welcome to AGIS Defence System", 
                 font=('Helvetica', 16, 'bold')).grid(row=0, column=0, pady=20)
        
        ttk.Label(main_frame, text="The installer needs the following permissions to protect your system:",
                 wraplength=500).grid(row=1, column=0, pady=10)
        
        # Permissions frame
        perm_frame = ttk.LabelFrame(main_frame, text="Required Permissions", padding="10")
        perm_frame.grid(row=2, column=0, pady=20, sticky=(tk.W, tk.E))
        
        # Permission checkboxes
        self.perm_vars = {}
        permissions_text = {
            "system_monitor": "System Monitoring Access\nRequired for real-time system protection",
            "network_access": "Network Traffic Analysis\nRequired for threat detection",
            "firewall_config": "Firewall Configuration\nRequired for automatic threat blocking",
            "logs_access": "System Logs Access\nRequired for threat analysis",
            "data_backup": "Data Backup & Recovery\nRequired for data protection"
        }
        
        for i, (key, text) in enumerate(permissions_text.items()):
            self.perm_vars[key] = tk.BooleanVar()
            frame = ttk.Frame(perm_frame)
            frame.grid(row=i, column=0, pady=5, sticky=(tk.W, tk.E))
            
            cb = ttk.Checkbutton(frame, variable=self.perm_vars[key])
            cb.grid(row=0, column=0, padx=5)
            
            text_parts = text.split('\n')
            ttk.Label(frame, text=text_parts[0], font=('Helvetica', 10, 'bold')).grid(row=0, column=1, sticky=tk.W)
            ttk.Label(frame, text=text_parts[1], font=('Helvetica', 9)).grid(row=1, column=1, sticky=tk.W)
        
        # Progress frame
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.grid(row=3, column=0, pady=20, sticky=(tk.W, tk.E))
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self.progress_frame, variable=self.progress_var, maximum=100)
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.status_label = ttk.Label(self.progress_frame, text="")
        self.status_label.grid(row=1, column=0, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=4, column=0, pady=20)
        
        self.install_button = ttk.Button(buttons_frame, text="Install", command=self.start_installation)
        self.install_button.grid(row=0, column=0, padx=5)
        
        ttk.Button(buttons_frame, text="Cancel", command=self.quit).grid(row=0, column=1, padx=5)
        
    def start_installation(self):
        """Start the installation process."""
        # Check if all permissions are granted
        if not all(var.get() for var in self.perm_vars.values()):
            messagebox.showerror("Error", "All permissions are required for the software to function properly.")
            return
            
        self.install_button.state(['disabled'])
        threading.Thread(target=self.install_process, daemon=True).start()
        
    def install_process(self):
        """Run the installation process."""
        try:
            # Update progress
            self.update_progress(0, "Starting installation...")
            
            # Check admin rights
            if not self.check_admin():
                self.update_progress(0, "Error: Administrator rights required!")
                return
                
            # Create installation directory
            self.update_progress(10, "Creating installation directory...")
            install_dir = self.create_install_directory()
            
            # Install dependencies
            self.update_progress(20, "Installing dependencies...")
            self.install_dependencies()
            
            # Configure firewall
            self.update_progress(40, "Configuring firewall...")
            self.configure_firewall()
            
            # Set up system monitoring
            self.update_progress(60, "Setting up system monitoring...")
            self.setup_system_monitoring()
            
            # Configure data backup
            self.update_progress(80, "Configuring data backup...")
            self.setup_data_backup()
            
            # Create startup entry
            self.update_progress(90, "Creating startup entry...")
            self.create_startup_entry()
            
            # Finish installation
            self.update_progress(100, "Installation completed successfully!")
            messagebox.showinfo("Success", "AGIS Defence System has been installed successfully!")
            self.quit()
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            messagebox.showerror("Error", f"Installation failed: {str(e)}")
            self.install_button.state(['!disabled'])
            
    def update_progress(self, value, status):
        """Update progress bar and status label."""
        self.progress_var.set(value)
        self.status_label.config(text=status)
        self.update()
        
    def check_admin(self):
        """Check if the installer has admin rights."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
            
    def create_install_directory(self):
        """Create the installation directory."""
        install_dir = Path(os.environ['ProgramFiles']) / 'AGIS Defence'
        install_dir.mkdir(parents=True, exist_ok=True)
        return install_dir
        
    def install_dependencies(self):
        """Install required dependencies."""
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        
    def configure_firewall(self):
        """Configure Windows Firewall for AGIS."""
        # Add firewall rules
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       'name="AGIS Defence"',
                       'dir=in',
                       'action=allow',
                       'program="C:\\Program Files\\AGIS Defence\\agis.exe"'])
        
    def setup_system_monitoring(self):
        """Set up system monitoring capabilities."""
        # Create monitoring service
        service_config = {
            'name': 'AGISMonitor',
            'display_name': 'AGIS Defence Monitor',
            'command': '"C:\\Program Files\\AGIS Defence\\monitor.exe"'
        }
        subprocess.run(['sc', 'create', service_config['name'],
                       'binPath=', service_config['command'],
                       'start=', 'auto',
                       'DisplayName=', service_config['display_name']])
        
    def setup_data_backup(self):
        """Configure data backup system."""
        backup_config = {
            'backup_dir': 'C:\\ProgramData\\AGIS Defence\\Backups',
            'interval': 3600,  # 1 hour
            'retention_days': 7
        }
        
        # Create backup directory
        os.makedirs(backup_config['backup_dir'], exist_ok=True)
        
        # Save backup configuration
        config_path = Path('C:\\ProgramData\\AGIS Defence\\config.json')
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(backup_config, f)
        
    def create_startup_entry(self):
        """Create Windows startup entry."""
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        winreg.SetValueEx(key, "AGIS Defence", 0, winreg.REG_SZ, 
                         r"C:\Program Files\AGIS Defence\agis.exe")
        winreg.CloseKey(key)

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = AGISInstaller()
        app.mainloop()

if __name__ == "__main__":
    main() 