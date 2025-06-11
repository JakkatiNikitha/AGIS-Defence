import os
import sys
import shutil
import subprocess
from pathlib import Path

def install():
    print("Installing AGIS Defence System...")
    
    # Get installation directory
    install_dir = Path.home() / "AGIS Defence"
    print(f"Installing to: {install_dir}")
    
    try:
        # Create installation directory
        install_dir.mkdir(parents=True, exist_ok=True)
        
        # Create virtual environment
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(install_dir / "venv")], check=True)
        
        # Install requirements
        print("Installing dependencies...")
        pip_path = str(install_dir / "venv" / "Scripts" / "pip.exe")
        subprocess.run([pip_path, "install", "flask==3.0.0", "werkzeug==3.0.1", "tensorflow==2.15.0", 
                       "numpy==1.24.3", "psutil==5.9.5", "requests==2.31.0", "scapy==2.5.0"], check=True)
        
        # Copy application files
        print("Copying application files...")
        app_dir = Path(__file__).parent.parent.parent / "agis_defence"
        if app_dir.exists():
            shutil.copytree(app_dir, install_dir / "agis_defence", dirs_exist_ok=True)
        
        # Create desktop shortcut
        print("Creating shortcuts...")
        desktop = Path.home() / "Desktop"
        shortcut_path = desktop / "AGIS Defence.bat"
        with open(shortcut_path, "w") as f:
            f.write(f'@echo off\ncd "{install_dir}"\ncall venv\\Scripts\\activate.bat\npython -m agis_defence\n')
        
        print("\nInstallation complete!")
        print(f"AGIS Defence System has been installed to: {install_dir}")
        print("You can start the application using the desktop shortcut.")
        input("\nPress Enter to exit...")
        
    except Exception as e:
        print(f"\nError during installation: {e}")
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    install() 