import os
import shutil
import zipfile
from pathlib import Path

def create_windows_installer():
    # Create a temporary directory for the installer contents
    installer_dir = Path("installer_temp")
    installer_dir.mkdir(exist_ok=True)
    
    # Copy the main application files
    shutil.copytree("agis_defence", installer_dir / "agis_defence", dirs_exist_ok=True)
    
    # Create requirements.txt
    with open(installer_dir / "requirements.txt", "w") as f:
        f.write("""flask>=2.0.1
flask-cors>=3.0.10
tensorflow>=2.8.0
numpy>=1.24.3
psutil>=5.9.5
requests>=2.31.0
scapy>=2.5.0
waitress>=2.1.2
""")
    
    # Create install.bat with more detailed setup
    with open(installer_dir / "install.bat", "w") as f:
        f.write("""@echo off
echo ====================================
echo AGIS Defence System Installer
echo ====================================
echo.

:: Check for Python installation
python --version > nul 2>&1
if errorlevel 1 (
    echo Python is not installed! Please install Python 3.8 or later.
    echo You can download Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo Failed to create virtual environment!
    pause
    exit /b 1
)

echo Activating virtual environment...
call venv\\Scripts\\activate.bat

echo Installing required packages...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo Creating shortcuts...
echo Set oWS = WScript.CreateObject("WScript.Shell") > create_shortcut.vbs
echo sLinkFile = oWS.SpecialFolders("Desktop") ^& "\\AGIS Defence.lnk" >> create_shortcut.vbs
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> create_shortcut.vbs
echo oLink.TargetPath = "%~dp0start.bat" >> create_shortcut.vbs
echo oLink.Save >> create_shortcut.vbs
cscript //nologo create_shortcut.vbs
del create_shortcut.vbs

echo Installation complete!
echo.
echo Would you like to start AGIS Defence System now? (Y/N)
choice /C YN /N
if errorlevel 2 goto END
if errorlevel 1 goto START

:START
start start.bat
goto END

:END
echo.
echo Thank you for installing AGIS Defence System!
pause
""")

    # Create start.bat
    with open(installer_dir / "start.bat", "w") as f:
        f.write("""@echo off
call venv\\Scripts\\activate.bat
python -m agis_defence
pause
""")

    # Create README.txt
    with open(installer_dir / "README.txt", "w") as f:
        f.write("""AGIS Defence System
===================

Installation Instructions:
1. Make sure you have Python 3.8 or later installed
2. Run install.bat to set up the environment
3. After installation, use the desktop shortcut or start.bat to run the system

For support, visit: https://agis-defence.com/support
""")

    # Ensure the website/downloads directory exists
    os.makedirs("website/downloads", exist_ok=True)

    # Create the installer package
    installer_zip = "website/downloads/AGIS-Defence-Setup-Win64.zip"
    with zipfile.ZipFile(installer_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in installer_dir.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(installer_dir))
    
    # Clean up
    shutil.rmtree(installer_dir)
    print(f"Installer created successfully at {installer_zip}")

if __name__ == "__main__":
    create_windows_installer() 