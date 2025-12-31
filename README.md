# AppLocker Policy Creator

A web-based tool for creating and managing Windows AppLocker policies. Create application control rules through an intuitive interface and export them as valid AppLocker XML files for use with Windows Group Policy or Microsoft Intune.

## Screenshots

<img width="1714" height="901" alt="image" src="https://github.com/user-attachments/assets/6a2a78f6-6bb9-4e47-89b2-3ef644d84e0d" />

## Requirements

- **Python 3.8+** - Required for the backend API
- **Node.js 16+** and **npm** - Required for the frontend
- **Bash** - Required to run the startup script

## Quick Start

1. Make sure you have Python 3.8+, Node.js 16+, and npm installed
2. Run the startup script:
   ```bash
   ./start.sh
   ```

The script will automatically:
- Create a Python virtual environment (if needed)
- Install backend dependencies
- Install frontend dependencies
- Start both the backend API (http://localhost:8080) and frontend web app (http://localhost:3000)

3. Open your browser and navigate to **http://localhost:3000**

4. Press `Ctrl+C` to stop all services when done

## What It Does

This tool provides a visual interface to create AppLocker rules for:
- Executables (.exe, .com)
- Scripts (.ps1, .bat, .cmd, .vbs, .js)
- DLLs (.dll, .ocx)
- Windows Installers (.msi, .msp, .mst)
- Packaged Apps (UWP/MSIX)

You can create rules based on file paths, publisher certificates, or file hashes, then export the complete policy as an XML file ready for deployment.

The tool also provides tips to make sure the policy is hardened against common known attacks.

**Windows Folder Bypass Risk**
<img width="870" height="541" alt="image" src="https://github.com/user-attachments/assets/5e493dd6-3067-40fb-9a1e-1452b7955ae4" /> </br>
**Living-Off-The-Land Binary Risk (Windows)**
<img width="854" height="473" alt="image" src="https://github.com/user-attachments/assets/3f9086a6-1ea8-4ce1-a5dd-8b7e759baa71" />
