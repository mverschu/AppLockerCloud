# AppLocker Policy Creator

A web-based tool for creating and managing Windows AppLocker policies. Create application control rules through an intuitive interface and export them as valid AppLocker XML files for use with Windows Group Policy or Microsoft Intune.

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
