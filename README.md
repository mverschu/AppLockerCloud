# AppLocker Policy Creator

A web-based tool for creating and managing Windows AppLocker policies. Create application control rules through an intuitive interface and export them as valid AppLocker XML files for use with Windows Group Policy or Microsoft Intune.

## Screenshots

<img width="1529" height="791" alt="image" src="https://github.com/user-attachments/assets/12ebee8b-7a67-4681-b59b-c65581694217" />

## Requirements

- **Node.js 16+** and **npm** - Required for the frontend

## Quick Start

1. Make sure you have Node.js 16+ and npm installed
2. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the development server:
   ```bash
   npm run dev
   ```

The application will start at **http://localhost:3000** and runs entirely in your browser. All data is stored locally using browser localStorage - no backend server required!

5. Press `Ctrl+C` to stop the development server when done

## Building for Production

To build a production version:
```bash
cd frontend
npm run build
```

The built files will be in the `frontend/dist` directory and can be served by any static web server.

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
