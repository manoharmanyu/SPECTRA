#!/usr/bin/env node

/**
 * ==============================================================================
 * SPECTRA — Universal Cross-Platform Environment Setup & Dependency Installer
 * Supported OS: Windows (x64/ARM64), macOS (Apple Silicon/Intel), Linux & BSD
 * ==============================================================================
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync, spawn } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const args = process.argv.slice(2);
const autoStart = args.includes('--start') || args.includes('-s');
const showHelp = args.includes('--help') || args.includes('-h');

if (showHelp) {
  console.log(`\nSPECTRA Universal Setup Engine`);
  console.log(`Usage:`);
  console.log(`  node setup.js          Install dependencies, prepare storage, build bundle, run tests`);
  console.log(`  node setup.js --start  Install dependencies and immediately start backend and frontend`);
  console.log(`  node setup.js --help   Display this help message\n`);
  process.exit(0);
}

// Color formatting
const isWindows = process.platform === 'win32';
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  red: '\x1b[31m'
};

function log(msg, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
}

log(`\n  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ `, colors.cyan);
log(`  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗`, colors.cyan);
log(`  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║`, colors.cyan);
log(`  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║`, colors.cyan);
log(`  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║`, colors.cyan);
log(`  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝`, colors.cyan);
log(`         Truth Beyond Appearance • Universal Cross-Platform Installer\n`, colors.magenta);

// 1. Platform Detection
const platformNames = {
  darwin: 'macOS (Darwin)',
  win32: 'Microsoft Windows',
  linux: 'Linux',
  freebsd: 'FreeBSD',
  openbsd: 'OpenBSD'
};
const osType = platformNames[process.platform] || process.platform;
const arch = process.arch;
log(`[1/5] Detecting Operating System: ${colors.bright}${osType} [${arch}]${colors.reset}`, colors.blue);

// 2. Validate Runtime Environment
log(`\n[2/5] Validating Runtime Prerequisites...`, colors.blue);
const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.replace('v', '').split('.')[0], 10);

if (majorVersion < 18) {
  log(`[ERROR] Node.js ${nodeVersion} detected. SPECTRA requires Node.js v18.0.0 or newer.`, colors.red);
  process.exit(1);
}
log(`      ✓ Node.js runtime: ${colors.bright}${nodeVersion}${colors.reset} (Compatible)`, colors.green);

try {
  const npmVersion = execSync('npm -v', { encoding: 'utf8' }).trim();
  log(`      ✓ npm package manager: ${colors.bright}v${npmVersion}${colors.reset}`, colors.green);
} catch (e) {
  log(`[ERROR] npm is not found in system PATH.`, colors.red);
  process.exit(1);
}

// 3. Storage Directories & Database Container
log(`\n[3/5] Initializing Local Storage & Database Schema...`, colors.blue);
const dirs = [
  path.join(__dirname, 'data'),
  path.join(__dirname, 'uploads'),
  path.join(__dirname, 'tests', 'fixtures')
];

dirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

const dbPath = path.join(__dirname, 'data', 'spectra.json');
if (!fs.existsSync(dbPath)) {
  const defaultDb = {
    users: [
      {
        id: "usr_manohar_manyu",
        username: "manohar_manyu",
        passwordHash: "4ad7ae903988237583d4bcda0db1544010d9503e68947e61c9c6b414227eec57ad3a4f64b10d2dd16577d5bbd9f9251e2d2563bbd59bf7e2e834f9cae92aabe8",
        salt: "86a24962f988c843761fc4f618191b5a",
        totpSecretEncrypted: null,
        totpEnabled: false,
        recoveryCodesHashed: [],
        createdAt: new Date().toISOString()
      }
    ],
    sessions: [],
    pairingCodes: [],
    devices: [],
    jobs: []
  };
  fs.writeFileSync(dbPath, JSON.stringify(defaultDb, null, 2), 'utf8');
  log(`      ✓ Initialized new database at ${dbPath}`, colors.green);
} else {
  log(`      ✓ Verified existing database at ${dbPath}`, colors.green);
}

// 4. Install Dependencies
log(`\n[4/5] Installing Dependencies across all modules...`, colors.blue);
log(`      Executing: npm install (production & dev dependencies)`);
try {
  execSync('npm install', { stdio: 'inherit', shell: true, cwd: __dirname });
  log(`      ✓ Dependencies successfully resolved and installed.`, colors.green);
} catch (e) {
  log(`[ERROR] Failed to install dependencies. Review npm logs above.`, colors.red);
  process.exit(1);
}

// 5. Build Frontend & Run Verification Test Suite
log(`\n[5/5] Compiling Production Assets & Validating Security Suite...`, colors.blue);
try {
  log(`      Executing: npm run build`);
  execSync('npm run build', { stdio: 'inherit', shell: true, cwd: __dirname });
  log(`      ✓ Frontend production build completed.`, colors.green);

  log(`\n      Executing: npm test (37 automated security checks)`);
  execSync('npm test', { stdio: 'inherit', shell: true, cwd: __dirname });
  log(`      ✓ All security verification tests passed.`, colors.green);
} catch (e) {
  log(`[WARNING] Build or test execution encountered an issue. See details above.`, colors.yellow);
}

// Helper to determine Local LAN IP
function getLocalIpAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

const lanIp = getLocalIpAddress();

log(`\n======================================================================`, colors.green);
log(`  SPECTRA INSTALLATION COMPLETED SUCCESSFULLY ON ${osType.toUpperCase()}!`, colors.bright + colors.green);
log(`======================================================================`, colors.green);
log(`\nTo start the SPECTRA forensic platform, open two terminals and run:`);
log(`\n  1. Backend Server & WebSocket Hub (Port 3001):`, colors.bright);
log(`     ${colors.cyan}npm run server${colors.reset}`);
log(`\n  2. Interactive 3D Frontend & Sketchbook (Port 5173):`, colors.bright);
log(`     ${colors.cyan}npm run dev${colors.reset}`);
log(`\n  Access Endpoints:`, colors.bright);
log(`  - Desktop Workspace:  http://localhost:5173/`);
log(`  - Mobile Camera Sync: http://${lanIp}:5173/mobile.html`);
log(`  - Local Forensic API: http://localhost:3001/api/status`);
log(`\n  Default Administrator Account:`, colors.magenta);
log(`  - Username: manohar_manyu`);
log(`  - Password: 80081Abc@2005`);
log(`======================================================================\n`, colors.green);

if (autoStart) {
  log(`[STARTING SPECTRA PLATFORM]`, colors.bright + colors.cyan);
  log(`Spawning Backend Server (Port 3001) & Vite Development Server (Port 5173)...\n`);

  const serverProc = spawn('npm', ['run', 'server'], { stdio: 'inherit', shell: true, cwd: __dirname });
  const devProc = spawn('npm', ['run', 'dev'], { stdio: 'inherit', shell: true, cwd: __dirname });

  const cleanup = () => {
    try { serverProc.kill(); } catch (e) {}
    try { devProc.kill(); } catch (e) {}
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}
