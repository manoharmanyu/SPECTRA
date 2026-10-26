#!/usr/bin/env bash
# ==============================================================================
# SPECTRA — Automated Environment Setup & Dependency Installer
# Truth Beyond Appearance • Neural Media Forensics & Secure Device Pairing
# Supported Platforms: macOS (Darwin) & Linux (Debian, Ubuntu, Arch, Fedora, Alpine)
# ==============================================================================

set -e

# ANSI Color Codes
CYAN='\033[0;36m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

SHOW_HELP=false
AUTO_START=false

for arg in "$@"; do
    case "$arg" in
        --start|-s)
            AUTO_START=true
            ;;
        --help|-h)
            SHOW_HELP=true
            ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    echo -e "${CYAN}${BOLD}SPECTRA Setup Script Usage:${NC}"
    echo -e "  ${BOLD}./install.sh${NC}          Install dependencies, initialize database, build assets, and run tests"
    echo -e "  ${BOLD}./install.sh --start${NC}  Run complete setup and immediately launch backend & frontend servers"
    echo -e "  ${BOLD}./install.sh --help${NC}   Show this help message\n"
    exit 0
fi

echo -e "${CYAN}${BOLD}"
echo "  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ "
echo "  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗"
echo "  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║"
echo "  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║"
echo "  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║"
echo "  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo -e "${MAGENTA}         Truth Beyond Appearance • Forensic Investigation Lab${NC}\n"

# 1. System Platform Detection
OS="$(uname -s)"
echo -e "${BLUE}[1/5]${NC} Detecting host operating system..."
case "${OS}" in
    Darwin*)    PLATFORM="macOS (Darwin)" ;;
    Linux*)     PLATFORM="Linux" ;;
    CYGWIN*|MINGW*|MSYS*) PLATFORM="Windows (POSIX environment)" ;;
    *)          PLATFORM="Unix-compatible (${OS})" ;;
esac
ARCH="$(uname -m)"
echo -e "      Detected platform: ${BOLD}${PLATFORM} [${ARCH}]${NC}"

# 2. Check Prerequisites (Node.js & npm)
echo -e "\n${BLUE}[2/5]${NC} Validating runtime prerequisites..."

if ! command -v node >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Node.js is not installed.${NC}"
    echo "Please install Node.js (version 18 or newer) from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//')
NODE_MAJOR=$(echo "${NODE_VERSION}" | cut -d. -f1)

if [ "${NODE_MAJOR}" -lt 18 ]; then
    echo -e "${RED}[ERROR] Node.js version ${NODE_VERSION} detected.${NC}"
    echo "SPECTRA requires Node.js v18.0.0 or higher. Please upgrade your Node runtime."
    exit 1
fi
echo -e "      ${GREEN}✓${NC} Node.js runtime: ${BOLD}v${NODE_VERSION}${NC} (Requirement >= v18 met)"

if ! command -v npm >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] npm is not installed.${NC}"
    exit 1
fi
NPM_VERSION=$(npm -v)
echo -e "      ${GREEN}✓${NC} Node package manager: ${BOLD}v${NPM_VERSION}${NC}"

# 3. Create Required Runtime Directories & Database Container
echo -e "\n${BLUE}[3/5]${NC} Initializing local storage directories..."
mkdir -p data uploads tests/fixtures

if [ ! -f "data/spectra.json" ]; then
    echo -e "      ${YELLOW}!${NC} Initializing fresh database container at data/spectra.json..."
    cat << 'EOF' > data/spectra.json
{
  "users": [
    {
      "id": "usr_manohar_manyu",
      "username": "manohar_manyu",
      "passwordHash": "4ad7ae903988237583d4bcda0db1544010d9503e68947e61c9c6b414227eec57ad3a4f64b10d2dd16577d5bbd9f9251e2d2563bbd59bf7e2e834f9cae92aabe8",
      "salt": "86a24962f988c843761fc4f618191b5a",
      "totpSecretEncrypted": null,
      "totpEnabled": false,
      "recoveryCodesHashed": [],
      "createdAt": "2026-10-26T10:01:28.784Z"
    }
  ],
  "sessions": [],
  "pairingCodes": [],
  "devices": [],
  "jobs": []
}
EOF
    echo -e "      ${GREEN}✓${NC} Default administrator profile configured."
else
    echo -e "      ${GREEN}✓${NC} Existing database found at data/spectra.json"
fi

# 4. Install Project Dependencies
echo -e "\n${BLUE}[4/5]${NC} Installing SPECTRA package dependencies..."
echo "      Resolving production and development packages via npm install:"
echo "      - Web framework & networking: Express, ws, multer"
echo "      - Cryptography & imaging: qrcode, jspdf, lucide-react"
echo "      - Frontend architecture: React 19, TypeScript, Vite, Tailwind CSS"

npm install

echo -e "      ${GREEN}✓${NC} All dependencies successfully installed and verified."

# 5. Build Production Bundle & Verify Installation
echo -e "\n${BLUE}[5/5]${NC} Compiling frontend production bundle & verifying security suite..."

npm run build

echo -e "\n      Running cryptographic verification & security isolation test harness:"
npm test

# Detect Local LAN IP for Mobile Device Pairing
LAN_IP=$(node -e '
  const os = require("os");
  const ifaces = os.networkInterfaces();
  let found = "localhost";
  for (const dev in ifaces) {
    for (const details of ifaces[dev]) {
      if (details.family === "IPv4" && !details.internal) {
        found = details.address;
        break;
      }
    }
    if (found !== "localhost") break;
  }
  console.log(found);
' 2>/dev/null || echo "localhost")

echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}  SPECTRA INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
echo -e "\n${BOLD}Access URLs:${NC}"
echo -e "  - Desktop Platform:   ${CYAN}http://localhost:5173/${NC}"
echo -e "  - Mobile Web Portal:  ${CYAN}http://${LAN_IP}:5173/mobile.html${NC}"
echo -e "  - Forensic API Hub:   ${CYAN}http://localhost:3001/api/status${NC}"

echo -e "\n${MAGENTA}Default Administrator Account:${NC}"
echo -e "  - Username: ${BOLD}manohar_manyu${NC}"
echo -e "  - Password: ${BOLD}80081Abc@2005${NC} (Change via the Identity Defense modal)"
echo -e "${GREEN}======================================================================${NC}\n"

if [ "$AUTO_START" = true ]; then
    echo -e "${CYAN}${BOLD}[STARTING SPECTRA PLATFORM]${NC}"
    echo -e "Launching Backend Gateway (Port 3001) and Frontend Interface (Port 5173)...\n"
    trap 'kill $(jobs -p) 2>/dev/null' EXIT
    npm run server &
    npm run dev &
    wait
else
    echo -e "To start SPECTRA now, run:"
    echo -e "  ${BOLD}npm run server${NC}  (in Terminal 1 for Backend & WebSockets)"
    echo -e "  ${BOLD}npm run dev${NC}     (in Terminal 2 for Vite Frontend & 3D Lab)"
    echo -e "\nOr run ${CYAN}./install.sh --start${NC} next time to launch both simultaneously.\n"
fi
