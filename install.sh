#!/usr/bin/env bash
# ==============================================================================
# SPECTRA — Automated Environment Setup & Dependency Installer
# Truth Beyond Appearance • Neural Media Forensics & Secure Device Pairing
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
    Darwin*)    PLATFORM="macOS" ;;
    Linux*)     PLATFORM="Linux" ;;
    CYGWIN*|MINGW*|MSYS*) PLATFORM="Windows (POSIX environment)" ;;
    *)          PLATFORM="Unknown (${OS})" ;;
esac
echo -e "      Detected platform: ${BOLD}${PLATFORM}${NC}"

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
echo -e "      ${GREEN}✓${NC} Node.js runtime: ${BOLD}v${NODE_VERSION}${NC} (Minimum requirement >= v18)"

if ! command -v npm >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] npm is not installed.${NC}"
    exit 1
fi
NPM_VERSION=$(npm -v)
echo -e "      ${GREEN}✓${NC} Node package manager: ${BOLD}v${NPM_VERSION}${NC}"

# 3. Create Required Runtime Directories
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
echo "      Running 'npm install' for production and development dependencies:"
echo "      - Express, WebSocket (ws), Multer, QRCode, jsPDF, Lucide React"
echo "      - Vite, TypeScript, React 19, and security audit tools"

npm install

echo -e "      ${GREEN}✓${NC} Dependencies successfully resolved and installed."

# 5. Build Production Bundle & Verify Installation
echo -e "\n${BLUE}[5/5]${NC} Compiling frontend production bundle & verifying security suite..."

npm run build

echo -e "\n      Running cryptographic verification & security isolation test suite:"
npm test

echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}  SPECTRA INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
echo -e "\nTo start the SPECTRA forensic platform, launch the two runtime processes:"
echo -e "\n  ${BOLD}1. Start the Secure Backend (Port 3001 & WebSocket Hub):${NC}"
echo -e "     ${CYAN}npm run server${NC}"
echo -e "\n  ${BOLD}2. Start the Vite Frontend (Port 5173 & 3D Forensic Sketchbook):${NC}"
echo -e "     ${CYAN}npm run dev${NC}"
echo -e "\n  ${BOLD}Direct Access URLs:${NC}"
echo -e "  - Desktop Platform:   ${BOLD}http://localhost:5173/${NC}"
echo -e "  - Mobile Web Portal:  ${BOLD}http://<your-lan-ip>:5173/mobile.html${NC}"
echo -e "  - Local Forensic API: ${BOLD}http://localhost:3001/api/status${NC}"
echo -e "\n${MAGENTA}Default Administrator Account:${NC}"
echo -e "  - Username: ${BOLD}manohar_manyu${NC}"
echo -e "  - Password: ${BOLD}80081Abc@2005${NC} (Change upon setup in Identity Defense modal)"
echo -e "${GREEN}======================================================================${NC}\n"
