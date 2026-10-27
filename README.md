
# 🛡️ SPECTRA
### Truth Beyond Appearance

<p align="center">
  <strong>AI-Powered Deepfake Detection & Digital Media Forensics</strong>
</p>

<p align="center">
  Investigate suspicious media. Analyze digital evidence. Understand the signals behind synthetic content.
</p>

<p align="center">
  <a href="https://thespectra.vercel.app" target="_blank">
    <img src="https://img.shields.io/badge/Vercel-Live%20Deployment-000000?style=for-the-badge&logo=vercel&logoColor=white" />
  </a>
  <img src="https://img.shields.io/badge/Platform-Web%20Application-7C3AED?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Focus-Digital%20Forensics-111827?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Security-First-2563EB?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Active%20Development-0891B2?style=for-the-badge" />
</p>

<p align="center">
  🚀 <strong>Live Production Desktop:</strong> <a href="https://thespectra.vercel.app">https://thespectra.vercel.app</a><br />
  📱 <strong>Live Mobile Portal:</strong> <a href="https://spectra-mobile.vercel.app/mobile.html">https://spectra-mobile.vercel.app/mobile.html</a>
</p>

---

## 🌐 About SPECTRA

**SPECTRA is an AI-powered deepfake and synthetic-media forensics platform designed to help investigate potentially manipulated digital content.**

In a world where artificial intelligence can generate realistic images, videos, and audio, distinguishing authentic media from manipulated content has become increasingly important.

SPECTRA brings media analysis, forensic indicators, digital evidence handling, and secure device synchronization together in a unified web experience.

The platform is designed to help users investigate suspicious media, examine available metadata, identify potential signs of manipulation, and review forensic findings through an intuitive dashboard.

> **Our mission:** To make digital media investigation more accessible, transparent, and security-conscious.

---

## 🎯 What Does SPECTRA Do?

SPECTRA is designed around four core capabilities:

| Capability | Description |
|---|---|
| 🔍 Media Forensics | Examine suspicious images and investigate potential manipulation indicators. |
| 🧠 Synthetic Media Analysis | Support the identification of potential AI-generated or altered content. |
| 📱 Device Synchronization | Connect a mobile device to the desktop website for image capture and upload. |
| 🔐 Secure Investigation | Incorporate authentication, two-factor verification, device pairing, and user-specific access controls. |

---

## ✨ Key Features

### 01. 🔬 Digital Media Forensics

Investigate suspicious images through a structured forensic workflow.

- File-format and signature inspection.
- SHA-256 integrity hashing.
- EXIF metadata examination.
- Camera information extraction when available.
- JPEG quantization-table analysis.
- Spatial entropy analysis.
- Inspection for known AI-generation metadata markers.
- Structured forensic report generation.

These techniques provide useful evidence indicators, but individual indicators cannot independently establish whether an image is authentic or manipulated.

### 02. 🧠 AI & Deepfake Investigation

SPECTRA is designed to support the investigation of synthetic and manipulated media.

Potential analysis areas include:

- AI-generated image detection.
- Face-manipulation investigation.
- Synthetic-media artifact analysis.
- Image-integrity examination.
- Forensic confidence and evidence reporting.

Advanced detection capabilities depend on the models and analysis engines actually integrated into the deployed version.

### 03. 📱 Mobile-to-Desktop Connectivity

Capture or select an image on a phone and send it to the associated SPECTRA desktop session.

The intended workflow includes:

- Temporary pairing codes.
- QR-assisted device pairing.
- Mobile camera and gallery access.
- Local Wi-Fi image uploads.
- Real-time analysis updates.
- Paired-device management and revocation.

This functionality is designed to connect the mobile experience with the desktop forensic dashboard.

### 04. 🔐 Security & Authentication

SPECTRA incorporates security mechanisms intended to protect accounts, devices, and forensic reports.

- User registration and login.
- Scrypt-based password hashing.
- TOTP-based two-factor authentication.
- AES-256-GCM encryption for stored TOTP secrets.
- Single-use recovery codes.
- Expiring device-pairing codes.
- Session management.
- Device trust revocation.
- User-specific report access controls.

Security depends on correct implementation and deployment configuration; the presence of these mechanisms alone does not guarantee complete protection.

### 05. ⚡ Real-Time Forensic Dashboard

The website is designed to provide a central interface for media investigation.

The dashboard can integrate:

- Media upload and analysis workflows.
- Forensic job status.
- Analysis progress notifications.
- Report and evidence summaries.
- Mobile device connection controls.
- Security and authentication controls.

---

## 🖥️ Website Overview

SPECTRA is organized around the following user experience:

```text
                    SPECTRA WEBSITE
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
      Desktop Dashboard           Mobile Portal
             │                           │
             ▼                           ▼
       Select Media              Capture / Select Image
             │                           │
             │                    Secure Pairing
             │                           │
             └─────────────┬─────────────┘
                           │
                           ▼
                    Backend Gateway
                           │
                           ▼
                    Forensic Pipeline
                           │
                           ▼
                   Analysis & Reports
```

The website connects the user interface, backend services, device-pairing workflow, and available forensic analysis components.

---

## 🧰 Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Interface | HTML5, CSS3, JavaScript |
| Backend | Node.js, Express.js |
| Communication | REST APIs, WebSockets |
| Authentication | Session-based authentication, TOTP |
| Cryptography | Scrypt, SHA-256, AES-256-GCM |
| Image Processing | File signatures, EXIF, JPEG analysis |
| File Uploads | Multer |
| Device Pairing | Temporary codes, QR codes |
| Network | Local Wi-Fi / LAN |

*The exact stack and available functionality depend on the current repository implementation.*

---

## 🔄 How It Works

### Step 1 — Access the Website

Open the SPECTRA dashboard and authenticate using the supported login workflow.

### Step 2 — Select or Capture Media

Upload a suspicious image from your computer or use the supported mobile interface to capture or select an image.

### Step 3 — Connect Your Device

Generate a temporary pairing code from the desktop session and use the mobile portal to pair the phone.

### Step 4 — Analyze the Evidence

The backend validates the uploaded file and runs the available forensic checks.

### Step 5 — Review the Results

Examine the available metadata, file-integrity information, analysis indicators, and generated report.

### Step 6 — Manage Your Devices

Review paired devices and revoke device access when necessary.

---

## 🏗️ System Architecture

SPECTRA follows a modular web-application architecture.

```text
Frontend: React + Vite
        │
        ▼
Vite Development Proxy
        │
        ▼
Backend: Node.js + Express
        │
        ├── Authentication & 2FA
        ├── Device Pairing
        ├── Image Uploads
        ├── WebSocket Events
        └── Forensic Analysis
                │
                ▼
        Local Data & Evidence Storage
```

During development, the documented default ports are:

| Service | Address |
|---|---|
| Desktop website | `http://localhost:5173/` |
| Mobile portal | `http://<LAN_IP>:5173/mobile.html` |
| Backend gateway | `http://localhost:3001` |

These addresses are for local development, not public production access.

---

## 🔒 Privacy & Security Philosophy

SPECTRA emphasizes controlled access, local-first workflows, and responsible evidence handling.

Design principles include:

- Minimize unnecessary external data transfers.
- Associate evidence and reports with the correct user.
- Protect account credentials and authentication secrets.
- Use expiring, single-use pairing credentials.
- Validate uploaded files.
- Provide device revocation controls.
- Keep private evidence and secrets out of public repositories.

Local-network operation does not automatically provide end-to-end encryption or eliminate all security risks. Production deployments require appropriate transport security, access controls, secure configuration, and testing.

---

## 🧪 Testing & Verification

The supplied implementation report records an initial automated security-verification run:

| Metric | Result |
|---|---:|
| Tests executed | 37 |
| Passed | 37 |
| Failed | 0 |
| Reported execution time | 1.82 seconds |

The reported test coverage includes password cryptography, 2FA, pairing-code lifecycle, image inspection, device revocation, and user isolation.

These are reported development-test results, not an independent security certification or a guarantee that every feature is production-ready.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** (version 18.0.0 or higher) — [https://nodejs.org/](https://nodejs.org/)
- **npm** (included with Node.js)
- **Git**
- A modern web browser (Chrome, Edge, Firefox, or Safari)

---

### ⚡ Automated Installation & Quickstart

SPECTRA features an automated cross-platform setup engine that handles everything in one go:
1. **Validates Runtime:** Checks that Node.js >= 18 and npm are present.
2. **Initializes Storage:** Automatically scaffolds `data/`, `uploads/`, and `tests/fixtures/`.
3. **Provisions Database:** Generates `data/spectra.json` with an initial administrator profile.
4. **Installs Dependencies:** Downloads and verifies all required npm packages (Express, ws, multer, qrcode, jspdf, React 19, Vite, Tailwind CSS).
5. **Compiles Assets:** Builds the production frontend bundle (`npm run build`).
6. **Runs Security Suite:** Runs all 37 automated cryptographic and isolation tests (`npm test`).
7. **Resolves Network Address:** Detects your local LAN IP and outputs the direct mobile pairing link.

#### 1. Clone the Repository
```bash
git clone https://github.com/manoharmanyu/SPECTRA.git
cd SPECTRA
```

#### 2. Run the Installer for Your Operating System

| Operating System | Method | Command | Description |
|---|---|---|---|
| 🍎 **macOS & 🐧 Linux** | Shell Script | `chmod +x install.sh && ./install.sh` | Interactive installer with colored logging and verification |
| 🍎 **macOS & 🐧 Linux (Auto-Start)** | Shell Script | `./install.sh --start` | Installs dependencies and immediately launches both servers |
| 🪟 **Windows** | Command Prompt (`cmd.exe`) | `install.bat` *(or double-click)* | Native Windows batch setup engine |
| 🪟 **Windows (Auto-Start)** | Command Prompt (`cmd.exe`) | `install.bat --start` | Sets up environment and launches backend + frontend |
| 🪟 **Windows** | PowerShell | `.\install.ps1` | Native PowerShell installer script |
| 🪟 **Windows (Auto-Start)** | PowerShell | `.\install.ps1 -start` | PowerShell installer with auto-start flag |
| 🌐 **Universal (All OS)** | Node.js Engine | `node setup.js` *(or `npm run setup`)* | Cross-platform JavaScript installer engine |
| 🌐 **Universal (Auto-Start)** | Node.js Engine | `node setup.js --start` | Installs and boots both servers simultaneously |

> [!TIP]
> If Windows PowerShell restricts script execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` before executing `.\install.ps1`.

---

### Manual Installation (All OS)

If you prefer to run each step manually:

```bash
git clone https://github.com/manoharmanyu/SPECTRA.git
cd SPECTRA

# 1. Install dependencies
npm install

# 2. Build production assets
npm run build

# 3. Verify security & cryptographic integrity
npm test
```

---

### 🖥️ Starting the Application

If you did not run the installer with `--start`, launch the two runtime processes in separate terminals:

```bash
# Terminal 1: Backend Gateway & Real-time WebSocket Hub (Port 3001)
npm run server
```

```bash
# Terminal 2: Interactive Forensic Dashboard & 3D Lab (Port 5173)
npm run dev
```

#### Application Endpoints:
- **Desktop Dashboard:** [http://localhost:5173/](http://localhost:5173/)
- **Mobile Web Portal:** `http://<YOUR_LAN_IP>:5173/mobile.html` *(Printed automatically by `install.sh` / `setup.js`)*
- **Forensic API Hub:** [http://localhost:3001/api/status](http://localhost:3001/api/status)

#### Default Administrator Credentials:
- **Username:** `manohar_manyu`
- **Password:** `80081Abc@2005`
*(You can update your credentials and configure TOTP 2FA in the **Identity Defense** modal upon login).*

---

## 🎯 Use Cases

SPECTRA is intended to support:

- Digital-forensics education.
- Investigation of suspicious online images.
- Synthetic-media research.
- Image metadata and integrity examination.
- Security-conscious evidence workflows.
- Media authenticity research.
- Mobile-to-desktop forensic demonstrations.

The platform is an investigative aid and should not replace expert forensic examination or corroborating evidence.

---

## 🗺️ Development Roadmap

- [x] Authentication and session foundation.
- [x] TOTP-based 2FA workflow.
- [x] Temporary device-pairing mechanism.
- [x] QR-assisted pairing workflow.
- [x] Local-network upload architecture.
- [x] Initial image-forensics checks.
- [x] Automated security-verification suite.
- [x] Advanced deepfake detection models & provider adapter interface.
- [x] Video, audio, and image forensic analysis with streaming storage.
- [x] Explainable AI findings, confidence reporting, and limitations.
- [x] Tamper-evident evidence audit trails with SQLAlchemy & Alembic.
- [x] FastAPI REST backend with n8n workflow integration.
- [x] Automated security-verification suite (Node.js & Pytest).
- [ ] Advanced case management and export PDF dossiers.
- [ ] Production multi-region deployment hardening.

---

## ⚡ FastAPI Media Forensics Backend (`backend/`)

SPECTRA incorporates a high-performance **Python 3.11+ FastAPI REST Backend** for streaming media intake, deep forensic extraction, n8n workflow orchestration, and multi-detector execution.

### 📐 Architecture
- **Framework:** FastAPI, Pydantic v2, SQLAlchemy 2, Alembic
- **Database:** PostgreSQL (with SQLite zero-config support for local testing)
- **Streaming Storage:** Chunk-based streaming (64 KB) with SHA-256 calculation on the fly and strict size enforcement (`MAX_UPLOAD_SIZE_BYTES`, default 100 MB). Supports local mounted storage or S3-compatible object storage under UUID keys.
- **Media Inspection:** 
  - **ExifTool** for image/embedded metadata (dimensions, format, EXIF, IPTC/XMP, genuine GPS if present).
  - **ffprobe** for audio/video stream tracks, codecs, durations, bitrates, and sample rates.
  - **Pure-Python Fallbacks:** Pillow + native binary chunk parsers (JPEG SOF, PNG IHDR, WebP VP8X, WAV RIFF, MP4 atoms) when system CLI binaries are not installed.
  - **C2PA / Content Credentials:** Detects JUMBF and C2PA manifest provenance.
- **Orchestration:** Dispatches `{ "job_id": "...", "media_type": "image|audio|video" }` to `N8N_WEBHOOK_URL` with header `X-SPECTRA-WEBHOOK-TOKEN`. If n8n is offline or unconfigured, background worker automatically executes stages locally in standalone mode.

---

### 🚀 Quickstart & Setup Commands

#### 1. Local Virtual Environment Setup
```bash
# Navigate to backend directory
cd backend

# Create virtual environment with Python 3.11
python3.11 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start the FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
OpenAPI documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

#### 2. Running Automated Pytest Suite
```bash
cd backend
pytest -v
```

#### 3. Docker Compose Setup (API + PostgreSQL + n8n)
```bash
# From repository root
docker compose up -d --build
```

---

### 📡 API Contract & Usage Examples

#### 1. Liveness & Readiness Checks
```bash
# Health check (Liveness)
curl -X GET http://localhost:8000/health

# Storage & DB Readiness
curl -X GET http://localhost:8000/ready
```

#### 2. Create Device Session
```bash
curl -X POST http://localhost:8000/api/v1/device-sessions \
  -H "Content-Type: application/json" \
  -d '{"device_name": "Field Officer iPhone 15", "device_fingerprint": "dev_fp_102"}'
```

#### 3. Multipart Media Upload
```bash
curl -X POST http://localhost:8000/api/v1/analyses \
  -F "file=@/path/to/evidence.jpg" \
  -F "source_origin=phone_simulator" \
  -F "capture_session_id=optional-session-uuid"
```
**Response (202 Accepted):**
```json
{
  "job_id": "b6a83120-7dfc-42cb-b169-826a7981d392",
  "status": "queued",
  "media_type": "image",
  "status_url": "/api/v1/analyses/b6a83120-7dfc-42cb-b169-826a7981d392",
  "report_url": "/api/v1/analyses/b6a83120-7dfc-42cb-b169-826a7981d392/report"
}
```

#### 4. Poll Status & Detailed Report
```bash
# Check status summary
curl -X GET http://localhost:8000/api/v1/analyses/b6a83120-7dfc-42cb-b169-826a7981d392

# Retrieve final report (202 while processing, 200 when completed)
curl -X GET http://localhost:8000/api/v1/analyses/b6a83120-7dfc-42cb-b169-826a7981d392/report
```

#### 5. Internal n8n Protected Stage Routes
Requires `Authorization: Bearer SPECTRA_INTERNAL_TOKEN`:
```bash
# Stage 1: Metadata extraction
curl -X POST http://localhost:8000/internal/analyses/JOB_ID/metadata \
  -H "Authorization: Bearer spectra_internal_dev_secret_token_change_in_production"

# Stage 2: AI / Deepfake detection
curl -X POST http://localhost:8000/internal/analyses/JOB_ID/detect \
  -H "Authorization: Bearer spectra_internal_dev_secret_token_change_in_production"

# Stage 3: Finalize report
curl -X POST http://localhost:8000/internal/analyses/JOB_ID/finalize \
  -H "Authorization: Bearer spectra_internal_dev_secret_token_change_in_production"
```

---

### 🔑 Provider Credentials Checklist

| Provider / Setting | Environment Variable | Required? | Purpose |
| :--- | :--- | :--- | :--- |
| **Database** | `DATABASE_URL` | **Yes** | PostgreSQL or SQLite connection string |
| **Internal Secret** | `SPECTRA_INTERNAL_TOKEN` | **Yes** | Constant-time bearer token for n8n stage calls |
| **Webhook Secret** | `SPECTRA_WEBHOOK_TOKEN` | **Yes** | Sent in `X-SPECTRA-WEBHOOK-TOKEN` header to n8n |
| **n8n Webhook URL** | `N8N_WEBHOOK_URL` | Optional | External workflow automation trigger |
| **Hive AI Key** | `HIVE_API_KEY` | Optional | Deepfake image, audio & video detection API |
| **Google Gemini Key** | `GEMINI_API_KEY` | Optional | Technical explanatory context summary only |

*Note: If `HIVE_API_KEY` is not provided, the platform honestly marks detector findings as `not_assessed` with an explicit reason—it NEVER invents fake scores.*

---

---

## ⚖️ Responsible Use

SPECTRA is intended for lawful digital-forensics investigation, education, and synthetic-media research.

Automated tools can produce false positives and false negatives. A forensic indicator or model confidence score should not be treated as definitive proof of authenticity, manipulation, identity, or intent.

Users must respect applicable privacy, intellectual-property, data-protection, and cybersecurity laws.

---

## 👨‍💻 Project Information

**Project:** SPECTRA  
**Tagline:** Truth Beyond Appearance  
**Category:** AI, Cybersecurity & Digital Media Forensics  
**Platform:** Web Application  
**Development Status:** Active Development

---

<p align="center">
  <strong>Secure the Evidence. Investigate the Signal. Seek the Truth.</strong>
</p>
