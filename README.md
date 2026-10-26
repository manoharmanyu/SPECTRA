
# 🛡️ SPECTRA
### Truth Beyond Appearance

<p align="center">
  <strong>AI-Powered Deepfake Detection & Digital Media Forensics</strong>
</p>

<p align="center">
  Investigate suspicious media. Analyze digital evidence. Understand the signals behind synthetic content.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Web%20Application-7C3AED?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Focus-Digital%20Forensics-111827?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Security-First-2563EB?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Active%20Development-0891B2?style=for-the-badge" />
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

- Node.js
- npm
- Git
- A modern web browser

### Installation

```bash
git clone <https://github.com/manoharmanyu/SPECTRA.git>
cd main
npm install
```

Replace the placeholders with your actual repository URL and project directory.

### Start the Application

Check the scripts available in `package.json`:

```bash
npm run
```

If your project defines the following scripts, start the backend and frontend in separate terminals:

```bash
npm run server
```

```bash
npm run dev
```

Open the desktop website:

```text
http://localhost:5173/
```

For mobile connectivity, use your computer's current local network IP address:

```text
http://<LAN_IP>:5173/mobile.html
```

Ensure that both devices are on the same reachable network and that your firewall permits the required connections.

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
- [ ] Advanced deepfake detection models.
- [ ] Video and audio forensic analysis.
- [ ] Explainable AI findings and confidence reporting.
- [ ] Tamper-evident evidence audit trails.
- [ ] Advanced case management and report export.
- [ ] Production deployment hardening.
- [ ] Independent security assessment.

*Roadmap items are subject to implementation and verification.*

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
