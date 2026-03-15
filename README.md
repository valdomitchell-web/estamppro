
# eStamp Pro — Starter v2 (MVP + Verify)

- Backend: Node/Express/Mongo
- PDF-only stamping, PNG stamp images
- Per-stamp password → scrypt + AES-256-GCM wrapped key
- **NEW:** `/verify` endpoint to validate stamped PDFs (MVP asks for stamp password)
- **Updated:** multer@^2 with file size limits
- Web UI includes verification section and position controls

## Quick Start

### Backend
```bash
cd server
cp .env.example .env
# set MONGO_URI etc.
npm install
npm run dev
```
### Web
```bash
cd web
npm install
npm run dev
```

## Verify endpoint
`POST /verify` (no auth in MVP)

- form-data:
  - `file`: stamped PDF
  - `password`: stamp password (used to unwrap the key)
- Response: `{ ok: boolean, details: {...} }`

Next steps: switch to server-signed XMP so third parties can verify without any password.
"# estamp-pro" 
# eStamp Pro

Secure digital stamping and document verification platform.

eStamp Pro allows organizations to create secure digital stamps, apply them to PDF documents, and verify document authenticity using cryptographic signatures and QR verification.

---

# Features

### Stamp Creation
- Design stamps using:
  - uploaded PNG images
  - drawing tools
  - text
  - shapes
- Save reusable stamps
- Password-protected stamp signing

### PDF Stamping
- Upload PDF documents
- Drag-and-drop stamp placement preview
- Apply stamps with:
  - position (X/Y)
  - scale
  - opacity
  - page number

### Cryptographic Verification
Each stamp contains:

- cryptographic signature
- verification code
- timestamp
- stamp metadata
- document reference

### QR Verification
Stamped PDFs include a QR code linking to a public verification page.

Example:
https://estamp-web.onrender.com/verify/V-123ABC

The page confirms whether the document matches a recorded stamp.

### Public Verification Portal
Anyone can verify a document using:

- QR code
- verification code
- uploaded PDF

---

# System Architecture
React Frontend
│
▼
Node.js / Express API
│
▼
MongoDB Database
│
▼
Cloudflare R2 Storage

Components:

| Component | Purpose |
|--------|--------|
| React + Vite | Frontend dashboard |
| Node.js / Express | API server |
| MongoDB | Stores stamps, documents, audits |
| Cloudflare R2 | File storage |
| pdf-lib | PDF stamping |
| QRCode | QR verification |

---

# Project Structure

---

estamp-pro-starter-v2

server/
src/
routes/
auth.js
documents.js
stamps.js
verify.js
verify_public.js
models/
util/

web/
src/
App.jsx
StampDesigner.jsx
VerifyPage.jsx
api.js
# Setup

## 1 Install dependencies
### Backend
cd server
npm install

### Frontend

cd web
npm install

---

# Environment Variables

Create `.env` in the **server folder**.
PORT=10000
JWT_SECRET=your_secret

MONGO_URI=your_mongodb_connection

S3_ENABLED=true
S3_BUCKET=estamppro
S3_ENDPOINT=https://xxxx.r2.cloudflarestorage.com

S3_ACCESS_KEY=xxxx
S3_SECRET_KEY=xxxx



---

# Running Locally

### Start backend
cd server
npm start

### Start frontend
cd web
npm run dev

Frontend:
http://localhost:5173


API:
http://localhost:10000

---

# Deployment

The project is designed for **Render** deployment.

### API Service
node src/index.js

### Web Service
npm run build
npm run preview

---

# Stamping Flow

1. User creates a stamp
2. User uploads PDF
3. Stamp is applied using coordinates
4. Metadata is embedded in the PDF
5. Audit record is stored
6. QR code is added
7. Document becomes verifiable

---

# Verification Flow

1. User scans QR code
2. Opens public verification page
3. Verification code checked in database
4. Audit metadata displayed

Verification includes:

- stamp ID
- document ID
- timestamp
- position
- scale
- opacity

---

# Security Model

Each stamp uses:

- AES encryption
- password-wrapped keys
- HMAC signatures
- audit logging

This prevents tampering and ensures authenticity.

---

# Audit Log

Every stamping event records:

- user ID
- document ID
- stamp ID
- timestamp
- signature
- device fingerprint

---

# Technologies Used

| Technology | Use |
|-----------|------|
React | Frontend UI |
Vite | Build system |
Node.js | Backend runtime |
Express | API framework |
MongoDB | Database |
Cloudflare R2 | Object storage |
pdf-lib | PDF manipulation |
QRCode | Verification QR |

---

# Future Improvements

Possible enhancements:

- document hash integrity verification
- blockchain anchor for stamp records
- multi-organization accounts
- role-based access
- batch stamping
- template stamps
- enterprise audit dashboards

---

# Author

**Valdo Mitchell**

Project: eStamp Pro

---

# License

MIT License
