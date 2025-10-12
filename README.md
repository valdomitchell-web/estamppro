
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
