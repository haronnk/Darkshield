# DarkShield

DarkShield is a full-stack repository security assessment platform built for ethical hacking and applied cryptography demos.
It clones a GitHub repository, scans it for leaked secrets and vulnerable dependencies, runs static analysis, scores the risk,
generates an AI-assisted summary, and signs the final report so its integrity can be verified later.

## What it does

- Clones public GitHub repositories for analysis
- Detects secrets with regex, entropy analysis, and git-history scanning
- Runs Semgrep for code-pattern and OWASP-oriented static analysis
- Runs Trivy for dependency vulnerability scanning
- Optionally enriches results with CodeQL-style analysis
- Generates AI reasoning and remediation hints through Groq
- Stores scan results in Supabase/Postgres
- Signs scan summaries with RSA-PSS/SHA-256
- Verifies signed reports through a dedicated integrity-check page

## Architecture

- Frontend: Next.js 16 + React
- Backend: FastAPI
- Database: Supabase/Postgres
- AI: Groq
- Security tools: Semgrep, Trivy, git history scanner, custom secret scanner
- Cryptography: RSA report signing, Fernet snippet encryption, HMAC secret hashing

## Main pages

- `Repositories` dashboard: register repos, run scans, view findings
- `Cross-Repo Clusters`: show reused secrets across repositories
- `Report Verifier`: verify payload integrity with the public key

## Scan pipeline

1. Validate the GitHub URL
2. Clone the repository
3. Profile the tech stack
4. Scan for secrets
5. Scan git history
6. Run Semgrep
7. Run Trivy
8. Run CodeQL-style analysis
9. Correlate findings and compute security score
10. Generate AI summary
11. Sign the report with RSA-PSS/SHA-256
12. Store results in Supabase

## Setup

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```powershell
cd frontend
npm install
npm run build
npm start
```

## Environment variables

The backend expects these values in `backend/.env`:

- `SUPABASE_URL`
- `SUPABASE_KEY`
- `GROQ_API_KEY`
- `HMAC_SECRET_KEY`
- `ENCRYPTION_KEY`
- `GITHUB_TOKEN` for GitHub API rate limits
- Optional SMTP settings for critical alerts

The frontend expects:

- `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000`

## Local URLs

- Backend: `http://127.0.0.1:8000`
- Frontend: `http://127.0.0.1:3000`
- Swagger docs: `http://127.0.0.1:8000/docs`

## Demo flow

1. Open the dashboard
2. Add a GitHub repository URL
3. Run a scan
4. Review findings and security score
5. Open the report verifier
6. Verify the signed payload
7. Modify the JSON payload and verify again to see tamper detection

## Notes

- The repo includes a custom crypto-misuse Semgrep rule pack and frontend security rules.
- Scan reports are signed separately from the vulnerability findings so the report itself can be checked for tampering.
- The project is intentionally built as a security lab so it can demonstrate offensive and defensive tooling in one workflow.
