# DarkShield

DarkShield is a full-stack repository security assessment platform for ethical hacking and applied cryptography.
It scans GitHub repositories for leaked secrets, insecure code patterns, vulnerable dependencies, and git-history exposure,
then signs the final report so its integrity can be verified later.

## Presentation Summary

DarkShield helps a user register a repository, run a security scan, and review the results in a dashboard.
It combines manual-style security checks with automated tools and cryptographic integrity verification.

## Core Capabilities

- Repository cloning and validation
- Secret detection using regex, entropy, and git-history analysis
- Static analysis with Semgrep
- Dependency scanning with Trivy
- Optional CodeQL-style analysis
- AI-assisted risk summaries and remediation hints through Groq
- Postgres persistence through Supabase
- RSA-PSS/SHA-256 report signing and verification

## Tools Used

- `FastAPI` for the backend API
- `Next.js` and `React` for the frontend UI
- `Supabase/Postgres` for storage
- `Semgrep` for code-pattern and OWASP-oriented scanning
- `Trivy` for dependency vulnerability scanning
- `Groq` for AI summaries and fix suggestions
- `RSA-PSS/SHA-256` for report integrity
- `Fernet` and `HMAC-SHA256` for data protection helpers

## Main Screens

- `Repositories`: add a repository, scan it, and inspect findings
- `Cross-Repo Clusters`: find secrets reused across multiple repos
- `Report Verifier`: confirm a signed payload has not been tampered with

## Scan Flow

1. Validate the GitHub URL
2. Clone the repository
3. Detect the tech stack
4. Scan for secrets
5. Scan git history
6. Run Semgrep
7. Run Trivy
8. Run CodeQL-style analysis
9. Correlate findings and compute a score
10. Generate AI reasoning
11. Sign the report
12. Save everything to Supabase

## Run Locally

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

## Environment Variables

Backend `backend/.env`:

- `SUPABASE_URL`
- `SUPABASE_KEY`
- `GROQ_API_KEY`
- `HMAC_SECRET_KEY`
- `ENCRYPTION_KEY`
- `GITHUB_TOKEN`
- Optional SMTP settings

Frontend:

- `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000`

## Local URLs

- Backend: `http://127.0.0.1:8000`
- Frontend: `http://127.0.0.1:3000`
- Swagger docs: `http://127.0.0.1:8000/docs`

## Demo Steps

1. Open the dashboard
2. Add a GitHub repository
3. Run a scan
4. Review findings and score
5. Open the report verifier
6. Verify the signature
7. Change the JSON and verify again to show tamper detection
