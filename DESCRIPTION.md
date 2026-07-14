# DarkShield Description

DarkShield is a repository security assessment platform that helps detect exposed secrets, insecure code, vulnerable dependencies,
and suspicious git-history leaks in GitHub projects.

The backend is built with FastAPI and the frontend is built with Next.js and React.
It uses Semgrep, Trivy, Supabase, Groq, and RSA-based report signing to deliver a complete security-scanning workflow.

For a presentation, the simplest way to explain it is:

1. A user submits a GitHub repository.
2. The backend clones and scans the repository with multiple security tools.
3. The system scores the risk and generates a report.
4. The report is signed cryptographically.
5. The frontend shows the results and allows tamper verification.
