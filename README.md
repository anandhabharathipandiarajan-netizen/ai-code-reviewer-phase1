# AI Code Reviewer & Security Scanner — Phase 1

A working Phase 1 prototype based on the project plan: FastAPI backend + Next.js frontend.

## Phase 1 modules
- Code paste and source-file upload
- Python AST structure summary
- Regex/rule-based secret detection
- SAST checks for SQL injection, command injection, unsafe deserialization, XSS sinks, eval, debug mode
- Severity counts and health score
- Optional OpenAI LLM review
- Dashboard UI

## Run backend (Windows PowerShell)

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000/docs

## Run frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:3000

The OpenAI key is optional. Without it, the system still performs Phase 1 static analysis and returns an offline AI-review-style summary.

## Phase 2 later
GitHub webhooks/PR bot, RAG/vector database, Celery/Redis, automatic patch/PR creation, PostgreSQL persistence, RBAC and enterprise analytics.
