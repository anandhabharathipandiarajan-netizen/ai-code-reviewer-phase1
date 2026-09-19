import io
import os
import zipfile
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .analyzer import StaticAnalyzer
from .ai_engine import AIReviewer

load_dotenv()

app = FastAPI(
    title="AI Code Reviewer & Security Scanner",
    version="1.0.0",
    description="Phase 1 core static analysis, AST inspection and optional LLM review."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = StaticAnalyzer()
ai_reviewer = AIReviewer()


class ReviewRequest(BaseModel):
    code: str = Field(min_length=1, max_length=50000)
    language: str = "python"


@app.get("/")
def root():
    return {"status": "online", "system": "AI Code Reviewer Phase 1"}


@app.get("/health")
def health():
    return {
        "server": "healthy",
        "ai_configured": bool(os.getenv("OPENAI_API_KEY")),
        "version": "phase-1"
    }


@app.post("/api/scan")
def scan(request: ReviewRequest):
    result = analyzer.scan(request.code, request.language)
    ai = ai_reviewer.review(
        request.code, request.language, result["findings"], result["score"]
    )
    return {
        "success": True,
        "language": request.language,
        "score": result["score"],
        "statistics": result["statistics"],
        "static_analysis": result["findings"],
        "ast": result["ast"],
        "ai_analysis": ai,
    }


@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, "File name is required.")
    allowed = {".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript"}
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed:
        raise HTTPException(400, "Supported files: .py, .js, .ts, .tsx, .jsx")
    raw = await file.read()
    if len(raw) > 500_000:
        raise HTTPException(413, "File is too large. Maximum is 500 KB.")
    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 text.")
    result = analyzer.scan(code, allowed[ext])
    ai = ai_reviewer.review(code, allowed[ext], result["findings"], result["score"])
    return {
        "success": True,
        "filename": file.filename,
        "language": allowed[ext],
        "score": result["score"],
        "statistics": result["statistics"],
        "static_analysis": result["findings"],
        "ast": result["ast"],
        "ai_analysis": ai,
    }


@app.post("/api/scan-zip")
async def scan_zip(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Please upload a ZIP file.")
    raw = await file.read()
    if len(raw) > 10_000_000:
        raise HTTPException(413, "ZIP is too large. Maximum is 10 MB.")

    allowed = {".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript"}
    reports = []
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            # Avoid path traversal and skip generated/vendor folders.
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts:
                continue
            ext = Path(name).suffix.lower()
            if ext not in allowed or any(part in {"node_modules", ".git", "venv", "__pycache__"} for part in Path(name).parts):
                continue
            if info.file_size > 500_000:
                continue
            try:
                code = z.read(info).decode("utf-8")
            except Exception:
                continue
            result = analyzer.scan(code, allowed[ext])
            reports.append({
                "filename": name,
                "language": allowed[ext],
                "score": result["score"],
                "statistics": result["statistics"],
                "findings": result["findings"],
            })

    if not reports:
        raise HTTPException(400, "No supported source files found in ZIP.")

    total_findings = sum(len(r["findings"]) for r in reports)
    avg_score = round(sum(r["score"] for r in reports) / len(reports))
    return {
        "success": True,
        "files_scanned": len(reports),
        "average_score": avg_score,
        "total_findings": total_findings,
        "files": reports,
    }
