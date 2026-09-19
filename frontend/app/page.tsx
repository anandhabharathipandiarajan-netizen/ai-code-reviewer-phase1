'use client';

import { useMemo, useState } from 'react';
import {
  ShieldCheck,
  Play,
  Upload,
  AlertTriangle,
  CheckCircle2,
  Code2,
  Cpu,
  FileCode2,
} from 'lucide-react';

const API = 'http://127.0.0.1:8000';

type Finding = {
  id: string;
  title: string;
  line: number;
  severity: string;
  category: string;
  code_snippet: string;
  recommendation: string;
};

type Result = {
  score: number;
  statistics: Record<string, number>;
  static_analysis: Finding[];
  ai_analysis: {
    overall_score: number;
    security_summary: string;
    issues: any[];
    positive_points: string[];
  };
  ast: any;
  filename?: string;
};

const samples = {
  python: `import sqlite3

password = "admin123"
AWS_KEY = "AKIA1234567890ABCDEF"

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
`,

  javascript: `const password = "admin123";

function login(userInput) {
    eval(userInput);
}
`,

  typescript: `const password: string = "admin123";

function executeCode(userInput: string): void {
    eval(userInput);
}
`,
};

export default function Home() {
  const [language, setLanguage] = useState<
    'python' | 'javascript' | 'typescript'
  >('python');

  const [code, setCode] = useState(samples.python);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState('');

  function changeLanguage(
    newLanguage: 'python' | 'javascript' | 'typescript'
  ) {
    setLanguage(newLanguage);
    setCode(samples[newLanguage]);
    setResult(null);
    setError('');
  }

  async function scan() {
    if (!code.trim()) {
      setError('Please enter some code before scanning.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`${API}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code,
          language,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Scan failed');
      }

      setResult(data);
    } catch (e: any) {
      setError(
        e.message ||
          'Backend connection failed. Make sure FastAPI is running.'
      );
    } finally {
      setLoading(false);
    }
  }

  async function upload(
    e: React.ChangeEvent<HTMLInputElement>
  ) {
    const file = e.target.files?.[0];

    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`${API}/api/scan-file`, {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Upload failed');
      }

      setResult(data);
      setCode('');
    } catch (e: any) {
      setError(e.message || 'File scan failed');
    } finally {
      setLoading(false);
    }
  }

  const counts = useMemo(
    () =>
      result?.statistics || {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
      },
    [result]
  );

  return (
    <div className="shell">
      <header className="header">
        <div className="brand">
          <div className="logo">
            <ShieldCheck size={22} />
          </div>

          <div>
            <h1>SentinelAI Code Reviewer</h1>
            <span>
              Phase 1 • Static Analysis + AI Review
            </span>
          </div>
        </div>

        <div className="status">
          <span>
            <i className="dot" />
            SAST Engine Active
          </span>

          <span>
            <Cpu size={13} />
            Optional LLM
          </span>
        </div>
      </header>

      <main className="main">
        <section className="card">
          <div className="cardhead">
            <div
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'center',
              }}
            >
              <Code2 size={16} />
              <span style={{ fontSize: 12 }}>
                Code Workspace
              </span>
            </div>

            <div className="tools">
              <select
                className="select"
                value={language}
                onChange={(e) =>
                  changeLanguage(
                    e.target.value as
                      | 'python'
                      | 'javascript'
                      | 'typescript'
                  )
                }
              >
                <option value="python">Python</option>
                <option value="javascript">
                  JavaScript
                </option>
                <option value="typescript">
                  TypeScript
                </option>
              </select>

              <button
                className="button primary"
                onClick={scan}
                disabled={loading}
              >
                <Play size={13} />
                {loading ? 'Scanning...' : 'Analyze Code'}
              </button>
            </div>
          </div>

          <textarea
            className="editor"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
          />

          <div className="upload">
            <label>
              <Upload size={12} />
              Scan a source file
            </label>

            <input
              type="file"
              accept=".py,.js,.ts,.tsx,.jsx"
              onChange={upload}
            />
          </div>
        </section>

        <section className="right">
          {!result && !loading && (
            <div className="card empty">
              <div>
                <FileCode2 size={42} />

                <h3>Awaiting Analysis</h3>

                <p>
                  Paste code or upload a source file, then
                  run the Phase 1 scanner.
                </p>
              </div>
            </div>
          )}

          {loading && (
            <div className="card empty">
              <Cpu size={42} />

              <div>
                <h3>Running Multi-Stage Scan...</h3>

                <p>
                  AST + secret detection + security rules +
                  AI review.
                </p>
              </div>
            </div>
          )}

          {error && (
            <div
              className="card"
              style={{
                padding: 16,
                color: '#fb7185',
                fontSize: 12,
              }}
            >
              <AlertTriangle size={14} /> {error}
            </div>
          )}

          {result && (
            <div className="card">
              <div className="score">
                <div>
                  <h2>Code Health Score</h2>

                  <div className="scorebig">
                    {result.ai_analysis?.overall_score ??
                      result.score}

                    <span
                      style={{
                        fontSize: 15,
                        color: '#71859e',
                      }}
                    >
                      /100
                    </span>
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <span className="pill">
                    {result.filename || language}
                  </span>

                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      color: '#9eafc2',
                    }}
                  >
                    {result.static_analysis.length} findings
                  </div>
                </div>
              </div>

              <div className="stats">
                {[
                  'CRITICAL',
                  'HIGH',
                  'MEDIUM',
                  'LOW',
                ].map((severity) => (
                  <div className="stat" key={severity}>
                    <b>{counts[severity] || 0}</b>
                    <small>{severity}</small>
                  </div>
                ))}
              </div>

              <div className="summary">
                <h3>
                  <ShieldCheck size={13} />
                  Security Summary
                </h3>

                <p>
                  {result.ai_analysis?.security_summary}
                </p>
              </div>

              {result.ast && (
                <div className="summary">
                  <h3>
                    <Code2 size={13} />
                    AST Structure
                  </h3>

                  <p>
                    Functions:{' '}
                    {(result.ast.functions || []).join(', ') ||
                      'None'}
                    <br />

                    Classes:{' '}
                    {(result.ast.classes || []).join(', ') ||
                      'None'}
                    <br />

                    Imports:{' '}
                    {(result.ast.imports || []).join(', ') ||
                      'None'}
                  </p>
                </div>
              )}

              <div className="issues">
                <h3 style={{ padding: '0 16px' }}>
                  Detected Issues
                </h3>

                {(
                  result.ai_analysis?.issues ||
                  result.static_analysis
                ).map((issue: any, index: number) => (
                  <div className="issue" key={index}>
                    <span className="sev">
                      {issue.severity}
                    </span>

                    <h4>{issue.title}</h4>

                    <p>
                      Line{' '}
                      {issue.line_number || issue.line}:{' '}
                      {issue.description ||
                        issue.recommendation}
                    </p>

                    {(issue.suggested_fix ||
                      issue.autofix_patch ||
                      issue.recommendation) && (
                      <div className="fix">
                        {issue.suggested_fix ||
                          issue.autofix_patch ||
                          issue.recommendation}
                      </div>
                    )}
                  </div>
                ))}

                {!result.static_analysis.length && (
                  <div
                    style={{
                      padding: 16,
                      color: '#8ff0c7',
                      fontSize: 12,
                    }}
                  >
                    <CheckCircle2 size={14} />
                    No Phase 1 rule-based findings detected.
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      </main>

      <div className="footer">
        Phase 1 scope: local code/file scanning, Python AST
        inspection, rule-based SAST/secret detection,
        dashboard, and optional LLM review. GitHub bot, RAG,
        auto-PR fixing, Redis/Celery and enterprise RBAC
        remain Phase 2.
      </div>
    </div>
  );
}