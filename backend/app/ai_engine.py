import json
import os
from typing import Any, Dict

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


class AIReviewer:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def review(self, code: str, language: str, findings: list, static_score: int) -> Dict[str, Any]:
        if not self.api_key or OpenAI is None:
            return self._offline_review(findings, static_score)

        prompt = f"""
You are a senior secure-code reviewer.
Review this {language} source code using the static findings below.
Return ONLY valid JSON:
{{
  "overall_score": 0,
  "security_summary": "short summary",
  "issues": [
    {{
      "title": "issue title",
      "line_number": 1,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "Security|Performance|Code Quality",
      "description": "concise explanation",
      "suggested_fix": "safe replacement or guidance",
      "explanation": "why the fix helps"
    }}
  ],
  "positive_points": ["..."]
}}
Do not invent vulnerabilities. If static findings are false positives, say so.

STATIC FINDINGS:
{json.dumps(findings, indent=2)}

SOURCE:
```{language}
{code[:18000]}
```
"""
        try:
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            data = json.loads(response.choices[0].message.content)
            data["overall_score"] = int(max(0, min(100, data.get("overall_score", static_score))))
            return data
        except Exception as exc:
            fallback = self._offline_review(findings, static_score)
            fallback["security_summary"] += f" AI review unavailable ({type(exc).__name__}); static analysis was used."
            return fallback

    def _offline_review(self, findings, static_score):
        issues = []
        for f in findings:
            issues.append({
                "title": f["title"],
                "line_number": f["line"],
                "severity": f["severity"],
                "category": f["category"],
                "description": f["recommendation"],
                "suggested_fix": f["recommendation"],
                "explanation": f"Detected by the Phase 1 rule-based analyzer ({f['type']})."
            })
        return {
            "overall_score": static_score,
            "security_summary": (
                "Phase 1 static analysis completed. "
                "Configure OPENAI_API_KEY to enable contextual LLM review."
            ),
            "issues": issues,
            "positive_points": [
                "Static analysis runs before the AI layer.",
                "Python AST structure is summarized when Python is selected."
            ],
        }
