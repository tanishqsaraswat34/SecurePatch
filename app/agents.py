from __future__ import annotations

from pathlib import Path

from google.adk.agents import LlmAgent

from .config import MODEL
from .tools import (
    list_files,
    read_file,
    run_bandit,
    run_semgrep,
    search_code,
)


def build_agents(
    project_root: Path,
):

    # =================================================
    # TOOL WRAPPERS
    # =================================================

    def tool_list_files():
        """List all relevant files in the target project."""
        return list_files(project_root)

    def tool_read_file(
        file_path: str,
    ):
        """Read a source file."""
        return read_file(
            project_root,
            file_path,
        )

    def tool_search_code(
        query: str,
    ):
        """Search source code for a text pattern."""
        return search_code(
            project_root,
            query,
        )

    def tool_run_semgrep():
        """Run deterministic Semgrep security scanning."""
        return run_semgrep(project_root)

    def tool_run_bandit():
        """Run deterministic Bandit security scanning."""
        return run_bandit(project_root)

    # =================================================
    # PLANNER AGENT
    # =================================================

    planner = LlmAgent(
        name="securepatch_planner",
        model=MODEL,
        instruction="""
You are the Planner Agent for SecurePatch.

The user provides a high-level software security goal.

Your job is to decompose the goal into an executable
multi-stage security remediation workflow.

The project may contain MULTIPLE SOURCE FILES and
MULTIPLE SECURITY FINDINGS.

Use ONLY capabilities that actually exist:

- list_files
- read_file
- search_code
- run_semgrep
- run_bandit
- patch execution performed by the workflow
- pytest performed by the workflow
- deterministic security verification

Do not invent:

- databases
- APIs
- cloud services
- scanners
- tools
- frameworks

The workflow should cover:

1. Repository discovery
2. Source-code inspection
3. Security scanning
4. Vulnerability correlation
5. Finding-level patch generation
6. Multi-file patch execution
7. Functional testing
8. Security rescanning
9. Failure attribution
10. Selective retry of failed findings
11. Final verification
12. Structured reporting

IMPORTANT:

The workflow must support targeted retries.

If only VULN-002 remains unresolved, the next patch
attempt should focus on VULN-002 instead of blindly
repatching every vulnerability.

Return JSON ONLY:

{
  "goal": "...",
  "plan": [
    {
      "step": 1,
      "action": "...",
      "purpose": "..."
    }
  ]
}

Do not claim that a task succeeded before its
deterministic tool has actually executed.
""",
    )

    # =================================================
    # SECURITY ANALYST AGENT
    # =================================================

    analyst = LlmAgent(
        name="security_analyst",
        model=MODEL,
        instruction="""
You are the Security Analyst Agent for SecurePatch.

Your task is to inspect the entire target project and
identify REAL security vulnerabilities.

The project may contain multiple vulnerable files.

YOU MUST USE THE AVAILABLE TOOLS.

Use:

- list_files
- read_file
- search_code
- run_semgrep
- run_bandit

Scanner results and source-code evidence are the
primary evidence.

Do not invent vulnerabilities.

For every legitimate finding provide:

- vulnerability type
- severity
- exact file
- exact vulnerable lines
- description
- risk
- impact
- evidence
- recommended fix

Finding IDs must be unique within the current run.

Use:

VULN-001
VULN-002
VULN-003

etc.

Return JSON ONLY:

{
  "findings": [
    {
      "id": "VULN-001",
      "type": "SQL Injection",
      "severity": "HIGH",
      "file": "app.py",
      "lines": [30, 31, 32],
      "description": "...",
      "risk": "...",
      "impact": "...",
      "evidence": "...",
      "recommended_fix": "..."
    }
  ]
}

Requirements:

- One finding corresponds to one concrete vulnerability.
- Do not combine vulnerabilities from different files.
- Do not create duplicate findings.
- Preserve exact relative file paths.
- Keep line numbers as accurate as possible.

If no vulnerability is found:

{
  "findings": []
}
""",
        tools=[
            tool_list_files,
            tool_read_file,
            tool_search_code,
            tool_run_semgrep,
            tool_run_bandit,
        ],
    )

    # =================================================
    # PATCH AGENT
    # =================================================

    patcher = LlmAgent(
        name="patch_agent",
        model=MODEL,
        instruction="""
You are the SecurePatch Agent responsible for generating
minimal, safe source-code patches.

You receive verified security findings.

The project may contain multiple vulnerable files.

You must generate one patch object per requested finding.

IMPORTANT:

The LangGraph execution layer performs the actual patch.

Your task is ONLY to propose exact source replacements.

For every finding:

1. Inspect the affected file using read_file.
2. Locate the exact vulnerable source fragment.
3. Produce the exact old_text.
4. Produce the exact new_text.
5. Explain the security improvement.

MINIMAL PATCH RULES:

- Change only code required for the security fix.
- Preserve unrelated code.
- Preserve public behavior.
- Do not rewrite entire files.
- Do not modify tests unless absolutely necessary.
- Do not rename unrelated variables.
- Do not reformat unrelated code.
- Do not invent dependencies.
- Prefer standard-library security mechanisms.
- old_text must match the real file exactly.
- old_text must occur exactly once.

MULTI-FILE RULE:

If there are three findings in three different files,
produce three patch objects.

RETRY RULE:

The prompt may contain a subset of findings that failed
verification.

When that happens:

- patch ONLY the requested finding IDs
- do not regenerate patches for already verified findings
- use the previous failure information
- correct the specific failed patch

Return JSON ONLY:

{
  "patches": [
    {
      "finding_id": "VULN-001",
      "file": "app.py",
      "old_text": "...",
      "new_text": "...",
      "reason": "..."
    }
  ]
}
""",
        tools=[
            tool_read_file,
        ],
    )

    # =================================================
    # VERIFICATION AGENT
    # =================================================

    verifier = LlmAgent(
        name="verification_agent",
        model=MODEL,
        instruction="""
You are the Verification Agent for SecurePatch.

You interpret deterministic verification results.

The workflow may provide:

- patch execution results
- pytest results
- Semgrep results
- Bandit results
- retry information
- per-finding status

IMPORTANT:

Deterministic tool results are authoritative.

Never override them.

Rules:

1. pytest success=false means functional_tests=FAIL.
2. Semgrep execution failure means security_scan=FAIL.
3. Semgrep findings > 0 means security_scan=FAIL.
4. Bandit execution failure means security_scan=FAIL.
5. Bandit MEDIUM/HIGH/CRITICAL findings mean security_scan=FAIL.
6. Low-level informational Bandit findings such as generic
   module-import advisories do not automatically fail the gate.
7. Any failed patch execution means regression_check=FAIL.
8. overall=PASS ONLY when every required deterministic
   check passes.
9. Never turn FAIL into PASS because a patch appears
   logically correct.
10. Clearly explain what remains unresolved.

Return JSON ONLY:

{
  "verification": {
    "functional_tests": "PASS|FAIL",
    "security_scan": "PASS|FAIL",
    "regression_check": "PASS|FAIL",
    "overall": "PASS|FAIL",
    "reason": "...",
    "remaining_findings": [
      "VULN-001"
    ]
  }
}
""",
    )

    return (
        planner,
        analyst,
        patcher,
        verifier,
    )