# 🛡️ SecurePatch
### Agentic AI for Autonomous Security Patching

> **Live Demo:** https://securepatch-276037872801.asia-south1.run.app/
>
> **GitHub:** https://github.com/tanishqsaraswat34/SecurePatch

SecurePatch is an agentic secure-coding assistant that analyzes a vulnerable Python project, identifies security vulnerabilities, generates targeted secure patches, applies them safely, and verifies the result using deterministic testing and security scanners.

This project was developed for the **Agentic AI Engineer Intern — Take-Home Assignment**, using the **Secure Coding Assistant** track.

---

## 🎯 Problem

Security vulnerabilities in source code often require several steps:

1. Understand the developer's security goal.
2. Inspect the project.
3. Identify vulnerabilities.
4. Understand their risk and impact.
5. Generate appropriate fixes.
6. Apply the fixes without breaking functionality.
7. Run tests and security scanners.
8. Detect failures.
9. Retry failed fixes.
10. Produce an auditable report.

SecurePatch automates this workflow using cooperating AI agents and deterministic verification tools.

---

# 🧠 Agentic Workflow

SecurePatch follows the agentic loop:

```text
PERCEIVE → PLAN → ACT → VERIFY → REPLAN
```

High-level flow:

```text
                  ┌─────────────────────┐
                  │      User / CLI     │
                  │   Security Goal     │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │    Planner Agent    │
                  │  Goal → Task Plan   │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │  Security Analyst   │
                  │ Find vulnerabilities│
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │     Patch Agent     │
                  │ Generate secure fix │
                  └──────────┬──────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     Deterministic Tools     │
              │                              │
              │ pytest │ Semgrep │ Bandit    │
              └──────────────┬───────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Verification Agent  │
                  │ Interpret results   │
                  └──────────┬──────────┘
                             │
                       Verification?
                      ┌──────┴──────┐
                      │             │
                     YES            NO
                      │             │
                      ▼             ▼
                ┌──────────┐  ┌──────────────┐
                │  Report  │  │ Selective    │
                │ VERIFIED │  │ Retry        │
                └──────────┘  └──────┬───────┘
                                     │
                                     └────► Patch Agent
```

📌 **Architecture diagram:** see `SecurePatch_Architecture.png` in the repository/submission materials.

---

# 🤖 Agents

SecurePatch uses specialized agents rather than one monolithic LLM call.

| Agent | Responsibility |
|---|---|
| **Planner Agent** | Understand the high-level goal and create the execution plan |
| **Security Analyst Agent** | Analyze source code, security findings, vulnerable LOC, risk and impact |
| **Patch Agent** | Generate minimal secure patches for identified findings |
| **Verification Agent** | Interpret deterministic verification results and decide whether another attempt is required |

The orchestration/state machine is handled by **LangGraph**.

The LLM is used for reasoning and patch generation; deterministic tools remain authoritative for execution and verification.

---

# 🔍 Security Tools

SecurePatch combines multiple tools during execution.

### Semgrep

Used for deterministic static security analysis.

The demonstration project contains custom rules for:

- SQL Injection
- Command Injection
- Cross-Site Scripting

### Bandit

Used as an additional Python security analysis layer.

### pytest

Used to verify that the original functionality is preserved after remediation.

### Patch / File Tools

SecurePatch includes deterministic tools for:

- safe file access
- source inspection
- code search
- exact patch application
- diff generation
- test execution
- security scanning

---

# 🔐 Important Design Decision

### LLM reasoning is NOT the final security authority.

The system separates:

```text
LLM
 │
 ├── Planning
 ├── Vulnerability reasoning
 ├── Patch generation
 └── Result interpretation
```

from:

```text
Deterministic execution
 │
 ├── Patch execution
 ├── pytest
 ├── Semgrep
 └── Bandit
```

A patch is only considered successfully verified when the deterministic verification layer confirms the expected state.

This prevents the agent from simply claiming:

> "The vulnerability is fixed."

without executable evidence.

---

# 🔄 Self-Correction & Failure Recovery

SecurePatch deliberately supports failure injection.

Normal execution:

```powershell
$env:SECUREPATCH_INDUCE_FAILURE="false"
python run_demo.py
```

Deliberate failure test:

```powershell
$env:SECUREPATCH_INDUCE_FAILURE="true"
python run_demo.py
```

The failure scenario demonstrates:

```text
Attempt 1
    ↓
Deliberate patch failure
    ↓
Deterministic verification
    ↓
Remaining finding identified
    ↓
Selective retry
    ↓
Attempt 2
    ↓
Deterministic verification
    ↓
VERIFIED
```

The retry mechanism works at the vulnerability/finding level rather than blindly restarting the entire workflow.

---

# 🧪 Synthetic Evaluation Project

Because the assignment does not provide a dataset, SecurePatch includes a small synthetic vulnerable Python project for deterministic evaluation.

The fixture intentionally contains:

| Finding ID | Vulnerability | File |
|---|---|---|
| `VULN-001` | SQL Injection | `app.py` |
| `VULN-002` | Command Injection | `utils.py` |
| `VULN-003` | Cross-Site Scripting | `web.py` |

The synthetic project also contains functional tests in:

```text
test_projects/vulnerable_app/test_app.py
```

The fixture provides a reproducible before/after state for evaluating the agent.

---

# ✅ Demonstrated Results

## Baseline

```text
pytest
4 passed

Semgrep
3 intentional security findings
```

The initial findings are:

```text
SQL Injection
Command Injection
Cross-Site Scripting
```

## Normal remediation

```text
Attempts             : 1
Findings discovered   : 3
Functional tests      : PASS
Semgrep findings      : 0
Bandit blocking       : 0
Regression check      : PASS
Overall verification  : PASS

FINAL STATUS: VERIFIED
```

## Deliberate failure + recovery

```text
Attempts             : 2
Findings discovered   : 3
Functional tests      : PASS
Semgrep findings      : 0
Bandit blocking      : 0
Regression check      : PASS
Overall verification  : PASS

FINAL STATUS: VERIFIED
```

The second run demonstrates the agent detecting a failed first attempt and recovering through a targeted retry.

---

# 📊 Structured Output

Each run produces:

```text
runs/latest_report.json
```

The report contains structured information about:

- execution goal
- generated plan
- vulnerability findings
- patch proposals
- patch execution
- test results
- Semgrep results
- Bandit results
- verification
- remaining findings
- retry/attempt history
- agent trace

Example verification structure:

```json
{
  "functional_tests": "PASS",
  "security_scan": "PASS",
  "regression_check": "PASS",
  "overall": "PASS",
  "remaining_findings": []
}
```

---

# 🏗️ Project Structure

```text
SecurePatch/
│
├── app/
│   ├── agents.py
│   ├── adk_runner.py
│   ├── config.py
│   ├── graph.py
│   └── tools.py
│
├── rules/
│   └── python-security.yml
│
├── test_projects/
│   └── vulnerable_app/
│       ├── app.py
│       ├── utils.py
│       ├── web.py
│       └── test_app.py
│
├── runs/
│   └── latest_report.json
│
├── run_demo.py
├── requirements.txt
├── .env.example
├── README.md
└── ...
```

---

# ⚙️ Technology Stack

| Component | Technology |
|---|---|
| Language | Python |
| Agent Framework | Google ADK |
| LLM | Gemini |
| LLM Platform | Google Vertex AI |
| Orchestration | LangGraph |
| Static Security Analysis | Semgrep |
| Python Security Analysis | Bandit |
| Functional Testing | pytest |
| Reporting | JSON / Markdown |
| Cloud Deployment | Google Cloud |

---

# 🚀 Local Setup

## 1. Clone

```bash
git clone https://github.com/tanishqsaraswat34/SecurePatch.git
cd SecurePatch
```

## 2. Create virtual environment

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Configure Google Cloud / Vertex AI

Create your local `.env` from `.env.example`.

Example:

```env
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_LOCATION=global
GOOGLE_GENAI_USE_VERTEXAI=TRUE
SECUREPATCH_MODEL=gemini-3.5-flash
SECUREPATCH_INDUCE_FAILURE=false
```

Use your own Google Cloud credentials locally.

**Never commit `.env`, API keys, access tokens, or service-account credentials to GitHub.**

---

# ▶️ Run SecurePatch

### Normal run

```powershell
$env:SECUREPATCH_INDUCE_FAILURE="false"
python run_demo.py
```

### Deliberate failure / recovery run

```powershell
$env:SECUREPATCH_INDUCE_FAILURE="true"
python run_demo.py
```

Reset the environment variable afterwards:

```powershell
Remove-Item Env:SECUREPATCH_INDUCE_FAILURE
```

---

# 🧪 Verify the Synthetic Project Manually

Before running the agent, the vulnerable baseline can be verified.

### Functional tests

```powershell
pytest -q test_projects\vulnerable_app
```

Expected:

```text
4 passed
```

### Security scan

```powershell
semgrep --config rules\python-security.yml test_projects\vulnerable_app
```

Expected baseline:

```text
3 findings
```

---

# ☁️ Google Cloud Deployment

The same SecurePatch implementation is intended to be demonstrated in a Google Cloud environment.

### Live Demo

**Deployment URL:**

```text
COMING SOON
```

Once the Cloud Run deployment is verified, this section will be updated with the public URL.

The GitHub repository remains the reproducible source-code submission; the cloud deployment is an additional demonstration of the implementation running in a cloud environment.

---

# 🔒 Security & Credentials

Credentials are intentionally excluded from the repository.

The repository should contain:

```text
.env.example
```

but never:

```text
.env
service-account.json
credentials.json
API keys
access tokens
```

Each user/developer should configure their own Google Cloud authentication when running the live LLM workflow locally.

---

# 📁 Submission Artifacts

The project submission includes:

- Source code
- Architecture diagram
- Normal sample run
- Deliberate failure/recovery sample run
- Baseline security scan
- Synthetic test-trace documentation
- Short design write-up

---

# 📌 Assignment Alignment

SecurePatch maps directly to the take-home requirements:

| Assignment Requirement | SecurePatch Implementation |
|---|---|
| High-level natural-language goal | Security remediation goal |
| Autonomous decomposition | Planner Agent |
| Visible planning trace | Agent trace / structured report |
| At least two tools | pytest, Semgrep, Bandit, file/patch tools |
| Step-by-step execution | LangGraph workflow |
| Deliberately induced failure | Failure injection flag |
| Recovery/self-correction | Finding-level selective retry |
| Structured final output | `runs/latest_report.json` |
| Architecture diagram | Included in submission |
| Sample transcripts | Included in submission |
| Documentation | README + design write-up |

---

# ⚠️ Limitations

SecurePatch is a focused technical prototype rather than a production-grade security sandbox.

The current implementation is designed around a controlled Python evaluation project.

It does not claim to safely execute arbitrary untrusted repositories.

A production version could add:

- isolated container/sandbox execution
- stronger resource limits
- broader language support
- dependency vulnerability scanning
- larger repository analysis
- generated regression tests
- persistent run history
- human approval for high-impact changes
- web-based project upload and review
- richer security policy configuration

---

# 🔮 Future Improvements

With more development time, SecurePatch could evolve into a repository-level security remediation platform supporting:

```text
GitHub Repository
       ↓
Repository Analysis
       ↓
Security Findings
       ↓
AI Remediation
       ↓
Automated Tests
       ↓
Security Rescan
       ↓
Human Review
       ↓
Pull Request
```

The current project intentionally focuses on demonstrating the core agentic loop and reliable deterministic verification.

---

# 👤 Author

**Tanishq Saraswat**

B.Tech Computer Science & Engineering  
Institute of Engineering and Technology, Lucknow

GitHub:  
https://github.com/tanishqsaraswat34

---

## Take-Home Assignment

**Role:** Agentic AI Engineer Intern

**Track:** Secure Coding Assistant

**Project:** SecurePatch — Autonomous Security Patching
