from __future__ import annotations

import difflib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


from .config import MAX_FILE_SIZE


SUPPORTED_SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".php",
}


def _safe_path(
    root: Path,
    relative_path: str,
) -> Path:
    """
    Resolve a path and prevent traversal outside the project root.
    """

    root = root.resolve()

    candidate = (
        root / relative_path
    ).resolve()

    if (
        candidate != root
        and root not in candidate.parents
    ):
        raise ValueError(
            "Path escapes project root."
        )

    return candidate


def reset_demo_workspace(
    fixture_root: Path,
    workspace_root: Path,
) -> Path:
    """
    Reset the working demo project from a pristine fixture.

    This prevents previous agent runs from affecting future runs.
    """

    if workspace_root.exists():
        shutil.rmtree(workspace_root)

    workspace_root.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copytree(
        fixture_root,
        workspace_root,
    )

    return workspace_root


def list_files(
    root: Path,
) -> dict[str, Any]:
    """
    List files inside the target project.
    """

    root = root.resolve()

    files = []

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        relative = path.relative_to(root)

        if any(
            part.startswith(".")
            for part in relative.parts
        ):
            continue

        files.append(
            str(relative)
        )

    return {
        "success": True,
        "files": sorted(files)[:500],
        "count": len(files),
    }


def read_file(
    root: Path,
    file_path: str,
) -> dict[str, Any]:
    """
    Read a text file safely.
    """

    try:

        path = _safe_path(
            root,
            file_path,
        )

        if not path.exists():
            return {
                "success": False,
                "error": "File does not exist.",
            }

        if not path.is_file():
            return {
                "success": False,
                "error": "Target is not a file.",
            }

        if (
            path.stat().st_size
            > MAX_FILE_SIZE
        ):
            return {
                "success": False,
                "error": (
                    f"File exceeds "
                    f"{MAX_FILE_SIZE} bytes."
                ),
            }

        content = path.read_text(
            encoding="utf-8",
        )

        return {
            "success": True,
            "file": file_path,
            "content": content,
        }

    except Exception as exc:

        return {
            "success": False,
            "error": str(exc),
        }


def search_code(
    root: Path,
    query: str,
) -> dict[str, Any]:
    """
    Search source code text.
    """

    root = root.resolve()

    results = []

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        if (
            path.suffix.lower()
            not in SUPPORTED_SOURCE_EXTENSIONS
        ):
            continue

        try:
            content = path.read_text(
                encoding="utf-8",
            )
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(
            content.splitlines(),
            start=1,
        ):

            if query.lower() in line.lower():

                results.append(
                    {
                        "file": str(
                            path.relative_to(root)
                        ),
                        "line": line_number,
                        "content": line.strip(),
                    }
                )

    return {
        "success": True,
        "query": query,
        "matches": results[:100],
        "count": len(results),
    }

def run_semgrep(
    root: Path,
) -> dict[str, Any]:
    """
    Run Semgrep security analysis.

    A Semgrep configuration/runtime error must NOT be treated
    as a clean security scan.
    """

    rule_file = (
        Path(__file__).resolve().parents[1]
        / "rules"
        / "python-security.yml"
    )

    command = [
        "semgrep",
        "--config",
        str(rule_file),
        str(root),
        "--json",
        "--quiet",
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(root),
        )

        try:

            parsed = (
                json.loads(
                    result.stdout
                )
                if result.stdout.strip()
                else {}
            )

        except json.JSONDecodeError:

            parsed = {
                "results": [],
                "errors": [],
                "raw_stdout": result.stdout,
            }

        findings = parsed.get(
            "results",
            [],
        )

        errors = parsed.get(
            "errors",
            [],
        )

        # -------------------------------------------------
        # IMPORTANT:
        # Semgrep may return non-zero when findings exist,
        # so findings alone do not mean execution failed.
        #
        # But configuration/runtime errors DO mean the
        # security scan failed.
        # -------------------------------------------------

        scan_success = not errors

        if (
            result.returncode >= 2
            and not errors
        ):
            scan_success = False

        return {
            "success": scan_success,
            "returncode": result.returncode,
            "finding_count": len(findings),
            "results": findings,
            "errors": errors,
            "stderr": result.stderr,
        }

    except FileNotFoundError:

        return {
            "success": False,
            "error_type": "EXECUTABLE_NOT_FOUND",
            "error": (
                "Semgrep is not installed "
                "or is not on PATH."
            ),
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "error_type": "TIMEOUT",
            "error": (
                "Semgrep timed out "
                "after 60 seconds."
            ),
        }

    except Exception as exc:

        return {
            "success": False,
            "error_type": type(
                exc
            ).__name__,
            "error": str(exc),
        }

def run_bandit(
    root: Path,
) -> dict[str, Any]:
    """
    Run Bandit through the currently active Python environment.
    """

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "-f",
        "json",
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(root),
        )

        try:

            parsed = (
                json.loads(
                    result.stdout
                )
                if result.stdout.strip()
                else {}
            )

        except json.JSONDecodeError:

            parsed = {}

        findings = parsed.get(
            "results",
            [],
        )

        return {
            "success": True,
            "returncode": result.returncode,
            "finding_count": len(findings),
            "results": findings,
            "metrics": parsed.get(
                "metrics",
                {},
            ),
            "stderr": result.stderr,
        }

    except FileNotFoundError:

        return {
            "success": False,
            "error_type": (
                "EXECUTABLE_NOT_FOUND"
            ),
            "error": (
                "Bandit is not installed."
            ),
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "error_type": "TIMEOUT",
            "error": (
                "Bandit timed out "
                "after 60 seconds."
            ),
        }

    except Exception as exc:

        return {
            "success": False,
            "error_type": type(
                exc
            ).__name__,
            "error": str(exc),
        }


def apply_patch(
    root: Path,
    file_path: str,
    old_text: str,
    new_text: str,
    simulate_failure: bool = False,
) -> dict[str, Any]:
    """
    Apply one exact source replacement.

    Exact matching prevents broad unintended changes.
    """

    if simulate_failure:

        return {
            "success": False,
            "retryable": True,
            "error_type": (
                "SIMULATED_TOOL_FAILURE"
            ),
            "error": (
                "The patch execution tool "
                "deliberately failed this first "
                "attempt to test recovery."
            ),
        }

    try:

        path = _safe_path(
            root,
            file_path,
        )

        if not path.exists():

            return {
                "success": False,
                "retryable": False,
                "error": (
                    "Target file does not exist."
                ),
            }

        content = path.read_text(
            encoding="utf-8",
        )

        occurrences = content.count(
            old_text
        )

        if occurrences != 1:

            return {
                "success": False,
                "retryable": False,
                "error": (
                    "Expected old_text exactly "
                    f"once, found {occurrences}."
                ),
            }

        updated = content.replace(
            old_text,
            new_text,
            1,
        )

        path.write_text(
            updated,
            encoding="utf-8",
        )

        return {
            "success": True,
            "file": file_path,
            "message": (
                "Patch applied successfully."
            ),
        }

    except Exception as exc:

        return {
            "success": False,
            "retryable": False,
            "error_type": type(
                exc
            ).__name__,
            "error": str(exc),
        }


def generate_diff(
    root: Path,
    file_path: str,
    before_content: str,
) -> dict[str, Any]:
    """
    Generate a unified diff.
    """

    try:

        path = _safe_path(
            root,
            file_path,
        )

        if not path.exists():

            return {
                "success": False,
                "error": (
                    "File does not exist."
                ),
            }

        after_content = path.read_text(
            encoding="utf-8",
        )

        diff = "".join(
            difflib.unified_diff(
                before_content.splitlines(
                    keepends=True
                ),
                after_content.splitlines(
                    keepends=True
                ),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            )
        )

        return {
            "success": True,
            "file": file_path,
            "diff": diff,
        }

    except Exception as exc:

        return {
            "success": False,
            "error": str(exc),
        }


def run_tests(
    root: Path,
) -> dict[str, Any]:
    """
    Run pytest using the current Python interpreter.

    This avoids Windows PATH problems where pytest.exe may
    come from another environment.
    """

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(root),
        )

        return {
            "success": (
                result.returncode == 0
            ),
            "returncode": result.returncode,
            "command": command,
            "stdout": (
                result.stdout[-10000:]
            ),
            "stderr": (
                result.stderr[-10000:]
            ),
        }

    except FileNotFoundError as exc:

        return {
            "success": False,
            "returncode": None,
            "command": command,
            "error_type": (
                "EXECUTABLE_NOT_FOUND"
            ),
            "error": str(exc),
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "returncode": None,
            "command": command,
            "error_type": "TIMEOUT",
            "error": (
                "Test suite timed out."
            ),
        }

    except Exception as exc:

        return {
            "success": False,
            "returncode": None,
            "command": command,
            "error_type": type(
                exc
            ).__name__,
            "error": str(exc),
        }