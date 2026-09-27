from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
from typing import Any

from app.graph import build_graph
from app.tools import reset_demo_workspace


ROOT = Path(__file__).resolve().parent

FIXTURE_ROOT = (
    ROOT
    / "test_projects"
    / "vulnerable_app"
)

WORKSPACE_ROOT = (
    ROOT
    / "runs"
    / "demo_workspace"
)

REPORT_PATH = (
    ROOT
    / "runs"
    / "latest_report.json"
)

GOAL = """
Analyze this Python project for security vulnerabilities.
Identify the vulnerable lines, explain the risk and impact,
apply secure fixes automatically, preserve existing functionality,
verify the fixes, and produce a structured security report.
""".strip()


def print_header() -> None:
    print()
    print("=" * 48)
    print("             SECUREPATCH DEMO")
    print("=" * 48)
    print()


def safe_get(
    data: Any,
    key: str,
    default: Any = None,
) -> Any:
    if isinstance(data, dict):
        return data.get(key, default)
    return default


def extract_verification(
    result: dict[str, Any],
) -> dict[str, Any]:
    final_report = safe_get(
        result,
        "final_report",
        {},
    )

    verification = safe_get(
        final_report,
        "verification",
        None,
    )

    if isinstance(verification, dict):
        return verification

    verification = safe_get(
        result,
        "verification",
        {},
    )

    return (
        verification
        if isinstance(verification, dict)
        else {}
    )


def extract_findings(
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    final_report = safe_get(
        result,
        "final_report",
        {},
    )

    findings = safe_get(
        final_report,
        "findings",
        {},
    )

    if isinstance(findings, dict):
        findings = findings.get(
            "findings",
            [],
        )

    if not isinstance(findings, list):
        return []

    return [
        item
        for item in findings
        if isinstance(item, dict)
    ]

def extract_attempts(
    result: dict[str, Any],
) -> int:
    final_report = safe_get(
        result,
        "final_report",
        {},
    )

    attempts = safe_get(
        final_report,
        "attempts",
        0,
    )

    try:
        attempts = int(attempts)
    except (TypeError, ValueError):
        attempts = 0

    # Fallback: derive the attempt number
    # from the actual agent trace.
    if attempts <= 0:
        trace = safe_get(
            final_report,
            "agent_trace",
            [],
        )

        if isinstance(trace, list):
            max_attempt = 0

            for entry in trace:
                if not isinstance(
                    entry,
                    dict,
                ):
                    continue

                component = str(
                    entry.get(
                        "component",
                        "",
                    )
                )

                prefix = (
                    "Patch Agent Attempt "
                )

                if component.startswith(prefix):
                    try:
                        attempt_number = int(
                            component[len(prefix):]
                        )
                        max_attempt = max(
                            max_attempt,
                            attempt_number,
                        )
                    except ValueError:
                        pass

            if max_attempt > 0:
                attempts = max_attempt

    return attempts

def extract_trace(
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    final_report = safe_get(
        result,
        "final_report",
        {},
    )

    trace = safe_get(
        final_report,
        "agent_trace",
        [],
    )

    if not isinstance(trace, list):
        return []

    return [
        item
        for item in trace
        if isinstance(item, dict)
    ]


def extract_security_stats(
    verification: dict[str, Any],
) -> tuple[int, int]:
    deterministic = safe_get(
        verification,
        "deterministic_results",
        {},
    )

    if not isinstance(
        deterministic,
        dict,
    ):
        return 0, 0

    semgrep = safe_get(
        deterministic,
        "semgrep",
        {},
    )

    bandit = safe_get(
        deterministic,
        "bandit",
        {},
    )

    semgrep_findings = safe_get(
        semgrep,
        "finding_count",
        0,
    )

    bandit_blocking = safe_get(
        bandit,
        "blocking_count",
        0,
    )

    try:
        semgrep_findings = int(
            semgrep_findings
        )
    except (
        TypeError,
        ValueError,
    ):
        semgrep_findings = 0

    try:
        bandit_blocking = int(
            bandit_blocking
        )
    except (
        TypeError,
        ValueError,
    ):
        bandit_blocking = 0

    return (
        semgrep_findings,
        bandit_blocking,
    )


def print_compact_summary(
    result: dict[str, Any],
) -> None:
    verification = extract_verification(
        result
    )

    findings = extract_findings(
        result
    )

    trace = extract_trace(
        result
    )

    attempts = extract_attempts(
        result
    )

    functional = safe_get(
        verification,
        "functional_tests",
        "UNKNOWN",
    )

    security = safe_get(
        verification,
        "security_scan",
        "UNKNOWN",
    )

    regression = safe_get(
        verification,
        "regression_check",
        "UNKNOWN",
    )

    overall = safe_get(
        verification,
        "overall",
        "UNKNOWN",
    )

    remaining = safe_get(
        verification,
        "remaining_findings",
        [],
    )

    if not isinstance(
        remaining,
        list,
    ):
        remaining = []

    semgrep_findings, bandit_blocking = (
        extract_security_stats(
            verification
        )
    )

    print()
    print("WORKFLOW COMPLETE")
    print("-" * 48)

    print(
        f"Attempts             : {attempts}"
    )

    print(
        f"Findings discovered   : {len(findings)}"
    )

    print(
        f"Functional tests      : {functional}"
    )

    print(
        f"Semgrep findings      : {semgrep_findings}"
    )

    print(
        f"Bandit blocking      : {bandit_blocking}"
    )

    print(
        f"Regression check      : {regression}"
    )

    print(
        f"Overall verification  : {overall}"
    )

    print()

    print("VULNERABILITY STATUS")
    print("-" * 48)

    finding_status = {}

    for finding in findings:
        finding_id = finding.get(
            "id",
            "UNKNOWN",
        )

        finding_type = finding.get(
            "type",
            "Unknown",
        )

        finding_status[
            str(finding_id)
        ] = finding_type

    if finding_status:
        for finding_id, finding_type in (
            finding_status.items()
        ):
            status = (
                "REMAINING"
                if finding_id in remaining
                else "FIXED"
            )

            print(
                f"{finding_id:<10} "
                f"{finding_type:<24} "
                f"{status}"
            )
    else:
        print("No findings reported.")

    print()

    print("AGENT TRACE")
    print("-" * 48)

    if trace:
        printed = set()

        for entry in trace:
            component = entry.get(
                "component",
                "Unknown",
            )

            if component in printed:
                continue

            printed.add(component)

            print(
                f"  -> {component}"
            )
    else:
        print("No agent trace available.")

    print()

    final_status = (
        "VERIFIED"
        if overall == "PASS"
        and not remaining
        else "UNVERIFIED"
    )

    print("=" * 48)
    print(
        f"FINAL STATUS: {final_status}"
    )
    print("=" * 48)

    print()
    print(
        "Full report:"
    )
    print(
        str(REPORT_PATH)
    )
    print()


def main() -> None:
    print_header()

    induce_failure = (
        os.getenv(
            "SECUREPATCH_INDUCE_FAILURE",
            "false",
        ).strip().lower()
        == "true"
    )

    print(
        "Mode                 : "
        + (
            "DELIBERATE FAILURE TEST"
            if induce_failure
            else "NORMAL"
        )
    )

    print(
        "Workspace             : "
        + str(WORKSPACE_ROOT)
    )

    print()
    print(
        "Starting autonomous workflow..."
    )
    print(
        "Detailed internal trace is being "
        "captured in the JSON report."
    )

    # Reset the demo project to its
    # pristine vulnerable state.
    workspace = reset_demo_workspace(
        FIXTURE_ROOT,
        WORKSPACE_ROOT,
    )

    # Build the LangGraph workflow.
    graph = build_graph(
        workspace
    )

    initial_state = {
        "goal": GOAL,
        "project_root": str(workspace),
        "plan": {},
        "findings": {},
        "patch_proposal": {},
        "patch_execution": {},
        "verification": {},
        "traces": [],
        "attempt": 0,
        "max_attempts": 3,
        "induce_failure": induce_failure,
    }

    # The graph currently prints very large JSON blocks
    # from its nodes. Capture that output so the terminal
    # remains readable while preserving the full trace
    # inside the returned state/report.
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()

    try:
        with contextlib.redirect_stdout(
            captured_stdout
        ), contextlib.redirect_stderr(
            captured_stderr
        ):
            result = graph.invoke(
                initial_state
            )

    except Exception as exc:
        print()
        print("=" * 48)
        print("WORKFLOW FAILED")
        print("=" * 48)
        print()
        print(
            f"Error: {type(exc).__name__}: {exc}"
        )
        print()
        print(
            "The detailed execution output was "
            "captured internally."
        )
        print()
        raise

    # Ensure the result is serializable before
    # writing the report ourselves.
    try:
        REPORT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        final_report = safe_get(
            result,
            "final_report",
            result,
        )

        with REPORT_PATH.open(
            "w",
            encoding="utf-8",
        ) as report_file:
            json.dump(
                final_report,
                report_file,
                indent=2,
                default=str,
            )

    except Exception as exc:
        print()
        print(
            "Warning: could not rewrite "
            "latest_report.json:"
        )
        print(exc)

    print_compact_summary(
        result
    )


if __name__ == "__main__":
    main()