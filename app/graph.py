from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .adk_runner import run_agent
from .agents import build_agents
from .tools import (
    apply_patch,
    generate_diff,
    read_file,
    run_bandit,
    run_semgrep,
    run_tests,
)


# ============================================================
# STATE
# ============================================================


class SecurePatchState(
    TypedDict,
    total=False,
):
    goal: str
    project_root: str

    plan: dict[str, Any]
    findings: dict[str, Any]

    patch_proposal: dict[str, Any]
    patch_execution: dict[str, Any]

    verification: dict[str, Any]

    traces: list[dict[str, Any]]

    attempt: int
    max_attempts: int

    induce_failure: bool

    retry_finding_ids: list[str]
    retry_reason: str

    patch_history: list[dict[str, Any]]
    verification_history: list[dict[str, Any]]

    final_report: dict[str, Any]


# ============================================================
# HELPERS
# ============================================================


def extract_json(
    text: str,
) -> dict[str, Any]:
    """
    Extract a structured object from model output.

    Primary parser: JSON.
    Fallback parser: Python literal syntax.

    This prevents a malformed single-quoted dictionary from
    crashing the entire LangGraph workflow.
    """

    text = text.strip()

    # Remove markdown code fences if present.
    if text.startswith("```"):

        lines = text.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

    start = text.find("{")
    end = text.rfind("}")

    if (
        start == -1
        or end == -1
    ):
        raise ValueError(
            "No JSON object found in model output:\n"
            + text
        )

    payload = text[
        start : end + 1
    ]

    try:
        parsed = json.loads(
            payload
        )

    except json.JSONDecodeError as json_error:

        try:

            parsed = ast.literal_eval(
                payload
            )

        except Exception:

            raise ValueError(
                "Model output was neither valid JSON "
                "nor a valid Python dictionary.\n"
                f"JSON error: {json_error}\n"
                f"Model output:\n{text}"
            ) from json_error

    if not isinstance(
        parsed,
        dict,
    ):
        raise ValueError(
            "Model output must be a JSON object."
        )

    return parsed


def append_trace(
    state: SecurePatchState,
    component: str,
    output: Any,
    tool_trace: list[dict[str, Any]] | None = None,
):
    traces = list(
        state.get(
            "traces",
            [],
        )
    )

    traces.append(
        {
            "component": component,
            "output": output,
            "tools": tool_trace or [],
        }
    )

    return traces


def normalize_path(
    value: str,
    project_root: Path,
) -> str:

    value = str(
        value
    ).replace(
        "\\",
        "/",
    )

    root = str(
        project_root.resolve()
    ).replace(
        "\\",
        "/",
    )

    if value.startswith(
        root.rstrip("/") + "/"
    ):
        value = value[
            len(root.rstrip("/")) + 1 :
        ]

    while value.startswith("./"):
        value = value[2:]

    return value


def scanner_rule_id(
    check_id: str,
) -> str:

    check_id = str(
        check_id or ""
    ).replace(
        "\\",
        "/",
    )

    known_rules = (
        "python-sql-injection",
        "python-command-injection",
        "python-xss",
    )

    for rule in known_rules:

        if check_id.endswith(
            rule
        ):
            return rule

    return check_id.split(
        "/"
    )[-1]


def scanner_vulnerability_type(
    check_id: str,
) -> str:

    check_id = scanner_rule_id(
        check_id
    )

    mapping = {
        "python-sql-injection": "SQL Injection",
        "python-command-injection": "Command Injection",
        "python-xss": "Cross-Site Scripting",
    }

    return mapping.get(
        check_id,
        check_id or "Security Vulnerability",
    )


def scanner_severity(
    raw: str | None,
) -> str:

    value = str(
        raw or ""
    ).upper()

    if value in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    }:
        return value

    return "MEDIUM"


def get_scanner_line(
    scanner_result: dict[str, Any],
) -> int:

    return int(
        scanner_result.get(
            "start",
            {},
        ).get(
            "line",
            0,
        )
        or 0
    )


def analyst_lines(
    finding: dict[str, Any],
) -> list[int]:

    lines = finding.get(
        "lines",
        [],
    )

    if isinstance(
        lines,
        list,
    ):

        return [
            int(line)
            for line in lines
            if str(line).isdigit()
        ]

    return []


def correlate_analyst_finding(
    scanner_result: dict[str, Any],
    analyst_findings: list[dict[str, Any]],
    project_root: Path,
    used_indexes: set[int],
) -> dict[str, Any] | None:

    scanner_file = normalize_path(
        scanner_result.get(
            "path",
            "",
        ),
        project_root,
    )

    scanner_line = get_scanner_line(
        scanner_result
    )

    scanner_type = scanner_vulnerability_type(
        scanner_result.get(
            "check_id",
            "",
        )
    )

    candidates = []

    for index, finding in enumerate(
        analyst_findings
    ):

        if index in used_indexes:
            continue

        finding_file = normalize_path(
            finding.get(
                "file",
                "",
            ),
            project_root,
        )

        if finding_file != scanner_file:
            continue

        finding_type = str(
            finding.get(
                "type",
                "",
            )
        ).lower()

        type_match = (
            scanner_type.lower()
            in finding_type
            or finding_type
            in scanner_type.lower()
        )

        lines = analyst_lines(
            finding
        )

        line_distance = 999999

        if lines:

            line_distance = min(
                abs(
                    line - scanner_line
                )
                for line in lines
            )

        candidates.append(
            (
                0 if type_match else 1,
                line_distance,
                index,
                finding,
            )
        )

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            item[0],
            item[1],
        )
    )

    selected = candidates[0]

    used_indexes.add(
        selected[2]
    )

    return selected[3]


def canonicalize_findings(
    analyst_output: dict[str, Any],
    semgrep_result: dict[str, Any],
    project_root: Path,
) -> list[dict[str, Any]]:

    analyst_findings = analyst_output.get(
        "findings",
        [],
    )

    if not isinstance(
        analyst_findings,
        list,
    ):
        analyst_findings = []

    scanner_results = semgrep_result.get(
        "results",
        [],
    )

    canonical = []

    used_indexes: set[int] = set()

    for index, scanner_result in enumerate(
        scanner_results,
        start=1,
    ):

        extra = scanner_result.get(
            "extra",
            {},
        )

        check_id = scanner_rule_id(
            scanner_result.get(
                "check_id",
                "",
            )
        )

        finding_type = scanner_vulnerability_type(
            check_id
        )

        analyst_match = correlate_analyst_finding(
            scanner_result,
            analyst_findings,
            project_root,
            used_indexes,
        )

        file_path = normalize_path(
            scanner_result.get(
                "path",
                "",
            ),
            project_root,
        )

        start_line = get_scanner_line(
            scanner_result
        )

        end_line = int(
            scanner_result.get(
                "end",
                {},
            ).get(
                "line",
                start_line,
            )
            or start_line
        )

        description = (
            analyst_match.get(
                "description",
                "",
            )
            if analyst_match
            else ""
        )

        if not description:
            description = extra.get(
                "message",
                f"Semgrep detected {finding_type}.",
            )

        evidence = extra.get(
            "lines",
            "",
        )

        if (
            not evidence
            and analyst_match
        ):
            evidence = analyst_match.get(
                "evidence",
                "",
            )

        risk = (
            analyst_match.get(
                "risk",
                "Potential security impact.",
            )
            if analyst_match
            else "Potential security impact."
        )

        impact = (
            analyst_match.get(
                "impact",
                "Could allow attacker-controlled behavior.",
            )
            if analyst_match
            else "Could allow attacker-controlled behavior."
        )

        recommended_fix = (
            analyst_match.get(
                "recommended_fix",
                "",
            )
            if analyst_match
            else ""
        )

        canonical.append(
            {
                "id": f"VULN-{index:03d}",
                "type": finding_type,
                "severity": scanner_severity(
                    extra.get(
                        "severity"
                    )
                ),
                "file": file_path,
                "lines": list(
                    range(
                        start_line,
                        end_line + 1,
                    )
                ),
                "description": description,
                "risk": risk,
                "impact": impact,
                "evidence": evidence,
                "recommended_fix": recommended_fix,
                "scanner_rule": check_id,
                "scanner_message": extra.get(
                    "message",
                    "",
                ),
            }
        )

    if not canonical:

        for index, finding in enumerate(
            analyst_findings,
            start=1,
        ):

            canonical.append(
                {
                    "id": f"VULN-{index:03d}",
                    "type": finding.get(
                        "type",
                        "Security Vulnerability",
                    ),
                    "severity": finding.get(
                        "severity",
                        "MEDIUM",
                    ),
                    "file": normalize_path(
                        finding.get(
                            "file",
                            "",
                        ),
                        project_root,
                    ),
                    "lines": analyst_lines(
                        finding
                    ),
                    "description": finding.get(
                        "description",
                        "",
                    ),
                    "risk": finding.get(
                        "risk",
                        "",
                    ),
                    "impact": finding.get(
                        "impact",
                        "",
                    ),
                    "evidence": finding.get(
                        "evidence",
                        "",
                    ),
                    "recommended_fix": finding.get(
                        "recommended_fix",
                        "",
                    ),
                }
            )

    return canonical


def find_remaining_finding_ids(
    semgrep_result: dict[str, Any],
    findings: list[dict[str, Any]],
    project_root: Path,
) -> list[str]:

    results = semgrep_result.get(
        "results",
        [],
    )

    remaining: list[str] = []

    for finding in findings:

        finding_file = normalize_path(
            finding.get(
                "file",
                "",
            ),
            project_root,
        )

        finding_type = str(
            finding.get(
                "type",
                "",
            )
        ).lower()

        finding_lines = analyst_lines(
            finding
        )

        for result in results:

            result_file = normalize_path(
                result.get(
                    "path",
                    "",
                ),
                project_root,
            )

            if result_file != finding_file:
                continue

            result_type = scanner_vulnerability_type(
                result.get(
                    "check_id",
                    "",
                )
            ).lower()

            if (
                result_type not in finding_type
                and finding_type not in result_type
            ):
                continue

            scanner_line = get_scanner_line(
                result
            )

            if (
                not finding_lines
                or scanner_line in finding_lines
                or min(
                    abs(
                        line - scanner_line
                    )
                    for line in finding_lines
                )
                <= 5
            ):

                remaining.append(
                    finding["id"]
                )

                break

    return remaining


def get_bandit_blocking_findings(
    bandit_result: dict[str, Any],
) -> list[dict[str, Any]]:

    results = bandit_result.get(
        "results",
        [],
    )

    if not isinstance(
        results,
        list,
    ):
        return []

    blocking_levels = {
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    return [
        result
        for result in results
        if str(
            result.get(
                "issue_severity",
                "",
            )
        ).upper()
        in blocking_levels
    ]


# ============================================================
# GRAPH
# ============================================================


def build_graph(
    project_root: Path,
):

    (
        planner,
        analyst,
        patcher,
        verifier,
    ) = build_agents(
        project_root
    )

    # ========================================================
    # PLAN
    # ========================================================

    def plan_node(
        state: SecurePatchState,
    ):

        print(
            "\n========== PLAN =========="
        )

        output, tools = run_agent(
            planner,
            state["goal"],
            "securepatch_planner",
        )

        plan = extract_json(
            output
        )

        print(
            json.dumps(
                plan,
                indent=2,
            )
        )

        return {
            "plan": plan,
            "traces": append_trace(
                state,
                "Planner",
                plan,
                tools,
            ),
        }

    # ========================================================
    # ANALYSIS
    # ========================================================

    def analysis_node(
        state: SecurePatchState,
    ):

        print(
            "\n========== SECURITY ANALYSIS =========="
        )

        prompt = f"""
High-level goal:

{state["goal"]}

Execution plan:

{json.dumps(
    state["plan"],
    indent=2,
)}

Analyze the following project:

{project_root}

Perform a complete multi-file security analysis.

Use the real available tools.

Identify every legitimate vulnerability and keep
each vulnerability as an independent finding.
"""

        output, tools = run_agent(
            analyst,
            prompt,
            "securepatch_analyst",
        )

        analyst_output = extract_json(
            output
        )

        baseline_semgrep = run_semgrep(
            project_root
        )

        canonical_findings = canonicalize_findings(
            analyst_output,
            baseline_semgrep,
            project_root,
        )

        findings = {
            "findings": canonical_findings,
            "scanner": {
                "success": baseline_semgrep.get(
                    "success",
                    False,
                ),
                "finding_count": baseline_semgrep.get(
                    "finding_count",
                    0,
                ),
                "errors": baseline_semgrep.get(
                    "errors",
                    [],
                ),
            },
        }

        print(
            json.dumps(
                findings,
                indent=2,
            )
        )

        return {
            "findings": findings,
            "retry_finding_ids": [],
            "retry_reason": "",
            "traces": append_trace(
                state,
                "Security Analyst",
                findings,
                tools
                + [
                    {
                        "tool": "deterministic_semgrep",
                        "result": baseline_semgrep,
                    }
                ],
            ),
        }

    # ========================================================
    # PATCH
    # ========================================================

    def patch_node(
        state: SecurePatchState,
    ):

        attempt = (
            state.get(
                "attempt",
                0,
            )
            + 1
        )

        print(
            f"\n========== PATCH ATTEMPT {attempt} =========="
        )

        all_findings = state[
            "findings"
        ].get(
            "findings",
            [],
        )

        requested_ids = state.get(
            "retry_finding_ids",
            [],
        )

        if not requested_ids:

            requested_ids = [
                finding["id"]
                for finding in all_findings
            ]

        target_findings = [
            finding
            for finding in all_findings
            if finding.get("id")
            in requested_ids
        ]

        retry_reason = state.get(
            "retry_reason",
            "",
        )

        if attempt == 1:
            retry_reason = (
                "Initial remediation pass."
            )

        prompt = f"""
High-level goal:

{state["goal"]}

This is patch attempt {attempt}.

Findings available:

{json.dumps(
    all_findings,
    indent=2,
)}

IMPORTANT:

You must patch ONLY these finding IDs during this
attempt:

{json.dumps(
    requested_ids,
    indent=2,
)}

Target findings:

{json.dumps(
    target_findings,
    indent=2,
)}

Previous verification:

{json.dumps(
    state.get(
        "verification",
        {},
    ),
    indent=2,
)}

Retry context:

{retry_reason}

Project:

{project_root}

Generate minimal secure patches.

Do NOT generate patches for findings that have already
passed deterministic security verification.

Return JSON ONLY.
"""

        # ----------------------------------------------------
        # Patch Agent robustness boundary.
        # ----------------------------------------------------

        try:

            output, tools = run_agent(
                patcher,
                prompt,
                "securepatch_patcher",
            )

            proposal = extract_json(
                output
            )

        except Exception as exc:

            print(
                "\nPATCH AGENT OUTPUT ERROR:"
            )

            print(
                str(exc)
            )

            execution_results = [
                {
                    "success": False,
                    "retryable": True,
                    "error_type": (
                        "PATCH_AGENT_OUTPUT_ERROR"
                    ),
                    "error": str(exc),
                    "finding_id": finding_id,
                }
                for finding_id in requested_ids
            ]

            execution = {
                "attempt": attempt,
                "target_finding_ids": requested_ids,
                "results": execution_results,
            }

            patch_history = list(
                state.get(
                    "patch_history",
                    [],
                )
            )

            patch_history.append(
                {
                    "attempt": attempt,
                    "target_finding_ids": requested_ids,
                    "proposal": {},
                    "execution": execution,
                }
            )

            return {
                "attempt": attempt,
                "patch_proposal": {},
                "patch_execution": execution,
                "patch_history": patch_history,
                "traces": append_trace(
                    state,
                    f"Patch Agent Attempt {attempt}",
                    {
                        "proposal": {},
                        "execution": execution,
                        "error": str(exc),
                    },
                    [],
                ),
            }

        print(
            "\nPATCH PROPOSAL:"
        )

        print(
            json.dumps(
                proposal,
                indent=2,
            )
        )

        execution_results = []

        patches = proposal.get(
            "patches",
            [],
        )

        allowed_ids = set(
            requested_ids
        )

        for index, patch in enumerate(
            patches
        ):

            finding_id = patch.get(
                "finding_id"
            )

            file_path = patch.get(
                "file"
            )

            old_text = patch.get(
                "old_text"
            )

            new_text = patch.get(
                "new_text"
            )

            if finding_id not in allowed_ids:

                execution_results.append(
                    {
                        "success": False,
                        "retryable": False,
                        "error_type": (
                            "UNAUTHORIZED_FINDING_PATCH"
                        ),
                        "error": (
                            "Patch targets a finding that "
                            "was not requested for this attempt."
                        ),
                        "finding_id": finding_id,
                        "file": file_path,
                    }
                )

                continue

            if not all(
                [
                    file_path,
                    old_text is not None,
                    new_text is not None,
                ]
            ):

                execution_results.append(
                    {
                        "success": False,
                        "retryable": True,
                        "error_type": (
                            "INVALID_PATCH_PROPOSAL"
                        ),
                        "error": (
                            "Patch proposal is missing "
                            "file, old_text or new_text."
                        ),
                        "finding_id": finding_id,
                        "file": file_path,
                    }
                )

                continue

            before = read_file(
                project_root,
                file_path,
            )

            if not before.get(
                "success"
            ):

                execution_results.append(
                    {
                        "success": False,
                        "retryable": True,
                        "error_type": (
                            "FILE_READ_ERROR"
                        ),
                        "error": (
                            "Unable to capture "
                            "pre-patch file."
                        ),
                        "finding_id": finding_id,
                        "file": file_path,
                    }
                )

                continue

            should_fail_once = (
                state.get(
                    "induce_failure",
                    False,
                )
                and attempt == 1
                and index == 0
            )

            result = apply_patch(
                project_root,
                file_path,
                old_text,
                new_text,
                simulate_failure=should_fail_once,
            )

            result["finding_id"] = finding_id
            result["file"] = file_path

            if result.get(
                "success"
            ):

                diff_result = generate_diff(
                    project_root,
                    file_path,
                    before["content"],
                )

                result["diff"] = diff_result.get(
                    "diff",
                    "",
                )

            execution_results.append(
                result
            )

        proposed_ids = {
            patch.get(
                "finding_id"
            )
            for patch in patches
        }

        for missing_id in (
            allowed_ids - proposed_ids
        ):

            execution_results.append(
                {
                    "success": False,
                    "retryable": True,
                    "error_type": (
                        "MISSING_PATCH"
                    ),
                    "error": (
                        "Patch Agent did not provide "
                        "a patch for this requested finding."
                    ),
                    "finding_id": missing_id,
                }
            )

        execution = {
            "attempt": attempt,
            "target_finding_ids": requested_ids,
            "results": execution_results,
        }

        print(
            "\nPATCH EXECUTION:"
        )

        print(
            json.dumps(
                execution,
                indent=2,
            )
        )

        patch_history = list(
            state.get(
                "patch_history",
                [],
            )
        )

        patch_history.append(
            {
                "attempt": attempt,
                "target_finding_ids": requested_ids,
                "proposal": proposal,
                "execution": execution,
            }
        )

        return {
            "attempt": attempt,
            "patch_proposal": proposal,
            "patch_execution": execution,
            "patch_history": patch_history,
            "traces": append_trace(
                state,
                f"Patch Agent Attempt {attempt}",
                {
                    "requested_finding_ids": requested_ids,
                    "proposal": proposal,
                    "execution": execution,
                },
                tools,
            ),
        }

    # ========================================================
    # VERIFICATION
    # ========================================================

    def verification_node(
        state: SecurePatchState,
    ):

        print(
            "\n========== VERIFICATION =========="
        )

        test_result = run_tests(
            project_root
        )

        semgrep_result = run_semgrep(
            project_root
        )

        bandit_result = run_bandit(
            project_root
        )

        patch_results = (
            state[
                "patch_execution"
            ][
                "results"
            ]
        )

        patch_success = (
            len(
                patch_results
            ) > 0
            and all(
                result.get(
                    "success",
                    False,
                )
                for result in patch_results
            )
        )

        functional_pass = bool(
            test_result.get(
                "success",
                False,
            )
        )

        semgrep_pass = (
            semgrep_result.get(
                "success",
                False,
            )
            and not semgrep_result.get(
                "errors",
                [],
            )
            and semgrep_result.get(
                "finding_count",
                0,
            )
            == 0
        )

        blocking_bandit_findings = (
            get_bandit_blocking_findings(
                bandit_result
            )
        )

        bandit_pass = (
            bandit_result.get(
                "success",
                False,
            )
            and len(
                blocking_bandit_findings
            )
            == 0
        )

        security_pass = (
            semgrep_pass
            and bandit_pass
        )

        regression_pass = (
            functional_pass
            and patch_success
        )

        deterministic_overall = (
            functional_pass
            and security_pass
            and regression_pass
        )

        canonical_findings = state[
            "findings"
        ].get(
            "findings",
            [],
        )

        remaining_ids = find_remaining_finding_ids(
            semgrep_result,
            canonical_findings,
            project_root,
        )

        retry_ids = list(
            remaining_ids
        )

        if (
            not retry_ids
            and not functional_pass
        ):

            retry_ids = [
                result.get(
                    "finding_id"
                )
                for result in patch_results
                if result.get(
                    "success",
                    False,
                )
                and result.get(
                    "finding_id"
                )
            ]

            retry_ids = [
                finding_id
                for finding_id in retry_ids
                if finding_id
            ]

        if (
            not retry_ids
            and not patch_success
        ):

            retry_ids = [
                result.get(
                    "finding_id"
                )
                for result in patch_results
                if result.get(
                    "finding_id"
                )
            ]

            retry_ids = [
                finding_id
                for finding_id in retry_ids
                if finding_id
            ]

        retry_reason = ""

        if remaining_ids:

            retry_reason = (
                "Deterministic Semgrep still reports "
                "unresolved vulnerabilities. Retry only "
                "the remaining finding IDs."
            )

        elif not functional_pass:

            retry_reason = (
                "Functional verification failed after "
                "patch execution."
            )

        elif not patch_success:

            retry_reason = (
                "At least one patch failed to execute."
            )

        elif not bandit_pass:

            retry_reason = (
                "Bandit still reports one or more "
                "blocking security findings."
            )

        deterministic_results = {
            "patch_execution": patch_results,

            "tests": test_result,

            "semgrep": semgrep_result,

            "bandit": {
                "success": bandit_result.get(
                    "success",
                    False,
                ),
                "finding_count": bandit_result.get(
                    "finding_count",
                    0,
                ),
                "blocking_count": len(
                    blocking_bandit_findings
                ),
                "blocking_findings": (
                    blocking_bandit_findings
                ),
            },

            "remaining_finding_ids": remaining_ids,
        }

        # ----------------------------------------------------
        # LLM interpretation.
        # ----------------------------------------------------

        prompt = f"""
Interpret these deterministic verification results.

Patch execution:

{json.dumps(
    patch_results,
    indent=2,
)}

Pytest:

{json.dumps(
    test_result,
    indent=2,
)}

Semgrep:

{json.dumps(
    semgrep_result,
    indent=2,
)}

Bandit:

{json.dumps(
    {
        "success": bandit_result.get(
            "success",
            False,
        ),
        "finding_count": bandit_result.get(
            "finding_count",
            0,
        ),
        "blocking_findings": blocking_bandit_findings,
    },
    indent=2,
)}

Remaining finding IDs:

{json.dumps(
    remaining_ids,
    indent=2,
)}

The deterministic status is authoritative.

Return JSON ONLY:

{{
  "verification": {{
    "functional_tests": "{'PASS' if functional_pass else 'FAIL'}",
    "security_scan": "{'PASS' if security_pass else 'FAIL'}",
    "regression_check": "{'PASS' if regression_pass else 'FAIL'}",
    "overall": "{'PASS' if deterministic_overall else 'FAIL'}",
    "reason": "...",
    "remaining_findings": {json.dumps(remaining_ids)}
  }}
}}
"""

        try:

            output, tools = run_agent(
                verifier,
                prompt,
                "securepatch_verifier",
            )

            llm_verification = extract_json(
                output
            )

        except Exception as exc:

            llm_verification = {
                "verification": {
                    "reason": (
                        "LLM interpretation failed, "
                        "but deterministic verification "
                        "remains authoritative."
                    ),
                    "error": str(exc),
                }
            }

            tools = []

        verification = {
            "functional_tests": (
                "PASS"
                if functional_pass
                else "FAIL"
            ),

            "security_scan": (
                "PASS"
                if security_pass
                else "FAIL"
            ),

            "regression_check": (
                "PASS"
                if regression_pass
                else "FAIL"
            ),

            "overall": (
                "PASS"
                if deterministic_overall
                else "FAIL"
            ),

            "reason": (
                llm_verification.get(
                    "verification",
                    {},
                ).get(
                    "reason",
                    "Deterministic verification completed.",
                )
            ),

            "remaining_findings": remaining_ids,

            "deterministic_results": (
                deterministic_results
            ),
        }

        verification_history = list(
            state.get(
                "verification_history",
                [],
            )
        )

        verification_history.append(
            {
                "attempt": state.get(
                    "attempt",
                    0,
                ),
                "verification": verification,
                "remaining_finding_ids": remaining_ids,
            }
        )

        print(
            json.dumps(
                verification,
                indent=2,
            )
        )

        return {
            "verification": verification,
            "retry_finding_ids": retry_ids,
            "retry_reason": retry_reason,
            "verification_history": verification_history,
            "traces": append_trace(
                state,
                "Verification Agent",
                {
                    "deterministic": verification,
                    "llm_interpretation": llm_verification,
                    "next_retry_ids": retry_ids,
                },
                tools,
            ),
        }

    # ========================================================
    # ROUTING
    # ========================================================

    def route_after_verification(
        state: SecurePatchState,
    ):

        verification = state[
            "verification"
        ]

        if (
            verification[
                "overall"
            ]
            == "PASS"
        ):

            return "report"

        if (
            state.get(
                "attempt",
                0,
            )
            >= state.get(
                "max_attempts",
                3,
            )
        ):

            return "report"

        retry_ids = state.get(
            "retry_finding_ids",
            [],
        )

        if not retry_ids:

            print(
                "\n>>> VERIFICATION FAILED "
                "BUT NO RETRY TARGET COULD BE "
                "ATTRIBUTED — STOPPING <<<"
            )

            return "report"

        print(
            "\n>>> VERIFICATION FAILED "
            "— RETRYING ONLY FAILED FINDINGS <<<"
        )

        print(
            "Retry targets:",
            retry_ids,
        )

        return "patch"

    # ========================================================
    # REPORT
    # ========================================================

    def report_node(
        state: SecurePatchState,
    ):

        verification = state[
            "verification"
        ]

        status = (
            "VERIFIED"
            if verification[
                "overall"
            ]
            == "PASS"
            else "UNVERIFIED"
        )

        all_findings = state[
            "findings"
        ].get(
            "findings",
            [],
        )

        remaining_ids = set(
            verification.get(
                "remaining_findings",
                [],
            )
        )

        resolved_findings = [
            finding
            for finding in all_findings
            if finding.get(
                "id"
            )
            not in remaining_ids
        ]

        remaining_findings = [
            finding
            for finding in all_findings
            if finding.get(
                "id"
            )
            in remaining_ids
        ]

        finding_status = []

        for finding in all_findings:

            finding_id = finding.get(
                "id"
            )

            finding_status.append(
                {
                    "finding_id": finding_id,
                    "file": finding.get(
                        "file"
                    ),
                    "type": finding.get(
                        "type"
                    ),
                    "severity": finding.get(
                        "severity"
                    ),
                    "status": (
                        "RESOLVED"
                        if finding_id
                        not in remaining_ids
                        else "UNRESOLVED"
                    ),
                }
            )

        deterministic_results = verification.get(
            "deterministic_results",
            {},
        )

        report = {
            "project": "SecurePatch",

            "goal": state[
                "goal"
            ],

            "status": status,

            "summary": {
                "total_findings": len(
                    all_findings
                ),
                "resolved_findings": len(
                    resolved_findings
                ),
                "remaining_findings": len(
                    remaining_findings
                ),
                "files_affected": len(
                    {
                        finding.get(
                            "file"
                        )
                        for finding in all_findings
                    }
                ),
                "attempts": state.get(
                    "attempt",
                    0,
                ),
            },

            "security_tools": {
                "semgrep": deterministic_results.get(
                    "semgrep",
                    {},
                ),
                "bandit": deterministic_results.get(
                    "bandit",
                    {},
                ),
            },

            "finding_status": finding_status,

            "findings": state[
                "findings"
            ],

            "resolved_findings": resolved_findings,

            "remaining_findings": remaining_findings,

            "patch_proposal": state.get(
                "patch_proposal",
                {},
            ),

            "patch_execution": state.get(
                "patch_execution",
                {},
            ),

            "patch_history": state.get(
                "patch_history",
                [],
            ),

            "verification": verification,

            "verification_history": state.get(
                "verification_history",
                [],
            ),

            "agent_trace": state.get(
                "traces",
                [],
            ),
        }

        print(
            "\n========== FINAL REPORT =========="
        )

        print(
            json.dumps(
                report,
                indent=2,
            )
        )

        return {
            "final_report": report
        }

    # ========================================================
    # GRAPH
    # ========================================================

    workflow = StateGraph(
        SecurePatchState
    )

    workflow.add_node(
        "plan",
        plan_node,
    )

    workflow.add_node(
        "analyze",
        analysis_node,
    )

    workflow.add_node(
        "patch",
        patch_node,
    )

    workflow.add_node(
        "verify",
        verification_node,
    )

    workflow.add_node(
        "report",
        report_node,
    )

    workflow.add_edge(
        START,
        "plan",
    )

    workflow.add_edge(
        "plan",
        "analyze",
    )

    workflow.add_edge(
        "analyze",
        "patch",
    )

    workflow.add_edge(
        "patch",
        "verify",
    )

    workflow.add_conditional_edges(
        "verify",
        route_after_verification,
        {
            "patch": "patch",
            "report": "report",
        },
    )

    workflow.add_edge(
        "report",
        END,
    )

    return workflow.compile()