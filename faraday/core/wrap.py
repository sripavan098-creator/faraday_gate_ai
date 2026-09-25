from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from faraday.adapters.registry import get_adapter
from faraday.core.audit import AuditChain
from faraday.core.flow import (
    add_scan_findings,
    append_findings,
    append_redactions,
    append_session_started,
    create_session_for_policy,
    finalize_session,
)
from faraday.core.policy import Policy
from faraday.models.local_model import MockLocalCoder
from faraday.redactor import redact_text
from faraday.redactor.text_redactor import RedactionRecord
from faraday.scanners.base import ScanFinding
from faraday.scanners.files import scan_path
from faraday.scanners.pipeline import scan_command, scan_text

BLOCK_ACTIONS = {"block", "quarantine"}
REDACT_ACTIONS = {"redact"}
WARN_ACTIONS = {"warn", "ask"}


@dataclass
class WrapResult:
    status: str
    exit_code: int
    adapter_name: str
    session_id: str

    findings: List[ScanFinding] = field(default_factory=list)
    blocked: List[ScanFinding] = field(default_factory=list)
    redactable: List[ScanFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    redacted_prompt: Optional[str] = None
    safe_output: str = ""

    files_scanned: int = 0
    prompt_tokens_scanned: int = 0
    egress_method: str = "faraday-originated"


def policy_action_for(finding: ScanFinding, policy: Policy) -> str:
    """Map a finding to the policy action for its category. Path denial always blocks."""

    if finding.type == "path":
        return "block"

    if finding.type == "secret":
        return policy.secrets.action

    if finding.type == "pii":
        return policy.pii.action

    if finding.type == "prompt_injection":
        return policy.prompt_injection.action

    if finding.type == "command_guard":
        return policy.commands.action

    return finding.recommended_action


def classify_findings(
    findings: List[ScanFinding],
    policy: Policy,
) -> Tuple[List[ScanFinding], List[ScanFinding], List[ScanFinding]]:
    """Classify findings into blocked, redactable, and warned groups per policy."""

    blocked: List[ScanFinding] = []
    redactable: List[ScanFinding] = []
    warned: List[ScanFinding] = []

    for finding in findings:
        action = policy_action_for(finding, policy)

        if action in BLOCK_ACTIONS:
            blocked.append(finding)
        elif action in REDACT_ACTIONS:
            redactable.append(finding)
        elif action in WARN_ACTIONS:
            warned.append(finding)

    return blocked, redactable, warned


def add_redaction_records_to_session(session, records: List[RedactionRecord]) -> None:
    """Attach redaction records to session findings using best-effort matching.

    The MVP matches by rule, line, and path/origin.
    """

    for record in records:
        finding_id = "unknown"

        for session_finding in session.findings:
            if (
                session_finding.rule == record.rule
                and session_finding.line == record.line
                and (
                    session_finding.path == record.path
                    or session_finding.source == record.origin
                )
            ):
                finding_id = session_finding.id
                break

        session.add_redaction(
            finding_id=finding_id,
            placeholder=record.placeholder,
            path=record.path,
            line=record.line,
        )


def run_wrap(
    *,
    command: List[str],
    policy: Policy,
    workdir: Optional[Path] = None,
    scan_repo: bool = False,
    execute: bool = False,
    max_files: int = 500,
    max_file_bytes: int = 1_000_000,
) -> WrapResult:
    """Run a protected wrapped command.

    Security behavior:
        - prompt is scanned
        - command is scanned by command guard
        - optional repository/workdir is scanned
        - blocking findings fail closed unless mode is observe-only
        - strict-local mode does not execute external processes
        - egress observations are explicitly labeled
    """

    if not command:
        raise ValueError("No command provided")

    chain = AuditChain()
    adapter = get_adapter(command)

    session = create_session_for_policy(policy, adapter.name or command[0])
    append_session_started(chain, session)

    chain.append(
        session_id=session.id,
        event="wrap_invocation",
        metadata={
            "adapter": adapter.name,
            "command_name": command[0],
            "args_count": len(command),
            "workdir": str(workdir) if workdir else None,
            "scan_repo": scan_repo,
            "execute": execute,
            "mode": policy.mode,
        },
    )

    prompt = adapter.extract_prompt(command) or ""
    session.prompt_tokens_scanned = len(prompt.split())

    findings: List[ScanFinding] = []
    warnings: List[str] = []

    prompt_findings: List[ScanFinding] = []

    if prompt:
        prompt_findings = scan_text(prompt, origin="prompt", policy=policy)
        findings.extend(prompt_findings)

    command_text = " ".join(command)
    command_findings = scan_command(command_text, origin="command", policy=policy)
    findings.extend(command_findings)

    for command_finding in command_findings:
        session.add_command_event(
            command=command[0],
            action="block",
            rule=command_finding.rule,
            reason="command_guard",
        )

    files_scanned = 0

    if scan_repo:
        target = workdir or Path.cwd()

        repo_result = scan_path(
            target,
            policy,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
        )

        findings.extend(repo_result.findings)
        files_scanned = repo_result.files_scanned
        session.files_scanned = files_scanned

        for scanned_file in repo_result.scanned_files:
            session.add_context_item(
                source="repository",
                path=scanned_file.path,
                content_hash=scanned_file.content_hash,
                size=scanned_file.size,
                classification=scanned_file.classification,
            )

    add_scan_findings(session, findings)
    append_findings(chain, session, findings)

    blocked, redactable, warned = classify_findings(findings, policy)

    operation_blocked = bool(blocked) and policy.mode != "observe-only"

    redacted_prompt = prompt

    if prompt and not operation_blocked:
        prompt_redactable = [
            finding for finding in redactable if finding.origin == "prompt"
        ]

        if prompt_redactable:
            redaction_result = redact_text(prompt, prompt_findings, mode="sensitive")

            redacted_prompt = redaction_result.redacted_text

            add_redaction_records_to_session(session, redaction_result.records)
            append_redactions(chain, session, redaction_result.records)

    model = MockLocalCoder()
    egress_method = "faraday-originated"
    safe_output = ""
    status = "completed"
    exit_code = 0

    if operation_blocked:
        safe_output = model.generate_blocked(blocked_count=len(blocked))

        session.add_model_event(
            backend_name=model.name,
            device_name="local",
            model_role="safe_response",
            status="blocked",
        )

        status = "blocked"
        exit_code = 1

    elif execute and policy.mode != "strict-local":
        egress_method = "not-measured"

        try:
            completed = subprocess.run(
                command,
                cwd=workdir,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            safe_output = f"Command not found: {command[0]}"
            status = "error"
            exit_code = 2
        except Exception as exc:
            safe_output = f"Command failed: {exc}"
            status = "error"
            exit_code = 3
        else:
            output_text = completed.stdout or completed.stderr

            output_findings = (
                scan_text(output_text, origin="output", policy=policy)
                if output_text
                else []
            )

            if output_findings:
                add_scan_findings(session, output_findings)
                append_findings(chain, session, output_findings)
                findings.extend(output_findings)

                output_blocked, output_redactable, _ = classify_findings(
                    output_findings,
                    policy,
                )

                if output_blocked and policy.mode != "observe-only":
                    safe_output = model.generate_blocked(
                        blocked_count=len(output_blocked)
                    )

                    session.add_model_event(
                        backend_name=model.name,
                        device_name="local",
                        model_role="output_guard",
                        status="output_blocked",
                    )

                    status = "blocked"
                    exit_code = 1
                else:
                    redaction_result = redact_text(
                        output_text,
                        output_findings,
                        mode="sensitive",
                    )

                    safe_output = redaction_result.redacted_text

                    add_redaction_records_to_session(
                        session,
                        redaction_result.records,
                    )
                    append_redactions(chain, session, redaction_result.records)

                    session.add_model_event(
                        backend_name="external-process",
                        device_name="subprocess",
                        model_role="output_sanitizer",
                        status="external_output_sanitized",
                    )

                    status = "completed"
                    exit_code = 0
            else:
                safe_output = output_text

                session.add_model_event(
                    backend_name="external-process",
                    device_name="subprocess",
                    model_role="external_tool",
                    status="executed",
                )

                status = "completed"
                exit_code = 0

    else:
        if execute and policy.mode == "strict-local":
            warnings.append(
                "--execute ignored in strict-local mode because external "
                "egress is denied by policy."
            )

        safe_output = model.generate(redacted_prompt or prompt)

        session.add_model_event(
            backend_name=model.name,
            device_name="local",
            model_role="coder",
            status="simulated",
        )

        status = "completed"
        exit_code = 0

    repo_unsanitized_redactions = any(
        finding.origin not in {"prompt", "output"} for finding in redactable
    )

    if repo_unsanitized_redactions:
        warnings.append(
            "Redactable findings exist in repository files. "
            "Sanitized workspace mode is not implemented in this MVP step. "
            "The safe output is simulated and no repository files were modified."
        )

    if policy.mode == "observe-only":
        warnings.append("observe-only mode reports findings but does not block.")

        if status == "completed" and findings:
            status = "degraded"

    if egress_method == "faraday-originated":
        egress_details = (
            "No external request was made by Faraday. Local/simulated path only."
        )
    else:
        egress_details = "External process executed. Egress was not measured in this MVP."

    session.add_egress_observation(
        method=egress_method,
        external_requests=0,
        bytes_sent=0,
        details=egress_details,
    )

    chain.append(
        session_id=session.id,
        event="policy_decision",
        metadata={
            "status": status,
            "mode": policy.mode,
            "blocked_findings": len(blocked),
            "redactable_findings": len(redactable),
            "warned_findings": len(warned),
            "files_scanned": files_scanned,
            "prompt_tokens_scanned": session.prompt_tokens_scanned,
            "egress_method": egress_method,
        },
    )

    finalize_session(
        chain,
        session,
        status=status,
        output_text=safe_output,
    )

    return WrapResult(
        status=status,
        exit_code=exit_code,
        adapter_name=adapter.name,
        session_id=session.id,
        findings=findings,
        blocked=blocked,
        redactable=redactable,
        warnings=warnings,
        redacted_prompt=redacted_prompt,
        safe_output=safe_output,
        files_scanned=files_scanned,
        prompt_tokens_scanned=session.prompt_tokens_scanned,
        egress_method=egress_method,
    )
