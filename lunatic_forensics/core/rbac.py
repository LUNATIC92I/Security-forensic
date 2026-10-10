"""Role based access control."""
from __future__ import annotations

from enum import Enum

from .errors import PermissionDenied


class Role(str, Enum):
    ADMIN = "admin"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class Perm(str, Enum):
    MANAGE_USERS = "manage_users"
    CREATE_CASE = "create_case"
    EDIT_CASE = "edit_case"
    VIEW_CASE = "view_case"
    MANAGE_MEMBERS = "manage_members"
    IMPORT_EVIDENCE = "import_evidence"
    ACQUIRE_DEVICE = "acquire_device"
    VIEW_ARTIFACTS = "view_artifacts"
    RUN_ANALYSIS = "run_analysis"
    WRITE_FINDINGS = "write_findings"
    GENERATE_REPORT = "generate_report"
    VIEW_AUDIT = "view_audit"
    VERIFY_INTEGRITY = "verify_integrity"
    BACKUP = "backup"
    VIEW_ALL_CASES = "view_all_cases"


ROLE_PERMISSIONS: dict[Role, frozenset[Perm]] = {
    Role.ADMIN: frozenset(Perm),
    Role.INVESTIGATOR: frozenset({
        Perm.CREATE_CASE, Perm.EDIT_CASE, Perm.VIEW_CASE, Perm.MANAGE_MEMBERS,
        Perm.IMPORT_EVIDENCE, Perm.ACQUIRE_DEVICE, Perm.VIEW_ARTIFACTS,
        Perm.RUN_ANALYSIS, Perm.WRITE_FINDINGS, Perm.GENERATE_REPORT,
        Perm.VERIFY_INTEGRITY, Perm.VIEW_AUDIT,
    }),
    Role.ANALYST: frozenset({
        Perm.VIEW_CASE, Perm.VIEW_ARTIFACTS, Perm.RUN_ANALYSIS,
        Perm.WRITE_FINDINGS, Perm.GENERATE_REPORT, Perm.VERIFY_INTEGRITY,
    }),
    # Auditors review custody & integrity; they do not read evidence content.
    Role.AUDITOR: frozenset({
        Perm.VIEW_CASE, Perm.VIEW_AUDIT, Perm.VERIFY_INTEGRITY, Perm.VIEW_ALL_CASES,
    }),
}


def has_perm(role: Role | str, perm: Perm) -> bool:
    return perm in ROLE_PERMISSIONS[Role(role)]


def require(role: Role | str, perm: Perm) -> None:
    if not has_perm(role, perm):
        raise PermissionDenied(f"Role '{Role(role).value}' is not allowed to perform '{perm.value}'.")
