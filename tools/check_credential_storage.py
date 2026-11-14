#!/usr/bin/env python3
"""Fail-closed SRC-006 accounting checks, not semantic or live acceptance."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = "docs/credential-storage/coverage.json"
MANIFEST = "docs/credential-storage/artifact-manifest.json"
GUIDE = "docs/credential-storage/README.md"
SPEC = "specs/credentials-handoff.md"
REQUIRED: dict[str, list[str]] = {
    "S01": ["save_permission", "use_permission", "no_values"],
    "S02": ["no_activation", "separate_evidence"],
    "R01": ["reference", "isolation", "observed_account"],
    "R02": ["principal", "account", "operation", "session", "lease", "before_read"],
    "R03": ["top_origin", "frame_origin", "before_read", "at_use", "invalidate"],
    "R04": ["helper", "temporal_fields", "tokens_cookies_profiles", "all_outcomes"],
    "R05": ["version", "refresh", "restart", "independent_status"],
    "R06": ["deny", "sanitized_errors", "no_fallback", "uncertainty"],
    "B01": ["endpoints", "redirects", "paths", "identity"],
    "B02": ["authentication", "transport", "custody", "no_configuration"],
    "B03": ["root_material", "personal_secrets", "public_boundary"],
    "A01": ["zero_reads", "zero_injections"],
    "A02": ["origin_race", "cleanup", "limits"],
    "A03": ["success", "failure", "audit_gap"],
    "A04": ["future_resolution", "stale_generation", "site_status"],
    "A05": ["fetch_denied", "site_independent", "unknown"],
    "A06": ["outage", "expiry", "reference", "redirect", "no_upstream_claim"],
    "E01": [
        "trusted_adapter",
        "identity",
        "outage_rotation",
        "audit",
        "separate_acceptance",
    ],
    "X01": ["safe_replacement"],
    "X02": ["safe_replacement"],
    "X03": ["safe_replacement"],
    "X04": ["safe_replacement"],
    "X05": ["safe_replacement"],
    "X06": ["safe_replacement"],
    "X07": ["safe_replacement"],
    "X08": ["safe_replacement"],
}
CASES: dict[str, list[str]] = {
    "S01": [],
    "S02": [],
    "R01": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_wrong_bindings_deny_before_read"
    ],
    "R02": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_wrong_bindings_deny_before_read",
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_invalid_grants_and_expired_identity_deny_before_read",
    ],
    "R03": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_unavailable_forged_stale_and_future_observations",
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_redirect_after_read_and_during_version_check",
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_stale_epoch_after_read_blocks_injection",
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_cancellation_releases_handle_and_fence",
    ],
    "R04": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_success_is_sanitized_and_once",
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_faults_cleanup_and_no_retry",
        "tests/test_synthetic_vault.py::SyntheticVaultTests.test_outage_denial_timeout_malformed_are_sanitized",
    ],
    "R05": [
        "tests/test_synthetic_vault.py::SyntheticVaultTests.test_vault_changes_during_second_observation_deny_injection",
        "tests/test_synthetic_vault.py::SyntheticVaultTests.test_identity_expiry_rotation_forgetting_are_distinct",
    ],
    "R06": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_faults_cleanup_and_no_retry",
        "tests/test_openbao.py::OpenBaoTests.test_default_and_wrong_scope_deny_before_token_or_http",
    ],
    "B01": [],
    "B02": [],
    "B03": [],
    "A01": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_wrong_bindings_deny_before_read"
    ],
    "A02": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_redirect_after_read_and_during_version_check",
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_stale_epoch_after_read_blocks_injection",
    ],
    "A03": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_success_is_sanitized_and_once",
        "tests/test_synthetic_vault.py::SyntheticVaultTests.test_outage_denial_timeout_malformed_are_sanitized",
    ],
    "A04": [
        "tests/test_synthetic_vault.py::SyntheticVaultTests.test_vault_changes_during_second_observation_deny_injection",
        "tests/test_storage_lifecycle.py::StorageLifecycleTests.test_rotation_does_not_delete_profile_or_revoke_site",
    ],
    "A05": [
        "tests/test_storage_lifecycle.py::StorageLifecycleTests.test_forgetting_operations_are_independent",
        "tests/test_storage_lifecycle.py::StorageLifecycleTests.test_uncertain_site_result_is_not_revoked",
    ],
    "A06": [
        "tests/test_trusted_credentials.py::TrustedCredentialsTests.test_invalid_grants_and_expired_identity_deny_before_read",
        "tests/test_synthetic_vault.py::SyntheticVaultTests.test_outage_denial_timeout_malformed_are_sanitized",
    ],
    "E01": [],
    "X01": [],
    "X02": [],
    "X03": [],
    "X04": [],
    "X05": [],
    "X06": [],
    "X07": [],
    "X08": [],
}
FILES: dict[str, str] = {
    "docs/credential-storage/coverage.json": "adapted_requirement_accounting",
    "docs/credential-storage/README.md": "adapted_review_documentation",
    "specs/credentials-handoff.md": "adapted_specification",
    "browser_testing/storage.py": "synthetic_specification_model",
    "tests/test_storage_lifecycle.py": "synthetic_tests",
    "tests/test_credential_storage.py": "artifact_checker_regression_tests",
    "tools/check_credential_storage.py": "structural_artifact_checker",
    "tools/validate.py": "existing_validation_entrypoint",
    "provenance.json": "public_provenance",
    "browser_testing/vault.py": "existing_synthetic_model",
    "tests/test_synthetic_vault.py": "existing_synthetic_tests",
    "tests/test_trusted_credentials.py": "existing_synthetic_adapter_tests",
    "tests/test_openbao.py": "existing_protocol_double_tests",
}


class Invalid(ValueError):
    """Only fixed diagnostics are exposed to callers."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def safe_file(root: Path, name: str) -> Path:
    require(type(name) is str and bool(name), "invalid artifact path")
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and str(path) == name
        and all(part not in {".", ".."} for part in path.parts)
        and "\\" not in name,
        "unsafe artifact path",
    )
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), "symlink artifact forbidden")
    require(current.is_file(), "artifact missing")
    require(current.resolve().is_relative_to(root.resolve()), "artifact escaped root")
    return current


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(root: Path, name: str) -> dict[str, Any]:
    data = json.loads(
        safe_file(root, name).read_text(), object_pairs_hook=no_duplicates
    )
    require(type(data) is dict, "JSON object required")
    return dict(data)


def check_case(root: Path, case: str) -> None:
    file, separator, symbol = case.partition("::")
    require(bool(separator) and file in FILES, "invalid test reference")
    parts = symbol.split(".")
    require(len(parts) == 2 and parts[1].startswith("test_"), "invalid test symbol")
    tree = ast.parse(safe_file(root, file).read_text())
    found = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == parts[0]
    ]
    require(len(found) == 1, "test class missing or duplicated")
    methods = [
        node
        for node in found[0].body
        if isinstance(node, ast.FunctionDef) and node.name == parts[1]
    ]
    require(len(methods) == 1, "test method missing or duplicated")


def validate(root: Path = ROOT) -> dict[str, Any]:
    coverage = read_json(root, COVERAGE)
    require(
        set(coverage)
        == {
            "schema_version",
            "source_id",
            "scope",
            "units",
            "issue_extensions",
            "unresolved_exclusions",
            "runtime_acceptance",
        },
        "coverage fields changed",
    )
    require(
        type(coverage["schema_version"]) is int and coverage["schema_version"] == 1,
        "invalid schema",
    )
    require(coverage["source_id"] == "SRC-006", "wrong source")
    require(coverage["scope"] == "one_selected_specification", "scope inflated")
    require(coverage["runtime_acceptance"] == "not_run", "acceptance inflated")
    require(coverage["unresolved_exclusions"] == [], "unresolved source exclusions")
    require(
        coverage["issue_extensions"] == ["P01", "P02", "P03"],
        "issue extensions missing",
    )
    rows = coverage["units"]
    require(
        type(rows) is list and len(rows) == len(REQUIRED), "source inventory changed"
    )
    seen: set[str] = set()
    for row in rows:
        require(type(row) is dict, "invalid source row")
        require(
            set(row)
            == {
                "id",
                "title",
                "disposition",
                "reason",
                "obligations",
                "cases",
                "target",
                "implementation_evidence",
            },
            "source row fields changed",
        )
        unit = row["id"]
        require(
            type(unit) is str and unit in REQUIRED and unit not in seen,
            "source unit missing or duplicated",
        )
        seen.add(unit)
        excluded = unit.startswith("X")
        require(
            row["disposition"] == ("excluded" if excluded else "adapted"),
            "source disposition changed",
        )
        for key in ("title", "reason"):
            require(
                type(row[key]) is str and len(row[key].strip()) >= 12,
                "source review explanation missing",
            )
        require(
            row["obligations"] == REQUIRED[unit], "source obligation inventory changed"
        )
        require(row["cases"] == CASES[unit], "synthetic evidence mapping changed")
        require(
            row["implementation_evidence"] == "not_established_by_source_coverage",
            "source coverage claimed as implementation",
        )
        target = GUIDE if excluded else SPEC
        require(
            row["target"] == target + "#" + unit.lower(), "source destination changed"
        )
        body = safe_file(root, target).read_text()
        anchor = '<a id="' + unit.lower() + '"></a>'
        require(body.count(anchor) == 1, "source anchor missing or duplicated")
        section = body.split(anchor)[1].split('<a id="')[0]
        require(len(section.strip()) > 100, "source disposition section empty")
        if not excluded:
            require(
                "Obligations: " + ", ".join(REQUIRED[unit]) + "." in section,
                "documented obligations missing",
            )
        for case in row["cases"]:
            check_case(root, case)
    require(seen == set(REQUIRED), "source inventory incomplete")
    for extension in ("P01", "P02", "P03"):
        require(
            "## " + extension + " " in safe_file(root, SPEC).read_text(),
            "extension section missing",
        )

    provenance = read_json(root, "provenance.json")
    records = [
        record for record in provenance["sources"] if record["source_id"] == "SRC-006"
    ]
    require(len(records) == 1, "source provenance missing or duplicated")
    source = records[0]
    require(source["status"] == "adapted_spec", "wrong source classification")
    require(
        source["selected_artifact_status"]
        == "complete_accounting_with_resolved_exclusions",
        "source completion missing",
    )
    require(
        source["migration_status"] == "selected_artifact_complete_overall_partial",
        "global migration inflated",
    )
    require(
        source["artifact_manifest"] == MANIFEST and source["coverage"] == COVERAGE,
        "provenance mapping changed",
    )
    require(source["runtime_acceptance"] == "not_run", "provenance acceptance inflated")
    status = read_json(root, "STATUS.json")
    require(
        status["selected_source_migration"] == "partial"
        and status["live_acceptance"] == "not_run",
        "product status inflated",
    )

    manifest = read_json(root, MANIFEST)
    require(
        set(manifest)
        == {
            "schema_version",
            "source_id",
            "evidence_class",
            "selected_artifact_status",
            "source_review",
            "historical_import",
            "runtime_acceptance",
            "files",
        },
        "manifest fields changed",
    )
    require(
        type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
        "invalid manifest schema",
    )
    require(manifest["source_id"] == "SRC-006", "wrong manifest source")
    require(
        manifest["evidence_class"] == "specification_source_accounting",
        "manifest evidence inflated",
    )
    require(
        manifest["selected_artifact_status"] == source["selected_artifact_status"],
        "manifest status disagrees",
    )
    require(
        manifest["source_review"]
        == "author_review_complete_independent_review_required_before_publication",
        "review claim changed",
    )
    require(
        manifest["historical_import"] == "none"
        and manifest["runtime_acceptance"] == "not_run",
        "manifest acceptance inflated",
    )
    files = manifest["files"]
    require(
        type(files) is dict and set(files) == set(FILES),
        "manifest file inventory changed",
    )
    for name, classification in FILES.items():
        record = files[name]
        require(
            type(record) is dict and set(record) == {"classification", "sha256"},
            "invalid artifact record",
        )
        require(
            record["classification"] == classification,
            "artifact classification changed",
        )
        require(
            type(record["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None,
            "invalid artifact hash",
        )
        require(
            hashlib.sha256(safe_file(root, name).read_bytes()).hexdigest()
            == record["sha256"],
            "artifact digest mismatch",
        )

    # Reject private locators in public accounting. This is a bounded backstop,
    # not a claim to detect every possible secret or sensitive fact.
    for name in (COVERAGE, MANIFEST, GUIDE, SPEC):
        body = safe_file(root, name).read_text()
        require(
            not re.search(
                r"/(?:workspace|home|Users)/|file://|https://github\.com/[^/]+/dots-",
                body,
            ),
            "private locator in public artifact",
        )
    return {
        "status": "passed",
        "source_id": "SRC-006",
        "evidence_class": "specification_source_accounting",
        "adapted_units": 18,
        "resolved_exclusions": 8,
        "files": len(FILES),
        "runtime_acceptance": "not_run",
    }


def main() -> None:
    try:
        result = validate()
        result["commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        result["manifest_sha256"] = hashlib.sha256(
            safe_file(ROOT, MANIFEST).read_bytes()
        ).hexdigest()
    except (
        Invalid,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        SyntaxError,
        subprocess.CalledProcessError,
    ):
        print(
            json.dumps(
                {
                    "status": "failed",
                    "evidence_class": "specification_source_accounting",
                    "runtime_acceptance": "not_run",
                },
                sort_keys=True,
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
