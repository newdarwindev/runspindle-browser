"""Pure specification model with invented identities and status flags only.

Grant/observation arguments are trusted test configuration, NOT authentication.
No secrets, profile bytes, encryption, provider calls, persistence or deletion
are implemented. This is not a runtime authority or credential store.
"""

from dataclasses import dataclass, replace

from browser_testing.vault import Denied, Scope

ACTIONS = frozenset(
    {
        "forget_credentials",
        "forget_profile",
        "revoke_site",
        "rotate",
        "expire_cookie",
        "terminate_browser",
    }
)


@dataclass(frozen=True)
class StorageState:
    credentials_present: bool = True
    profile_present: bool = True
    site_status: str = "active"
    browser_running: bool = True
    credential_generation: int = 1


class StorageModel:
    """One selected synthetic account; no clock-driven retention policy."""

    def __init__(self, scope: Scope) -> None:
        scope.validate()
        self.scope = scope
        self.state = StorageState()

    def apply(
        self,
        action: str,
        grant: Scope | None,
        observed: Scope | None,
        *,
        site_result: str = "unknown",
    ) -> str:
        """Require an exact modeled operation/target/epoch before any transition.

        Site outcome is injected readback in this model, never a real assertion
        of logout. Unknown is the default and never silently becomes revoked.
        """
        if action not in ACTIONS:
            raise Denied("synthetic storage denied")
        expected = replace(self.scope, operation=action)
        if type(grant) is not Scope or type(observed) is not Scope:
            raise Denied("synthetic storage denied")
        if grant != expected or observed != expected:
            raise Denied("synthetic storage denied")
        state = self.state
        if action == "forget_credentials":
            self.state = replace(
                state,
                credentials_present=False,
                credential_generation=state.credential_generation + 1,
            )
        elif action == "forget_profile":
            self.state = replace(state, profile_present=False)
        elif action == "revoke_site":
            if site_result not in {"revoked", "unknown", "failed"}:
                raise Denied("synthetic storage denied")
            if site_result == "failed":
                return "failed"
            self.state = replace(state, site_status=site_result)
            return site_result
        elif action == "rotate":
            if not state.credentials_present:
                raise Denied("synthetic storage denied")
            self.state = replace(
                state, credential_generation=state.credential_generation + 1
            )
        elif action == "expire_cookie":
            self.state = replace(state, site_status="expired")
        elif action == "terminate_browser":
            self.state = replace(state, browser_running=False)
        return "completed"
