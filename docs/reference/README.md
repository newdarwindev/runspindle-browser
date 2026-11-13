# Historical browser references

These two inert `.py.txt` files preserve selected legacy prototype logic for review while Runspindle targets Rust integrations. They are not installed, imported, served or called by this scaffold. Source IDs resolve to the private source record; no private repository location is published here. Original rights remain unchanged.

| Reference | Retained behavior | Runspindle adaptation and unresolved work |
|---|---|---|
| `openbao-resolver.py.txt` | Constrained KV references, explicit loopback endpoint, redirect refusal, narrow provider boundary | Replace prototype loopback authentication with reviewed central OpenBao workload identity and TLS. Verify principal/account/origin/operation/current lease before retrieval and again at injection. Mounted-file resolution is historical, not a production fallback. |
| `fixture-gateway.py.txt` | Account/controller checks, leased command path, takeover, bounded viewer closure and verified handback hooks | Add persistent epochs and distributed authority; separate read-only viewing from interactive control; authenticate release; verify actual origins and redact backend responses. Existing fixture server must never be exposed as a production gateway. |

The historical gateway imports supporting controller and handback modules. Those modules are not included or claimed to have been independently selected for migration. These inert references are deliberately not a runnable dependency bundle. The new service must satisfy [credentials and handoff](../../specs/credentials-handoff.md), including failure and secret-canary tests.

Validation here covers preservation and Python syntax only, without imports or execution. It does not qualify OpenBao, PinchTab, KasmVNC, live credentials, recovery or production origin enforcement.
