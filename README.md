# BROWSER — SCOPED ACCESS, CONTINUITY AND HUMAN CONTROL

Keep the account, the operation and the current controller together.

**Status: Bounded browser components and local integration evidence; no deployed or production-ready system.**

Normal text describes implemented boundaries; *italic text marks upcoming work or qualification*. Neither is permission to activate services or use live accounts.

## BROWSER CONNECTS THE ACCOUNT TO THE AUTHORIZED OPERATION

**BROWSER** implements bounded credential-resolution, control-lease, guarded-effect and encrypted-profile components. Account, origin, native-session and lease identities remain explicit. A stored credential reference or a previously observed control state is not a new grant of authority.

OpenBao supplies the selected credential and key-management foundation; PinchTab supplies browser interaction. **BROWSER** supplies the account/origin checks, reference-only outcomes, control fencing and recovery semantics around those upstream capabilities. The existing [OpenBao adapter](specs/openbao-kv-adapter.md), [trusted resolver](specs/trusted-credential-resolver.md) and [guarded effect journal](specs/guarded-effect-journal-v1.md) document exactly where local verification ends.

**PROFILE CONTINUITY** uses real local SQLite transactions, AES-GCM encryption and filesystem capture/materialization in bounded tests with synthetic authority and provider fixtures. [Profile component composition](specs/profile-component-integration.md) preserves unknown outcomes and separates key access, ciphertext retention, plaintext cleanup and forgetting. This is not proof that a real website session restores safely.

**PASSIVE CONTROL STATUS** reads scoped durable metadata without issuing an input handle or changing control. [Observation admission](specs/passive-control-status-v1.md) is separate from takeover, credentials and browser actions. KasmVNC remains the selected viewing route for supported desktops, not a capability provided by this status API.

*Upcoming qualification joins production OpenBao access, actual PinchTab lifecycle, real browser checkpointing, supported KasmVNC viewing and authenticated human takeover/handback. Live account and native-browser acceptance remain open; local profile tests do not close them.*

## ENGINEERING MAP

| Responsibility | Contract and evidence |
| --- | --- |
| Scoped credentials | [Resolver](specs/trusted-credential-resolver.md) · [Evidence](docs/trusted-credential-evidence.json) |
| Current control | [Leases](specs/control-leases-v1.md) · [Passive status](specs/passive-control-status-v1.md) |
| Unknown external effects | [Guarded journal](specs/guarded-effect-journal-v1.md) |
| Profile retention and recovery | [Encrypted store](specs/encrypted-profile-store-v1.md) · [Directory](specs/profile-directory-v1.md) · [Key custody](specs/profile-key-custody-v1.md) |

## VISUAL STORY AND PRODUCT CONTEXT

[![Conceptual sign-in expired during invoice #107; not a runtime screenshot](https://newdarwindev.github.io/runspindle_for_bloomberg/gallery/15.webp)](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle_Gallery_Index.html#page-15)

**Conceptual illustration, not implementation evidence:** “Sign-in expired during invoice #107,” gallery page 15. The asset remains hosted by the [Runspindle for Bloomberg source library](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/a109172363736d4312d303e292f8c0d3a857e394/ASSETS.md); it is linked here, not copied or relicensed. The gallery uses fictional businesses and synthetic values. No Bloomberg affiliation, endorsement, live integration or measured savings is implied.

- [Open the exact slide in the 37-page gallery](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle_Revised_Gallery.pdf#page=15) · [Original 29-page UI gallery](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle-UI-gallery.pdf).
- [Product concept: 16-page brief](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/a109172363736d4312d303e292f8c0d3a857e394/assets/runspindle_bloomberg_product.pdf) · [40 proposed workflow scenarios](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/a109172363736d4312d303e292f8c0d3a857e394/assets/runspindle_bloomberg_workflows.csv).
- [Research proposal: maintained workflows under explicit authority](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/a109172363736d4312d303e292f8c0d3a857e394/assets/runspindle-paper.pdf) · [Full-cost model, not measured savings](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/a109172363736d4312d303e292f8c0d3a857e394/economics/README.md).

These materials explain the product thesis: useful work should leave a checkable record. Their conceptual scenes do not supersede this repository's implementation evidence or acceptance gates.

## DEVELOPMENT AND ACCEPTANCE

This repository is one boundary of [Runspindle](https://github.com/newdarwindev/runspindle). Repository boundaries do not require one microservice each.

- Read [specifications](specs/README.md), [agent guidance](AGENTS.md), [provenance](provenance.json), [status](STATUS.json) and [legal status](LEGAL.md).
- Run `python3 tools/check_scaffold.py` for structural validation only.
- Operational entrypoints and acceptance gates deliberately fail closed until implemented.
- GitHub Actions use isolated **self-hosted local runners only**. No GitHub-hosted fallback. Runner capacity is not established by publishing workflows.
- No credentials, real sessions, messages, datasets, browser profiles or live host inventory belong here.

No old repository is retired by this scaffold. Migration and archival are separate verified gates.

Selected historical code is preserved as [inert migration references](docs/reference/README.md). It is not installed or executed.

New conceptual documentation is in [docs/product](docs/product/README.md). These HTML pages are conceptual adaptations; browser visual QA and runtime acceptance are not established.

## Implemented validation

Run `python3 tools/validate.py` for all implemented structural, language, fixture, artifact and mutation checks in this repository. The same entrypoint runs on trusted `main` and `ci/*` pushes and manual qualification using disposable Strix x64 guests. Logs include the checkout SHA, image/tool identities, command results and applicable artifact checksums. Unimplemented builds and product acceptance remain explicit in `STATUS.json`; blocked acceptance workflows retain their failing conclusions. ARM64 and native macOS qualification remain pending.


Read [the component-specific technical intent](specs/desired-intent.md) for interfaces, privacy boundaries and acceptance obligations.
