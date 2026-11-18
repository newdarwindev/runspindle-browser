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

**DURABLE WEBSITE EFFECTS** reserve an operation before submission and reconcile
uncertain results without blind retries. The journal admits at most 1,024
operations, bounds retained fields, and preserves duplicate/readback access at
capacity without eviction. [F07 acceptance](docs/F07_ACCEPTANCE.md) maps the
contract to actual SQLite, isolated HTTP/Chromium and Core/Temporal evidence.
These lanes use synthetic accounts and authority, not live account access.

## FROM A REQUEST TO A CHECKABLE OUTCOME

These are concrete product scenarios, not claims of live automation. The implemented contracts below support bounded parts of the journey; *italic text describes the remaining end-to-end behavior*.

### RESTORE THE INVOICE ACCOUNT, NOT AN ARBITRARY SIGNED-IN TAB

A bookkeeper returns to invoice #107 after sign-in expires. **BROWSER** binds credential use and control to the exact account, origin and session; its [passive status](specs/passive-control-status-v1.md) cannot grant input authority. *The completed journey will pause the invoice, let the operator authenticate in the same supported browser, verify the account and invoice context, and resume only after authenticated handback.* The outcome is continuity of the intended work, not a claim that a restored profile proves a valid login. [Concept slide 15](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle_Revised_Gallery.pdf#page=15).

### MATCH INVOICE #107 AND PRESERVE AN UNCERTAIN RESULT

An operator asks to match the invoice to its intended record rather than submit a second copy. **BROWSER'S GUARDED EFFECT JOURNAL** retains identity and unknown outcomes so a missing response does not become permission for a blind retry. *The live invoice adapter will verify the exact destination record independently and return a matched receipt or an unresolved exception, not infer success from a click.* [Effect contract](specs/guarded-effect-journal-v1.md) · [Concept slide 4](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle_Revised_Gallery.pdf#page=4).

### FIND A GENUINELY INDEPENDENT SUPPLIER

In the fictional Switchyard Components scenario, two backup distributors may depend on the same manufacturer. *An authorized workflow will compare the Terminal SPLC observation with ERP part identity and supplier-portal lot evidence, pause when the manufacturer is unconfirmed, and produce a quote draft for buyer approval. Delivery proof and the freight bill, not the draft, will establish the eventual business outcome.* **BROWSER** contributes scoped portal access and effect boundaries; it does not establish data rights or supplier independence by itself. [Catalog case 2](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/main/assets/runspindle_bloomberg_workflows.csv).

### AUDIT ROYALTY FX AGAINST THE CONTRACT'S FIXING

Lantern Film Receipts is a fictional example: a €80,000 royalty statement pays $87,200 while its named historical fixing implies $88,000. *The workflow will compare the exact fixing date and contract, reconcile deductions in the workbook and prepare an $800 dispute for approval. Only an accepted adjustment and matching cash receipt will establish recovery.* A live FX quote is not a substitute for the contracted fixing. **BROWSER** supplies account/origin-bound access, not authority to send the claim. [Catalog case 5](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/main/assets/runspindle_bloomberg_workflows.csv).

The Bloomberg examples use synthetic amounts. Entitled Terminal access, applicable BFIX/data-use rights, approved destination access and live integration remain prerequisites, not capabilities conferred by these scenarios.

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
