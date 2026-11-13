# Desired intent: Scoped access and recoverable human exceptions

Status: engineering direction and acceptance obligations, not a new implementation
claim, grant of authority, or replacement for existing versioned contracts.

## System intent and evidence boundary

Runspindle is intended to turn an authorized one-off task into a repeatable,
maintained workflow by composing scoped access, managed native/browser sessions,
explicit human takeover, and evaluated workflow candidates. The useful capability
is the composition: cross-application execution can retain identity and evidence
across interruptions, while approved examples can inform later DSPy experiments.
This is a design objective, not evidence of emergent intelligence, autonomous
self-improvement, deployed integration, or measured gains.

A workflow revision must identify its inputs, permitted effects, target bindings,
exception policy, acceptance criteria and resource budget. Repetition does not
create a recurring schedule or expand permission. Human intervention is first an
execution event; only a separately reviewed, consented and sanitized example may
enter a dataset. A successful evaluation is evidence for review, not authority to
promote, serve, spend, publish or act in another account.

## Component responsibility

The browser boundary should make authorized website work possible without
turning a credential store into ambient agent authority. Account-isolated managed
sessions supply continuity across tasks only within explicit grants. Human
control is the exception path for interactive judgment or authentication, not a
way to bypass policy, collect secret demonstrations or claim broader autonomy.

## Interfaces and acceptance obligations

- Resolve secret references only inside trusted helpers bound to principal,
  account, approved origin, operation, browser instance and current lease epoch.
  Validate trusted top-level and frame origins immediately before secret use;
  redirects or mutable page content cannot retarget authority.
- Keep secrets, cookies, encrypted profile material and interactive control
  handles out of prompts, traces, receipts, screenshots and training exports.
  Encryption at rest does not make a profile safe to expose or reuse across users.
- Agent input and human interactive input must be mutually exclusive. Fence
  queued/in-flight commands before granting takeover; passive viewing has a
  separate read-only capability. A UI button alone is not evidence of fencing.
- Resume only after authenticated release, closure of viewer input, current epoch
  and fresh observations of the same account/target. Restart, timeout or viewer
  disconnect must not silently restore agent authority.
- Distinguish credential forgetting, profile deletion and target-site session
  revocation. Do not invent retention TTLs or imply vault rotation logs out sites.
- Validate wrong-account/origin denial, redirect races, stale leases, forged
  releases, interrupted takeover, restart and uncertain submission with synthetic
  secret canaries. Scan failure paths as well as successful receipts for leakage.

## Present scope

The component is a scaffold with inert historical references and synthetic fixture
consumers. OpenBao, PinchTab and KasmVNC integration, trusted origin observations,
distributed fencing and live acceptance are not established. The detailed
[credential and handoff contract](credentials-handoff.md) retains those boundaries.
