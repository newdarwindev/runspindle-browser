# Bounded local control-lease storage

`LeaseStore` retains at most 1,024 browser ownership records. A new browser is
rejected at capacity before any backend fence callback. Existing holders may
still perform otherwise authorized transitions or reconciliation; capacity never
evicts an old epoch or permits a fresh initialization of retained ownership.
The check and insertion share SQLite's immediate writer transaction, including
when separate processes compete for the final slot.

Before materializing a retained row, SQL checks the bounded row count, types and
UTF-8 byte lengths: browser 128 bytes, scope 16 KiB, holder 256 bytes, transition
32 KiB, positive integer epoch and exact active/pending phase. Admission bounds
schema inventory to 16 entries and schema text to 16 KiB before returning it to
Python. The existing exact schema/application/version checks remain unchanged.
Oversized or overfull stores fail closed without repair. New encoded scope and
transition values are bounded before reservation. These are logical row/value
bounds, not a filesystem quota or guarantee against hostile SQLite files or
storage-device power loss.

Run the focused synthetic tests from the repository root:

```sh
PYTHONPATH=tests python3 -m unittest test_control_capacity test_control_leases test_control_reconciliation test_passive_control_status test_lease_credentials
PYTHONPATH=tests python3 -O -m unittest test_control_capacity test_control_leases test_control_reconciliation test_passive_control_status test_lease_credentials
```

The new capacity tests use actual SQLite and a separate file-backed fence ledger.
They cover full-store existing transitions, zero new fences on overflow,
oversized retained JSON before selected-row materialization, unchanged rejected
files, a fresh-process last-slot race and a deliberate capacity mutation that
produces the forbidden extra fence. Backend and authenticated observations are
synthetic: this does not qualify real browser/viewer fencing or live authority.
Browser #9/#16 remain open pending their complete acceptance and dependencies.
