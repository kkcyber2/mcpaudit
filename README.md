# mcpaudit

A tamper-evident audit log for agent tool calls.

When an agent is allowed to send email, write files, or move money, the log of
*what it did and why it was allowed* is the only thing an auditor can check. A
plain append-only file is not enough: whoever runs the agent can rewrite it.

This stores every decision as a leaf in an RFC 6962-style Merkle tree, so a
reviewer holding only a small signed tree head can confirm that a given entry is
in the log, and detect any entry that was altered after the fact.

```bash
pip install -e ".[dev]"

mcpaudit append log.json --kind call-blocked --subject rm_rf \
  --decision deny --reason "no rule allows this tool"
mcpaudit head   log.json
mcpaudit verify log.json
mcpaudit prove  log.json 1
```

```
OK: all 3 entr(ies) prove into head ce5edbb329ea...
```

## Deny by default

`Gate` is the policy layer. Nothing is callable unless a rule names it or a
human approved it:

```python
from mcpaudit import AuditLog, Gate

gate = Gate(AuditLog())
gate.add_rule("read_*", "allow")
gate.approve("send_email", digest="sha256:9f2c...")

gate.check("read_file")                    # allowed by rule
gate.check("delete_bucket")                # denied, no rule
gate.check("send_email", digest="sha256:1a44...")   # denied: definition changed
```

Every call — allowed or not — is written to the log with its reason.

## The two design decisions that matter

**Domain separation.** Leaves hash as `SHA256(0x00 || data)` and interior nodes as
`SHA256(0x01 || left || right)`. Without the distinct prefixes, an attacker can
present a single leaf whose *content* is two concatenated hashes and produce a
root identical to a two-leaf tree — the second-preimage attack that makes a log
rebuildable. `test_a_crafted_leaf_cannot_collide_with_an_interior_node` pins this.

**Approval binds to the definition, not the name.** An agent that was approved to
call `read_file` must not silently inherit approval when `read_file` is replaced
with something that reads `~/.ssh`. The gate stores a digest at approval time and
blocks when the digest changes. This is the change-detection gap behind most
tool-poisoning incidents.

## Rules are first-match

```python
gate.add_rule("read_secret", "deny")   # must come first
gate.add_rule("read_*", "allow")
```

Order is the override mechanism, stated plainly in the docs and covered by a test
that asserts an allow placed *before* a deny does not win. If you want the deny to
be absolute, put it first.

## Verifying without the log

`verify_inclusion(index, size, data, proof, root_hex)` is a pure function. An
auditor can run it against a tree head published anywhere, with an inclusion proof
exported by `prove`, and confirm the entry without ever touching the log file:

```python
from mcpaudit import verify_inclusion

verify_inclusion(1, 3, event_bytes, proof, root_hex)   # -> True
```

A forged sibling, a truncated proof, a wrong index, a non-hex or wrong-length
entry, and a mismatched root all return `False` rather than raising — a verifier
must answer "no", not crash.

## Tests

```bash
python3 -m pytest -v
```

83 tests. Proofs are checked exhaustively for tree sizes 1–9, 15–17 and 33, so the
unbalanced-node handling is exercised rather than assumed.

## Limits

- No signing of tree heads. Publish the head somewhere you trust (a repo commit, a
  transparency log, a customer-facing status page) — this tool gives you the hash,
  not the witness.
- No persistent store; `to_json`/`replay` are the storage interface, so durability
  and replication are yours.
- Timestamps come from the local clock. A hostile operator can backdate entries
  that were never appended; the tree proves *consistency*, not *when*.

## Licence

MIT. Copyright (c) 2026 Konain Sultan Khan.
