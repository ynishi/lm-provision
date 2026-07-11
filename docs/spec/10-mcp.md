# 10. MCP — lm-provision-mcp

Status: specified (contract for the Phase H build; wraps the frozen
07/08/09 surfaces). Layer 5. Upstream deps: 07, 08, 09.
MVP: Phase H.

## Purpose

The MCP server that exposes `lm-provision` to MCP clients — in
particular an external pod manager that delegates its provisioning
half to this server while keeping pod lifecycle on its own side
(chapter 08 provisioning boundary).

## Inputs

### Tool set (1 tool per CLI subcommand + driver-side reads)

| tool | arguments | backing surface |
|---|---|---|
| `lm_validate` | `profile_path` string | 07 `validate` |
| `lm_hash` | `profile_path` string | 07 `hash` |
| `lm_plan` | `profile_path` string | 07 `plan` |
| `lm_apply` | `profile_path` string; `pod_id` string; `dry_run` bool (default false) | 08 upload / invoke / collect |
| `lm_ledger_list` | `pod_id?` string; `profile_hash?` string; `limit?` int | 09 ledger rows, newest first |
| `lm_ledger_get` | row locator (server-assigned id) | 09 single row |

- `profile_path` is a path visible to the MCP server host; profile
  authoring/upload is out of scope (the profile file is the unit of
  exchange, chapter 01).
- `lm_apply` runs the full chapter 08 protocol against the pod named
  by `pod_id` and appends the ledger row on collect. Pod transport
  configuration (how the server reaches pods) is server deployment
  configuration, not tool arguments.
- Secrets: the MCP server process environment is the secret source
  (chapter 06 / 08 env-only delivery). Tool arguments never carry
  secret values; a tool call cannot inject env.

## Outputs

- `lm_validate` / `lm_plan`: the chapter 03 artifacts as structured
  tool results (JSON passthrough of the CLI stdout).
- `lm_hash`: `{ hash: "<64-hex>" }`.
- `lm_apply`: `{ report: <chapter 09 report>, exit_code: int,
  ledger_appended: bool }` — the report is returned even when apply
  failed (exit 1 + parseable report is the informative case,
  chapter 08).
- `lm_ledger_*`: chapter 09 ledger rows verbatim.

## Error surface

- Upstream errors propagate with class preserved: precondition
  (validate reject / missing secret env), runtime (failing step —
  returned inside the report, not as an MCP error), transport
  (chapter 08 upload/invoke/collect failures), ledger (chapter 09
  append failures reported via `ledger_appended = false` plus an
  MCP-level warning).
- MCP transport errors (malformed arguments, unknown tool) follow
  MCP conventions and never reach the pod.
- A tool call that fails before invoke leaves the pod untouched;
  failure semantics after invoke are chapter 08's.

## Stability

- Tool names and argument schemas: **stable once Phase H closes** —
  downstream integrations pin against them.
- Provisioning-boundary contract with the external pod manager (this
  server owns provisioning; the pod manager owns pod lifecycle and
  calls these tools): **stable**.
- `lm_ledger_*` row locator format: **provisional** until the ledger
  storage owner fixes it (chapter 09 physical encoding is internal).

## Upstream references

- chapter 07 CLI — subcommand surface and artifacts.
- chapter 08 push driver protocol — apply invocation, collect
  semantics, provisioning boundary.
- chapter 09 apply report + ledger — result and row shapes.

## MVP scope

Ships in Phase H: the six tools above over the Phase G subcommand +
driver + ledger set, and the external pod manager's binding against
them.
