# 10. MCP — lm-provision-mcp

Status: specified (redesigned with dsl-kit-mcp). Layer 5.
Upstream deps: 01, 02, 07, 08, 09. MVP: Phase H.

## Purpose

The MCP server that exposes `lm-provision` and its profiles to AI clients and external orchestrators. Served as `lm-provision mcp` — a subcommand of the operator CLI, over stdio, which is the transport a client spawning a local server uses. Grounded in `dsl-kit-mcp`, it wraps the `ProfileNode` AST (chapter 01) and `DslHost` runtime to provide a debugger-grade MCP surface for profile generation, inspection, step execution, and pod provisioning.

## Tool Surface (`dsl-kit-mcp` + Provisioning Tools)

### 1. `dsl-kit-mcp` Debugger & AST Tools

By wrapping `ProfileNode` in `DslMcpHandler`, the server automatically exposes the standard `dsl-kit` debugger surface:

| tool | arguments | description |
|---|---|---|
| `load` | `text` string \| `json` object | Loads and validates a profile document into the session. |
| `ast` | — | Returns the structural AST representation (`ProfileNode`). |
| `schema` | — | Returns the exported `DslSchema` for LLM few-shot generation. |
| `step` | `count?` int \| `until?` string | Step-executes the profile evaluation / plan execution. |
| `breakpoint` | `action` ("add"\|"remove"\|"list"), `node_id?` string | Manages breakpoints prior to step execution. |
| `state` | — | Inspects current frame tree and variable env state. |

### 2. Pod Provisioning & Operator Tools

| tool | arguments | backing surface |
|---|---|---|
| `lm_validate` | `profile_path` string | 07 `validate` |
| `lm_hash` | `profile_path` string | 07 `hash` |
| `lm_plan` | `profile_path` string | 07 `plan` |
| `lm_apply` | `profile_path` string; `pod_id` string; `dry_run` bool | 08 upload / invoke / collect |
| `lm_machine_list` | `provider` string | 08 §Acquisitions and sweep, the listing half (read-only) |
| `lm_endpoint_list` | `acquisitions?` string; `forwards?` string; `endpoints_file?` string; `prices?` string | 09 §Endpoint inventory (read-only; the same reading as `machine endpoints`) |
| `lm_price_sync` | `provider` string; `prices?` string | 09 §Price record (writes the record) |
| `lm_cost` | `provider` string; `model` string; `usage` object; `usage_format?` string; `at?` string; `prices?` string | 09 §Cost (read-only) |
| `lm_ledger_list` | `pod_id?` string; `profile_hash?` string; `limit?` int | 09 ledger rows |
| `lm_ledger_get` | row locator | 09 single row |

## Error surface

- Precondition and validation errors are surfaced directly as typed `BuildError` / `Diagnostic` values.
- Step execution errors in `dsl-kit-core` yield observable suspensions or detailed frame backtraces.

## Stability

- Debugger tool surface (`dsl-kit-mcp` standard): **stable**.
- Pod provisioning tools: **stable once Phase H closes**.
