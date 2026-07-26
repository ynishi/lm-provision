# 01. Profile DSL surface

Status: specified (redesigned with dsl-kit). Layer 1.
Upstream deps: none. MVP: Phase F.

## Purpose

The profile definition surface that operators or AI clients write against. Grounded in `dsl-kit`, it defines how a profile document (in JSON or canonical text DSL format) is loaded, checked against the schema, built into a typed AST (`ProfileNode`), and evaluated.

## Core Schema Source of Truth (`dsl-kit`)

The profile AST is defined directly in Rust as a `dsl-kit` node enum (`ProfileNode`) using `#[derive(DslNode, DslSchema, DslBuild, DslExec)]`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, DslNode, DslSchema, DslBuild, DslExec)]
pub enum ProfileNode {
    /// Top-level Profile Spec.
    #[dsl_exec(seq)]
    Spec {
        id: NodeId,
        name: String,
        version: Option<String>,
        description: Option<String>,
        capabilities: Vec<String>,
        env: Vec<String>,
        env_secrets: Vec<String>,
        paths: Vec<String>,
        http_allowlist: Vec<String>,
        phases: Vec<ProfileNode>,
    },
    // Catalog phase variants defined in chapter 02 ...
}
```

This single declaration generates:
1. **DslSchema**: The structural schema representation consumed by validation and tooling.
2. **PEG Grammar**: Canonical text parser (`schema_gen::checked_grammar_from_schema_with`).
3. **JSON Bridge**: Serde-compatible JSON front-end (`serde_bridge::from_json_value`).
4. **Typed Builder**: Conformance-checked AST instantiation with fresh `NodeId` minting.
5. **AI Examples & MCP**: Machine-derived few-shot examples and MCP debugger interface (`dsl-kit-mcp`).

## Surface Formats

Profiles can be specified in two equivalent canonical formats that map to the identical `ParseTree` and `ProfileNode` AST.

### 1. Canonical Text Format (PEG Parser)

A human-readable, left-recursion-free canonical syntax generated directly from the schema:

```text
Spec(
    name: "vllm-pod",
    version: "1.0.0",
    capabilities: ["sh.exec", "net.transfer"],
    phases: [
        SystemApt(packages: "[\"git\", \"curl\", \"ffmpeg\"]"),
        PythonDeps(deps: "[\"torch\", \"vllm\"]", in_comfy_venv: false),
        PostInstall(script: "echo 'Setup complete!'")
    ]
)
```

### 2. JSON Format (Serde Bridge)

An AI-native JSON representation ideal for programmatic generation and tool integrations:

```json
{
  "type": "Spec",
  "name": "vllm-pod",
  "version": "1.0.0",
  "capabilities": ["sh.exec", "net.transfer"],
  "phases": [
    {
      "type": "SystemApt",
      "packages": ["git", "curl", "ffmpeg"]
    },
    {
      "type": "PythonDeps",
      "deps": ["torch", "vllm"],
      "in_comfy_venv": false
    },
    {
      "type": "PostInstall",
      "script": "echo 'Setup complete!'"
    }
  ]
}
```

## `Spec` fields

| field | type | required | default | rule |
|---|---|---|---|---|
| `name` | string | yes | — | non-empty |
| `version` | string | no | `"0.0.0"` | semver string |
| `description` | string | no | `nil` | — |
| `capabilities` | list\<string\> | no | `{}` | entries from `KNOWN_CAPABILITIES` (chapter 05 L4) |
| `env` | list\<string\> | no | `{}` | non-secret env name declaration (distinct from a phase's `env` keyed slot, below) |
| `env_secrets` | list\<string\> | no | `{}` | secret allowlist; every `EnvSecret` reference must name an entry here |
| `paths` | list\<string\> | no | `{}` | filesystem path root allowlist (chapter 05 §L3 path policy) |
| `http_allowlist` | list\<string\> | no | `{}` | HTTP URL pattern allowlist (chapter 05 §L3 HTTP policy) |
| `phases` | list\<ProfileNode\> | no | `{}` | phase nodes per chapter 02 |

Optional fields (`Option<T>` / list-typed) may be omitted on the wire
(dsl-kit ≥ 0.3 built-in mapping): an absent key binds to `None` /
empty list. Explicit `null` (JSON) / `none` (canonical text) / `[]`
remain accepted spellings of the same values.

The declared lists `capabilities`, `env`, `env_secrets`, `paths`,
and `http_allowlist` are **set-shaped** (declaration order is not
significant): the canonical encoder (chapter 03 §canonical) sorts them
lexicographically before hashing, so two profiles that differ only in
the order these entries were written yield the same profile hash.
Phase order is semantic and is preserved by canonical.

The profile hash (chapter 03 §hash) is **frontend-independent**: the
canonical text grammar and the JSON serde bridge that both build the
same `ProfileNode` AST produce byte-identical canonical output and
therefore the same hash, even though `NodeId`s minted by `IdGen`
differ between the two builds.

## Env keyed slots and value nodes

Phases that inject environment variables (`sh.exec`, `sync.pull`,
`staging.push` — chapter 02) carry an `env` field that is a **keyed
slot**: an ordered map from variable name to a *value node*, rather
than a scalar map. There are exactly two value nodes:

| node | meaning |
|---|---|
| `EnvLiteral { value }` | a plain string written in the profile |
| `EnvSecret { name }` | a reference to a host-environment secret, resolved at consumption time (chapter 06) |

Both are value nodes: they inhabit an `env` slot and never appear as a
top-level phase. `EnvSecret` carries the logical name only — there is
no field in which a secret value could be written, which is what makes
opacity a property of the shape (chapter 06 §The opacity contract).

JSON form:

```json
{
  "type": "ShExec",
  "argv": ["huggingface-cli", "whoami"],
  "env": {
    "HF_HUB_ENABLE_HF_TRANSFER": { "type": "EnvLiteral", "value": "1" },
    "HF_TOKEN": { "type": "EnvSecret", "name": "HF_TOKEN" }
  }
}
```

Canonical text form — braces distinguish a keyed slot from the
bracketed list idiom; a key is written bare when it is an identifier
and quoted otherwise:

```text
ShExec(
    argv: ["huggingface-cli", "whoami"],
    env: {
        HF_HUB_ENABLE_HF_TRANSFER: EnvLiteral(value: "1"),
        HF_TOKEN: EnvSecret(name: "HF_TOKEN")
    }
)
```

An omitted `env` binds to the empty map. Key order is not significant:
the slot is stored ordered by key, and canonical (chapter 03) emits it
in that order, so two profiles differing only in the order env entries
were written hash identically.

Representing env as a keyed slot of nodes — rather than a JSON string
field, a list of pairs, or a scalar map — is what lets the schema, the
grammar, validate, and canonical all see *inside* the value: validate
cross-checks each `EnvSecret` name against `env_secrets`, and canonical
encodes it as the `{"__secret":"NAME"}` marker. `dsl-kit`'s
`Multiplicity::Map` supports self-recursive node values, which is
exactly this shape; a map of *scalar* values is not yet supported
upstream, which is why the value side is a node rather than a string.

## Escape / Fragment Policy

- **Inner escape**: `PostInstall` carries an arbitrary shell `script` string (chapter 02). This is the single sanctioned place for raw shell inside a profile.
- **Outer escape / Code Generation**: Fragment reuse and dynamic composition are performed by external tools (e.g. Python scripts or AI tools) generating JSON/Text profiles against the exported `DslSchema`. The DSL vocabulary is not grown for templating or scripting constructs.

## Output AST (`ProfileNode::Spec`)

Parsing produces a fully typed `ProfileNode::Spec` instance where:
- Every node carries a unique `NodeId` assigned by `IdGen`.
- The AST is ready for direct evaluation via `dsl-kit-core`'s engine / stepper or pipeline transformation.

## Stability

- `ProfileNode` Rust enum structure and `DslSchema` contract: **stable**.
- Canonical PEG text syntax & JSON bridge shapes: **stable**.
