# lm-provision

Universal GPU / LLM Infrastructure Profile DSL — spec-first redesign.

Declarative profile description for provisioning LLM-capable compute on
RunPod / Colab / Pulumi-managed clouds / local. Lua DSL surface + Rust
host + pluggable backends.

## Status

Spec-first redesign of the working `lm-provision POC` POC (Rust host +
embedded `lm.*` Lua modules, 135-test suite). External interfaces are
specified in `docs/spec/`, grounded in the POC's proven behaviour;
the implementation in this repo lands against those specs.

## Layout

```
docs/spec/   # External IF specifications (the current deliverable)
```

## License

Dual-licensed under either of:

- MIT License ([`LICENSE-MIT`](LICENSE-MIT))
- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option.
