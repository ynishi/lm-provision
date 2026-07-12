//! M2-2 (`lm.canonical` + `lm.hash` + the sha256 battery) regression
//! tests.
//!
//! Exercises `lm.canonical.encode` / `lm.canonical.decode` and
//! `lm.hash.sha256_hex` through the sandboxed VM boot path
//! ([`lm_provision::vm::boot_vm`]), with `env.ref`
//! ([`lm_provision::bridge::env_ref`]) and the sha256 battery
//! ([`lm_provision::batteries::hash`]) installed as their runtime
//! dependencies — not the full registration order (04-bridge.md
//! §Registration order), which is out of scope for the pure pipeline
//! stages this milestone ships (03-pipeline-stage-artifacts.md
//! §Inputs: "All five stages are pure Lua computation ... no bridge
//! calls").
//!
//! Covers 03-pipeline-stage-artifacts.md §canonical (encode rules,
//! empty-table rule, secret-marker canonical-equivalence, decode
//! round-trip, error surface) and §hash (64-char lowercase hex,
//! declared-list-permutation invariance, phase-order sensitivity,
//! unavailable-provider error).

use lm_provision::batteries;
use lm_provision::bridge::env_ref;
use lm_provision::vm::boot_vm;
use lm_provision::vm::eval::evaluate_profile_source;
use mlua::{Function, Lua, Table, Value};

/// Boots a VM with `env.ref` (06-secret-handling.md §Inputs, needed for
/// secret-marker rehydration) and the sha256 battery (`lm.hash`'s
/// provider) installed.
fn boot_test_vm() -> Lua {
    let lua = boot_vm().expect("boot_vm should succeed");
    env_ref::install(&lua).expect("env.ref install should succeed");
    batteries::hash::install(&lua).expect("hash battery install should succeed");
    lua
}

/// Evaluates `require('lm.canonical').encode(<lua_value_expr>)` and
/// returns the canonical bytes.
fn encode(lua: &Lua, lua_value_expr: &str) -> String {
    lua.load(format!(
        "return require('lm.canonical').encode({lua_value_expr})"
    ))
    .eval()
    .unwrap_or_else(|err| panic!("encode({lua_value_expr}) should succeed: {err}"))
}

/// Evaluates `require('lm.canonical').encode(<lua_value_expr>)`
/// expecting a Lua error, and returns its message.
fn encode_err(lua: &Lua, lua_value_expr: &str) -> String {
    lua.load(format!(
        "return require('lm.canonical').encode({lua_value_expr})"
    ))
    .eval::<Value>()
    .expect_err("encode should raise")
    .to_string()
}

/// A tiny closure over `lm.canonical` + `lm.hash` that hashes an IR
/// table directly, for tests that build the IR via `lm.profile`
/// (`evaluate_profile_source`) rather than a literal Lua expression.
fn hash_of_ir(lua: &Lua, ir: &Table) -> String {
    let f: Function = lua
        .load(
            r#"
            return function(ir)
                local canonical = require('lm.canonical')
                local hash = require('lm.hash')
                return hash.sha256_hex(canonical.encode(ir))
            end
            "#,
        )
        .eval()
        .expect("hash_of_ir helper should compile");
    f.call(ir.clone()).expect("hash should compute")
}

// ---------------------------------------------------------------------
// encode: empty-table rule, objects, arrays
// ---------------------------------------------------------------------

#[test]
fn encode_empty_table_produces_braces() {
    let lua = boot_test_vm();
    assert_eq!(encode(&lua, "{}"), "{}");
}

#[test]
fn encode_sorts_object_keys_lexicographically_recursive() {
    let lua = boot_test_vm();
    assert_eq!(
        encode(&lua, "{ b = { z = 1, a = 2 }, a = 1 }"),
        r#"{"a":1,"b":{"a":2,"z":1}}"#
    );
}

#[test]
fn encode_preserves_array_element_order() {
    let lua = boot_test_vm();
    assert_eq!(encode(&lua, "{ 3, 1, 2 }"), "[3,1,2]");
}

#[test]
fn encode_nested_array_of_objects() {
    let lua = boot_test_vm();
    assert_eq!(
        encode(&lua, "{ { b = 1, a = 2 }, { z = 1 } }"),
        r#"[{"a":2,"b":1},{"z":1}]"#
    );
}

// ---------------------------------------------------------------------
// encode: strings
// ---------------------------------------------------------------------

#[test]
fn encode_escapes_quote_backslash_and_named_control_chars() {
    let lua = boot_test_vm();
    let result = encode(&lua, r#""a\"b\\c\nd\re\tf\bg\fh""#);
    assert_eq!(result, r#""a\"b\\c\nd\re\tf\bg\fh""#);
}

#[test]
fn encode_escapes_other_control_characters_as_u00xx() {
    let lua = boot_test_vm();
    // `string.char(1)` builds the single byte 0x01 (avoids Lua's
    // backslash-digit decimal-escape syntax in the source snippet).
    let expected: String = ['"', '\\', 'u', '0', '0', '0', '1', '"'].iter().collect();
    assert_eq!(encode(&lua, "string.char(1)"), expected);
}

#[test]
fn encode_passes_through_utf8_multibyte_content_raw() {
    let lua = boot_test_vm();
    // `string.char(195, 169)` builds the 2-byte UTF-8 encoding of
    // U+00E9 (e-acute), i.e. "é".
    let expected: String = ['"', 'c', 'a', 'f', '\u{e9}', '"'].iter().collect();
    assert_eq!(
        encode(&lua, r#"("caf" .. string.char(195, 169))"#),
        expected
    );
}

// ---------------------------------------------------------------------
// encode: numbers
// ---------------------------------------------------------------------

#[test]
fn encode_small_integers_use_plain_digit_form() {
    let lua = boot_test_vm();
    assert_eq!(encode(&lua, "0"), "0");
    assert_eq!(encode(&lua, "123"), "123");
    assert_eq!(encode(&lua, "-123"), "-123");
}

#[test]
fn encode_boolean_values() {
    let lua = boot_test_vm();
    assert_eq!(encode(&lua, "true"), "true");
    assert_eq!(encode(&lua, "false"), "false");
}

#[test]
fn encode_raises_on_nan() {
    let lua = boot_test_vm();
    let message = encode_err(&lua, "0/0");
    assert!(message.to_lowercase().contains("nan"), "message: {message}");
}

#[test]
fn encode_raises_on_positive_infinity() {
    let lua = boot_test_vm();
    let message = encode_err(&lua, "math.huge");
    assert!(
        message.to_lowercase().contains("infinite"),
        "message: {message}"
    );
}

#[test]
fn encode_raises_on_negative_infinity() {
    let lua = boot_test_vm();
    let message = encode_err(&lua, "-math.huge");
    assert!(
        message.to_lowercase().contains("infinite"),
        "message: {message}"
    );
}

#[test]
fn non_integer_numbers_round_trip_exactly_through_encode_decode() {
    let lua = boot_test_vm();
    let round_tripped: bool = lua
        .load(
            r#"
            local canonical = require('lm.canonical')
            local encoded = canonical.encode(1.5)
            return canonical.decode(encoded) == 1.5
            "#,
        )
        .eval()
        .expect("round trip should evaluate");
    assert!(round_tripped);
}

#[test]
fn integers_at_and_above_the_1e15_threshold_round_trip_exactly() {
    let lua = boot_test_vm();
    let round_tripped: bool = lua
        .load(
            r#"
            local canonical = require('lm.canonical')
            -- 999999999999999 < 1e15 (%d path); the other two are >= 1e15
            -- (%.17g path). All three must still round-trip exactly.
            local values = { 999999999999999, 1000000000000000, 1234567890123456 }
            for _, v in ipairs(values) do
                if canonical.decode(canonical.encode(v)) ~= v then
                    return false
                end
            end
            return true
            "#,
        )
        .eval()
        .expect("round trip should evaluate");
    assert!(round_tripped);
}

// ---------------------------------------------------------------------
// encode: unsupported values
// ---------------------------------------------------------------------

#[test]
fn encode_raises_on_a_function_value() {
    let lua = boot_test_vm();
    let message = encode_err(&lua, "function() end");
    assert!(
        message.contains("unsupported value type function"),
        "message: {message}"
    );
}

#[test]
fn encode_raises_on_a_thread_value() {
    let lua = boot_test_vm();
    let message = encode_err(&lua, "coroutine.create(function() end)");
    assert!(
        message.contains("unsupported value type thread"),
        "message: {message}"
    );
}

// ---------------------------------------------------------------------
// encode: secret markers (canonical-equivalence)
// ---------------------------------------------------------------------

#[test]
fn encode_secret_ref_userdata_produces_the_marker() {
    let lua = boot_test_vm();
    let result: String = lua
        .load(
            r#"
            local canonical = require('lm.canonical')
            return canonical.encode(env.ref("HF_TOKEN"))
            "#,
        )
        .eval()
        .expect("encode should succeed");
    assert_eq!(result, r#"{"__secret":"HF_TOKEN"}"#);
}

#[test]
fn encode_literal_marker_table_is_canonical_equivalent_to_secret_ref() {
    let lua = boot_test_vm();
    let result: String = lua
        .load(
            r#"
            return require('lm.canonical').encode({ __secret = "HF_TOKEN" })
            "#,
        )
        .eval()
        .expect("encode should succeed");
    assert_eq!(
        result, r#"{"__secret":"HF_TOKEN"}"#,
        "06 §Outputs: userdata refs and literal marker tables are canonical-equivalent"
    );
}

// ---------------------------------------------------------------------
// decode / round-trip
// ---------------------------------------------------------------------

#[test]
fn round_trip_is_byte_identical_for_a_representative_ir_with_a_secret() {
    let lua = boot_test_vm();
    let (equal, encoded): (bool, String) = lua
        .load(
            r#"
            local profile = require('lm.profile')
            local canonical = require('lm.canonical')
            local ir = profile {
                name = "demo",
                env_secrets = { "HF_TOKEN" },
                paths = { "/workspace" },
                phases = {
                    {
                        kind = "fs.write",
                        path = "/workspace/secret.txt",
                        content = env.ref("HF_TOKEN"),
                    },
                },
            }
            local encoded = canonical.encode(ir)
            local decoded = canonical.decode(encoded)
            local re_encoded = canonical.encode(decoded)
            return encoded == re_encoded, encoded
            "#,
        )
        .eval()
        .expect("round trip should evaluate");
    assert!(equal, "encode(decode(bytes)) must equal bytes: {encoded}");
    assert!(encoded.contains(r#""__secret":"HF_TOKEN""#));
}

#[test]
fn round_trip_rehydrates_a_secret_marker_into_an_opaque_secret_ref() {
    let lua = boot_test_vm();
    let rendered: String = lua
        .load(
            r#"
            local decoded = require('lm.canonical').decode('{"__secret":"HF_TOKEN"}')
            return tostring(decoded)
            "#,
        )
        .eval()
        .expect("decode should succeed");
    assert_eq!(rendered, "[secret:HF_TOKEN]");
}

#[test]
fn decode_raises_when_env_ref_is_not_registered() {
    // Deliberately boot_vm() only (no env_ref::install), so `env.ref`
    // is unavailable for the marker to rehydrate against.
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load(r#"return require('lm.canonical').decode('{"__secret":"HF_TOKEN"}')"#)
        .eval::<Value>()
        .expect_err("decode should raise without env.ref registered");
    let message = err.to_string();
    assert!(
        message.contains("env.ref is not registered"),
        "message: {message}"
    );
}

#[test]
fn decode_raises_on_malformed_canonical_bytes() {
    let lua = boot_test_vm();
    let err = lua
        .load(r#"return require('lm.canonical').decode('{"a":}')"#)
        .eval::<Value>()
        .expect_err("malformed bytes must raise");
    assert!(err.to_string().contains("lm.canonical.decode"));
}

#[test]
fn decode_raises_on_a_non_string_argument() {
    let lua = boot_test_vm();
    let err = lua
        .load("return require('lm.canonical').decode(42)")
        .eval::<Value>()
        .expect_err("non-string bytes must raise");
    assert!(err.to_string().contains("bytes must be a string"));
}

// ---------------------------------------------------------------------
// hash: shape, determinism, known vectors, error surface
// ---------------------------------------------------------------------

#[test]
fn hash_is_64_char_lowercase_hex() {
    let lua = boot_test_vm();
    let digest: String = lua
        .load(r#"return require('lm.hash').sha256_hex(require('lm.canonical').encode({ a = 1 }))"#)
        .eval()
        .expect("hash should succeed");
    assert_eq!(digest.len(), 64);
    assert!(digest
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn hash_is_deterministic_across_repeated_calls() {
    let lua = boot_test_vm();
    let (a, b): (String, String) = lua
        .load(
            r#"
            local hash = require('lm.hash')
            local bytes = require('lm.canonical').encode({ name = "demo" })
            return hash.sha256_hex(bytes), hash.sha256_hex(bytes)
            "#,
        )
        .eval()
        .expect("hash calls should evaluate");
    assert_eq!(
        a, b,
        "sha256_hex must be a pure function of its input bytes"
    );
}

#[test]
fn hash_matches_known_nist_sha256_test_vectors() {
    let lua = boot_test_vm();
    let empty: String = lua
        .load(r#"return require('lm.hash').sha256_hex("")"#)
        .eval()
        .expect("hash of the empty string");
    // NIST FIPS 180-4 SHA-256 test vector.
    assert_eq!(
        empty,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let abc: String = lua
        .load(r#"return require('lm.hash').sha256_hex("abc")"#)
        .eval()
        .expect("hash of 'abc'");
    // NIST FIPS 180-4 SHA-256 test vector.
    assert_eq!(
        abc,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hash_raises_when_the_batteries_provider_is_unavailable() {
    // Deliberately boot_vm() only: no batteries::hash::install.
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load(r#"return require('lm.hash').sha256_hex("x")"#)
        .eval::<Value>()
        .expect_err("sha256_hex should raise when the battery is not installed");
    assert!(err
        .to_string()
        .contains("the batteries hash provider is unavailable"));
}

// ---------------------------------------------------------------------
// hash: declared-list permutation invariance / phase-order sensitivity
// (03-pipeline-stage-artifacts.md §hash)
// ---------------------------------------------------------------------

#[test]
fn hash_is_byte_identical_across_reordered_declared_lists() {
    let a = evaluate_profile_source(
        r#"
        local profile = require('lm.profile')
        return profile {
            name = "demo",
            capabilities = { "sh.exec", "fs.write", "env.ref" },
            env = { "ZETA", "ALPHA", "MID" },
            env_secrets = { "HF_TOKEN", "B2_KEY" },
            paths = { "/workspace", "/data" },
            http_allowlist = { "https://z.example.com/", "https://a.example.com/" },
        }
        "#,
        "profile-a",
    )
    .expect("profile a should evaluate");
    let b = evaluate_profile_source(
        r#"
        local profile = require('lm.profile')
        return profile {
            name = "demo",
            capabilities = { "env.ref", "fs.write", "sh.exec" },
            env = { "MID", "ALPHA", "ZETA" },
            env_secrets = { "B2_KEY", "HF_TOKEN" },
            paths = { "/data", "/workspace" },
            http_allowlist = { "https://a.example.com/", "https://z.example.com/" },
        }
        "#,
        "profile-b",
    )
    .expect("profile b should evaluate");

    batteries::hash::install(&a.lua).expect("battery install should succeed");
    batteries::hash::install(&b.lua).expect("battery install should succeed");

    let hash_a = hash_of_ir(&a.lua, &a.ir);
    let hash_b = hash_of_ir(&b.lua, &b.ir);
    assert_eq!(
        hash_a, hash_b,
        "01 §List-shape rule stable-sort + 03 §hash: declared-list \
         permutations must hash identically"
    );
}

#[test]
fn hash_changes_when_phase_order_is_permuted() {
    let a = evaluate_profile_source(
        r#"
        local profile = require('lm.profile')
        return profile {
            name = "demo",
            phases = {
                { kind = "system.apt", packages = { "curl" } },
                { kind = "hooks.post_install", script = "echo hi" },
            },
        }
        "#,
        "profile-a",
    )
    .expect("profile a should evaluate");
    let b = evaluate_profile_source(
        r#"
        local profile = require('lm.profile')
        return profile {
            name = "demo",
            phases = {
                { kind = "hooks.post_install", script = "echo hi" },
                { kind = "system.apt", packages = { "curl" } },
            },
        }
        "#,
        "profile-b",
    )
    .expect("profile b should evaluate");

    batteries::hash::install(&a.lua).expect("battery install should succeed");
    batteries::hash::install(&b.lua).expect("battery install should succeed");

    let hash_a = hash_of_ir(&a.lua, &a.ir);
    let hash_b = hash_of_ir(&b.lua, &b.ir);
    assert_ne!(
        hash_a, hash_b,
        "03 §hash: hash is sensitive to phase order (semantic, not sorted)"
    );
}
