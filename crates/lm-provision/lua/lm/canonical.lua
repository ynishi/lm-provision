--- lm.canonical — canonical byte encoding of the IR.
--
-- ## Design
--
-- Produces the hash-critical, order-independent JSON encoding consumed
-- by `lm.hash` (03-pipeline-stage-artifacts.md §canonical). Both
-- `encode` and `decode` are pure Lua: no bridge calls, no policy
-- checks (03 §Inputs: "All five stages are pure Lua computation over
-- the IR table ... no bridge calls").
--
-- ## Encode rules (03 §canonical, byte-for-byte contract)
--
-- - Objects: keys sorted lexicographically (recursive). Object keys
--   must be Lua strings (the IR never carries non-string object keys).
-- - Arrays (contiguous integer-keyed tables `1..n`, nothing else):
--   element order preserved.
-- - Empty-table rule: an empty table always encodes as `{}`, checked
--   *before* the array/object distinction — empty array and empty
--   object are indistinguishable in canonical form.
-- - Strings: `"` `\` and the named control escapes (`\n` `\r` `\t`
--   `\b` `\f`); every other byte `< 0x20` as `\u00XX` (lowercase hex);
--   everything else (including UTF-8 continuation/lead bytes) passes
--   through raw.
-- - Numbers: NaN / ±Inf raise (not encodable). A number whose value is
--   mathematically integral *and* `|v| < 1e15` renders via `%d`;
--   every other finite number renders via `%.17g` (17 significant
--   digits — sufficient to round-trip any IEEE-754 double exactly).
--   This is decided by *value*, not by Lua's `integer`/`float`
--   subtype, so canonical bytes stay identical regardless of which
--   subtype produced a mathematically-integral number.
-- - Booleans: `true` / `false` (03 §canonical enumerates the error
--   cases — "any other userdata / function / thread value raises an
--   error" — booleans are not in that error set, so they are encoded
--   like any other primitive Lua value; not literally itemized in the
--   spec's Outputs list, reported as an interpretive extension in the
--   impl-lead M2-2 report).
-- - Secret markers: a SecretRef userdata (chapter 06) is duck-typed
--   (see `secret_ref_name` below — `getmetatable(ud).__lm_secret_name`
--   is unreachable from Lua because mlua's generated `UserData`
--   metatables are `__metatable`-protected) and encodes to
--   `{"__secret":"NAME"}`. A *literal* Lua table shaped
--   `{ __secret = "NAME" }` requires no special-casing at all: the
--   generic object-encode path already produces the identical single-key
--   object, which is exactly the "userdata refs and literal marker
--   tables are canonical-equivalent" guarantee (03 §canonical).
-- - Any other userdata / function / thread value raises an error.
--
-- ## Decode
--
-- The inverse parse: canonical JSON bytes → Lua value, with
-- `{"__secret":"NAME"}` markers rehydrated into SecretRef userdata via
-- the global `env.ref` factory (06-secret-handling.md §Inputs
-- `env.ref`) — the only Lua-visible SecretRef constructor. `env.ref`
-- is registered as a plain global before any pipeline stage runs
-- (04-bridge.md §Registration order step 3); since it performs no
-- policy check (06 §Inputs: "Validation timing rationale"), calling it
-- from decode carries no bridge/effect semantics — it is construction,
-- not consumption. If `env.ref` is not registered on this VM, decode
-- raises a clear host-wiring error rather than silently degrading to a
-- plain marker table.
--
-- `encode ∘ decode` is byte-identity on canonical bytes (03 §canonical
-- "This bidirectionality is what enables ledger reconstruction").

local M = {}

-- ---------------------------------------------------------------------
-- encode
-- ---------------------------------------------------------------------

local ESCAPE_BYTES = {
	[34] = '\\"', -- 0x22 "
	[92] = "\\\\", -- 0x5C backslash
	[10] = "\\n", -- 0x0A
	[13] = "\\r", -- 0x0D
	[9] = "\\t", -- 0x09
	[8] = "\\b", -- 0x08
	[12] = "\\f", -- 0x0C
}

--- Encodes `s` as a canonical JSON string literal, including the
--- surrounding quotes (03 §canonical "Strings").
local function encode_string(s)
	local parts = { '"' }
	for i = 1, #s do
		local byte = s:byte(i)
		local mapped = ESCAPE_BYTES[byte]
		if mapped then
			parts[#parts + 1] = mapped
		elseif byte < 0x20 then
			parts[#parts + 1] = string.format("\\u%04x", byte)
		else
			parts[#parts + 1] = s:sub(i, i)
		end
	end
	parts[#parts + 1] = '"'
	return table.concat(parts)
end

--- Encodes a Lua number per the `%d` / `%.17g` / error rule (03
--- §canonical "Numbers"). Raises on NaN / ±Inf.
local function encode_number(v)
	if v ~= v then
		error("lm.canonical.encode: NaN is not encodable (03 §canonical Numbers)", 0)
	end
	if v == math.huge or v == -math.huge then
		error("lm.canonical.encode: an infinite number is not encodable (03 §canonical Numbers)", 0)
	end
	local abs_v = v < 0 and -v or v
	if v == math.floor(v) and abs_v < 1e15 then
		return string.format("%d", math.tointeger(v) or v)
	end
	return string.format("%.17g", v)
end

-- Forward-declared: `encode_value` recurses into tables via
-- `encode_table`, which recurses back into `encode_value` for element
-- / field values.
local encode_value

--- Returns `n` (the array length, `1..n`) when `t` is shaped like a
--- contiguous integer-keyed table starting at `1`, or `nil` when it is
--- not (03 §canonical "Arrays (contiguous integer-keyed tables)").
--- Never called on an empty table — that case is handled by the
--- empty-table rule before this check runs.
local function array_length_or_nil(t)
	local n = 0
	local count = 0
	for k in pairs(t) do
		count = count + 1
		if type(k) ~= "number" or k ~= math.floor(k) or k < 1 then
			return nil
		end
		if k > n then
			n = k
		end
	end
	if count ~= n then
		return nil
	end
	return n
end

--- Encodes an object: keys sorted lexicographically (recursive, 03
--- §canonical "Objects"). Every key must be a Lua string — the IR
--- never carries non-string object keys; a non-string key is a caller
--- error, not a canonical-form ambiguity.
local function encode_object(t, out)
	local keys = {}
	for k in pairs(t) do
		if type(k) ~= "string" then
			error(string.format("lm.canonical.encode: object key must be a string, got %s", type(k)), 0)
		end
		keys[#keys + 1] = k
	end
	table.sort(keys)
	out[#out + 1] = "{"
	for i, k in ipairs(keys) do
		if i > 1 then
			out[#out + 1] = ","
		end
		out[#out + 1] = encode_string(k)
		out[#out + 1] = ":"
		encode_value(t[k], out)
	end
	out[#out + 1] = "}"
end

--- Encodes a table: the empty-table rule first (both empty array and
--- empty object canonicalize to `{}`), then dispatches to the array or
--- object form (03 §canonical "Empty-table rule").
local function encode_table(t, out)
	if next(t) == nil then
		out[#out + 1] = "{}"
		return
	end
	local n = array_length_or_nil(t)
	if n then
		out[#out + 1] = "["
		for i = 1, n do
			if i > 1 then
				out[#out + 1] = ","
			end
			encode_value(t[i], out)
		end
		out[#out + 1] = "]"
	else
		encode_object(t, out)
	end
end

--- Duck-types a SecretRef userdata and returns its logical name, or
--- `nil` when `v` is not a SecretRef. `getmetatable(v).__lm_secret_name`
--- is unreachable — mlua protects every generated `UserData`
--- metatable with `__metatable`, so `getmetatable` never yields the
--- real metatable to Lua code. The only Lua-visible SecretRef surface
--- is `ref:name()` and `tostring(ref)` (06-secret-handling.md
--- §Outputs "the only value-bearing operation visible to Lua"); this
--- checks both so an arbitrary unrelated userdata that merely happens
--- to expose a `name` method is not mistaken for a SecretRef.
local function secret_ref_name(v)
	local ok, name = pcall(function()
		return v:name()
	end)
	if not ok or type(name) ~= "string" then
		return nil
	end
	local ok2, rendered = pcall(tostring, v)
	if not ok2 or rendered ~= ("[secret:" .. name .. "]") then
		return nil
	end
	return name
end

--- Encodes any IR-shaped Lua value (03 §Inputs "canonical: any
--- IR-shaped Lua value (encode)").
encode_value = function(v, out)
	local t = type(v)
	if t == "string" then
		out[#out + 1] = encode_string(v)
	elseif t == "number" then
		out[#out + 1] = encode_number(v)
	elseif t == "boolean" then
		out[#out + 1] = v and "true" or "false"
	elseif t == "table" then
		encode_table(v, out)
	elseif t == "userdata" then
		local name = secret_ref_name(v)
		if name == nil then
			error("lm.canonical.encode: unsupported userdata value (not a SecretRef)", 0)
		end
		out[#out + 1] = '{"__secret":' .. encode_string(name) .. "}"
	else
		error(string.format("lm.canonical.encode: unsupported value type %s", t), 0)
	end
end

--- `lm.canonical.encode(ir) -> canonical JSON bytes (string)` (03
--- §canonical).
function M.encode(value)
	local out = {}
	encode_value(value, out)
	return table.concat(out)
end

-- ---------------------------------------------------------------------
-- decode
-- ---------------------------------------------------------------------

--- Rehydrates a `{"__secret":"NAME"}` marker into a SecretRef userdata
--- via the global `env.ref` factory (06-secret-handling.md §Inputs).
--- Raises with a clear host-wiring message when `env.ref` is not
--- registered on this VM, rather than silently returning the marker
--- table (03 §canonical "Decode ... rehydrated into SecretRef
--- userdata").
local function rehydrate_secret(name)
	if type(env) ~= "table" or type(env.ref) ~= "function" then
		error(
			"lm.canonical.decode: cannot rehydrate secret marker '"
				.. tostring(name)
				.. "': env.ref is not registered in this VM",
			0
		)
	end
	return env.ref(name)
end

--- Called on every freshly-parsed JSON object: recognizes the
--- exactly-one-key `{"__secret":"NAME"}` shape and swaps it for a
--- rehydrated SecretRef; every other object is returned as-is.
local function finalize_object(obj)
	local count = 0
	local secret_name = nil
	for k, v in pairs(obj) do
		count = count + 1
		if k == "__secret" and type(v) == "string" then
			secret_name = v
		end
	end
	if count == 1 and secret_name ~= nil then
		return rehydrate_secret(secret_name)
	end
	return obj
end

--- `lm.canonical.decode(bytes) -> ir` (03 §canonical). `bytes` must be
--- canonical JSON produced by `M.encode` (or shaped identically);
--- raises on malformed input (03 §Error surface "decode: raises on
--- malformed canonical bytes").
function M.decode(bytes)
	if type(bytes) ~= "string" then
		error(string.format("lm.canonical.decode: bytes must be a string, got %s", type(bytes)), 0)
	end

	local pos = 1
	local len = #bytes

	local function fail(msg)
		error(string.format("lm.canonical.decode: %s at byte %d", msg, pos), 0)
	end

	local function skip_ws()
		while pos <= len do
			local c = bytes:sub(pos, pos)
			if c == " " or c == "\t" or c == "\n" or c == "\r" then
				pos = pos + 1
			else
				break
			end
		end
	end

	local function expect(ch)
		if bytes:sub(pos, pos) ~= ch then
			fail(string.format("expected %q", ch))
		end
		pos = pos + 1
	end

	local function parse_string()
		expect('"')
		local parts = {}
		while true do
			if pos > len then
				fail("unterminated string")
			end
			local c = bytes:sub(pos, pos)
			if c == '"' then
				pos = pos + 1
				break
			elseif c == "\\" then
				pos = pos + 1
				local e = bytes:sub(pos, pos)
				if e == '"' then
					parts[#parts + 1] = '"'
				elseif e == "\\" then
					parts[#parts + 1] = "\\"
				elseif e == "/" then
					parts[#parts + 1] = "/"
				elseif e == "n" then
					parts[#parts + 1] = "\n"
				elseif e == "r" then
					parts[#parts + 1] = "\r"
				elseif e == "t" then
					parts[#parts + 1] = "\t"
				elseif e == "b" then
					parts[#parts + 1] = "\b"
				elseif e == "f" then
					parts[#parts + 1] = "\f"
				elseif e == "u" then
					local hex = bytes:sub(pos + 1, pos + 4)
					if #hex ~= 4 or not hex:match("^%x%x%x%x$") then
						fail("invalid \\u escape")
					end
					parts[#parts + 1] = string.char(tonumber(hex, 16) % 256)
					pos = pos + 4
				else
					fail("invalid escape character")
				end
				pos = pos + 1
			else
				parts[#parts + 1] = c
				pos = pos + 1
			end
		end
		return table.concat(parts)
	end

	local function parse_number()
		local start = pos
		if bytes:sub(pos, pos) == "-" then
			pos = pos + 1
		end
		while pos <= len and bytes:sub(pos, pos):match("%d") do
			pos = pos + 1
		end
		local is_float = false
		if bytes:sub(pos, pos) == "." then
			is_float = true
			pos = pos + 1
			while pos <= len and bytes:sub(pos, pos):match("%d") do
				pos = pos + 1
			end
		end
		local exp_marker = bytes:sub(pos, pos)
		if exp_marker == "e" or exp_marker == "E" then
			is_float = true
			pos = pos + 1
			local sign = bytes:sub(pos, pos)
			if sign == "+" or sign == "-" then
				pos = pos + 1
			end
			while pos <= len and bytes:sub(pos, pos):match("%d") do
				pos = pos + 1
			end
		end
		local text = bytes:sub(start, pos - 1)
		local n = tonumber(text)
		if n == nil then
			fail(string.format("invalid number literal %q", text))
		end
		if not is_float then
			n = math.tointeger(n) or n
		end
		return n
	end

	local parse_value -- forward declaration (mutual recursion below)

	local function parse_array()
		expect("[")
		skip_ws()
		local t = {}
		if bytes:sub(pos, pos) == "]" then
			pos = pos + 1
			return t
		end
		local idx = 0
		while true do
			skip_ws()
			idx = idx + 1
			t[idx] = parse_value()
			skip_ws()
			local c = bytes:sub(pos, pos)
			if c == "," then
				pos = pos + 1
			elseif c == "]" then
				pos = pos + 1
				break
			else
				fail("expected ',' or ']' in array")
			end
		end
		return t
	end

	local function parse_object()
		expect("{")
		skip_ws()
		local t = {}
		if bytes:sub(pos, pos) == "}" then
			pos = pos + 1
			return finalize_object(t)
		end
		while true do
			skip_ws()
			if bytes:sub(pos, pos) ~= '"' then
				fail("expected string key")
			end
			local key = parse_string()
			skip_ws()
			expect(":")
			skip_ws()
			t[key] = parse_value()
			skip_ws()
			local c = bytes:sub(pos, pos)
			if c == "," then
				pos = pos + 1
			elseif c == "}" then
				pos = pos + 1
				break
			else
				fail("expected ',' or '}' in object")
			end
		end
		return finalize_object(t)
	end

	parse_value = function()
		skip_ws()
		local c = bytes:sub(pos, pos)
		if c == "{" then
			return parse_object()
		elseif c == "[" then
			return parse_array()
		elseif c == '"' then
			return parse_string()
		elseif c == "t" then
			if bytes:sub(pos, pos + 3) == "true" then
				pos = pos + 4
				return true
			end
			fail("invalid literal")
		elseif c == "f" then
			if bytes:sub(pos, pos + 4) == "false" then
				pos = pos + 5
				return false
			end
			fail("invalid literal")
		elseif c == "n" then
			if bytes:sub(pos, pos + 3) == "null" then
				pos = pos + 4
				-- `null` never appears in bytes produced by `M.encode`
				-- (nil is not an encodable value, 03 §canonical); decoded
				-- as Lua `nil` for completeness. Storing `nil` into a
				-- table key/index is a Lua no-op, so a `null` array
				-- element or object value simply vanishes rather than
				-- round-tripping — not exercised by the encode/decode
				-- round-trip contract this stage guarantees.
				return nil
			end
			fail("invalid literal")
		elseif c == "-" or c:match("%d") then
			return parse_number()
		else
			fail(string.format("unexpected character %q", c))
		end
	end

	skip_ws()
	local result = parse_value()
	skip_ws()
	if pos <= len then
		fail("trailing data after top-level value")
	end
	return result
end

return M
