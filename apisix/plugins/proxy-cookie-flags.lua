--
-- proxy-cookie-flags plugin
--
-- Sets or removes cookie attributes (Secure, HttpOnly, SameSite) on
-- Set-Cookie response headers.  This is the APISIX equivalent of nginx's
-- proxy_cookie_flags directive.
--
-- Configuration:
--   rules:
--     - match: "sessionid"
--       flags: ["SameSite=None", "Secure"]
--     - match: "*"
--       flags: ["HttpOnly"]
--

local core   = require("apisix.core")
local ngx    = ngx
local re     = require("ngx.re")
local ipairs = ipairs
local type   = type
local table_insert = table.insert
local table_concat = table.concat

local plugin_name = "proxy-cookie-flags"

local schema = {
    type = "object",
    properties = {
        rules = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    match = {
                        type = "string",
                        minLength = 1,
                    },
                    flags = {
                        type = "array",
                        items = {
                            type = "string",
                            minLength = 1,
                        },
                        minItems = 1,
                    },
                },
                required = {"match", "flags"},
            },
            minItems = 1,
        },
    },
    required = {"rules"},
}

local _M = {
    version = 0.1,
    priority = 3989,
    name = plugin_name,
    schema = schema,
    -- run in rewrite phase (header_filter runs the actual work)
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- Parse a Set-Cookie header value into segments.
-- Returns: { "name=value", "attr1", "attr2", ... }
local function parse_set_cookie(value)
    if not value or value == "" then
        return nil
    end
    local parts = {}
    local idx = 1
    for seg in value:gmatch("[^;]+") do
        local trimmed = seg:match("^%s*(.-)%s*$")
        parts[idx] = trimmed
        idx = idx + 1
    end
    return parts
end

-- Reassemble segments back into a single Set-Cookie value.
local function assemble_set_cookie(parts)
    local result = parts[1]
    for i = 2, #parts do
        result = result .. "; " .. parts[i]
    end
    return result
end

-- Extract cookie name from "name=value".
local function cookie_name(value)
    return value:match("^([^=]+)")
end

-- Check if a cookie name matches a rule's match pattern.
local function matches_cookie(name, pattern)
    if pattern == "*" then
        return true
    end
    if pattern:sub(1, 1) == "~" then
        local regex = pattern:sub(2)
        local from, _, err = re.find(name, regex, "jo")
        if err then
            core.log.error("proxy-cookie-flags: regex error: ", err)
            return false
        end
        return from ~= nil
    end
    return name:lower() == pattern:lower()
end

-- Remove all occurrences of an attribute (case-insensitive) from parts.
local function remove_attr(parts, attr_lower)
    local new_parts = {parts[1]}
    for i = 2, #parts do
        if parts[i]:lower() ~= attr_lower then
            table_insert(new_parts, parts[i])
        end
    end
    return new_parts
end

-- Remove attributes matching a prefix (case-insensitive).
local function remove_attr_prefix(parts, prefix_lower)
    local new_parts = {parts[1]}
    for i = 2, #parts do
        if not parts[i]:lower():match("^" .. prefix_lower) then
            table_insert(new_parts, parts[i])
        end
    end
    return new_parts
end

-- Check if an attribute (exact, case-insensitive) already exists.
local function has_attr(parts, attr_lower)
    for i = 2, #parts do
        if parts[i]:lower() == attr_lower then
            return true
        end
    end
    return false
end

-- Apply a single flag to the cookie parts.
local function apply_flag(parts, flag)
    local lower = flag:lower()

    -- SameSite=<value>
    local samesite_value = flag:match("^SameSite=(%S+)$")
    if samesite_value then
        parts = remove_attr_prefix(parts, "samesite=")
        table_insert(parts, "SameSite=" .. samesite_value)
        return parts
    end

    -- noSameSite
    if lower == "nosamesite" then
        return remove_attr_prefix(parts, "samesite=")
    end

    -- Secure
    if lower == "secure" then
        if not has_attr(parts, "secure") then
            table_insert(parts, "Secure")
        end
        return parts
    end

    -- noSecure
    if lower == "nosecure" then
        return remove_attr(parts, "secure")
    end

    -- HttpOnly
    if lower == "httponly" then
        if not has_attr(parts, "httponly") then
            table_insert(parts, "HttpOnly")
        end
        return parts
    end

    -- noHttpOnly
    if lower == "nohttponly" then
        return remove_attr(parts, "httponly")
    end

    core.log.warn("proxy-cookie-flags: unknown flag: ", flag)
    return parts
end

-- Process a single Set-Cookie value against all rules.
local function process_cookie(value, conf)
    local parts = parse_set_cookie(value)
    if not parts then
        return value
    end
    local name = cookie_name(value)
    if not name then
        return value
    end
    for _, rule in ipairs(conf.rules) do
        if matches_cookie(name, rule.match) then
            for _, flag in ipairs(rule.flags) do
                parts = apply_flag(parts, flag)
            end
            break  -- only the first matching rule applies
        end
    end
    return assemble_set_cookie(parts)
end

function _M.header_filter(conf, ctx)
    -- Read Set-Cookie from upstream response via ngx API
    local raw = ngx.header["Set-Cookie"]
    if not raw then
        return
    end

    -- ngx.header["Set-Cookie"] returns a string for single, table for multiple
    local cookies
    if type(raw) == "table" then
        cookies = raw
    else
        cookies = {raw}
    end

    -- Process each cookie
    local modified = false
    local new_cookies = {}
    for i, val in ipairs(cookies) do
        local new_val = process_cookie(val, conf)
        new_cookies[i] = new_val
        if new_val ~= val then
            modified = true
        end
    end

    if not modified then
        return
    end

    -- Write back all Set-Cookie headers at once (table assignment replaces all)
    ngx.header["Set-Cookie"] = new_cookies
end

return _M
