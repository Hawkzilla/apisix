--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
--
-- proxy-cookie-path plugin
--
-- Rewrites the Path attribute in Set-Cookie response headers.
-- This is the APISIX equivalent of nginx's proxy_cookie_path directive.
--
-- Configuration:
--   path_pairs:
--     - cookie: "sessionid"      -- (optional) only rewrite this cookie
--       match: "/old-path"       -- literal path to match
--       replacement: "/new-path" -- replacement path
--     - match: "~ ^/api/(.*)"    -- regex match (~ prefix indicates regex)
--       replacement: "/$1"       -- no cookie = match all cookies
--

local core   = require("apisix.core")
local string = string
local re     = require("ngx.re")
local ipairs = ipairs
local pairs  = pairs
local type   = type

local plugin_name = "proxy-cookie-path"

local schema = {
    type = "object",
    properties = {
        path_pairs = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    cookie = {
                        type = "string",
                        minLength = 1,
                        description = "Cookie name to match; omit to match all cookies",
                    },
                    match = {
                        type = "string",
                        minLength = 1,
                    },
                    replacement = {
                        type = "string",
                    },
                },
                required = {"match", "replacement"},
            },
            minItems = 1,
        },
    },
    required = {"path_pairs"},
}

local _M = {
    version = 0.1,
    priority = 3990,  -- runs after response-rewrite (default 3995)
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- Extract cookie name from a Set-Cookie header value.
-- "sessionid=abc123; Path=/; HttpOnly" → "sessionid"
local function extract_cookie_name(header_value)
    if not header_value or header_value == "" then
        return nil
    end
    local name = header_value:match("^%s*([^=;]+)")
    if name then
        name = name:match("^%s*(.-)%s*$")
    end
    return name
end

-- Parse a Set-Cookie header value into the cookie portion and attributes.
-- Returns: cookie_parts (table of key=value segments), has_path (bool), path_index (number)
local function parse_set_cookie(header_value)
    if not header_value or header_value == "" then
        return nil
    end

    -- Split by "; " to get attributes
    local parts = {}
    local path_idx = nil

    local idx = 1
    for seg in header_value:gmatch("[^;]+") do
        local trimmed = seg:match("^%s*(.-)%s*$")
        parts[idx] = trimmed
        if trimmed:lower():match("^path=") then
            path_idx = idx
        end
        idx = idx + 1
    end

    return parts, path_idx ~= nil, path_idx
end

-- Reassemble Set-Cookie parts into a header value
local function assemble_set_cookie(parts)
    local result = parts[1]
    for i = 2, #parts do
        result = result .. "; " .. parts[i]
    end
    return result
end

-- Check if a match pattern is a regex (starts with ~)
local function is_regex_pattern(pattern)
    return pattern:sub(1, 1) == "~"
end

-- Extract the actual regex from a pattern (strip leading ~ and optional flag)
local function extract_regex(pattern)
    -- ~ regex, ~* case-insensitive regex
    local regex = pattern:match("^~[%*]?%s*(.+)$")
    return regex or pattern
end

-- Check if a pair should apply to the given cookie name.
-- If pair.cookie is nil/empty, it matches all cookies.
local function matches_cookie(pair, cookie_name)
    local target = pair.cookie
    if not target or target == "" then
        return true  -- no filter, matches all
    end
    return cookie_name == target
end

-- Apply path rewriting to a single Set-Cookie value
local function rewrite_cookie_path(value, conf)
    local cookie_name = extract_cookie_name(value)
    local parts, has_path, path_idx = parse_set_cookie(value)
    if not parts then
        return value
    end

    -- Extract current path value (case-insensitive: Path, PATH, path)
    local current_path = nil
    if has_path and path_idx then
        current_path = parts[path_idx]:match("^[Pp][Aa][Tt][Hh]=(.*)$")
    end

    -- If no path attribute, no rewrite needed
    if not current_path then
        return value
    end

    local new_path = nil

    for _, pair in ipairs(conf.path_pairs) do
        -- Skip if this pair targets a different cookie
        if matches_cookie(pair, cookie_name) then
            local match_pattern = pair.match
            local replacement = pair.replacement

            if is_regex_pattern(match_pattern) then
                -- Regex match
                local regex = extract_regex(match_pattern)
                local from, to, err = re.sub(current_path, regex, replacement, "jo")
                if err then
                    core.log.error("proxy-cookie-path: regex error: ", err)
                elseif from ~= current_path then
                    new_path = from
                    break
                end
            else
                -- Simple string match
                if current_path == match_pattern then
                    new_path = replacement
                    break
                end
            end
        end
    end

    if new_path then
        parts[path_idx] = "path=" .. new_path
        return assemble_set_cookie(parts)
    end

    return value
end

function _M.header_filter(conf, ctx)
    local set_cookie_headers = ngx.header["Set-Cookie"]
    if not set_cookie_headers then
        return
    end

    if type(set_cookie_headers) == "table" then
        local new_headers = {}
        for i, val in ipairs(set_cookie_headers) do
            new_headers[i] = rewrite_cookie_path(val, conf)
        end
        ngx.header["Set-Cookie"] = new_headers
    else
        local new_val = rewrite_cookie_path(set_cookie_headers, conf)
        if new_val ~= set_cookie_headers then
            ngx.header["Set-Cookie"] = new_val
        end
    end
end

return _M
