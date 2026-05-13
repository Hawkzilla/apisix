--
-- session-cookie-hash plugin
--
-- Reads a configured session cookie, hashes it, and writes the hash into a
-- request header (default: X-Session-Hash). This only prepares a hash value;
-- the actual sticky routing policy must be configured separately, for example
-- with BackendTrafficPolicy or another APISIX upstream/load-balancing resource.
--
-- Example config:
--   cookie_name: "INGRESSCOOKIE"
--   algorithm: "sha1"          -- sha1 | md5 | sha256
--   header_name: "X-Session-Hash"
--   fallback: "pass"           -- pass | empty
--   generate_cookie: true
--   cookie_path: "/"             -- optional; omit or set "" to skip Path
--   cookie_httponly: false
--

local core = require("apisix.core")
local cookie = require("resty.cookie")
local ngx = ngx

local plugin_name = "session-cookie-hash"

local schema = {
    type = "object",
    properties = {
        cookie_name = {
            type = "string",
            minLength = 1,
        },
        algorithm = {
            type = "string",
            enum = {"sha1", "md5", "sha256"},
        },
        header_name = {
            type = "string",
            minLength = 1,
            default = "X-Session-Hash",
        },
        fallback = {
            type = "string",
            enum = {"pass", "empty"},
            default = "pass",
        },
        generate_cookie = {
            type = "boolean",
            default = true,
        },
        cookie_path = {
            type = "string",
        },
        cookie_httponly = {
            type = "boolean",
            default = false,
        },
        cookie_secure = {
            type = "boolean",
            default = false,
        },
        cookie_samesite = {
            type = "string",
            enum = {"Lax", "Strict", "None"},
        },
    },
    required = {"cookie_name", "algorithm"},
}

local _M = {
    version = 0.1,
    priority = 3990,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function hash_value(value, algorithm)
    if algorithm == "sha1" then
        return ngx.sha1_bin(value)
    end
    if algorithm == "md5" then
        return ngx.md5_bin(value)
    end
    -- sha256
    return ngx.sha256_bin(value)
end

local function to_hex(binary)
    return (binary:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function generate_cookie_value(conf, ctx)
    local seed = table.concat({
        ngx.now(),
        ngx.worker.pid(),
        ngx.var.connection or "",
        ngx.var.connection_requests or "",
        ngx.var.request_id or "",
        ngx.var.remote_addr or "",
        conf.cookie_name,
    }, ":")

    return to_hex(hash_value(seed, conf.algorithm))
end

local function append_request_cookie(cookie_name, cookie_value)
    local headers = ngx.req.get_headers()
    local current = headers["Cookie"] or headers["cookie"]

    if current and current ~= "" then
        ngx.req.set_header("Cookie", current .. "; " .. cookie_name .. "=" .. cookie_value)
        return
    end

    ngx.req.set_header("Cookie", cookie_name .. "=" .. cookie_value)
end

local function build_set_cookie(conf, value)
    local parts = {
        conf.cookie_name .. "=" .. value,
    }

    if conf.cookie_path and conf.cookie_path ~= "" then
        parts[#parts + 1] = "Path=" .. conf.cookie_path
    end

    if conf.cookie_httponly then
        parts[#parts + 1] = "HttpOnly"
    end
    if conf.cookie_secure then
        parts[#parts + 1] = "Secure"
    end
    if conf.cookie_samesite then
        parts[#parts + 1] = "SameSite=" .. conf.cookie_samesite
    end

    return table.concat(parts, "; ")
end

local function append_set_cookie(value)
    local current = ngx.header["Set-Cookie"]
    if not current then
        ngx.header["Set-Cookie"] = value
        return
    end

    if type(current) == "table" then
        current[#current + 1] = value
        ngx.header["Set-Cookie"] = current
        return
    end

    ngx.header["Set-Cookie"] = {current, value}
end

function _M.rewrite(conf, ctx)
    local ck, err = cookie:new()
    if not ck then
        core.log.error("session-cookie-hash: failed to init cookie reader: ", err)
        return
    end

    local v, get_err = ck:get(conf.cookie_name)
    if get_err then
        core.log.info("session-cookie-hash: cookie ", conf.cookie_name, " not found: ", get_err)
    end

    if not v or v == "" then
        if conf.generate_cookie ~= false then
            v = generate_cookie_value(conf, ctx)
            append_request_cookie(conf.cookie_name, v)
            ctx.session_cookie_hash_set_cookie = build_set_cookie(conf, v)
        end
    end

    if not v or v == "" then
        if conf.fallback == "empty" then
            core.request.set_header(ctx, conf.header_name or "X-Session-Hash", "")
        end
        return
    end

    local digest_bin = hash_value(v, conf.algorithm)
    local digest_hex = to_hex(digest_bin)
    core.request.set_header(ctx, conf.header_name or "X-Session-Hash", digest_hex)
end

function _M.header_filter(conf, ctx)
    if ctx.session_cookie_hash_set_cookie then
        append_set_cookie(ctx.session_cookie_hash_set_cookie)
    end
end

return _M
