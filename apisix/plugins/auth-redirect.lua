--
-- auth-redirect.lua
-- Intercepts 401/403 responses and redirects to a signin URL.
-- Equivalent to NGINX Ingress's error_page 401 + buildAuthSignURL.
--
-- Behavior matches nginx-ingress buildAuthSignURL exactly:
--   1. Resolve variables ($host, $request_uri, $escaped_request_uri, $uri)
--   2. Parse the resolved URL to check if "rd" (or custom param) already exists
--   3. If no query params: append ?rd=<full_origin_url>
--   4. If has query params but no rd: append &rd=<full_origin_url>
--   5. If rd already exists: do nothing
--
-- The rd value is a FULL URL: scheme://host/path?query
-- (matches $pass_access_scheme://$http_host$request_uri in nginx-ingress)
--

local core = require("apisix.core")
local ngx   = ngx

local plugin_name = "auth-redirect"

local schema = {
    type = "object",
    properties = {
        signin_url = {
            type        = "string",
            description = "URL to redirect to when auth fails (401/403). Supports $host, $request_uri, $escaped_request_uri, $uri.",
        },
    },
    required = { "signin_url" },
}

local _M = {
    version   = 0.1,
    priority  = 4010,
    name      = plugin_name,
    schema    = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- safe_gsub escapes % in the replacement string so gsub won't interpret
-- %1, %2, etc. as capture indices.
local function safe_gsub(str, pattern, replacement)
    local safe_replacement = replacement:gsub("%%", "%%%%")
    return str:gsub(pattern, safe_replacement)
end

-- url_has_param checks if a URL query string contains the given parameter.
local function url_has_param(url, param_name)
    -- Find where query string starts
    local qs_start = url:find("?", 1, true)
    if not qs_start then
        return false
    end
    local qs = url:sub(qs_start + 1)

    -- Check for param= or param& at the beginning of qs
    if qs:sub(1, #param_name + 1) == param_name .. "=" then
        return true
    end
    -- Check for &param=
    if qs:find("&" .. param_name .. "=", 1, true) then
        return true
    end
    return false
end

-- url_has_query checks if a URL has any query string (contains ?)
local function url_has_query(url)
    return url:find("?", 1, true) ~= nil
end

function _M.header_filter(conf, ctx)
    local status = ngx.status

    if status ~= 401 and status ~= 403 then
        return
    end

    local signin_url = conf.signin_url
    if not signin_url then
        return
    end

    -- Resolve request context values
    local host = ctx.var.host or ngx.var.host or ""
    local uri = ctx.var.uri or ngx.var.uri or "/"
    local args = ngx.var.args or ""
    local request_uri = uri
    if args ~= "" then
        request_uri = uri .. "?" .. args
    end
    local escaped_request_uri = ngx.escape_uri(request_uri)

    -- Determine scheme (matches $pass_access_scheme)
    local scheme = ctx.var.scheme or ngx.var.scheme or "http"

    -- Build the full origin URL: scheme://host$escaped_request_uri
    -- Matches nginx-ingress's $pass_access_scheme://$http_host$escaped_request_uri
    -- Only the URI part is escaped; scheme://host remain readable
    local full_origin = scheme .. "://" .. host .. escaped_request_uri

    -- Replace variables in signin_url
    local redirect_url = signin_url
    redirect_url = safe_gsub(redirect_url, "%$escaped_request_uri", escaped_request_uri)
    redirect_url = safe_gsub(redirect_url, "%$request_uri", request_uri)
    redirect_url = safe_gsub(redirect_url, "%$host", host)
    redirect_url = safe_gsub(redirect_url, "%$uri", uri)

    -- Ensure URL has a path component (e.g. https://host → https://host/)
    -- Matches Go's url.Parse which normalizes "scheme://host" to "scheme://host/"
    if redirect_url:match("^%w+://[^/]+$") then
        redirect_url = redirect_url .. "/"
    end

    -- Append rd=<full_origin_url> unless "rd=" already present.
    -- Matches nginx-ingress's buildAuthSignURL logic exactly:
    --   no query params ? append ?rd= : (has rd ? keep : append &rd=)
    -- The rd value is NOT double-encoded; it's placed as a readable URL.
    if not url_has_param(redirect_url, "rd") then
        if not url_has_query(redirect_url) then
            redirect_url = redirect_url .. "?rd=" .. full_origin
        else
            redirect_url = redirect_url .. "&rd=" .. full_origin
        end
    end

    -- Override the response to a 302 redirect
    ngx.status = ngx.HTTP_MOVED_TEMPORARILY
    ngx.header["Location"] = redirect_url
    ngx.header["Content-Type"] = nil
    ngx.header["Content-Length"] = nil
end

return _M
