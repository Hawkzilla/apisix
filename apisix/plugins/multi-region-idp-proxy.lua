--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
--
-- multi-region-idp-proxy plugin
--
-- Migrates an nginx configuration-snippet that rewrites request cookies for
-- multi-region IDP/SP flows and optionally proxies to a region-specific
-- upstream from the region_url cookie.
--
-- Configuration:
--   proxy_scheme: "https"
--   proxy_port: 443
--   allowed_region_hosts: ["10.0.0.12", "idp.example.local"] -- optional
--   exclude_namespaces: ["multi-region", "iam"] -- optional; namespaces to skip
--   exclude_paths: ["/ems_dashboard_api/auth", ...] -- optional; paths to skip
--

local core     = require("apisix.core")
local upstream = require("apisix.upstream")
local ngx      = ngx
local pairs    = pairs

local plugin_name = "multi-region-idp-proxy"

local schema = {
    type = "object",
    properties = {
        proxy_scheme = {
            type = "string",
            enum = {"http", "https"},
            default = "https",
        },
        proxy_port = {
            type = "integer",
            minimum = 1,
            maximum = 65535,
            default = 443,
        },
        allowed_region_hosts = {
            type = "array",
            items = {
                type = "string",
                minLength = 1,
            },
        },
        exclude_namespaces = {
            type = "array",
            items = {
                type = "string",
                minLength = 1,
            },
        },
        exclude_paths = {
            type = "array",
            items = {
                type = "string",
                minLength = 1,
            },
        },
    },
}

local _M = {
    version = 0.1,
    priority = 1009,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function cookie(name)
    return ngx.var["cookie_" .. name] or ""
end

local function set_request_header(ctx, name, value)
    if value and value ~= "" then
        core.request.set_header(ctx, name, value)
    end
end

local function join_cookie(parts)
    local out = {}
    for _, item in ipairs(parts) do
        if item.value and item.value ~= "" then
            out[#out + 1] = item.name .. "=" .. item.value
        end
    end
    return table.concat(out, ";")
end

local function normalize_host(value)
    if not value or value == "" then
        return nil
    end

    value = value:gsub("^https?://", "")
    value = value:gsub("/.*$", "")
    value = value:gsub("%s+", "")

    if value == "" then
        return nil
    end
    return value
end

local function host_allowed(conf, host)
    if not conf.allowed_region_hosts or #conf.allowed_region_hosts == 0 then
        return true
    end

    for _, allowed in ipairs(conf.allowed_region_hosts) do
        if host == allowed then
            return true
        end
    end
    return false
end

local function route_namespace(ctx)
    local route = ctx.matched_route
    if not route or not route.value or not route.value.name then
        return nil
    end

    -- 路由名由 apisix-ingress-controller 以 "<namespace>_<name>_<rule>"
    -- 的形式生成,而 k8s 的 namespace 是 DNS-1123 标签(不含下划线),
    -- 因此第一个 "_" 之前的部分就是 namespace。
    local name = route.value.name
    local pos = name:find("_", 1, true)
    if not pos then
        return nil
    end
    return name:sub(1, pos - 1)
end

local function namespace_excluded(conf, ns)
    if not conf.exclude_namespaces or #conf.exclude_namespaces == 0 then
        return false
    end

    if not ns then
        return false
    end

    for _, excluded in ipairs(conf.exclude_namespaces) do
        if ns == excluded then
            return true
        end
    end
    return false
end

local function path_excluded(conf, uri)
    if not conf.exclude_paths or #conf.exclude_paths == 0 then
        return false
    end

    if not uri then
        return false
    end

    -- 去掉 query string(如 /xx?yy=zz 只比较 /xx)。
    local q = uri:find("?", 1, true)
    if q then
        uri = uri:sub(1, q - 1)
    end

    for _, excluded in ipairs(conf.exclude_paths) do
        -- 去掉 excluded 末尾斜杠,统一处理
        local e = excluded
        while #e > 1 and e:sub(-1) == "/" do
            e = e:sub(1, -2)
        end

        -- 精确匹配:uri 必须等于 e,或等于 e 加一个尾斜杠
        -- (尾斜杠之后不能再有其它路径段)。
        if uri == e or uri == e .. "/" then
            return true
        end
    end
    return false
end

local function set_dynamic_upstream(ctx, conf, host)
    -- 当插件以全局规则运行时,未匹配任何路由的请求走到这里时
    -- ctx.matched_route 为 nil,提前返回以避免下方解引用空路由报错。
    if not ctx.matched_route then
        return
    end

    if not host_allowed(conf, host) then
        core.log.warn("multi-region-idp-proxy: blocked region host: ", host)
        return
    end

    local port = conf.proxy_port or 443
    if host:find(":", 1, true) then
        -- host already contains port, e.g. "10.0.0.12:8443"
        local h, p = core.utils.parse_addr(host)
        host = h
        port = p
    end

    local up_conf = {
        type = "roundrobin",
        scheme = conf.proxy_scheme or "https",
        pass_host = "pass",
        nodes = {
            {host = host, port = port, weight = 1},
        },
    }

    local ok, err = upstream.check_schema(up_conf)
    if not ok then
        core.log.error("multi-region-idp-proxy: invalid upstream schema: ", err)
        return
    end

    local matched_route = ctx.matched_route
    up_conf.parent = matched_route

    local upstream_key = "multi-region-idp-proxy#route_"
        .. matched_route.value.id .. "_" .. host .. ":" .. port

    -- 使用路由自身的版本号而非 ctx.conf_version:以全局规则运行时,
    -- rewrite 阶段 ctx.conf_version 会被临时替换成全局规则的版本号。
    upstream.set(ctx, upstream_key, matched_route.modifiedIndex, up_conf)

    -- 关键:仅设置 upstream_conf 不足以让 nginx 以 https 连接上游,
    -- 必须同步 upstream_scheme,否则 proxy_pass 会以明文 http 连上游,
    -- 表现为 "400 The plain HTTP request was sent to HTTPS port"。
    upstream.set_scheme(ctx, up_conf)
end

local function handle_from_idp(ctx)
    local sp_cookie = join_cookie({
        {name = "sessionid", value = cookie("sp_sessionid")},
        {name = "escookie", value = cookie("sp_escookie")},
        {name = "csrftoken", value = cookie("sp_csrftoken")},
        {name = "ems_dashboard_api_language", value = cookie("sp_ems_dashboard_api_language")},
    })

    set_request_header(ctx, "Cookie", sp_cookie)
    set_request_header(ctx, "X-Csrftoken", cookie("sp_csrftoken"))
    ctx.multi_region_clear_set_cookie = true
end

local function handle_region_url(ctx, conf)
    local host = normalize_host(cookie("region_url"))
    if not host then
        return
    end

    local sp_cookie = join_cookie({
        {name = "sessionid", value = cookie("sessionid")},
        {name = "escookie", value = cookie("escookie")},
        {name = "csrftoken", value = cookie("csrftoken")},
        {name = "sp_sessionid", value = cookie("sp_sessionid")},
        {name = "sp_escookie", value = cookie("sp_escookie")},
        {name = "sp_csrftoken", value = cookie("sp_csrftoken")},
        {name = "sp_ems_dashboard_api_language", value = cookie("sp_http_language")},
        {name = "region_label", value = "fromidp"},
    })

    set_request_header(ctx, "Cookie", sp_cookie)
    set_request_header(ctx, "X-Forwarded-Host", ctx.var.host)
    set_dynamic_upstream(ctx, conf, host)
end

function _M.rewrite(conf, ctx)
    local uri = ctx.var.uri
    local ns = route_namespace(ctx)
    local raw_cookie = ngx.var.http_cookie or ""

    core.log.warn("multi-region-idp-proxy: path=", uri, " namespace=", tostring(ns))

    if namespace_excluded(conf, ns) or path_excluded(conf, uri) then
        core.log.warn("multi-region-idp-proxy: SKIP(excluded) uri=", uri,
                      " namespace=", tostring(ns))
        return
    end



    if raw_cookie:find("region_label=fromidp", 1, true) then
        core.log.warn("multi-region-idp-proxy: branch=from_idp")
        ctx.skip_proxy_rewrite = true
        handle_from_idp(ctx)
        return
    end

    if raw_cookie:find("region_url=", 1, true) then
        local region_url = raw_cookie:match("region_url=([^;]+)")
        if region_url and region_url ~= "" and region_url ~= ctx.var.host then
            ctx.skip_proxy_rewrite = true
            handle_region_url(ctx, conf)
            core.log.warn("multi-region-idp-proxy: branch=region_url")
        end
    end
end

local function should_drop_set_cookie(value)
    if not value then
        return false
    end

    local lower = value:lower()
    return lower:find("^sessionid=") ~= nil or lower:find("^csrftoken=") ~= nil
end

-- 判断是否为 "sessionid 值为空" 的 Set-Cookie(即删除 sessionid 的指令)
local function is_empty_session_cookie(value)
    if not value then
        return false
    end

    local lower = value:lower()
    return lower:find("^sessionid=;") ~= nil or lower:find("^sessionid=$") ~= nil
end

-- 把 Location 里的 host 替换为当前请求的 host(保留 scheme/端口/路径)
local function rewrite_location_host(location, new_host)
    if not location or not new_host then
        return location
    end

    local scheme, host_port, rest = location:match("^(https?://)([^/]+)(.*)$")
    if not scheme or not host_port then
        return location
    end

    local host = host_port:match("^([^:]+)")
    if not host or host == new_host then
        return location
    end

    return scheme .. new_host .. host_port:sub(#host + 1) .. rest
end

function _M.header_filter(conf, ctx)
    -- 打印上游返回的原始状态码和 Location
    core.log.warn("multi-region-idp-proxy: upstream_status=",
                  tostring(ngx.var.upstream_status),
                  " upstream_location=", tostring(ngx.var.upstream_http_location))

    -- 把 Location 里的 host 改写为当前请求的 host
    local location = ngx.header["Location"]
    if location then
        local current_host = ctx.var.host
        if type(location) == "table" then
            for i, v in ipairs(location) do
                location[i] = rewrite_location_host(v, current_host)
            end
            ngx.header["Location"] = location
        else
            ngx.header["Location"] = rewrite_location_host(location, current_host)
        end
        core.log.warn("multi-region-idp-proxy: rewritten_location=",
                      tostring(ngx.header["Location"]))
    end

    local set_cookie = ngx.header["Set-Cookie"]
    if not set_cookie then
        return
    end

    local function should_drop(value)
        -- 无条件拦截 "sessionid 值为空" 的 Set-Cookie
        if is_empty_session_cookie(value) then
            return true
        end
        -- from_idp 分支下,额外拦截 sessionid=/csrftoken= 开头的
        if ctx.multi_region_clear_set_cookie and should_drop_set_cookie(value) then
            return true
        end
        return false
    end

    if type(set_cookie) == "table" then
        local kept = {}
        for _, value in ipairs(set_cookie) do
            if not should_drop(value) then
                kept[#kept + 1] = value
            end
        end

        if #kept == 0 then
            ngx.header["Set-Cookie"] = nil
        else
            ngx.header["Set-Cookie"] = kept
        end
        return
    end

    if should_drop(set_cookie) then
        ngx.header["Set-Cookie"] = nil
    end
end

return _M
