--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local plugin_name = "custom-error-page"

local ngx = ngx
local core = require("apisix.core")
local apisix_plugin = require("apisix.plugin")
local apisix_utils = require("apisix.core.utils")

local function default_html(img)
    return string.format([[
<!DOCTYPE html>
<html>
  <head>
    <style>
      * {
        margin: 0;
        padding: 0;
      }
      html, body {
        width: 100%%;
        height: 100%%;
      }
      img {
        display: block;
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        margin: auto;
      }
    </style>
  </head>
  <body>
    <img src="%s" alt="">
  </body>
</html>
]], img)
end

local function default_page(img)
    return {
        body = default_html(img),
        ["content-type"] = "text/html; charset=utf-8",
    }
end

local page_schema = {
    type = "object",
    additionalProperties = false,
    properties = {
        body = {
            type = "string",
        },
        ["content-type"] = {
            type = "string",
        },
    },
    required = {"body", "content-type"},
}

local conf_schema = {
    type = "object",
    additionalProperties = false,
    properties = {
        enable = {
            type = "boolean",
            default = true,
        },
        codes = {
            type = "array",
            minItems = 1,
            uniqueItems = true,
            default = {404, 500},
            items = {
                type = "integer",
                minimum = 400,
                maximum = 599,
            },
        },
        error_404 = page_schema,
        error_500 = page_schema,
        error_502 = page_schema,
        error_503 = page_schema,
    },
}

local _M = {
    version = 0.1,
    priority = 0,
    name = plugin_name,
    schema = conf_schema,
    metadata_schema = conf_schema,
}

local default_conf = {
    enable = true,
    codes = {404, 500},
    error_404 = default_page("/es404.png"),
    error_500 = default_page("/es500.png"),
}

local function make_response(page)
    return {
        body = page.body,
        headers = {
            ["Content-Type"] = page["content-type"],
        },
    }
end

local function status_in_codes(status, codes)
    for _, code in ipairs(codes or {}) do
        if code == status then
            return true
        end
    end

    return false
end

local function get_error_key(status)
    return "error_" .. tostring(status)
end

local function resolve_page(conf, status)
    local page = conf[get_error_key(status)]
    if page then
        return page
    end

    return conf.error_404
end

local function merge_conf(base, extra)
    if not extra then
        return base
    end

    if extra.enable ~= nil then
        base.enable = extra.enable
    end

    if extra.codes and #extra.codes > 0 then
        base.codes = extra.codes
    end

    for k, v in pairs(extra) do
        if type(k) == "string" and k:match("^error_%d%d%d$") then
            base[k] = v
        end
    end

    return base
end

local function get_effective_conf(plugin_conf)
    local effective_conf = {
        enable = true,
        codes = default_conf.codes,
        error_404 = default_conf.error_404,
        error_500 = default_conf.error_500,
    }

    local metadata = apisix_plugin.plugin_metadata(plugin_name)
    if metadata and metadata.value then
        effective_conf = merge_conf(effective_conf, metadata.value)
    end

    if plugin_conf and type(plugin_conf) == "table" then
        effective_conf = merge_conf(effective_conf, plugin_conf)
    end

    if not effective_conf.error_404 then
        effective_conf.error_404 = default_conf.error_404
    end

    return effective_conf
end

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(conf_schema, conf)
    end

    return core.schema.check(conf_schema, conf)
end

function _M.header_filter(conf, ctx)
    local effective_conf = get_effective_conf(conf)
    if not effective_conf.enable then
        return
    end

    if not status_in_codes(ngx.status, effective_conf.codes) then
        return
    end

    local page = resolve_page(effective_conf, ngx.status)
    if not page then
        return
    end

    local custom_response = make_response(page)

    for key, value in pairs(custom_response.headers) do
        ngx.header[key] = value
    end

    custom_response.body = apisix_utils.resolve_var(custom_response.body, ngx.var)

    ngx.header["Content-Length"] = #custom_response.body
    ngx.header["Content-Encoding"] = nil

    ctx.custom_error_page_body = custom_response.body
end

function _M.body_filter(_, ctx)
    if not ctx.custom_error_page_body then
        return
    end

    local body = core.response.hold_body_chunk(ctx)
    if ngx.arg[2] == false and not body then
        return
    end

    ngx.arg[1] = ctx.custom_error_page_body
    ngx.arg[2] = true
    ctx.custom_error_page_body = nil
end

return _M
