local core = require("apisix.core")

local plugin_name = "fixed-location-rewrite"

local schema = {
    type = "object",
    properties = {
        from_scheme = {
            type = "string",
            minLength = 1,
            default = "http://",
        },
        to_scheme = {
            type = "string",
            minLength = 1,
            default = "https://",
        },
        status_codes = {
            type = "array",
            minItems = 1,
            items = {
                type = "integer",
                minimum = 100,
                maximum = 599,
            },
            default = {301, 302, 303, 307, 308},
        },
    },
}

local _M = {
    version = 0.1,
    priority = 899,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.header_filter(conf, ctx)
    local current_status = ngx.status
    local matched = false

    for _, code in ipairs(conf.status_codes or {}) do
        if current_status == code then
            matched = true
            break
        end
    end

    if not matched then
        return
    end

    local location = ngx.header["Location"]
    if not location then
        return
    end

    if type(location) == "table" then
        location = location[1]
    end

    if type(location) ~= "string" then
        return
    end

    if location:sub(1, #conf.from_scheme) ~= conf.from_scheme then
        return
    end

    local rewritten = conf.to_scheme .. location:sub(#conf.from_scheme + 1)
    core.response.set_header("Location", rewritten)
end

return _M
