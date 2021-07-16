local etcdv3  = require("etcd.v3")
local require = require
local pcall   = pcall

local _M = {version = 0.9}

-- 默认使用json
local function require_serializer(serializer_name)
    if serializer_name then
        local ok, module = pcall(require, "etcd.serializers." .. serializer_name)
        if ok then
            return module
        end
    end
    return require("etcd.serializers.json")
end

function _M.new(opts)
    opts = opts or {}
    if type(opts) ~= "table" then
        return nil, 'opts must be table'
    end

    opts.timeout = opts.timeout or 5    -- 5 sec
    opts.http_host = opts.http_host or "http://127.0.0.1:2379"
    opts.ttl  = opts.ttl or -1

    local protocol = opts and opts.protocol or "v3" --默认v3
    local serializer_name = (type(opts.serializer) == "string") and opts.serializer
    Log.d("serializeer name =",serializer_name)
    opts.serializer = require_serializer(serializer_name)
    opts.api_prefix = "/v3"
    return etcdv3.new(opts)
end


return _M
