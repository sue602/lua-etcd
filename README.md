# lua-etcd

`
local etcd = require "etcd"
local cli, err = etcd.new()
if not cli then
    Log.e("etcd cli error:", err)
    return
end
local callback = function(status,content)
    print("status =",status)
    dump(content,"content =",10)
end
cli:watch('/foo',callback)
dump(res,"etcd get ==" .. tostring(err),10)
print("etcd watch ==",res,err)

<!-- set 设置 -->
curl -L http://localhost:2379/v3/kv/put   -X POST -d '{"key": "L2Zvbw==", "value": "InRlc3QyIg=="}'
`