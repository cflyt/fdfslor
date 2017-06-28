local lor = require("lor.index")
local fsRouter = lor:Router() -- 生成一个group router对象

fsRouter:post("/new/", function(req, res, next)
    local data = {}
    -- for key, v in pairs(req) do
    --    data[key] = tostring(v)
    -- end
    -- for key, v in pairs(req.params) do
    --     data[key] = tostring(v)
    -- end
    args = req:args()
    for key, v in pairs(args) do
        data[key] = tostring(v)
    end

    if args.bigofile and args.bigofile.filename then
        file = args.bigofile.file
        file:seek("set", 0)
        local data
        while true do
            data = file:read(1024)
            if nil == data then
                break
            end
            ngx.print(data)
            ngx.flush(true)
        end
        file:close()
     else
         res:json({
             success = true,
             data = data
         })
     end

    local body_reader = req:body_reader()
    -- res:set_header("Content-Length", 600)
    -- ngx.send_headers()
    -- ngx.flush(true)
    -- local sock, err = ngx.req.socket(true)
    -- if not sock then
    --     ngx.log(ngx.ERR, "get socket fail: " ..  err)
    --     ngx.exit(500)
    -- end
    repeat
        local chunk, err = body_reader(100)
        if err then
            ngx.log(ngx.ERR, err)
            break
        end

        if chunk then
            --sock:send(chunk)
            ngx.print(chunk)
        end
    until not chunk
end)


return fsRouter


