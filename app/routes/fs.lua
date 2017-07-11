local lor = require("lor.index")
local fdfsClient = require("fastdfs.fdfs_client")
local fsinfo = require("fastdfs.fdfs_fileinfo")
local utils = require("app.utils")
local slen = string.len
local ssub = string.sub
local smatch = string.match
local fsRouter = lor:Router() -- 生成一个group router对象
local fdfs = fdfsClient:new()
fdfs:set_trackers({{host="192.168.56.10",port=22122}})
fdfs:set_timeout(20)
fdfs:set_tracker_keepalive(0, 100)
fdfs:set_storage_keepalive(0, 100)
local default_chunk_size = 32*1024


local function _getextension(filename)
    ngx.log(ngx.ERR, "form file name:", filename)
    return smatch(filename, ".+%.(%w+)$")
end

fsRouter:post("/new/", function(req, res, next)
    local reader = nil
    local filesize = 0
    local ext_name = nil
    local args = req:args()
    for k,v in pairs(args) do
        ngx.log(ngx.ERR, k .. tostring(v))
    end
    if req:is_multipart() then
        local args = req:args()
        if args.bigofile and args.bigofile.filename then
            ext_name = _getextension(args.bigofile.filename)
            file = args.bigofile.file
            file:seek("set", 0)
            filesize = file:seek("end")
            file:seek("set", 0)
            reader = utils.make_reader(file, default_chunk_size)
        end
    else
        reader = req:body_reader(default_chunk_size)
        filesize = req.content_length
    end
    ngx.log(ngx.ERR, "filesize ", filesize, " ext ", ext_name, "chunk ", default_chunk_size)
    local fileid = nil
    local group = nil
    local re, err = fdfs:do_upload(group, reader, filesize, ext_name, default_chunk_size)
    if not re then
        ngx.say("ERR: " .. err)
        ngx.exit(500)
    elseif re then
        fileid = string.format("%s/%s",re.group_name, re.file_name)
    else
        ngx.exit(406)
    end

    local fileinfo = fsinfo.get_fileinfo(fileid)
    fileinfo["file_id"] = fileid
    res:set_header("Content-Length", string.len(utils.dump(fileinfo)))
    res:send(utils.dump(fileinfo))
    --res:json({
    --    success = true,
    --    data = args
    --})

    -- local body_reader = req:body_reader()
    -- res:set_header("Content-Length", 600)
    -- ngx.send_headers()
    -- ngx.flush(true)
    -- local sock, err = ngx.req.socket(true)
    -- if not sock then
    --     ngx.log(ngx.ERR, "get socket fail: " ..  err)
    --     ngx.exit(500)
    -- end
    -- repeat
    --     local chunk, err = body_reader(100)
    --     if err then
    --         ngx.log(ngx.ERR, err)
    --         break
    --     end

    --     if chunk then
    --         --sock:send(chunk)
    --         ngx.print(chunk)
    --     end
    -- until not chunk
end)


fsRouter:post("/appender/", function(req, res, next)

    ngx.log(ngx.ERR, "appender request" )
    local reader = nil
    local filesize = 0
    local args = req:args()
    if req:is_multipart() then
        local args = req:args()
        if args.bigofile and args.bigofile.filename then
            local extname = _getextension(args.bigofile.filename)
            file = args.bigofile.file
            file:seek("set", 0)
            filesize = file:seek("end")
            file:seek("set", 0)
            reader = utils.make_reader(file, default_chunk_size)
        end
    else
        reader = req:body_reader(default_chunk_size)
        filesize = req.content_length
    end
    ngx.log(ngx.ERR, "filesize ", filesize, " ext ", ext_name, "chunk ", default_chunk_size)
    local fileid = nil
    local group = nil
    --local re, err = fdfs:do_upload2(reader, filesize, ext_name, default_chunk_size)
    local re, err = fdfs:do_upload_appender(group, reader, filesize, ext_name, default_chunk_size)
    if not re then
        ngx.say("ERR: " .. err)
        ngx.exit(500)
    elseif re then
        fileid = string.format("%s/%s",re.group_name, re.file_name)
    else
        ngx.exit(406)
    end

    local fileinfo = fsinfo.get_fileinfo(fileid)
    fileinfo["file_id"] = fileid
    res:set_header("Content-Length", string.len(utils.dump(fileinfo)))
    res:send(utils.dump(fileinfo))

end)

fsRouter:patch("/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
    ngx.log(ngx.ERR, "append request" )
    local reader = nil
    local filesize = 0
    local args = req:args()
    if req:is_multipart() then
        local args = req:args()
        if args.bigofile and args.bigofile.filename then
            local extname = _getextension(args.bigofile.filename)
            file = args.bigofile.file
            file:seek("set", 0)
            filesize = file:seek("end")
            file:seek("set", 0)
            reader = utils.make_reader(file, default_chunk_size)
        end
    else
        reader = req:body_reader(default_chunk_size)
        filesize = req.content_length
    end
    ngx.log(ngx.ERR, "filesize ", filesize, " ext ", ext_name, "chunk ", default_chunk_size)
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    --local re, err = fdfs:do_upload2(reader, filesize, ext_name, default_chunk_size)
    local re, err = fdfs:do_append(fileid, reader, filesize, default_chunk_size)
    if not re then
        --ngx.say("ERR: " .. (err or "append failed"))
        ngx.exit(500)
    elseif re then
        res:set_header("Content-Length", string.len(utils.dump(re)))
        res:send(utils.dump(re))
    else
        ngx.exit(406)
    end

    -- ngx.log(ngx.ERR, utils.dump(args))
    --res:json({
    --    success = true,
    --    data = args
    --})

end)

fsRouter:get("/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
    ngx.log(ngx.ERR, "download file~~~~~~~" .. req.uri)
    -- ngx.say(req.params.group_id)
    -- ngx.say(req.params.storage_path)
    -- ngx.say(req.params.dir1)
    -- ngx.say(req.params.dir2)
    -- ngx.say(req.params.filename)
    -- ngx.say(type(ngx.socket.tcp()))
    ngx.log(ngx.ERR, tostring(req.range))
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    local start, stop = 0, 0
    if req.range then
        start = req.range.start
        stop = req.range.stop
    end
    local fileinfo = fsinfo.get_fileinfo(fileid)
    local filesize = fileinfo.filesize
    if fileinfo.is_appender then
        local update_info = fdfs:get_fileinfo_from_storage(fileid)
        if update_info then
            filesize = update_info.filesize
        end
    end
    local reader, len = fdfs:do_download(fileid, start, stop)
    if not reader then
        return res:status(500):send("can not read")
    end
    res:set_header("Content-Length", len)
    if req.range then
        req.range.stop = req.range.start + len
        res:set_header("Content-Range", tostring(req.range:content_range(filesize)))
        res:status(206)
    else
        res:status(200)
    end
    if len == 0 then
        ngx.eof()
    else
        while true do
            local chunk = reader(1024, len)
            if not chunk then
                break
            end
            res:send(chunk)
            ngx.flush(true)
        end
        ngx.eof()
    end

end)

fsRouter:get("info/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    local fileinfo = fsinfo.get_fileinfo(fileid)
    -- local fileinfo = fdfs:get_fileinfo_from_storage(fileid)
    if fileinfo then
        res:status(200)
        res:json(fileinfo)
    else
        res:status(400)
        res:send("cann't get file info")
    end
end)

return fsRouter
