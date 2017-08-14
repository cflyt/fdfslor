local lor = require("lor.index")
local fdfsClient = require("fastdfs.fdfs_client")
local fsinfo = require("fastdfs.fdfs_fileinfo")
local iputils = require("fastdfs.ip")
local utils = require("app.utils")
local slen = string.len
local ssub = string.sub
local smatch = string.match
local sendfile = sendfile
local fsRouter = lor:Router() -- 生成一个group router对象
local fdfs = fdfsClient:new()
--fdfs:set_trackers({{host="192.168.56.10",port=22122}})
--fdfs:set_timeout(20)
--fdfs:set_tracker_keepalive(0, 100)
--fdfs:set_storage_keepalive(0, 100)
--
local config = require("conf.config")
local storage_ids = config.storage_ids
local store_paths = config.store_paths
local FILE_SYNC_MAX_TIME = config.file_sync_max_time
fdfs:set_timeout(config.tracker_timeout)
fdfs:set_trackers(config.trackers)
fdfs:set_tracker_keepalive(config.tracker_keepalive)
fdfs:set_storage_keepalive(config.storage_keepalive)

local FDFS_FILE_EXT_NAME_MAX_LEN =  6
local FDFS_TRUNK_FILE_HEADER_SIZE = 17 + FDFS_FILE_EXT_NAME_MAX_LEN + 1

local default_chunk_size = 32*1024


local function _getextension(filename)
    return smatch(filename, ".+%.(%w+)$")
end

fsRouter:post("/file/new/", function(req, res, next)
    local reader = nil
    local filesize = 0
    local ext_name = nil
    local args = req:args()
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
    if not reader then
        --ngx.say("ERR: upload reader is nil")
        ngx.exit(500)
        return
    end
    local fileid = nil
    local group = nil
    local re, err = fdfs:do_upload(group, reader, filesize, ext_name, default_chunk_size)
    if not re then
        res:status(500):send("ERR: " .. err)
        return
    elseif re then
        fileid = string.format("%s/%s",re.group_name, re.file_name)
    else
        ngx.exit(406)
        return
    end

    local fileinfo = fsinfo.get_fileinfo(fileid)
    fileinfo["file_id"] = fileid

    local json_str = string.format('{"fileid":"%s", "crc32": %s}', fileid, fileinfo.crc32)
    res:set_header("Content-Length", string.len(json_str))
    res:set_header('Content-Type', 'application/json; charset=utf-8')
    res:send(json_str)
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


fsRouter:post("/file/appender/", function(req, res, next)
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
    local fileid = nil
    local group = nil
    --local re, err = fdfs:do_upload2(reader, filesize, ext_name, default_chunk_size)
    local re, err = fdfs:do_upload_appender(group, reader, filesize, ext_name, default_chunk_size)
    if not re then
        res:status(500):send("ERR: " .. err)
        return
    elseif re then
        fileid = string.format("%s/%s",re.group_name, re.file_name)
    else
        ngx.exit(406)
    end

    local fileinfo = fsinfo.get_fileinfo(fileid)

    local json_str = string.format('{"fileid":"%s", "crc32": %s}', fileid, fileinfo.crc32)
    res:set_header("Content-Length", string.len(json_str))
    res:set_header('Content-Type', 'application/json; charset=utf-8')
    res:send(json_str)

end)

fsRouter:patch("/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
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
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    --local re, err = fdfs:do_upload2(reader, filesize, ext_name, default_chunk_size)
    local re, err = fdfs:do_append(fileid, reader, filesize, default_chunk_size)
    if not re then
        res:status(500):send("ERR: " .. (err or "append failed"))
        return
    elseif re then
        ngx.exit(204)
        return
    else
        ngx.exit(406)
    end

    -- ngx.log(ngx.ERR, utils.dump(args))
    --res:json({
    --    success = true,
    --    data = args
    --})

end)

local function get_source_ip_port(fileinfo)
    if not fileinfo then
       return nil, nil
    end
    local source_ip_addr = fileinfo.source_ip_addr
    local source_port = nil
    if source_ip_addr == "" then
        if not fileinfo.source_id or fileinfo.source_id == "" then
            return nil,nil
        end
        if storage_ids[fileinfo.source_id] then
            source_ip_addr = storage_ids[fileinfo.source_id].ip
            source_port = storage_ids[fileinfo.source_id].port
        end
    end
    if not source_ip_addr or source_ip_addr == "" then
        return nil,nil
    end
    return source_ip_addr, source_port
end

local function is_local_ip(source_ip_addr)
    if not source_ip_addr or source_ip_addr == "" then
        return false
    end
    local g_cache = ngx.shared.g_cache or {}
    local ips = g_cache:get("local_ips")
    if not ips then
        local table_ips = iputils.get_local_ip()
        ips = table.concat(table_ips, ";")
        local succ, err, forcible = g_cache:set("local_ips", ips)
        if not succ then
            ngx.log(ngx.ERR, "set cache err:", err)
        end
    end
    if string.match(ips, source_ip_addr) then
        return true
    else
        return false
    end
end

local function get_full_path_file(store_path_str, high_dir, low_dir, filename, fileinfo)
    store_path_str = string.sub(store_path_str, 2)  --M00, get 00
    local store_path_index = tonumber(store_path_str, 16)
    local store_path = string.format("%s/data", store_paths[store_path_index+1])
    local filesize = nil
    local offset = 0
    if fileinfo and fileinfo.is_trunk then
        filename = string.format("%06d", fileinfo.trunk_id)
        offset = fileinfo.offset
        filesize = fileinfo.filesize
    end
    local full_filepath = string.format("%s/%s/%s/%s",
                                store_path,
                                high_dir,
                                low_dir,
                                filename)
    ngx.log(ngx.DEBUG, "full file path:", full_filepath)
    return full_filepath
end

fsRouter:get("/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
    ngx.log(ngx.DEBUG, tostring(req.range))
    ngx.log(ngx.DEBUG, utils.dump(req.params))
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    local start, stop = 0, 0
    if req.range then
        start = req.range.start
        stop = req.range.stop
    end

    local fileinfo, err = fsinfo.get_fileinfo_ex(req.params.filename)
    if not fileinfo then
        res:status(404):send("Not Fount")
        return
    end
    local source_ip_addr = get_source_ip_port(fileinfo)
    local filesize = fileinfo.filesize
    local reader, len ,err
    local is_exist_file = false
    local is_local_host = is_local_ip(source_ip_addr)
    local full_file_path = get_full_path_file(req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename, fileinfo)

    local fp, err = io.open(full_file_path, "rb")
    if fp then --file exist local
        local create_time = fileinfo.timestamp
        local now = ngx.now()
        local elapse = now - create_time
        if is_local_host or elapse > FILE_SYNC_MAX_TIME then
            local offset = 0
            if fileinfo.is_trunk then
                offset = fileinfo.offset or 0
                fp:seek("set", offset)
                local trunk_header = fp:read(FDFS_TRUNK_FILE_HEADER_SIZE)
                --ngx.log(ngx.ERR, "trunk header:", trunk_header)
                if string.len(trunk_header) ~= FDFS_TRUNK_FILE_HEADER_SIZE then
                    res:status(404):send("File Not Found")
                    return
                end
                local file_type = string.sub(trunk_header, 1, 1)
                --ngx.log(ngx.ERR, "file type:", file_type)
                if file_type == '\0' then
                    res:status(404):send("File Not Found")
                    return
                end
                offset = offset + FDFS_TRUNK_FILE_HEADER_SIZE
            end

            if fileinfo.is_slave or fileinfo.is_appender then
                fp:seek("set", 0)
                filesize = fp:seek("end")
            end
            if req.range then
                start, stop = req.range:range_for_length(filesize)
                if not start then
                    res:status(400):send("Invalid Range")
                    return
                end
            else
                start = 0
                stop = filesize
            end
            offset = offset + start

            --directly use sendfile zero copy
            if sendfile then
                ngx.log(ngx.DEBUG, "local file, use sendfile")
                fp:close()
                res:set_header("Content-Length", stop-start)
                if req.range then
                    req.range.start = start
                    req.range.stop = stop
                    res:set_header("Content-Range", tostring(req.range:content_range(filesize)))
                    res:set_header("Cache-Control", "max-age=315360000")
                    res:status(206)
                else
                    res:set_header("Cache-Control", "max-age=315360000")
                    res:status(200)
                end
                ngx.log(ngx.DEBUG, "start:", start, "stop:", stop, "offset:", offset)
                sendfile(full_file_path, offset, stop-start)
                return
            end

            ngx.log(ngx.DEBUG, "local file, use file:read()")
            --use file:read
            fp:seek("set", offset)
            reader = utils.make_reader(fp, chunk_size, stop-start,
                    function(fp)
                        fp:close()
                     end)
            len = stop - start
            is_exist_file = true
        end
    end

    local errno = nil
    if not is_exist_file then
        if not is_local_host then
            if config.remote_response_mode == "redirect" then
                ngx.log(ngx.DEBUG, "redirect response")
                return res:redirect("http://" .. source_ip_addr  .. ngx.var.request_uri)
            elseif config.remote_response_mode == "proxy" then
                ngx.log(ngx.DEBUG, "proxy response")
                return res:internal_redirect("/internal", {source_ip_addr=source_ip_addr})
            end
        end
        --appender file need get filesize from server
        if fileinfo.is_slave or fileinfo.is_appender then
            local update_info = fdfs:get_fileinfo_from_storage(fileid, source_ip_addr)
            if update_info then
                filesize = update_info.filesize
            end
        end
        if req.range then
            start, stop = req.range:range_for_length(filesize)
            if not start then
                res:status(400):send("Invalid Range")
                return
            end
        else
            start = 0
            stop = filesize
        end

        ngx.log(ngx.DEBUG, "storage response")
        reader, len, err = fdfs:do_download(fileid, start, stop, source_ip_addr)
        errno = len -- if failed, #2 return value marks status
    end

    if not reader then
        if errno then
            res:status(404):send("File Not Found, Err ", errno)
        else
            res:status(500):send("Can't Read, Err:".. err)
        end
        return
    end
    res:set_header("Content-Length", len)
    if req.range then
        req.range.start = start
        req.range.stop = stop
        res:set_header("Content-Range", tostring(req.range:content_range(filesize)))
        res:set_header("Cache-Control", "max-age=315360000")
        res:status(206)
    else
        res:set_header("Cache-Control", "max-age=315360000")
        res:status(200)
    end
    if len == 0 then
        ngx.eof()
    else
        while true do
            local chunk = reader(default_chunk_size, len)
            if not chunk then
                break
            end
            res:send(chunk)
            ngx.flush(true)
        end
        ngx.eof()
    end
end)

fsRouter:head("/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
    ngx.log(ngx.DEBUG, tostring(req.range))
    ngx.log(ngx.DEBUG, utils.dump(req.params))
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    local start, stop = 0, 0
    if req.range then
        start = req.range.start
        stop = req.range.stop
    end

    local fileinfo, err = fsinfo.get_fileinfo_ex(req.params.filename)
    if not fileinfo then
        res:status(404):send("Not Fount")
        return
    end
    local source_ip_addr = get_source_ip_port(fileinfo)
    local filesize = fileinfo.filesize
    local reader, len ,err
    local is_exist_file = false
    local is_local_host = is_local_ip(source_ip_addr)
    local full_file_path = get_full_path_file(req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename, fileinfo)

    local fp, err = io.open(full_file_path, "rb")
    if fp then --file exist local
        if fileinfo.is_slave or fileinfo.is_appender then
            fp:seek("set", 0)
            filesize = fp:seek("end")
        end
        fp:close()
    else
        if not is_local_host then
            if config.remote_response_mode == "redirect" then
                ngx.log(ngx.DEBUG, "redirect response")
                return res:redirect("http://" .. source_ip_addr  .. ngx.var.request_uri)
            elseif config.remote_response_mode == "proxy" then
                ngx.log(ngx.DEBUG, "proxy response")
                return res:internal_redirect("/internal", {source_ip_addr=source_ip_addr})
            end
        end
        --appender file need get filesize from server
        if fileinfo.is_slave or fileinfo.is_appender then
            local update_info = fdfs:get_fileinfo_from_storage(fileid, source_ip_addr)
            if update_info then
                filesize = update_info.filesize
            end
        end
    end

    if req.range then
        start, stop = req.range:range_for_length(filesize)
        if not start then
            res:status(400):send("Invalid Range")
            return
        end
    else
        start = 0
        stop = filesize
    end

    res:set_header("Content-Length", stop-start)
    res:set_header("Cache-Control", "max-age=315360000")
    res:set_header("Source-Ip-Addr",  source_ip_addr)
    res:set_header("Is-Trunk",  tostring(fileinfo.is_trunk))
    res:set_header("Is-Appender",  tostring(fileinfo.is_appender))
    res:set_header("Is-Slave",  tostring(fileinfo.is_slave))
    res:set_header("Create-Time",  os.date("%c", fileinfo.timestamp))
    if req.range then
        req.range.start = start
        req.range.stop = stop
        res:set_header("Content-Range", tostring(req.range:content_range(filesize)))
        res:status(206)
    else
        res:status(200)
    end

    ngx.eof()

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
        res:send("Cann't Get File Info")
    end
end)


fsRouter:delete("/:group_id/:storage_path/:dir1/:dir2/:filename", function(req, res, next)
    local token = req:args().token
    if not token then
        --ngx.exit(403)
        res:status(403)
        res:send("Require Token")
        return
    end
    local fileid = table.concat( {req.params.group_id,req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    local ok, err = fdfs:do_delete(fileid, source_ip_addr)
    res:status(200)
    if ok then
        local json_str = '{"status": 0}'
        res:set_header("Content-Length", string.len(json_str))
        res:send(json_str)
    else
        local json_str = string.format('{"status": -1, "err": %s}', err)
        res:set_header("Content-Length", string.len(json_str))
        res:send(json_str)
    end
end)


return fsRouter
