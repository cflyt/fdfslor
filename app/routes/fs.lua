local lor = require("lor.index")
local fdfsClient = require("fastdfs.fdfs_client")
local fsinfo = require("fastdfs.fdfs_fileinfo")
local iputils = require("fastdfs.ip")
local utils = require("app.utils")
local slen = string.len
local ssub = string.sub
local smatch = string.match
local tostring = tostring
local sendfile = sendfile
local bit = bit
local fsRouter = lor:Router() -- 生成一个group router对象
local fdfs = fdfsClient:new()
--fdfs:set_trackers({{host="192.168.56.10",port=22122}})
--fdfs:set_timeout(20)
--fdfs:set_tracker_keepalive(0, 100)
--fdfs:set_storage_keepalive(0, 100)
--
local http = require "resty.http"
local config = require("conf.config")
local storage_ids = config.storage_ids
local store_paths = config.store_paths
local storage_change_ip_history_map = config.storage_change_ip_history_map
local FILE_SYNC_MAX_TIME = config.file_sync_max_time
fdfs:set_timeout(config.tracker_timeout)
fdfs:set_trackers(config.trackers)
fdfs:set_tracker_keepalive(config.tracker_keepalive)
fdfs:set_storage_keepalive(config.storage_keepalive)

--lru cache
local lrucache = require "resty.lrucache"
local lruc, err = lrucache.new(1000)  -- allow up to 1000 items in the cache
if not lruc then
    return error("failed to create the lrccache: " .. (err or "unknown"))
end

local FDFS_LOGIC_FILE_NAME_MAX_LEN = 128
local FDFS_FILE_EXT_NAME_MAX_LEN =  6
local FDFS_TRUNK_FILE_HEADER_SIZE = 17 + FDFS_FILE_EXT_NAME_MAX_LEN + 1
local FDFS_TRUNK_FILE_TYPE_NONE =    '\0'
local FDFS_TRUNK_FILE_TYPE_REGULAR  = 'F'
local FDFS_TRUNK_FILE_TYPE_LINK   =  'L'

local default_chunk_size = 32*1024


local function _getextension(filename)
    return smatch(filename, ".+%.(%w+)$")
end

--data filename format:
--MHH/HH/HH/filename: HH for 2 uppercase hex chars
local function fdfs_check_data_filename(filename)
    local len = string.len(filename)
    if len < 10 then
        ngx.log(ngx.ERR, string.format("the length=%d of filename \"%s\" is too short", len, filename))
        return false
    end
    if string.sub(filename,1,1) ~= 'M' or
            not utils.is_upper_hex(string.sub(filename,2,2)) or
            not utils.is_upper_hex(string.sub(filename, 3, 3)) or
            string.sub(filename,4, 4) ~= '/' or
            not utils.is_upper_hex(string.sub(filename,5,5 )) or
            not utils.is_upper_hex(string.sub(filename, 6,6)) or
            string.sub(filename,7, 7) ~= '/' or
            not utils.is_upper_hex(string.sub(filename,8,8 )) or
            not utils.is_upper_hex(string.sub(filename, 9,9)) or
            string.sub(filename,10, 10) ~= '/' then

        ngx.log(ngx.ERR, string.format('the format of filename "%s" is invalid', filename))
        return false
    end

    return true
end

local function _file_type(buf)
    local c1, c2 = string.byte(buf, 1, 2)
    local typecode = tonumber(c1..c2)
    ngx.log(ngx.DEBUG, 'file code ', typecode)
    local code_map = {
        [7790] = 'exe',
        [7784] = 'midi',
        [8297] = 'rar',
        [255216] = 'jpg',
        [7173] = 'gif',
        [6677] = 'bmp',
        [13780] = 'png',
        [3533] = 'amr',
        [7368] = 'mp3',
    }
    return code_map[typecode] or 'unknown'
end

local function get_buddy_storages_from_id(storage_id, limit_num)
    if not storage_id or type(storage_id) ~= "number" then
        return nil
    end
    if not limit_num or limit_num <= 0 then
        limit_num = 3
    end
    local buddies = {}
    local index = bit.band(storage_id, 0x03) --最后两位
    local base = bit.lshift(bit.rshift(storage_id, 2), 2) --remove last two bit
    local bid
    for i=0, limit_num-1 do
        bid = base + i
        if bid ~= storage_id then
            table.insert(buddies, bid)
        end
    end
    return buddies
end

fsRouter:post("/file/new/", function(req, res, next)
    local reader = nil
    local filesize = 0
    local ext_name = nil
    local args = req:args()
    if req:is_multipart() then
        local args = req:args()
        if args.bigofile and args.file.filename then
            ext_name = _getextension(args.bigofile.filename)
            file = args.bigofile.file
            file:seek("set", 0)
            local ty = _file_type(file:read(2))
            ngx.log(ngx.DEBUG, 'file type ', ty)
            file:seek("set", 0)
            filesize = file:seek("end")
            file:seek("set", 0)
            reader = utils.make_reader(file, default_chunk_size,
                function(file)
                    file:close()
                end
            )
        end
    else
        reader = req:body_reader(default_chunk_size)
        filesize = req.content_length
    end
    if not reader then
        --ngx.say("ERR: upload reader is nil")
        res:status(500):send("Upload File Not Fount")
        --ngx.exit(500)
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
    local logic_filename = table.concat( {req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    if string.len(logic_filename) > FDFS_LOGIC_FILE_NAME_MAX_LEN then
        res:status(404):send("Not Fount")
        return
    end
    local fileid = table.concat( {req.params.group_id, logic_filename}, "/")

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
        if type(storage_ids) == "table" and storage_ids[fileinfo.source_id] then
            source_ip_addr = storage_ids[fileinfo.source_id].ip
            source_port = storage_ids[fileinfo.source_id].port
        end
    end
    if not source_ip_addr or source_ip_addr == "" then
        return nil,nil
    end
    if type(storage_change_ip_history_map) == "table" then
        source_ip_addr = storage_change_ip_history_map[source_ip_addr] or source_ip_addr
        ngx.log(ngx.DEBUG, 'source ip addr: ', source_ip_addr)
    end
    return source_ip_addr, source_port
end

local function has_same_trackers(group_name)
    if not group_name or group_name == "" then
        return false
    end
    local groups = lruc:get("tracker_groups")
    if not groups then
        ngx.log(ngx.DEBUG, "track groups set lrucache ")
        local res, err = fdfs:list_groups()
        if res and type(res) == "table" then
            own_groups = res["groups"] or {}
            groups = {}
            local count = res["count"] or 0
            for _, g in pairs(own_groups) do
                if g["group_name"] and g["group_name"] ~= "" then
                    groups[g["group_name"]] = 1
                end
            end
            if count > 0 then
                lruc:set("tracker_groups", groups)
            end
        end
    end
    if groups[group_name] then
        return true
    else
        return false
    end

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
    local errno = 404
    local logic_filename = table.concat( {req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    if string.len(logic_filename) > FDFS_LOGIC_FILE_NAME_MAX_LEN or not fdfs_check_data_filename(logic_filename) then
        res:status(404):send("Not Fount")
        return
    end
    local fileid = table.concat( {req.params.group_id, logic_filename}, "/")
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

    if config.group_name and req.params.group_id ~= config.group_name and req.params.group_id ~= "" then -- file not belong to this group
        is_exist_file = false
    else
        local full_file_path = get_full_path_file(req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename, fileinfo)
        local fp, err = io.open(full_file_path, "rb")
        if fp then --file exist local
            local create_time = fileinfo.timestamp
            local now = ngx.now()
            local elapse = now - create_time
            if is_local_host or elapse > FILE_SYNC_MAX_TIME or req.headers['Failover'] then
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
                    if file_type == FDFS_TRUNK_FILE_TYPE_NONE then
                        res:status(404):send("File Not Found")
                        return
                    elseif file_type ~= FDFS_TRUNK_FILE_TYPE_REGULAR and file_type ~= FDFS_TRUNK_FILE_TYPE_LINK then
                        res:status(404):send("File Type Invalid")
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
                        res:status(416):send("Invalid Range")
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

                ngx.log(ngx.DEBUG, "local file, use file:read(), chunk size ", default_chunk_size)
                --use file:read
                fp:seek("set", offset)
                reader = utils.make_reader(fp, default_chunk_size, stop-start,
                        function(fp)
                            fp:close()
                         end)
                len = stop - start
                is_exist_file = true
            end
        end
    end
    if not is_exist_file and not req.headers['Failover'] then
        if not is_local_host and config.remote_response_mode == "redirect" and source_ip_addr then
            ngx.log(ngx.DEBUG, "redirect response")
            return res:redirect("http://" .. source_ip_addr  .. ngx.var.request_uri)
        end
        if not is_local_host and config.remote_response_mode == "proxy" and source_ip_addr then
            ngx.req.set_header("Failover",  ngx.var.server_addr)
            return res:internal_redirect("/internal", {source_ip_addr=source_ip_addr})
        end

        local buddies_storage = get_buddy_storages_from_id(fileinfo.source_id) or {}
        local buddies_ip = {}
        table.insert(buddies_ip, source_ip_addr)
        for i, b_id in pairs(buddies_storage) do
            if storage_ids and type(storage_ids) == "table" and storage_ids[b_id] then
                local b_ip = storage_ids[b_id].ip
                table.insert(buddies_ip, b_ip)
            end
        end
        if table.getn(buddies_ip) then
            err = "Storage Ip List Empty"
        end
        ngx.log(ngx.DEBUG, "buddy storages  ", utils.dump(buddies_ip))

        if config.remote_response_mode == "proxy_lua" then
            ngx.req.set_header("Failover",  ngx.var.server_addr)
            ngx.log(ngx.DEBUG, "proxy_lua response")

            local ok, re, err
            local httpc = http.new()

            -- The generic form gives us more control. We must connect manually.
            httpc:set_timeout(config.proxy_connect_timeout or 1000)

            for i, b_ip in pairs(buddies_ip) do
                if not is_local_ip(b_ip) then
                    ok, err = httpc:connect(b_ip, 80)
                    if not ok then
                        ngx.log(ngx.ERR, b_ip, " http_lua connect error, ", err, ", try next storage ", buddies_ip[i+1])
                    else
                        re, err = httpc:proxy_request()
                        if not re then
                            ngx.log(ngx.ERR, b_ip, " http_lua download error, ", err, ", try next storage ", buddies_ip[i+1])
                        elseif re.status > 400 then
                            err = re:read_body()
                            ngx.log(ngx.ERR, b_ip, " http_lua download error, status ", re.status, ', ', err, ", try next storage ", buddies_ip[i+1])
                        else
                            break
                        end
                    end
                end
            end

            if not ok then
                res:status(500):send("Can't Connect upstream")
                return
            end

            httpc:proxy_response(re)
            local keepalive = config.proxy_keepalive
            if keepalive then
                httpc:set_keepalive(keepalive.timeout, keepalive.size)
            end
            return
        end

        -- storage query
        ngx.log(ngx.DEBUG, "storage response")
        if has_same_trackers(req.params.group_id) then
            ngx.log(ngx.DEBUG, "storage response, track failover")
            --appender file need get filesize from server
            if req.range and (fileinfo.is_slave or fileinfo.is_appender) then
                local update_info
                update_info, errno, err = fdfs:get_fileinfo_from_storage(fileid, source_ip_addr, true)
                if update_info then
                    filesize = update_info.filesize
                else
                    ngx.log(ngx.ERR, "slave or appender file get true filesize failed", err)
                    if errno then
                        res:status(404):send("Can't Read File Info, Err:".. err)
                    else
                        res:status(500):send("Can't Read File Info, Err:".. err)
                    end
                end
            end
            if req.range then
                start, stop = req.range:range_for_length(filesize)
                if not start then
                    res:status(416):send("Invalid Range")
                    return
                end
            else
                start = 0
                stop = filesize
            end

            ngx.log(ngx.DEBUG, 'query start ', start, ' stop ', stop, 'f_read_stop', f_read_stop, ' fileszie ', filesize)
            reader, len, err = fdfs:do_download(fileid, start, stop, source_ip_addr, true)
            errno = len -- if failed, #2 return value marks status
        else
            ngx.log(ngx.DEBUG, "storage response, storage failover")
            for i, b_ip in pairs(buddies_ip) do
                if not is_local_ip(b_ip) then
                    if filesize <= 0 and (fileinfo.is_slave or fileinfo.is_appender) then
                        local update_info
                        update_info, errno, err = fdfs:get_fileinfo_from_storage(fileid, b_ip, false)
                        if update_info then
                            filesize = update_info.filesize
                        else
                            ngx.log(ngx.ERR, b_ip, " slave or appender file get true filesize failed,", err, " try next ", buddies_ip[i+1])
                        end
                    end

                    if filesize > 0 then
                        if req.range then
                            start, stop = req.range:range_for_length(filesize)
                            if not start then
                                res:status(416):send("Invalid Range")
                                return
                            end
                        else
                            start = 0
                            stop = filesize
                        end
                        ngx.log(ngx.DEBUG, "query start ", start, " stop ", stop, " fileszie ", filesize)
                        reader, len, err = fdfs:do_download(fileid, start, stop, b_ip, false)
                        if reader then
                            break
                        else
                            errno = len -- if failed, #2 return value marks status
                            ngx.log(ngx.ERR, b_ip, " download err, ", err, ", try next storage ", buddies_ip[i+1])
                        end
                   end
                end
            end
        end
    end

    if not reader then
        if errno then
            res:status(404):send("File Not Found, Err " .. errno)
        else
            ngx.log(ngx.ERR, "Download Failed, " ..  tostring(err))
            res:status(500):send("Can't Read, Err:".. tostring(err))
        end
        return
    end
    if filesize <= 0 then
        filesize = len
    end
    if req.range then
        res:set_header("Content-Length", len)
        req.range.start = start
        req.range.stop = stop
        res:set_header("Content-Range", tostring(req.range:content_range(filesize)))
        res:set_header("Cache-Control", "max-age=315360000")
        res:status(206)
    else
        res:set_header("Content-Length", len)
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
    local logic_filename = table.concat( {req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    if string.len(logic_filename) > FDFS_LOGIC_FILE_NAME_MAX_LEN then
        res:status(404):send("Not Fount")
        return
    end
    local fileid = table.concat( {req.params.group_id, logic_filename}, "/")
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
            res:status(416):send("Invalid Range")
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
    local source_ip_addr = get_source_ip_port(fileinfo)
    if fileinfo and source_ip_addr then
        fileinfo["source_ip_addr"] = source_ip_addr
    end
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

    local logic_filename = table.concat( {req.params.storage_path, req.params.dir1, req.params.dir2, req.params.filename}, "/")
    if string.len(logic_filename) > FDFS_LOGIC_FILE_NAME_MAX_LEN then
        res:status(404):send("Not Fount")
        return
    end
    local fileid = table.concat( {req.params.group_id, logic_filename}, "/")
    local fileinfo, err = fsinfo.get_fileinfo_ex(req.params.filename)
    if not fileinfo then
        res:status(404):send("Not Fount")
        return
    end

    local source_ip_addr = get_source_ip_port(fileinfo)
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
