
local utils = require("app.utils")
local lor_utils = require("lor.lib.utils.utils")
setmetatable(utils, {__index=lor_utils})
--local base64 = require("lor.lib.utils.base64")
--local base64 = require("lor.lib.utils.ee5_base64")
local base64 = require("app.fdfs_base64")
local iputils = require("lor.lib.utils.ip")
local string = string
local table  = table
local bit    = bit
local ngx    = ngx
local tonumber = tonumber
local setmetatable = setmetatable
local error = error
local type = type
local pairs = pairs
local tostring = tostring


local VERSION = '0.1'

local FDFS_PROTO_PKG_LEN_SIZE = 8
local TRACKER_PROTO_CMD_SERVICE_QUERY_STORE_WITHOUT_GROUP_ONE = 101
local TRACKER_PROTO_CMD_SERVICE_QUERY_STORE_WITH_GROUP_ONE = 104
local TRACKER_PROTO_CMD_SERVICE_QUERY_UPDATE = 103
local TRACKER_PROTO_CMD_SERVICE_QUERY_FETCH_ONE = 102
local STORAGE_PROTO_CMD_UPLOAD_FILE = 11
local STORAGE_PROTO_CMD_DELETE_FILE = 12
local STORAGE_PROTO_CMD_DOWNLOAD_FILE = 14
local STORAGE_PROTO_CMD_UPLOAD_SLAVE_FILE = 21
local STORAGE_PROTO_CMD_QUERY_FILE_INFO = 22
local STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE = 23
local STORAGE_PROTO_CMD_APPEND_FILE = 24
local FDFS_FILE_EXT_NAME_MAX_LEN = 6
local FDFS_PROTO_CMD_QUIT = 82
local TRACKER_PROTO_CMD_RESP = 100


--filename info
local FDFS_FILENAME_BASE64_LENGTH = 27
local FDFS_FILE_EXT_NAME_MAX_LEN = 6
local FDFS_STORAGE_STORE_PATH_PREFIX_CHAR = 'M'
local FDFS_STORAGE_ID_MAX_SIZE = 16
local FDFS_ONE_MB =  (1024 * 1024)
local FDFS_TRUNK_FILE_HEADER_SIZE = (17 + FDFS_FILE_EXT_NAME_MAX_LEN + 1)
local FDFS_GROUP_NAME_MAX_LEN = 16
local FDFS_MAX_SERVERS_EACH_GROUP = 32
local FDFS_MAX_GROUPS = 512
local FDFS_MAX_TRACKERS = 16

local FDFS_MAX_META_NAME_LEN = 64
local FDFS_MAX_META_VALUE_LEN = 256

local FDFS_FILE_PREFIX_MAX_LEN = 16
local FDFS_LOGIC_FILE_PATH_LEN = 10
local FDFS_TRUE_FILE_PATH_LEN =  6
local FDFS_FILENAME_BASE64_LENGTH = 27
local FDFS_TRUNK_FILE_INFO_LEN = 16
--local FDFS_MAX_SERVER_ID        ((1 << 24) - 1)
--
local FDFS_MAX_SERVER_ID = bit.lshift(1, 24) - 1

local FDFS_ID_TYPE_SERVER_ID = 1
local FDFS_ID_TYPE_IP_ADDRESS = 2
local IP_ADDRESS_SIZE = 16

local BASE64_IGNORE = -1
local BASE64_PAD =  -2

local FDFS_FILE_ID_SEPERATOR  = '/'
local FDFS_FILE_ID_SEPERATE_STR =  "/"

local FDFS_FILE_EXT_NAME_MAX_LEN  = 6
local FDFS_TRUNK_FILE_HEADER_SIZE = (17 + FDFS_FILE_EXT_NAME_MAX_LEN + 1)

--local FDFS_TRUNK_FILE_MARK_SIZE  = (512 * 1024 * 1024 * 1024 * 1024 * 1024)
local FDFS_TRUNK_FILE_MARK_SIZE  = bit.lshift(1, 27) -- 高32位的值

--local INFINITE_FILE_SIZE = (256 * 1024 * 1024 * 1024 * 1024 * 1024)
local INFINITE_FILE_SIZE = bit.lshift(1, 26)  --高32位的值
local FDFS_APPENDER_FILE_SIZE = INFINITE_FILE_SIZE

local FDFS_NORMAL_LOGIC_FILENAME_LENGTH  = (FDFS_LOGIC_FILE_PATH_LEN +
        FDFS_FILENAME_BASE64_LENGTH + FDFS_FILE_EXT_NAME_MAX_LEN + 1)

local FDFS_NORMAL_FILENAME_LENGTH_NO_PATH  = (
        FDFS_FILENAME_BASE64_LENGTH + FDFS_FILE_EXT_NAME_MAX_LEN + 1)

local FDFS_TRUNK_FILENAME_LENGTH = (FDFS_TRUE_FILE_PATH_LEN +
        FDFS_FILENAME_BASE64_LENGTH + FDFS_TRUNK_FILE_INFO_LEN +
        1 + FDFS_FILE_EXT_NAME_MAX_LEN)

local FDFS_TRUNK_FILENAME_LENGTH_NO_PATH = (
        FDFS_FILENAME_BASE64_LENGTH + FDFS_TRUNK_FILE_INFO_LEN +
        1 + FDFS_FILE_EXT_NAME_MAX_LEN)

local FDFS_TRUNK_LOGIC_FILENAME_LENGTH =  (FDFS_TRUNK_FILENAME_LENGTH +
        (FDFS_LOGIC_FILE_PATH_LEN - FDFS_TRUE_FILE_PATH_LEN))


local IP_ADDRESS_SIZE = 16

local base64 = base64:new(0, '-', '_', '.')

local function IS_UPPER_HEX(ch)
    return ((ch >= '0' and ch <= '9') or (ch >= 'A' and ch <= 'F'))
end

local _M = {}
local mt = { __index = _M }

local function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function _M.new(self)
    return setmetatable({}, mt)
end

function _M.set_tracker(self, host, port)
    local tracker = {host = host, port = port}
    self.tracker = tracker
end

function _M.set_timeout(self, timeout)
    if timeout then
        self.timeout = timeout
    end
end

function _M.set_tracker_keepalive(self, timeout, size)
    local keepalive = {timeout = timeout, size = size}
    self.tracker_keepalive = keepalive
end

function _M.set_storage_keepalive(self, timeout, size)
    local keepalive = {timeout = timeout, size = size}
    self.storage_keepalive = keepalive
end

local function int2buf(n)
    -- ngx.log(ngx.ERR,  string.format("%d:%d:%d:%d", bit.band(bit.rshift(n, 24), 0xff), bit.band(bit.rshift(n, 16), 0xff), bit.band(bit.rshift(n, 8), 0xff), bit.band(n, 0xff)))
    --return string.rep("\00", 4) .. string.char(bit.band(bit.rshift(n, 24), 0xff), bit.band(bit.rshift(n, 16), 0xff), bit.band(bit.rshift(n, 8), 0xff), bit.band(n, 0xff))
    return string.char(bit.band(bit.rshift(n, 24), 0xff), bit.band(bit.rshift(n, 16), 0xff), bit.band(bit.rshift(n, 8), 0xff), bit.band(n, 0xff))
end

local function buf2int(buf)
    -- local c1, c2, c3, c4 = string.byte(buf, 5, 8)
    local c1, c2, c3, c4 = string.byte(buf, 1, 4)
    return bit.bor(bit.lshift(c1, 24), bit.lshift(c2, 16),bit.lshift(c3, 8), c4)
end

local function long2buf(n)
    return string.rep("\00", 4) .. string.char(bit.band(bit.rshift(n, 24), 0xff), bit.band(bit.rshift(n, 16), 0xff), bit.band(bit.rshift(n, 8), 0xff), bit.band(n, 0xff))

    --return string.char(bit.band(bit.rshift(n, 56), 0xff),
    --                     bit.band(bit.rshift(n, 48), 0xff),
    --                     bit.band(bit.rshift(n, 40), 0xff),
    --                     bit.band(bit.rshift(n, 32), 0xff),
    --                     bit.band(bit.rshift(n, 24), 0xff),
    --                     bit.band(bit.rshift(n, 16), 0xff),
    --                     bit.band(bit.rshift(n, 8), 0xff),
    --                     bit.band(n, 0xff))
end

function buf2long(buf)
    --local c1, c2, c3, c4,c5,c6,c7,c8 = string.byte(buf, 1, 8)
    --return bit.bor(bit.lshift(c1, 56),
    --                bit.lshift(c2, 48),
    --                bit.lshift(c3, 40),
    --                bit.lshift(c4, 32),
    --                bit.lshift(c5, 24),
    --                bit.lshift(c6, 16),
    --                bit.lshift(c7, 8),
    --                c8)
    local c1, c2, c3, c4 = string.byte(buf, 5, 8)
    return bit.bor(bit.lshift(c1, 24), bit.lshift(c2, 16),bit.lshift(c3, 8), c4)
end


local function read_fdfs_header(sock)
    local header = {}
    local buf, err = sock:receive(10)
    if not buf then
        ngx.log(ngx.ERR, "fdfs: read header error", err)
        sock:close()
        ngx.exit(500)
    end
    -- header.len = buf2int(string.sub(buf, 1, 8))
    header.len = buf2long(string.sub(buf, 1, 8))
    header.cmd = string.byte(buf, 9)
    header.status = string.byte(buf, 10)
    return header
end

local function fix_string(str, fix_length)
    if not str then
        str = ""
    end
    local len = string.len(str)
    if len > fix_length then
        len = fix_length
    end
    local fix_str = string.sub(str, 1, len)
    if len < fix_length then
        fix_str = fix_str .. string.rep("\00", fix_length - len )
    end
    return fix_str
end

local function strip_string(str)
    local pos = string.find(str, "\00")
    if pos then
        return string.sub(str, 1, pos - 1)
    else
        return str
    end
end

local function get_ext_name(filename)
    local extname = filename:match("%.(%w+)$")
    if extname then
        return fix_string(extname, FDFS_FILE_EXT_NAME_MAX_LEN)
    else
        return nil
    end
end

local function read_tracket_result(sock, header)
    if header.len > 0 then
        local res = {}
        local buf = sock:receive(header.len)
        res.group_name = strip_string(string.sub(buf, 1, 16))
        res.host       = strip_string(string.sub(buf, 17, 31))
        -- res.port       = buf2int(string.sub(buf, 32, 39))
        res.port       = buf2long(string.sub(buf, 32, 39))
        res.store_path_index = string.byte(string.sub(buf, 40, 40))
        return res
    else
        return nil
    end
end

local function read_storage_result(sock, header)
    if header.len > 0 then
        local res = {}
        local buf = sock:receive(header.len)
        res.group_name = strip_string(string.sub(buf, 1, 16))
        res.file_name  = strip_string(string.sub(buf, 17, header.len))
        return res
    else
        return nil
    end
end

function _M.query_upload_storage(self, group_name)
    local tracker = self.tracker
    if not tracker then
        return nil
    end
    local out = {}
    if group_name then
        -- query upload with group_name
        -- package length
        table.insert(out, long2buf(16))
        -- cmd
        table.insert(out, string.char(TRACKER_PROTO_CMD_SERVICE_QUERY_STORE_WITH_GROUP_ONE))
        -- status
        table.insert(out, "\00")
        -- group name
        table.insert(out, fix_string(group_name, 16))
    else
        -- query upload without group_name
        -- package length
        table.insert(out,  string.rep("\00", FDFS_PROTO_PKG_LEN_SIZE))
        -- cmd
        table.insert(out, string.char(TRACKER_PROTO_CMD_SERVICE_QUERY_STORE_WITHOUT_GROUP_ONE))
        -- status
        table.insert(out, "\00")
    end
    -- init socket
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    -- connect tracker
    local ok, err = sock:connect(tracker.host, tracker.port)
    if not ok then
        return nil, err
    end
    -- send request
    local bytes, err = sock:send(out)
    -- read request header
    local hdr = read_fdfs_header(sock)
    -- read body
    local res = read_tracket_result(sock, hdr)
    -- keepalive
    local keepalive = self.tracker_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res
end

function _M.do_upload_appender(self, ext_name)
    local storage = self:query_upload_storage()
    if not storage then
        return nil
    end
    -- ext_name
    if ext_name then
        ext_name = fix_string(ext_name, FDFS_FILE_EXT_NAME_MAX_LEN)
    end
    -- get file size
    local file_size = tonumber(ngx.var.content_length)
    if not file_size or file_size <= 0 then
        return nil
    end
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    -- send header
    local out = {}
    table.insert(out, long2buf(file_size + 15))
    table.insert(out, string.char(STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE))
    -- status
    table.insert(out, "\00")
    -- store_path_index
    table.insert(out, string.char(storage.store_path_index))
    -- filesize
    table.insert(out, long2buf(file_size))
    -- exitname
    table.insert(out, ext_name)
    local bytes, err = sock:send(out)
    -- send file data
    local send_count = 0
    local req_sock, err = ngx.req.socket()
    if not req_sock then
        ngx.log(ngx.ERR, err)
        ngx.exit(500)
    end
        while true do
        local chunk, _, part = req_sock:receive(1024 * 32)
        if not part then
            local bytes, err = sock:send(chunk)
            if not bytes then
                ngx.log(ngx.ngx.ERR, "fdfs: send body error")
                sock:close()
                ngx.exit(500)
            end
            send_count = send_count + bytes
        else
            -- part have data, not read full end
            local bytes, err = sock:send(part)
            if not bytes then
                ngx.log(ngx.ngx.ERR, "fdfs: send body error")
                sock:close()
                ngx.exit(500)
            end
            send_count = send_count + bytes
            break
        end
    end
    if send_count ~= file_size then
        -- send file not full
        ngx.log(ngx.ngx.ERR, "fdfs: read file body not full")
        sock:close()
        ngx.exit(500)
    end
    -- read response
    local res_hdr = read_fdfs_header(sock)
    local res = read_storage_result(sock, res_hdr)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res
end

function _M.do_upload_appender2(self, reader, filesize, ext_name, chunk_size)
    local storage = self:query_upload_storage()
    if not storage then
        return nil
    end
     -- get file size
    local file_size = filesize or 0

    ext_name = fix_string(ext_name, FDFS_FILE_EXT_NAME_MAX_LEN)
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    -- send header
    local out = {}
    table.insert(out, long2buf(file_size + 15))
    table.insert(out, string.char(STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE))
    -- status
    table.insert(out, "\00")
    -- store_path_index
    table.insert(out, string.char(storage.store_path_index))
    -- filesize
    table.insert(out, long2buf(file_size))
    -- exitname
    table.insert(out, ext_name)
    local bytes, err = sock:send(out)

    chunk_size = chunk_size or 1024
    -- send file data
    local send_count = 0
    while reader do
        local chunk = reader(chunk_size)
        if not chunk then
            break
        end
        local bytes, err = sock:send(chunk)
        if not bytes then
            ngx.log(ngx.ngx.ERR, "fdfs: send body error")
            sock:close()
            ngx.exit(500)
        end

        --ngx.log(ngx.ERR, "read len ", string.len(chunk), " send ", bytes)
        send_count = send_count + bytes
    end
    if send_count ~= file_size then
        -- send file not full
        ngx.log(ngx.ERR, "fdfs: read file body not full, send: " .. send_count, " file size: " .. file_size)
        sock:close()
        ngx.exit(500)
    end

    -- read response
    local res_hdr = read_fdfs_header(sock)
    local res = read_storage_result(sock, res_hdr)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res
end

function _M.do_upload2(self, reader, file_size, ext_name, chunk_size)
    if not chunk_size then
        chunk_size = 1024
    end

    local reader = reader
    if not reader then
        return nil, "reader is nil"
    end

    local storage = self:query_upload_storage()
    if not storage then
        return nil, "can't query storage"
    end

    --ngx.log(ngx.ERR, storage.host, storage.port)
    -- ext_name
    if not ext_name then
        ext_name = ""
    end
    ext_name = fix_string(ext_name, FDFS_FILE_EXT_NAME_MAX_LEN)
    -- get file size
    -- local file_size = tonumber(ngx.var.content_length)
    if not file_size or file_size <= 0 then
        return nil, "invalid file size" .. file_size
    end

    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end

    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end

    -- send header
    local out = {}
    table.insert(out, long2buf(file_size + 15))
    table.insert(out, string.char(STORAGE_PROTO_CMD_UPLOAD_FILE))
    -- status
    table.insert(out, "\00")
    -- store_path_index
    table.insert(out, string.char(storage.store_path_index))
    -- filesize
    table.insert(out, long2buf(file_size))
    -- exitname
    table.insert(out, ext_name)
    local bytes, err = sock:send(out)
    if not bytes then
        return nil, err
    end

    -- send file data
    local send_count = 0
    while reader do
        local chunk = reader(chunk_size)
        if not chunk then
            break
        end
        local bytes, err = sock:send(chunk)
        if not bytes then
            ngx.log(ngx.ngx.ERR, "fdfs: send body error")
            sock:close()
            ngx.exit(500)
        end

        --ngx.log(ngx.ERR, "read len ", string.len(chunk), " send ", bytes)
        send_count = send_count + bytes
    end
    if send_count ~= file_size then
        -- send file not full
        ngx.log(ngx.ERR, "fdfs: read file body not full, send: " .. send_count, " file size: " .. file_size)
        sock:close()
        ngx.exit(500)
    end

    -- read response
    local res_hdr = read_fdfs_header(sock)
    local res = read_storage_result(sock, res_hdr)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res

end

function _M.do_upload(self, ext_name)
    local storage = self:query_upload_storage()
    if not storage then
        return nil
    end
    -- ext_name
    if ext_name then
        ext_name = fix_string(ext_name, FDFS_FILE_EXT_NAME_MAX_LEN)
    end
    -- get file size
    local file_size = tonumber(ngx.var.content_length)
    if not file_size or file_size <= 0 then
        return nil
    end
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    -- send header
    local out = {}
    table.insert(out, long2buf(file_size + 15))
    table.insert(out, string.char(STORAGE_PROTO_CMD_UPLOAD_FILE))
    -- status
    table.insert(out, "\00")
    -- store_path_index
    table.insert(out, string.char(storage.store_path_index))
    -- filesize
    table.insert(out, long2buf(file_size))
    -- exitname
    table.insert(out, ext_name)
    local bytes, err = sock:send(out)
    -- send file data
    local send_count = 0
    local req_sock, err = ngx.req.socket()
    if not req_sock then
        ngx.log(ngx.ERR, err)
        ngx.exit(500)
    end
    while true do
        local chunk, _, part = req_sock:receive(1024 * 32)
        if not part then
            local bytes, err = sock:send(chunk)
            if not bytes then
                ngx.log(ngx.ngx.ERR, "fdfs: send body error")
                sock:close()
                ngx.exit(500)
            end
            send_count = send_count + bytes
        else
            -- part have data, not read full end
            local bytes, err = sock:send(part)
            if not bytes then
                ngx.log(ngx.ngx.ERR, "fdfs: send body error")
                sock:close()
                ngx.exit(500)
            end
            send_count = send_count + bytes
            break
        end
    end
    if send_count ~= file_size then
        -- send file not full
        ngx.log(ngx.ngx.ERR, "fdfs: read file body not full")
        sock:close()
        ngx.exit(500)
    end
    -- read response
    local res_hdr = read_fdfs_header(sock)
    local res = read_storage_result(sock, res_hdr)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res
end

function _M.query_update_storage_ex(self, group_name, file_name)
    local out = {}
    -- package length
    table.insert(out, long2buf(16 + string.len(file_name)))
    -- cmd
    table.insert(out, string.char(TRACKER_PROTO_CMD_SERVICE_QUERY_UPDATE))
    -- status
    table.insert(out, "\00")
    -- group_name
    table.insert(out, fix_string(group_name, 16))
    -- file name
    table.insert(out, file_name)
    -- get tracker
    local tracker = self.tracker
    if not tracker then
        return nil
    end
    -- init socket
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    -- connect tracker
    local ok, err = sock:connect(tracker.host, tracker.port)
    if not ok then
        return nil, err
    end
    -- send request
    local bytes, err = sock:send(out)
    -- read request header
    local hdr = read_fdfs_header(sock)
    -- read body
    local res = read_tracket_result(sock, hdr)
    -- keepalive
    local keepalive = self.tracker_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res
end

function _M.query_update_storage(self, fileid)
    local pos = fileid:find('/')
    if not pos then
        return nil
    else
        local group_name = fileid:sub(1, pos-1)
        local file_name  = fileid:sub(pos + 1)
        local res = self:query_update_storage_ex(group_name, file_name)
        if res then
            res.file_name = file_name
        end
        return res
    end
end

function _M.do_delete(self, fileid)
    local storage = self:query_update_storage(fileid)
    if not storage then
        return nil
    end
    local out = {}
    table.insert(out, long2buf(16 + string.len(storage.file_name)))
    table.insert(out, string.char(STORAGE_PROTO_CMD_DELETE_FILE))
    table.insert(out, "\00")
    -- group name
    table.insert(out, fix_string(storage.group_name, 16))
    -- file name
    table.insert(out, storage.file_name)
    -- init socket
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    sock:settimeout(self.timeout)
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    local bytes, err = sock:send(out)
    if not bytes then
        ngx.log(ngx.ngx.ERR, "fdfs: send body error")
        sock:close()
        ngx.exit(500)
    end
    -- read request header
    local hdr = read_fdfs_header(sock)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return hdr
end

function _M.query_download_storage(self, fileid)
    local pos = fileid:find('/')
    if not pos then
        return nil
    else
        local group_name = fileid:sub(1, pos-1)
        local file_name  = fileid:sub(pos + 1)
        local res = self:query_download_storage_ex(group_name, file_name)
        res.file_name = file_name
        return res
    end
end

function _M.query_download_storage_ex(self, group_name, file_name)
    local out = {}
    -- package length
    table.insert(out, long2buf(16 + string.len(file_name)))
    -- cmd
    table.insert(out, string.char(TRACKER_PROTO_CMD_SERVICE_QUERY_FETCH_ONE))
    -- status
    table.insert(out, "\00")
    -- group_name
    table.insert(out, fix_string(group_name, 16))
    -- file name
    table.insert(out, file_name)
    -- get tracker
    local tracker = self.tracker
    if not tracker then
        return nil
    end
    -- init socket
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    -- connect tracker
    local ok, err = sock:connect(tracker.host, tracker.port)
    if not ok then
        return nil, err
    end
    -- send request
    local bytes, err = sock:send(out)
    -- read request header
    local hdr = read_fdfs_header(sock)
    -- read body
    local res = read_tracket_result(sock, hdr)
    -- keepalive
    local keepalive = self.tracker_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res
end

function _M.do_download2(self, fileid, start, stop)
    local storage = self:query_download_storage(fileid)
    if not storage then
        return nil
    end
    local out = {}
    -- file_offset(8)  download_bytes(8)  group_name(16)  file_name(n)
    table.insert(out, long2buf(32 + string.len(storage.file_name)))
    table.insert(out, string.char(STORAGE_PROTO_CMD_DOWNLOAD_FILE))
    table.insert(out, "\00")
    -- file_offset  download_bytes  8 + 8
    local offset = start or 0
    local download_bytes = 0
    if stop then
        download_bytes = stop - start
    end
    table.insert(out, long2buf(offset))
    table.insert(out, long2buf(download_bytes))
    -- table.insert(out, string.rep("\00", 16))
    -- group name
    table.insert(out, fix_string(storage.group_name, 16))
    -- file name
    table.insert(out, storage.file_name)

    -- init socket
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    sock:settimeout(self.timeout)
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    local bytes, err = sock:send(out)
    if not bytes then
        ngx.log(ngx.ERR, "fdfs: send request error" .. err)
        sock:close()
        ngx.exit(500)
    end

    -- read request header
    local hdr = read_fdfs_header(sock)
    --ngx.log(ngx.ERR, "hdr: ", hdr.len)

    --local keepalive = self.storage_keepalive
    --if keepalive then
    --    sock:setkeepalive(keepalive.timeout, keepalive.size)
    --end
    --
    local chunk_size = 1024 * 64
    return utils.make_reader(sock, chunk_size, hdr.len, function(sock)
        local keepalive = self.storage_keepalive
        if keepalive then
            sock:setkeepalive(keepalive.timeout, keepalive.size)
        end
    end), hdr.len

    -- read request bodya
     --local data, partial
     --if hdr.len > 0 then
     --    data, err, partial = sock:receive(hdr.len)
     --    if not data then
     --        ngx.log(ngx.ERR, "read file body error:" .. err)
     --        sock:close()
     --        ngx.exit(500)
     --    end
     --end
     --return data, hdr.len
end


function _M.do_download(self, fileid)
    local storage = self:query_download_storage(fileid)
    if not storage then
        return nil
    end
    local out = {}
    -- file_offset(8)  download_bytes(8)  group_name(16)  file_name(n)
    table.insert(out, long2buf(32 + string.len(storage.file_name)))
    table.insert(out, string.char(STORAGE_PROTO_CMD_DOWNLOAD_FILE))
    table.insert(out, "\00")
    -- file_offset  download_bytes  8 + 8
    table.insert(out, string.rep("\00", 16))
    -- group name
    table.insert(out, fix_string(storage.group_name, 16))
    -- file name
    table.insert(out, storage.file_name)
    -- init socket
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    sock:settimeout(self.timeout)
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    local bytes, err = sock:send(out)
    if not bytes then
        ngx.log(ngx.ERR, "fdfs: send request error" .. err)
        sock:close()
        ngx.exit(500)
    end
    -- read request header
    local hdr = read_fdfs_header(sock)
    -- read request bodya
    local data, partial
    if hdr.len > 0 then
        data, err, partial = sock:receive(hdr.len)
        if not data then
            ngx.log(ngx.ERR, "read file body error:" .. err)
            sock:close()
            ngx.exit(500)
        end
    end
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return data
end

function _M.do_append2(self, fileid, reader, file_size, chunk_size )
    local storage = self:query_update_storage(fileid)
    if not storage then
        return nil
    end
    local file_name = storage.file_name
    local file_name_len = string.len(file_name)
    -- get file size
    if not file_size or file_size <= 0 then
        ngx.log(ngx.ERR, "fdfs: append file size nil")
        return nil
    end
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    -- send request
    local out = {}
    table.insert(out, long2buf(file_size + file_name_len + 16))
    table.insert(out, string.char(STORAGE_PROTO_CMD_APPEND_FILE))
    -- status
    table.insert(out, "\00")
    table.insert(out, long2buf(file_name_len))
    table.insert(out, long2buf(file_size))
    table.insert(out, file_name)
    local bytes, err = sock:send(out)

    -- send file data
    local send_count = 0
    chunk_size = chunk_size or 1024
    while reader do
        local chunk = reader(chunk_size)
        if not chunk then
            break
        end
        local bytes, err = sock:send(chunk)
        if not bytes then
            ngx.log(ngx.ngx.ERR, "fdfs: send body error")
            sock:close()
            ngx.exit(500)
        end

        --ngx.log(ngx.ERR, "read len ", string.len(chunk), " send ", bytes)
        send_count = send_count + bytes
    end
    if send_count ~= file_size then
        -- send file not full
        ngx.log(ngx.ERR, "fdfs: read file body not full, send: " .. send_count, " file size: " .. file_size)
        sock:close()
        ngx.exit(500)
    end

    -- read response
    local res_hdr = read_fdfs_header(sock)
    if res_hdr.status ~= 0 then
        ngx.log(ngx.ngx.ERR, "fdfs: append file failed, status ", res_hdr.status)
        ngx.exit(500)
    end

    local res = read_storage_result(sock, res_hdr)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res_hdr
end

function _M.do_append(self, fileid)
    local storage = self:query_update_storage(fileid)
    if not storage then
        return nil
    end
    local file_name = storage.file_name
    local file_name_len = string.len(file_name)
    -- get file size
    local file_size = tonumber(ngx.var.content_length)
    if not file_size or file_size <= 0 then
        return nil
    end
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end
    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        return nil, err
    end
    -- send request
    local out = {}
    table.insert(out, long2buf(file_size + file_name_len + 16))
    table.insert(out, string.char(STORAGE_PROTO_CMD_APPEND_FILE))
    -- status
    table.insert(out, "\00")
    table.insert(out, long2buf(file_name_len))
    table.insert(out, long2buf(file_size))
    table.insert(out, file_name)
    local bytes, err = sock:send(out)

    -- send file data
    local send_count = 0
    local req_sock, err = ngx.req.socket()
    if not req_sock then
        ngx.log(ngx.ERR, err)
        ngx.exit(500)
    end
    while true do
        local chunk, _, part = req_sock:receive(1024 * 32)
        if not part then
            local bytes, err = sock:send(chunk)
            if not bytes then
                ngx.log(ngx.ngx.ERR, "fdfs: send body error")
                sock:close()
                ngx.exit(500)
            end
            send_count = send_count + bytes
        else
            -- part have data, not read full end
            local bytes, err = sock:send(part)
            if not bytes then
                ngx.log(ngx.ngx.ERR, "fdfs: send body error")
                sock:close()
                ngx.exit(500)
            end
            send_count = send_count + bytes
            break
        end
    end
    if send_count ~= file_size then
        -- send file not full
        ngx.log(ngx.ngx.ERR, "fdfs: read file body not full")
        sock:close()
        ngx.exit(500)
    end
    -- read response
    local res_hdr = read_fdfs_header(sock)
    if res_hdr.status ~= 0 then
        ngx.log(ngx.ngx.ERR, "fdfs: append file failed, status ", res_hdr.status)
        ngx.exit(500)
    end

    local res = read_storage_result(sock, res_hdr)
    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end
    return res_hdr
end



local function fdfs_get_server_id_type(id)
    if id > 0 and id <= FDFS_MAX_SERVER_ID then
       return FDFS_ID_TYPE_SERVER_ID
    else
        return FDFS_ID_TYPE_IP_ADDRESS
    end
end

local function IS_TRUNK_FILE(file_size)
    -- ngx.log(ngx.ERR, "bit.band: ", bit.band(file_size, FDFS_TRUNK_FILE_MARK_SIZE))
    return bit.band(file_size, FDFS_TRUNK_FILE_MARK_SIZE) ~= 0
end

local function IS_SLAVE_FILE(filename_len, file_size)
    -- ngx.log(ngx.ERR, "slave file: ", filename_len, ":",file_size )
    --return ((filename_len > FDFS_TRUNK_LOGIC_FILENAME_LENGTH) or
    --(filename_len > FDFS_NORMAL_LOGIC_FILENAME_LENGTH and not IS_TRUNK_FILE(file_size)))
    return ((filename_len > FDFS_TRUNK_FILENAME_LENGTH_NO_PATH) or
    (filename_len > FDFS_NORMAL_FILENAME_LENGTH_NO_PATH and not IS_TRUNK_FILE(file_size)))
end

local function IS_APPENDER_FILE(file_size)
     --ngx.log(ngx.ERR, "append filesize: ",  file_size, ":",  FDFS_APPENDER_FILE_SIZE)
    return (bit.band(file_size, FDFS_APPENDER_FILE_SIZE) ~=0 )
end

function _M.get_fileinfo_ex(self, filename_without_path, get_from_server)
    local filename_ori = filename_without_path or ""
    local filename_len = string.len(filename_ori)

    if filename_len < FDFS_NORMAL_FILENAME_LENGTH_NO_PATH then
        ngx.log(ngx.ERR, string.format("filename is to short %d < %d",
                filename_len, FDFS_NORMAL_FILENAME_LENGTH_NO_PATH))
        return nil
    end

    local offset = 1
    local filename = string.sub(filename_ori, 1, FDFS_FILENAME_BASE64_LENGTH)

    --filename = base64.decode(filename)
    filename = base64:base64_decode_auto(filename)

    local ip_addr = string.sub(filename, 1, 4)
    offset = offset + 4

    local ip_addr_num  = buf2int(ip_addr)

    ip_addr_num = iputils.ntohl(ip_addr_num)
    --ngx.log(ngx.ERR, "ip_addr_str:", ip_addr, " num:", ip_addr_num)

    local source_ip_addr = ""
    local source_id = ""
    if fdfs_get_server_id_type(ip_addr_num) == FDFS_ID_TYPE_SERVER_ID then
        source_id = ip_addr_num
    else
        source_ip_addr = iputils.inet_ntoa(iputils.ntohl(ip_addr_num))
    end

    local timestamp_str = string.sub(filename, offset, offset+3)
    offset = offset + 4
    local timestamp = buf2int(timestamp_str)
    -- ngx.log(ngx.ERR, "timestamp_str:", timestamp_str, " num:", timestamp)

    local filesize_str_1 = string.sub(filename, offset, offset+3)
    offset = offset + 4

    local filesize_str_2 = string.sub(filename, offset, offset+3)
    offset = offset + 4

    local filesize_1 = buf2int(filesize_str_1)
    local filesize_2 = buf2int(filesize_str_2)
    local filesize = filesize_2

    local is_slave = IS_SLAVE_FILE(filename_len, filesize_1)
    local is_appender = IS_APPENDER_FILE(filesize_1)
    if ( is_slave or is_appender or get_from_server) then
        -- ngx.log(ngx.ERR, "IS A appender FILE")
        filesize = -1
    end

    -- ngx.log(ngx.ERR, "filesize :" , filesize)
    local is_trunk = IS_TRUNK_FILE(filesize_1)
    if bit.arshift(filesize, 63) ~= 0 then
        filesize = bit.band(filesize, 0xFFFFFFFF) -- low 32 bits is file size
    elseif is_trunk then
        -- ngx.log(ngx.ERR, "IS A TRUNCK FILE")
        filesize = bit.band(filesize,0xFFFFFFFF)
    end

    -- ngx.log(ngx.ERR, "filesize :" , filesize)

    local crc32 = buf2int(string.sub(filename, offset))

    local fileinfo = {
        source_id = source_id,
        source_ip_addr = source_ip_addr,
        is_trunk = is_trunk,
        is_appender = is_appender,
        is_slave = is_slave,
        timestamp = timestamp,
        crc32 = crc32,
        filesize = filesize
    }
    if is_trunk then
        local filename = string.sub(filename_ori, FDFS_FILENAME_BASE64_LENGTH+1)
        filename = base64:base64_decode_auto(filename)
        offset = 1
        local trunk_id_str = string.sub(filename, offset, offset+3)
        offset = offset + 4
        local trunk_id = buf2int(trunk_id_str)

        local file_offset_str = string.sub(filename, offset, offset+3)
        offset = offset + 4
        local file_offset = buf2int(file_offset_str)

        local size_str = string.sub(filename, offset, offset+3)
        offset = offset + 4
        local size = buf2int(size_str)

        fileinfo["trunk_id"] = trunk_id
        fileinfo["offset"] = file_offset
        fileinfo["size"] = size
     end

    return fileinfo
end

function _M.get_fileinfo(self, fileid)
    fileid = utils.clear_slash(fileid)
    fileid = utils.trim_prefix_slash(fileid)
    fileid = utils.trim_suffix_slash(fileid)
    local segments = utils.split(fileid, "/")
    local group = segments[1]
    local filename_ori = segments[5] or ""
    local filename_len = string.len(filename_ori)
    return self:get_fileinfo_ex(filename_ori)
end

-- build request
local function build_request(cmd, group_name, file_name)
    if not group_name then
        return nil, "not group_name"
    end
    if not file_name then
        return nil, "not file_name"
    end
    local req = {}
    table.insert(req, int2buf(16 + string.len(file_name)))
    table.insert(req, string.char(cmd))
    table.insert(req, "\00")
    table.insert(req, fix_string(group_name, 16))
    table.insert(req, file_name)
    return req
end


local function read_file_info_result(sock)
    local sock = sock
    if not sock then
        ngx.log(ngx.ERR, "read file info sock nil ")
        return nil, "not initialized"
    end
    local hdr, err = read_fdfs_header(sock)
    if not hdr then
        ngx.log(ngx.ERR, "read  header error")
        return nil, "read storage header error:" .. err
    end
    if hdr.status ~= 0 then
        ngx.log(ngx.ERR, "read  header status error: " .. hdr.status)
        return nil, "read storage status error:" .. hdr.status
    end
    if hdr.len > 0 then
        local data, err, partial = sock:receive(hdr.len)
        if not data then
            return nil, "read file body error:" .. err
        end
        ngx.log(ngx.ERR, "read data: " .. data, " len:", hdr.len)

        local offset = 1
        local filesize_str = string.sub(data, offset, offset+8-1)
        offset = offset + 8
        local filesize = buf2long(filesize_str)

        local timestamp_str = string.sub(data, offset, offset+8-1)
        offset = offset + 8
        local timestamp = buf2long(timestamp_str)

        local crc32_str = string.sub(data, offset, offset+8-1)
        offset = offset + 8
        local crc32 = buf2long(crc32_str)

        local source_ip_addr = strip_string(string.sub(data, offset))

        local fileinfo = {
            source_ip_addr = source_ip_addr,
            timestamp = timestamp,
            crc32 = crc32,
            filesize = filesize
        }
        return fileinfo
    else
        ngx.log(ngx.ERR, "read  header len: " .. hdr.len)
    end
    return nil
end

function _M.get_fileinfo_from_storage(self, fileid)
    local storage, err = self:query_update_storage(fileid)
    if not storage then
        return nil, err
    end
    local req, err = build_request(STORAGE_PROTO_CMD_QUERY_FILE_INFO, storage.group_name, storage.file_name)
    if not req then
        return nil, err
    end

    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, err
    end
    if self.timeout then
        sock:settimeout(self.timeout)
    end

    local ok, err = sock:connect(storage.host, storage.port)
    if not ok then
        ngx.log(ngx.ERR, "fdfs: connect failed: " .. err)
        return nil, err
    end

    local bytes, err = sock:send(req)

    if not bytes then
        ngx.log(ngx.ERR, "fdfs: send request error" .. err)
        sock:close()
        ngx.exit(500)
    end

    local res = read_file_info_result(sock)

    local keepalive = self.storage_keepalive
    if keepalive then
        sock:setkeepalive(keepalive.timeout, keepalive.size)
    end

    return res

end

-- _M.query_upload_storage = query_upload_storage
-- _M.do_upload_storage    = do_upload_storage
-- _M.do_delete_storage    = do_delete_storage

local class_mt = {
    -- to prevent use of casual module global variables
    __newindex = function (table, key, val)
        error('attempt to write to undeclared variable "' .. key .. '"')
    end
}

setmetatable(_M, class_mt)
return _M
