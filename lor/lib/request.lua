local upload = require("resty.upload")
local byterange = require("lor.lib.byterange")
local Range = byterange.Range
local ContentRange = byterange.ContentRange
local sfind = string.find
local smatch = string.match
local ssub = string.sub
local slen = string.len
local pairs = pairs
local type = type
local setmetatable = setmetatable
local utils = require("lor.lib.utils.utils")
local co_yield = coroutine.yield
local co_create = coroutine.create
local co_status = coroutine.status
local co_resume = coroutine.resume
local io = io

local Request = {}
-- local Request = {__index = function(table, key)
--                     local ok, err = pcall(type(table[key]))
--                     if not ok then
--                         return nil
--                     else
--                         return table[key]
--                     end
--                 end}
--
local MAX_POST_ARGS_NUM = 64
local default_chunk_size = 100


function dump(o)
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

-- Reimplemented coroutine.wrap, returning "nil, err" if the coroutine cannot
-- be resumed. This protects user code from inifite loops when doing things like
-- repeat
--   local chunk, err = res.body_reader()
--   if chunk then -- <-- This could be a string msg in the core wrap function.
--     ...
--   end
-- until not chunk
local co_wrap = function(func)
    local co = co_create(func)
    if not co then
        return nil, "could not create coroutine"
    else
        return function(...)
            if co_status(co) == "suspended" then
                return select(2, co_resume(co, ...))
            else
                return nil, "can't resume a " .. co_status(co) .. " coroutine"
            end
        end
    end
end

function Request:new()
    local headers = ngx.req.get_headers()
    local length = tonumber(headers["Content-Length"])
    ngx.log(ngx.ERR, 'header range:', headers["Range"])
    local range = nil
    if headers["Range"] then
        range = Range:parse(headers["Range"])
    end

    local content_type = ngx.var.content_type
    if not content_type then
        content_type = "application/x-www-form-urlencoded"
    end
    local instance = {
        path = ngx.var.uri, -- uri
        method = ngx.req.get_method(),
        params = {},
        uri = ngx.var.request_uri,
        content_type = content_type,
        headers = headers, -- request headers
        content_length = length,
        version = ngx.req.http_version(),
        range = range,
        -- uri_args = ngx.var.args,
        body_read = false,
        found = false -- 404 or not
    }
    setmetatable(instance, { __index = self })
    return instance
end

function Request:is_multipart()
    local content_type = self.content_type
    if not content_type then
        return false
    end
    local s = smatch(content_type, "multipart/form%-data")
    if s then
        return true
    else
        return false
    end
end

local function _multipart_formdata()
    local form, err = upload:new()
    if not form then
        ngx.log(ngx.ERR, "failed to new upload: ", err)
        ngx.exit(500)
    end
    form:set_timeout(5)

    local success, msg = false, ""
    local file, origin_filename, filename, err
    local post_args, last_key, readfile = {}, "", false
    while true do
        local typ, res, err = form:read()
        if not typ then
            success = false
            msg = "failed to read"
            ngx.log(ngx.ERR, "failed to read: ", err)
            return nill, err
        end
        if typ == "header" then
            if res[1] == "Content-Disposition" then
                last_key = smatch(res[2], "name=\"(.-)\"")
                origin_filename = smatch(res[2], "filename=\"(.-)\"")
                post_args[last_key] = { name=last_key }
                if origin_filename then
                    post_args[last_key]['filename'] = origin_filename
                end
            elseif res[1] == "Content-Type" then
                filetype = res[2]
                post_args[last_key]["content_type"] = filetype
                if post_args[last_key]['filename'] and filetype then
                    file, err = io.tmpfile()
                    if err then
                        success = false
                        msg = "upload open temp file error"
                        ngx.log(ngx.ERR, "upload open temp file error:", err)
                        return nil, err
                    end
                    post_args[last_key]['file']=file
                    readfile = true
                end
            end
        elseif typ == "body" then
            if file and readfile then
                file:write(res)
                success = true
            elseif res ~= "\r\n" then
                post_args[last_key]["value"] = res
            end
        elseif typ == "part_end" then
            readfile = false
        elseif typ == "eof" then
            break
        else
            -- do nothing
        end
    end

    return post_args, err
end

function Request:GET()
    return ngx.req.get_uri_args()
end

function Request:POST()
    -- for k,v in pairs(self) do
    --    ngx.log(ngx.ALERT, k .. ": " .. tostring(v))
    -- end
    local methods = {"POST", "PUT", "PATCH"}
    local valid = false
    for _, v in pairs(methods) do
        if self.method == v then
            valid = true
            break
        end
    end
    if not valid then
        return {}
    end

    if sfind(self.content_type, "application/x-www-form-urlencoded", 1, true) then
        self.read_body = true
        ngx.req.read_body()
        return ngx.req.get_post_args(MAX_POST_ARGS_NUM)
    elseif sfind(self.content_type, "application/json", 1, true) then
        ngx.req.read_body()
        self.read_body = true
        local json_str = ngx.req.get_body_data()
        return utils.json_decode(json_str)
    elseif sfind(self.content_type, "multipart", 1, true) then
        -- upload request, should not invoke ngx.req.read_body()
        -- parsed as raw by default
        post_args, err = _multipart_formdata()
        self.read_body = true
        if not post_args then
            return {}
        end
        return post_args
    else
        return {}
    end
end

function Request:args()
    if self._args then
        local args = self._args
        return args
    end
    local ar = self:GET()
    local post = self:POST() or {}
    for k,v in pairs(post) do
        if sfind(self.content_type, "multipart", 1, true) then
            if v.filename then
                ar[k] = v
            else
                ar[k] = v.value
            end
        else
            ar[k] = v
        end
    end
    self._args = ar
    return ar
end

function Request:body_raw()
    ngx.req.read_body()
    local body_raw = ngx.req.get_body_data() or ""
    local body_file_name = ngx.req.get_body_file()
    local body_data = ""
    if body_file_name then
        local body_file = io.open(body_file_name, "rb")
        file_data = body_file:read("*a")
        body_file:close()
    end
    self.read_body = true
    return body_raw .. file_data
end

local function _body_file_reader(max_chunk_size)
    return co_wrap(function(max_chunk_size)
        local max_chunk_size = max_chunk_size or default_chunk_size
        local body_buffer = ngx.req.get_body_data() or ""
        local buffer_remain = slen(body_buffer)
        local buffer_offset = 1
        local body_file, err = nil, err
        local body_file_name = ngx.req.get_body_file()
        if body_file_name then
            body_file, err = io.open(body_file_name, "rb")
            if not body_file then
                ngx.log(ngx.ERR, "open temp file error: " , err)
            end
        end
        ngx.log(ngx.ERR, "buffer_remain:" .. buffer_remain)
        ngx.log(ngx.ERR, "max_chunk_size:" .. max_chunk_size)
        -- ngx.log(ngx.ERR, "body_buffer: " .. body_buffer)

        repeat
            ngx.log(ngx.ERR, "repeat: " .. buffer_offset)
            local chunk = nil
            local need_read_bytes = max_chunk_size
            if buffer_remain > 0 then
                if buffer_remain <= max_chunk_size then
                    ngx.log(ngx.ERR, "buffer_offset:" .. buffer_offset)
                    ngx.log(ngx.ERR, "buffer_offset+buffer_remain:" .. (buffer_offset))
                    chunk = ssub(body_buffer, buffer_offset, buffer_offset+buffer_remain-1)
                    buffer_offset = buffer_offset + buffer_remain
                    need_read_bytes = max_chunk_size - buffer_remain
                    buffer_remain = 0
                else
                    ngx.log(ngx.ERR, "buffer_offset:" .. buffer_offset)
                    ngx.log(ngx.ERR, "buffer_offset+max_chunk_size:" .. (buffer_offset+max_chunk_size))
                    chunk = ssub(body_buffer, buffer_offset, buffer_offset+max_chunk_size-1)
                    buffer_remain = buffer_remain - max_chunk_size
                    buffer_offset = buffer_offset + max_chunk_size
                    need_read_bytes = max_chunk_size
                end
            end

            if body_file and buffer_remain == 0 then
                local chunk2 = body_file:read(need_read_bytes)
                if chunk then
                    chunk = chunk .. chunk2
                else
                    chunk = chunk2
                end
            end
            if chunk then
                co_yield(chunk)
            end

       until not chunk

       if body_file then
           body_file:close()
       end
    end)
end

local function _chunked_body_reader(sock, default_chunk_size)
    return co_wrap(function(max_chunk_size)
        local max_chunk_size = max_chunk_size or default_chunk_size
        local remaining = 0
        local length

        repeat
            -- If we still have data on this chunk
            if max_chunk_size and remaining > 0 then

                if remaining > max_chunk_size then
                    -- Consume up to max_chunk_size
                    length = max_chunk_size
                    remaining = remaining - max_chunk_size
                else
                    -- Consume all remaining
                    length = remaining
                    remaining = 0
                end
            else -- This is a fresh chunk

                -- Receive the chunk size
                local str, err = sock:receive("*l")
                if not str then
                    co_yield(nil, err)
                end

                length = tonumber(str, 16)

                if not length then
                    co_yield(nil, "unable to read chunksize")
                end

                if max_chunk_size and length > max_chunk_size then
                    -- Consume up to max_chunk_size
                    remaining = length - max_chunk_size
                    length = max_chunk_size
                end
            end

            if length > 0 then
                local str, err = sock:receive(length)
                if not str then
                    co_yield(nil, err)
                end

                max_chunk_size = co_yield(str) or default_chunk_size

                -- If we're finished with this chunk, read the carriage return.
                if remaining == 0 then
                    sock:receive(2) -- read \r\n
                end
            else
                -- Read the last (zero length) chunk's carriage return
                sock:receive(2) -- read \r\n
            end

        until length == 0
    end)
end


local function _body_reader(sock, content_length, default_chunk_size)
    return co_wrap(function(max_chunk_size)
        local max_chunk_size = max_chunk_size or default_chunk_size

        if not content_length and max_chunk_size then
            -- We have no length, but wish to stream.
            -- HTTP 1.0 with no length will close connection, so read chunks to the end.
            repeat
                local str, err, partial = sock:receive(max_chunk_size)
                if not str and err == "closed" then
                    max_chunk_size = tonumber(co_yield(partial, err) or default_chunk_size)
                end

                max_chunk_size = tonumber(co_yield(str) or default_chunk_size)
                if max_chunk_size and max_chunk_size < 0 then max_chunk_size = nil end

                if not max_chunk_size then
                    ngx_log(ngx_ERR, "Buffer size not specified, bailing")
                    break
                end
            until not str

        elseif not content_length then
            -- We have no length but don't wish to stream.
            -- HTTP 1.0 with no length will close connection, so read to the end.
            co_yield(sock:receive("*a"))

        elseif not max_chunk_size then
            -- We have a length and potentially keep-alive, but want everything.
            co_yield(sock:receive(content_length))

        else
            -- We have a length and potentially a keep-alive, and wish to stream
            -- the response.
            local received = 0
            repeat
                local length = max_chunk_size
                if received + length > content_length then
                    length = content_length - received
                end

                if length > 0 then
                    local str, err = sock:receive(length)
                    if not str then
                        max_chunk_size = tonumber(co_yield(nil, err) or default_chunk_size)
                    end
                    received = received + length

                    max_chunk_size = tonumber(co_yield(str) or default_chunk_size)
                    if max_chunk_size and max_chunk_size < 0 then max_chunk_size = nil end

                    if not max_chunk_size then
                        ngx_log(ngx_ERR, "Buffer size not specified, bailing")
                        break
                    end
                end

            until length == 0
        end
    end)
end

function Request:body_reader()
    local body_reader = nil
    local err = nil
    if self.read_body then
        ngx.log(ngx.ALERT, "get_body_file reader................")
        return _body_file_reader()
    end
    -- Receive the body_reader
    local sock, err = ngx.req.socket()
    if not sock then
        ngx.log(ngx.ALERT, "open sock failed :", err)
        return nil, err
    end
    local ok, encoding = pcall(string.lower, self.headers["Transfer-Encoding"])
    if ok and self.version == 1.1 and encoding == "chunked" then
        body_reader, err = _chunked_body_reader(sock)
    else
        local ok, length = pcall(tonumber, self.content_length)
        if ok then
            body_reader, err = _body_reader(sock, length)
        end
    end

    return body_reader, err
end

--[[
-- new request: init args/params/body etc from http request
function Request:new()
    local body = {} -- body params
    local headers = ngx.req.get_headers()

    local header = headers['Content-Type']
    -- the post request have Content-Type header set
    if header then
        if sfind(header, "application/x-www-form-urlencoded", 1, true) then
            ngx.req.read_body()
            local post_args = ngx.req.get_post_args()
            if post_args and type(post_args) == "table" then
                for k,v in pairs(post_args) do
                    body[k] = v
                end
            end
        elseif sfind(header, "application/json", 1, true) then
            ngx.req.read_body()
            local json_str = ngx.req.get_body_data()
            body = utils.json_decode(json_str)
        -- form-data request
        elseif sfind(header, "multipart", 1, true) then
            -- upload request, should not invoke ngx.req.read_body()
        -- parsed as raw by default
        else
            ngx.req.read_body()
            body = ngx.req.get_body_data()
        end
    -- the post request have no Content-Type header set will be parsed as x-www-form-urlencoded by default
    else
        ngx.req.read_body()
        local post_args = ngx.req.get_post_args()
        if post_args and type(post_args) == "table" then
            for k,v in pairs(post_args) do
                body[k] = v
            end
        end
    end

    local instance = {
        path = ngx.var.uri, -- uri
        method = ngx.req.get_method(),
        query = ngx.req.get_uri_args(),
        params = {},
        body = body,
        body_raw = ngx.req.get_body_data(),
        url = ngx.var.request_uri,
        origin_uri = ngx.var.request_uri,
        uri = ngx.var.request_uri,
        headers = headers, -- request headers

        req_args = ngx.var.args,
        found = false -- 404 or not
    }
    setmetatable(instance, { __index = self })
    return instance
end

]]

function Request:is_found()
    return self.found
end

function Request:set_found(found)
    self.found = found
end

return Request
