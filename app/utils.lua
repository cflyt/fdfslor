local co_yield = coroutine.yield
local co_create = coroutine.create
local co_status = coroutine.status
local co_resume = coroutine.resume
local ngx = ngx

local _M = {}

-- Reimplemented coroutine.wrap, returning "nil, err" if the coroutine cannot
-- be resumed. This protects user code from inifite loops when doing things like
-- repeat
--   local chunk, err = res.body_reader()
--   if chunk then -- <-- This could be a string msg in the core wrap function.
--     ...
--   end
-- until not chunk
local function co_wrap(func)
    local co = co_create(func)
    if not co then
        return nil, "could not create coroutine"
    else
        return function(...)
            if co_status(co) == "suspended" then
                --ngx.log(ngx.ERR, "suspended,,,")
                return select(2, co_resume(co, ...))
            else
                return nil, "can't resume a " .. co_status(co) .. " coroutine"
            end
        end
    end
end

function _M.make_reader(data, chunk_size, total_size, cb_done)
    -- ngx.log(ngx.ALERT, "make reader ", tostring(data), "chunk size:",chunk_size, "total_size:", total_size, "cb:", tostring(cb_done) )
    if type(data) == "string" then
        return co_wrap(function(chunk_size, total_size)
            local remain_length = total_size or slen(data)
            local offset = 1
            local length = 0
            repeat
                local chunk = nil
                local need_read_bytes = chunk_size
                if chunk_size >= remain_length then
                    chunk = data
                    length = remain_length
                    remain_length = 0
                else
                    chunk = ssbub(data, offset, offset+chunk_size-1)
                    offset = offset + chunk_size
                    remain_length = remain_length - chunk_size
                    length = chunk_size
                end
                if chunk then
                    co_yield(chunk)
                else
                    return nil
                end
            until remain_length <= 0
            if cb_done then
                cb_done(data)
            end
        end)
    elseif io.type(data) == "file" then
        local file = data
        return co_wrap(function(chunk_size, total_size)
            repeat
                local chunk = nil
                chunk = file:read(chunk_size)
                if chunk then
                    co_yield(chunk)
                else
                    return nil
                end
            until not chunk
            if cb_done then
                cb_done(file)
            end
        end)
    elseif type(data) == "table" and data.receive then
        local sock = data
        return co_wrap(function(chunk_size, total_size)
            if not total_size and chunk_size then
            -- We have no length, but wish to stream.
            -- HTTP 1.0 with no length will close connection, so read chunks to the end.
                repeat
                    local chunk, err, partial = sock:receive(chunk_size)
                    if not chunk and (err == "closed" or err == "timeout") then
                        co_yield(partial)
                    elseif chunk then
                        co_yield(chunk)
                    else
                        ngx_log(ngx_ERR, "Buffer size not specified, bailing")
                        break
                    end
                until not chunk

            elseif not total_size then
            -- We have no length but don't wish to stream.
            -- HTTP 1.0 with no length will close connection, so read to the end.
                co_yield(sock:receive("*a"))

            elseif not chunk_size then
                -- We have a length and potentially keep-alive, but want everything.
                co_yield(sock:receive(total_size))

            else
                -- We have a length and potentially a keep-alive, and wish to stream
                -- the response.
                local received = 0
                repeat
                    local length = chunk_size
                    if received + length >= total_size then
                        length = total_size - received
                        -- ngx.log(ngx.ERR, "part length:", length)
                    end

                    if length > 0 then
                        local chunk, err, partial = sock:receive(length)
                        if not chunk and (err == "closed" or err == "timeout") then
                            ngx.log(ngx.ERR, "read partial: ".. err)
                            co_yield(partial)
                            break
                        elseif chunk then
                            co_yield(chunk)
                        else
                            ngx.log(ngx.ERR, "read nil: ".. err)
                            break
                        end
                        received = received + length
                    end

                until length <= 0
                -- ngx.log(ngx.ERR, "receive bytes:", received)
            end

            if cb_done then
                cb_done(sock)
            end

        end)
    else
        return nil, "data type can't make reader"
    end
end


--- 去除字符串收尾空格
----
---- @param string str
---- @return string
function _M.trim(str)
    return (string.gsub(str, "^%s*(.-)%s*$", "%1"))
end


function _M.dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. _M.dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

return _M
