
local logger = ngx.log
local LOG_ERR = ngx.ERR
local LOG_INFO = ngx.INFO

local _rx_range = 'bytes *= *(%d*) *- *(%d*)'
local _rx_content_range = 'bytes (?:(%d+)-(%d+)|[*])/(?:(%d+)|[*])'

local function _is_content_range_valid(start, stop, length, response)
    if (not start) ~= (not stop) then
        return  false
    elseif not start then
        return not length or length >= 0
    elseif not length then
        return 0 <= start and start < stop
    elseif start >= stop then
        return false
    elseif response and stop > length then
        -- "content-range: bytes 0-50/10" is invalid for a response
        -- "range: bytes 0-50" is valid for a request to a 10-bytes entity
        return false
    else
        return 0 <= start and start < length
    end
end


local ContentRange = {}

   --[[
    Represents the Content-Range header

    This header is ``start-stop/length``, where start-stop and length
    can be ``*`` (represented as None in the attributes).
    --]]

function ContentRange:new(start, stop, length)
    if not _is_content_range_valid(start, stop, length) then
        error(string.format("Bad start:stop/length: %s-%s/%s" , tostring(start), tostring(stop), tostring(length)))
    end
    ngx.log(ngx.ERR, "Content range:", start, ":", stop, ":", length)
    local instance = {
        start = start,
        stop = stop,  -- this is python-style range stop (non-inclusive)
        length = length,
    }
    setmetatable(instance,
    {
        __index = self,
        __tostring = function(self)
                local length = 0
                if not self.length then
                    length = '*'
                else
                    length = self.length
                end

                if not self.start then
                    if not self.stop then
                        error(string.format("Bad Range stop nil" ))
                    end
                    return string.format("bytes */%s" , length)
                end

                local stop = self.stop - 1 --  from non-inclusive to HTTP-style
                return string.format("bytes %s-%s/%s" , tostring(self.start), tostring(stop), tostring(length))
        end
    })
    return instance
end

function ContentRange:parse(value)
    --[[
        Parse the header.  May return None if it cannot parse.
    --]]
    local s,e,l  = string.match(value or "", _rx_content_range)
    if s then
        s = tonumber(s)
        e = tonumber(e) + 1
    end
    l = tonumber(l)
    if not _is_content_range_valid(s, e, l, true) then
        return nil
    end
    return self:new(s, e, l)
end


local Range= {}

function Range:new(start, stop)
    if not stop  or stop < 0 then
        logger(LOG_ERR, "Bad range stop : " .. stop)
    end
    local instance = {
        start = start,
        stop = stop
    }
    setmetatable(instance, {__index = self,
                 __tostring = function(self)
                    local s,e = self.start, self.stop
                    if not e then
                        r = "bytes=" .. s
                        if s >= 0 then
                            r = r .. "-"
                        end
                        return r
                    end
                    return string.format("bytes=%d-%d", s, e-1)
                end
               })
    return instance
end

function Range:range_for_length(length)
   --[[
        *If* there is only one range, and *if* it is satisfiable by
        the given length, then return a (start, stop) non-inclusive range
        of bytes to serve.  Otherwise return None
   --]]
    --if not length then
    --    return nil
    --end
    local start, stop = self.start, self.stop
    if not stop then
        stop = length
        if start < 0 and length then
            start = start + length
        end
    end
    if _is_content_range_valid(start, stop, length) then
        if length and stop > length then
            stop = length
        end
        return start, stop
    else
        return nil
    end
end

function Range:content_range(length)
   --[[
        Works like range_for_length; returns None or a ContentRange object

        You can use it like::

            response.content_range = req.range:content_range(response.content_length)

        Though it's still up to you to actually serve that content range!
   --]]
    local start, stop = self:range_for_length(length)
    if not start then
        return nil
    end
    local cr = ContentRange
    return cr:new(start, stop, length)
end


function Range:parse(header)

   --     Parse the header; may return None if header is invalid
    local header = header or ""
    local start, stop = string.match(header, _rx_range)
    if not start and not stop then
        return nil
    end

    if not start then
        return self:new(-tonumber(stop), nil)
    end
    start = tonumber(start)
    if not stop then
        return self:new(start, nil)
    end
    stop = tonumber(stop) + 1  -- return val is non-inclusive
    if start >= stop then
        return nil
    end
    return self:new(start, stop)
end


local _M = {}
_M.Range = Range
_M.ContentRange = ContentRange


return _M
