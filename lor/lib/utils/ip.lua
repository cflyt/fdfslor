
local bit  = bit
local string = string
local setmetatable = setmetatable

local _M = {}

--- Test whether the current system is operating in big endian mode.
-- @return  Boolean value indicating whether system is big endian
local function bigendian()
    return string.byte(string.dump(function() end), 7) == 0
end

--- Boolean; true if system is little endian
local LITTLE_ENDIAN = not bigendian()

--- Boolean; true if system is big endian
local BIG_ENDIAN    = not LITTLE_ENDIAN

--- Specifier for IPv4 address family
local FAMILY_INET4  = 0x04

--- Specifier for IPv6 address family
local FAMILY_INET6  = 0x06


--- Convert given short value to network byte order on little endian hosts
-- @param x Unsigned integer value between 0x0000 and 0xFFFF
-- @return  Byte-swapped value
-- @see     htonl
-- @see     ntohs
function _M.htons(x)
    if LITTLE_ENDIAN then
        return bit.bor(
            bit.rshift( x, 8 ),
            bit.band( bit.lshift( x, 8 ), 0xFF00 )
        )
    else
        return x
    end
end

--- Convert given long value to network byte order on little endian hosts
-- @param x Unsigned integer value between 0x00000000 and 0xFFFFFFFF
-- @return  Byte-swapped value
-- @see     htons
-- @see     ntohl
function _M.htonl(x)
    if LITTLE_ENDIAN then
        return bit.bor(
            bit.lshift( _M.htons( bit.band( x, 0xFFFF ) ), 16 ),
            _M.htons( bit.rshift( x, 16 ) )
        )
    else
        return x
    end
end

--- Convert given short value to host byte order on little endian hosts
-- @class   function
-- @name    ntohs
-- @param x Unsigned integer value between 0x0000 and 0xFFFF
-- @return  Byte-swapped value
-- @see     htonl
-- @see     ntohs
_M.ntohs = _M.htons

--- Convert given short value to host byte order on little endian hosts
-- @class   function
-- @name    ntohl
-- @param x Unsigned integer value between 0x00000000 and 0xFFFFFFFF
-- @return  Byte-swapped value
-- @see     htons
-- @see     ntohl
_M.ntohl = _M.htonl

function _M.inet_ntoa(n)
     return string.format("%d.%d.%d.%d", bit.band(bit.rshift(n, 24), 0xff),
                    bit.band(bit.rshift(n, 16), 0xff),
                    bit.band(bit.rshift(n, 8), 0xff),
                    bit.band(n, 0xff))
end


return _M
