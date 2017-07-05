
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
_M.LITTLE_ENDIAN = not bigendian()

--- Boolean; true if system is big endian
_M.BIG_ENDIAN    = not LITTLE_ENDIAN

--- Specifier for IPv4 address family
_M.FAMILY_INET4  = 0x04

--- Specifier for IPv6 address family
_M.FAMILY_INET6  = 0x06


local function __array16( x, family )
    local list

    if type(x) == "number" then
        list = { bit.rshift(x, 16), bit.band(x, 0xFFFF) }

    elseif type(x) == "string" then
        if x:find(":") then x = IPv6(x) else x = IPv4(x) end
        if x then
            assert( x[1] == family, "Can't mix IPv4 and IPv6 addresses" )
            list = { unpack(x[2]) }
        end

    elseif type(x) == "table" and type(x[2]) == "table" then
        assert( x[1] == family, "Can't mix IPv4 and IPv6 addresses" )
        list = { unpack(x[2]) }

    elseif type(x) == "table" then
        list = { unpack(x) }
    end

    assert( list, "Invalid operand" )

    return list
end

local function __mask16(bits)
    return bit.lshift( bit.rshift( 0xFFFF, 16 - bits % 16 ), 16 - bits % 16 )
end

local function __not16(bits)
    return bit.band( bit.bnot( __mask16(bits) ), 0xFFFF )
end

local function __maxlen(family)
    return ( family == FAMILY_INET4 ) and 32 or 128
end

local function __sublen(family)
    return ( family == FAMILY_INET4 ) and 30 or 127
end


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
            bit.lshift( htons( bit.band( x, 0xFFFF ) ), 16 ),
            htons( bit.rshift( x, 16 ) )
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
