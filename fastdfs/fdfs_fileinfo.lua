local base64 = require("fastdfs.fdfs_base64")
local base64 = base64:new(0, '-', '_', '.')
local iputils = require("fastdfs.ip")
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


local _M = {}

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

local function int2buf(n)
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

local function buf2long(buf)
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

local function fdfs_get_server_id_type(id)
    if id > 0 and id <= FDFS_MAX_SERVER_ID then
       return FDFS_ID_TYPE_SERVER_ID
    else
        return FDFS_ID_TYPE_IP_ADDRESS
    end
end

local function IS_UPPER_HEX(ch)
    return ((ch >= '0' and ch <= '9') or (ch >= 'A' and ch <= 'F'))
end

local function IS_TRUNK_FILE(file_size)
    return bit.band(file_size, FDFS_TRUNK_FILE_MARK_SIZE) ~= 0
end

local function IS_SLAVE_FILE(filename_len, file_size)
    --return ((filename_len > FDFS_TRUNK_LOGIC_FILENAME_LENGTH) or
    --(filename_len > FDFS_NORMAL_LOGIC_FILENAME_LENGTH and not IS_TRUNK_FILE(file_size)))
    return ((filename_len > FDFS_TRUNK_FILENAME_LENGTH_NO_PATH) or
    (filename_len > FDFS_NORMAL_FILENAME_LENGTH_NO_PATH and not IS_TRUNK_FILE(file_size)))
end

local function IS_APPENDER_FILE(file_size)
    return (bit.band(file_size, FDFS_APPENDER_FILE_SIZE) ~=0 )
end

function _M.get_fileinfo_ex(filename_without_path)
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
    if (is_appender) then
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

function _M.get_fileinfo(fileid)
    fileid = string.gsub(fileid, "(/+)", "/")
    fileid = string.gsub(fileid, "^(//*)", "")
    fileid = string.gsub(fileid, "(//*)$", "")
    local filename_without_path = string.match(fileid, ".*/(.*)") or ""
    local filename_len = string.len(filename_without_path)
    return _M.get_fileinfo_ex(filename_without_path)
end

local class_mt = {
    -- to prevent use of casual module global variables
    __newindex = function (table, key, val)
        error('attempt to write to undeclared variable "' .. key .. '"')
    end
}

setmetatable(_M, class_mt)
return _M
