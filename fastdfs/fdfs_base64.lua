local string=string
local bit=bit

local _alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
local BASE64_IGNORE =  -1
local BASE64_PAD   = -2

local _M ={}

local base64_context = {}

function _M:new(line_length, ch_plus, ch_splash, ch_pad)
    local _alpha2 = _alpha..ch_plus..ch_splash
    local value_to_char = {}
    local char_to_value = {}
    for i=1, #_alpha2 do
        local v = string.sub(_alpha2, i, i)
        table.insert(value_to_char, v)
       char_to_value[v] = i - 1
    end
    char_to_value[ch_pad] = BASE64_PAD
    local instance = {
        line_length = line_length,
        line_spparator = {"\n", "\0"},
        line_sep_len = 1,
        value_to_char = value_to_char,
        char_to_value = char_to_value,
        pad_ch = ch_pad,
    }
    setmetatable(instance, {__index = self})
    return instance
end

function _M:base64_decode(src)
    local cycle = 0
    local combined = 0
    local  dummies = 0
    local  value = 0
    local dest = ""

    for i=1, #src do
        value = self.char_to_value[string.sub(src, i,i)]
        if value == BASE64_IGNORE then
        else
            if value == BASE64_PAD then
               value = 0;
               dummies = dummies + 1
            end
            if cycle == 0 then
                combined = value
                cycle = 1
            elseif cycle == 1 then
                combined = bit.lshift(combined, 6)
                combined = bit.bor(combined, value)
                cycle = 2
            elseif cycle == 2 then
                combined = bit.lshift(combined, 6)
                combined = bit.bor(combined, value)
                cycle = 3
            elseif cycle == 3 then
                combined = bit.lshift(combined, 6)
                combined = bit.bor(combined, value)
                 -- we have just completed a cycle of 4 chars.
                 --the four 6-bit values are in combined in big-endian order
                 -- peel them off 8 bits at a time working lsb to msb
                 -- to get our original 3 8-bit bytes back
                 dest = dest..string.char(bit.rshift(combined, 16))
                 dest = dest..string.char(bit.rshift(bit.band(combined, 0x0000FF00), 8))
                 dest = dest..string.char(bit.band(combined, 0x000000FF))
                 cycle = 0
             end
        end
    end
    if cycle ~= 0 then
        ngx.log(ngx.ERR,  "Input to decode not an even multiple of 4 characters; pad with: ", self.pad_ch)
        dest = ""
        return dest
    end

   return dest

end


function _M:base64_decode_auto(src)
    local remain = 0
    local pad_len = 0

    remain = string.len(src) % 4
    if (remain == 0) then
        return self:base64_decode(src)
    end

    pad_len = 4 - remain
    src = src .. string.rep(self.pad_ch, pad_len)

    return self:base64_decode(src)
end


return _M
