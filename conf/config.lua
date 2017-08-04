# -*- coding:utf8 -*-

local ONLINE = true

local config = nil

if not ONLINE then
    config = require "conf/config-dev"
else
    config = require "conf/config-online"
end

return config


