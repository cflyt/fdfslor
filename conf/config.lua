# -*- coding:utf8 -*-

local _M = {}

_M.file_sync_max_time = 86400

_M.remote_response_mode = "proxy"
--_M.remote_response_mode = "redirect"
--_M.remote_response_mode = "storage"

_M.trackers = {
    { host="192.168.56.12", port=22122},
    { host="192.168.56.10", port=22122},
}

_M.storage_ids = {
    [10001] = {
        id = 10001,
        ip = "192.168.56.10",
        port = 23000
    },
    [10002] = {
        id = 10002,
        ip = "192.168.56.12",
        port = 23000
    }
}

_M.tracker_timeout = 10
_M.storage_timeout = 10
_M.tracker_keepalive = {0, 100} -- 连接池参数{超时时间，池大小}
_M.storage_keepalive = {0, 100}

_M.store_paths = {
    "/home/vagrant/project/fastdfs/storage1",
}

--_M.store_paths = {
--    "/data1/storage",
--    "/data2/storage",
--    "/data3/storage",
--    "/data4/storage",
--    "/data5/storage",
--    "/data6/storage",
--    "/data7/storage",
--    "/data8/storage",
--    "/data9/storage",
--    "/data10/storage",
--    "/data11/storage",
--    "/data12/storage",
--}

return _M


