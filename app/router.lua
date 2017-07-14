-- 业务路由管理
local userRouter = require("app.routes.user")
local fsRouter = require("app.routes.fs")

return function(app)

    -- simple router: hello world!
    app:get("/hello", function(req, res, next)
        res:send("hi! welcome to lor bigo dfs.")
    end)

    -- simple router: render html, visit "/" or "/?name=foo&desc=bar
    app:get("/", function(req, res, next)
        local data = {
            name = "bigo dfs",
            desc =  "bigo file store service"
        }
        res:render("index", data)
    end)

    app:use("/:product", fsRouter())

end

