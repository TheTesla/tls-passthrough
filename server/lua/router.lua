local redis = require "resty.redis"

local function route()
    -- Redis initialisieren
    local red = redis:new()
    red:set_timeout(2000)

    -- Mit Redis verbinden
    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "REDIS CONNECT ERROR: ", err)
        return
    end

    -- SNI lesen
    local sni = ngx.var.ssl_preread_server_name
    ngx.log(ngx.ERR, "SNI RECEIVED: ", sni)

    if not sni or sni == "" then
        ngx.log(ngx.ERR, "NO SNI PROVIDED")
        return
    end

    -- Backend aus Redis holen
    local backend, err = red:get("sni:" .. sni)
    if not backend or backend == ngx.null then
        ngx.log(ngx.ERR, "NO BACKEND FOR SNI ", sni)
        return
    end

    -- Backend setzen (Format: ip:port)
    ngx.var.dynamic_backend = backend
    ngx.log(ngx.ERR, "ROUTED TO BACKEND: ", backend)
end

return {
    route = route
}

