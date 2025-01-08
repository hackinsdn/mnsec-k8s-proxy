ngx.req.read_body()
local body_data = ngx.req.get_body_data()
if body_data then
    ngx.req.set_header("X-Body", body_data)
end
