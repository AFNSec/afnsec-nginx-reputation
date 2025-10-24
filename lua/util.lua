local _M = {}

local cjson = require "cjson.safe"

-- read simple KEY=VALUE file
function _M.read_env(path)
  local f, err = io.open(path, "r")
  if not f then return nil, "open:" .. (err or "unknown") end
  local cfg = {}
  for line in f:lines() do
    local s = line:match("^%s*(.-)%s*$")
    if s ~= "" and not s:match("^#") then
      local k, v = s:match("^([A-Za-z0-9_%-]+)=(.*)$")
      if k then
        cfg[k] = v
      end
    end
  end
  f:close()
  return cfg
end

-- trim + split by comma
local function trim(s) return (s or ""):match("^%s*(.-)%s*$") end
function _M.split_csv(s)
  local out = {}
  if not s or s == "" then return out end
  for token in s:gmatch("([^,]+)") do
    table.insert(out, trim(token))
  end
  return out
end

-- lowercase set from csv
function _M.csv_set_lower(s)
  local t = {}
  for _, v in ipairs(_M.split_csv(s)) do
    t[v:lower()] = true
  end
  return t
end

-- render very small template {{key}}
function _M.render_template(path, ctx)
  local f = io.open(path, "r")
  if not f then return nil, "cannot open block template" end
  local html = f:read("*a")
  f:close()
  local out = html:gsub("{{%s*([%w_]+)%s*}}", function(k)
    return tostring(ctx[k] or "")
  end)
  return out
end

-- cheap policy hash (stable ordering)
function _M.policy_hash(verdict_set)
  local arr = {}
  for k,_ in pairs(verdict_set) do table.insert(arr, k) end
  table.sort(arr)
  return table.concat(arr, ",")
end

-- best-effort client IP extraction
function _M.client_ip(use_xff)
  local ip = ngx.var.remote_addr
  if use_xff and ngx.var.http_x_forwarded_for then
    local xff = ngx.var.http_x_forwarded_for
    local first = xff:match("^%s*([^,%s]+)")
    if first and first ~= "" then ip = first end
  end
  return ip or "0.0.0.0"
end

-- tiny id
function _M.req_id()
  return string.format("%08x%08x", math.random(0,0xffffffff), math.random(0,0xffffffff))
end

function _M.json_encode(x) return cjson.encode(x) end
function _M.json_decode(s) return cjson.decode(s) end

-- Private/loopback/link-local/CGN/multicast detection (basic)
function _M.is_private_ip(ip)
  if not ip then return true end
  -- IPv4
  if ip:match("^127%.") then return true end
  if ip:match("^10%.") then return true end
  if ip:match("^192%.168%.") then return true end
  local a,b = ip:match("^(%d+)%.(%d+)%.")
  a = tonumber(a or "0"); b = tonumber(b or "0")
  if a == 172 and b >= 16 and b <= 31 then return true end
  if a == 169 and b == 254 then return true end
  if a == 100 and b >= 64 and b <= 127 then return true end
  if a >= 224 and a <= 239 then return true end
  -- IPv6 (loopback, ULA, link-local)
  if ip:match("^::1$") then return true end
  if ip:match("^fc[0-9a-fA-F]") or ip:match("^fd[0-9a-fA-F]") then return true end
  if ip:match("^fe80:") then return true end
  return false
end

return _M
