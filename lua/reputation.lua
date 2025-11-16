local util  = require "util"
local cjson = require "cjson.safe"

local _M = {}

local cfg   = {}
local cache = ngx.shared.afnsec_reputation_cache

local function log(level, msg, fields)
  fields = fields or {}
  fields.event = "afnsec.reputation"
  fields.msg   = msg
  local line = cjson.encode(fields) or ('{"event":"afnsec.reputation","msg":"'..(msg or "?")..'"}')
  if level == "debug" then
    if cfg.LOG_LEVEL == "debug" then ngx.log(ngx.DEBUG, line) end
  elseif level == "warn" then
    ngx.log(ngx.WARN, line)
  else
    ngx.log(ngx.INFO, line)
  end
end

local function normalize()
  cfg.API_KEY                    = (cfg.API_KEY or ""):match("^%s*(.-)%s*$")
  cfg.AFNSEC_VERDICT             = (cfg.AFNSEC_VERDICT or "malicious,suspicious")
  cfg.REQUEST_TIMEOUT            = tonumber(cfg.REQUEST_TIMEOUT) or 1000
  cfg.AFNSEC_CACHE_EXPIRATION    = tonumber(cfg.AFNSEC_CACHE_EXPIRATION) or 600
  cfg.AFNSEC_BLOCK_TEMPLATE_PATH = cfg.AFNSEC_BLOCK_TEMPLATE_PATH or "/var/www/afnsec/block.html"
  cfg.FAIL_MODE                  = (cfg.FAIL_MODE or "open"):lower()
  cfg.RESPECT_XFF                = ((cfg.RESPECT_XFF or "on"):lower() == "on")
  cfg.LOG_LEVEL                  = (cfg.LOG_LEVEL or "info"):lower()

  local excl = util.split_csv(cfg.EXCLUDE_LOCATION or "")
  cfg.EXCLUDE_SET = {}
  for _, pfx in ipairs(excl) do
    if pfx and pfx ~= "" then cfg.EXCLUDE_SET[pfx] = true end
  end
  -- exclude our own health endpoint
  cfg.EXCLUDE_SET["/afnsec-reputation/healthz"] = true

  -- policy
  if cfg.AFNSEC_VERDICT == "all" then
    cfg.VERDICT_SET = util.csv_set_lower("malicious,suspicious")
  else
    cfg.VERDICT_SET = util.csv_set_lower(cfg.AFNSEC_VERDICT)
  end
  cfg.POLICY_HASH = util.policy_hash(cfg.VERDICT_SET)
end

local function is_excluded(uri)
  local set = cfg and cfg.EXCLUDE_SET
  if type(set) ~= "table" or not uri then return false end
  for pfx,_ in pairs(set) do
    if pfx ~= "" and uri:sub(1, #pfx) == pfx then
      return true
    end
  end
  return false
end

local function cache_key(ip)
  return ("afnsec:%s|%s"):format(ip, cfg.POLICY_HASH)
end

local function render_block(ctx)
  local html, err = util.render_template(cfg.AFNSEC_BLOCK_TEMPLATE_PATH, ctx)
  if not html then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Access blocked")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.header["Content-Type"] = "text/html; charset=utf-8"
  ngx.say(html)
  return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function https_get(host, path, headers, timeout_ms)
  local sock = ngx.socket.tcp()
  sock:settimeout(timeout_ms or 1000)

  local ok, err = sock:connect(host, 443)
  if not ok then return nil, "connect:"..tostring(err) end

  ok, err = sock:sslhandshake(nil, host, true) -- verify
  if not ok then sock:close(); return nil, "ssl:"..tostring(err) end

  local req = {}
  req[#req+1] = "GET "..path.." HTTP/1.1"
  req[#req+1] = "Host: "..host
  for k,v in pairs(headers or {}) do req[#req+1] = k..": "..v end
  req[#req+1] = "Connection: close"
  req[#req+1] = ""
  req[#req+1] = ""
  local payload = table.concat(req, "\r\n")

  local sent; sent, err = sock:send(payload.."\r\n")
  if not sent then sock:close(); return nil, "send:"..tostring(err) end

  local status_line; status_line, err = sock:receive("*l")
  if not status_line then sock:close(); return nil, "status:"..tostring(err) end
  local status = tonumber(status_line:match("HTTP/%d%.%d%s+(%d+)")) or 0

  local hdrs = {}
  while true do
    local line; line, err = sock:receive("*l")
    if not line then sock:close(); return nil, "hdr:"..tostring(err) end
    if line == "" then break end
    local k,v = line:match("^([^:]+):%s*(.*)$")
    if k then hdrs[k:lower()] = v end
  end

  local body
  local cl = tonumber(hdrs["content-length"] or 0)
  if cl and cl > 0 then
    body = sock:receive(cl)
  else
    local chunks = {}
    while true do
      local chunk, rerr, part = sock:receive(8192)
      if chunk then chunks[#chunks+1] = chunk
      elseif part and #part > 0 then chunks[#chunks+1] = part
      else break end
    end
    body = table.concat(chunks)
  end

  sock:close()
  return { status = status, headers = hdrs, body = body }, nil
end

local function query_api(ip)
  local path = "/api/v1/ip/" .. ip
  local headers = {
    ["User-Agent"] = "AFNSec-Nginx-Reputation/1.0",
    ["X-API-Key"]  = cfg.API_KEY or "",
    ["Accept"]     = "application/json",
  }
  local res, err = https_get("api.afnsec.com", path, headers, cfg.REQUEST_TIMEOUT)
  if not res then return nil, err end
  if res.status < 200 or res.status >= 300 then return nil, "status:"..res.status end
  local j, derr = cjson.decode(res.body or "")
  if not j then return nil, "json:"..tostring(derr) end
  local verdict = (((j.assessment and j.assessment.verdict) or j.verdict or j.VERDICT or j.status or "unknown")..""):lower()
  local ttl     = tonumber(j.ttl or j.cache_ttl or 0) or 0
  return { verdict = verdict, ttl = ttl }, nil
end

function _M.global_init(path)
  local env, err = util.read_env(path)
  if not env then
    ngx.log(ngx.ERR, "afnsec.reputation failed to load config: "..(err or "unknown"))
    env = {}
  end
  cfg = env
  normalize()
  if (cfg.API_KEY or "") == "" then
    ngx.log(ngx.WARN, "afnsec.reputation missing API_KEY; running but will allow on fail (open mode).")
  end
end

local function health_probe()
  local headers = {
    ["User-Agent"] = "AFNSec-Nginx-Reputation/1.0",
    ["Accept"]     = "application/json",
  }
  local t0 = ngx.now()
  local res, err = https_get("api.afnsec.com", "/healthz", headers, 1200)
  local took = math.floor((ngx.now()-t0)*1000)

  if not res then
    log("warn", "api_health", { status = "fail", error = err or "unknown", latency_ms = took })
    if cache then
      cache:set("health:last_status", "fail", 300)
      cache:set("health:last_latency_ms", took, 300)
      cache:set("health:echo_needed", 1, 300)
    end

    ngx.sleep(0.5)
    t0 = ngx.now()
    res, err = https_get("api.afnsec.com", "/healthz", headers, 1200)
    took = math.floor((ngx.now()-t0)*1000)
    if not res then
      log("warn", "api_health", { status = "fail", error = err or "unknown", latency_ms = took })
      return
    end
  end

  if res.status < 200 or res.status >= 300 then
    log("warn", "api_health", { status = "fail:"..tostring(res.status), latency_ms = took })
    if cache then
      cache:set("health:last_status", "fail", 300)
      cache:set("health:last_latency_ms", took, 300)
      cache:set("health:echo_needed", 1, 300)
    end
    return
  end

  local j, derr = cjson.decode(res.body or "")
  if not j or j.ok ~= true then
    log("warn", "api_health", { status = "fail", error = "unexpected payload", latency_ms = took })
    if cache then
      cache:set("health:last_status", "fail", 300)
      cache:set("health:last_latency_ms", took, 300)
      cache:set("health:echo_needed", 1, 300)
    end
    return
  end

  log("info", "api_health", { status = "ok", latency_ms = took })
  if cache then
    cache:set("health:last_status", "ok", 600)
    cache:set("health:last_latency_ms", took, 600)
    cache:set("health:echo_needed", 1, 600)
  end
end

function _M.worker_init()
  ngx.timer.at(0, function(_) pcall(health_probe) end)
end

function _M.healthz()
  local resp = {
    status          = "ok",
    log_level       = cfg.LOG_LEVEL,
    fail_mode       = cfg.FAIL_MODE,
    respect_xff     = cfg.RESPECT_XFF,
    policy          = cfg.AFNSEC_VERDICT,
    cache_capacity  = cache and cache:capacity() or 0,
    cache_bytes_free= cache and cache:free_space() or 0,
  }
  ngx.header["Content-Type"] = "application/json"
  ngx.say(util.json_encode(resp))
end

function _M.enforce()
  do
    local echo = cache and cache:get("health:echo_needed")
    if echo then
      local hs   = cache:get("health:last_status") or "unknown"
      local hlat = tonumber(cache:get("health:last_latency_ms") or 0)
      log("info", "api_health", { status = hs, latency_ms = hlat, echo = true })
      if cache and cache.delete then cache:delete("health:echo_needed") end
    end
  end

  local uri = ngx.var.uri or "/"
  -- hard bypass our own health endpoint
  if uri:sub(1, 25) == "/afnsec-reputation/healthz" then return end
  if is_excluded(uri) then return end

  local start  = ngx.now()
  local req_id = util.req_id()
  local ip     = util.client_ip(cfg.RESPECT_XFF)
  local ck     = cache_key(ip)

  local cached = cache and cache:get(ck)
  if cached then
    local data = cjson.decode(cached)
    if data and cfg.VERDICT_SET[data.verdict] then
      log("info", "cache_block", { ip=ip, verdict=data.verdict, cache="hit", req_id=req_id, latency_ms=math.floor((ngx.now()-start)*1000) })
      return render_block({ ip = ip, verdict = verdict, req_id = req_id, ts = os.date("!%Y-%m-%dT%H:%M:%SZ"), reason = "IP reputation match"})
    else
      log("debug", "cache_allow", { ip=ip, verdict=data and data.verdict or "unknown", cache="hit", req_id=req_id, latency_ms=math.floor((ngx.now()-start)*1000) })
      return
    end
  end

  local decision, err = query_api(ip)
  if not decision then
    if cfg.FAIL_MODE == "closed" then
      log("warn", "api_fail_block", { ip=ip, error=err, req_id=req_id })
      return render_block({ ip=ip, verdict="unavailable", req_id=req_id, ts=os.date("!%Y-%m-%dT%H:%M:%SZ") })
    else
      log("warn", "api_fail_allow", { ip=ip, error=err, req_id=req_id })
      return
    end
  end

  local verdict = decision.verdict or "unknown"
  local ttl     = tonumber(decision.ttl) or 0

  local verdict_ttls = {
    malicious  = 3600, -- 1 hour
    suspicious = 900,  -- 15 minutes
    unknown    = 120   -- 2 minutes
  }
  if ttl <= 0 then
    local base = verdict_ttls[verdict] or cfg.AFNSEC_CACHE_EXPIRATION
    local jitter = math.random(-math.floor(0.1 * base), math.floor(0.1 * base))
    ttl = math.max(60, base + jitter)
  end

  if cache then cache:set(ck, cjson.encode({ verdict = verdict }), ttl) end

  local took = math.floor((ngx.now()-start)*1000)
  if cfg.VERDICT_SET[verdict] then
    log("info", "live_block", { ip=ip, verdict=verdict, cache="miss", req_id=req_id, latency_ms=took })
    return render_block({ ip=ip, verdict=verdict, req_id=req_id, ts=os.date("!%Y-%m-%dT%H:%M:%SZ"), reason="IP reputation match"})
  else
    log("debug", "live_allow", { ip=ip, verdict=verdict, cache="miss", req_id=req_id, latency_ms=took })
    return
  end
end

return _M
