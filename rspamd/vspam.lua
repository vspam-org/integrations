--[[
vspam.org community abuse intelligence for Rspamd.

Install to $LOCAL_CONFDIR/plugins.d/vspam.lua (usually /etc/rspamd/plugins.d/)
and configure in local.d/vspam.conf. The module stays disabled until that
config file exists, so dropping the file in alone changes nothing.

Two transports, in this order:

  1. The local vspam-agent on 127.0.0.1:10046. One POST per message covers
     the sender domain, the connecting IP and every URL at once, answered
     from the agent's BoltDB cache, and what this server saw is fed back to
     the pool automatically.

  2. The public API, if no agent answers. One GET per indicator, and only a
     SHA-256 of the indicator crosses the network -- the domain itself never
     leaves the machine. Slower and it reports nothing back, but it means an
     operator can try the module before deciding to run a daemon.

Both fail open. A timeout, a refused connection or an unparseable body
inserts VSPAM_FAIL (weight 0) and lets the message through. A blocklist that
takes down mail flow when it is unreachable is worse than no blocklist.
]] --

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_ip = require "rspamd_ip"
local lua_util = require "lua_util"
local ucl = require "ucl"

local N = 'vspam'

local settings = {
  -- Transport
  agent_url = 'http://127.0.0.1:10046',
  api_url = 'https://api.vspam.org',
  api_key = '',
  use_agent = true,
  fallback_to_api = true,
  -- Seconds to stop calling a dead agent for. Every message would otherwise
  -- pay a full connect timeout before falling back.
  agent_cooldown = 60,

  -- What to look up
  check_sender_domain = true,
  check_client_ip = true,
  check_urls = true,
  max_urls = 10,

  -- Who to check. Rspamd's shared convention, read by
  -- lua_util.config_check_local_or_authed: off means your own networks and
  -- your own authenticated submissions are skipped, which is what a public
  -- blocklist should do.
  check_local = false,
  check_authed = false,

  timeout = 2.0,
  no_ssl_verify = false,

  symbols = {
    phishing = 'VSPAM_PHISHING',
    malware = 'VSPAM_MALWARE',
    botnet = 'VSPAM_BOTNET',
    spam = 'VSPAM_SPAM',
    tor = 'VSPAM_TOR',
    threat = 'VSPAM_THREAT',
  },
  symbol_suspicious = 'VSPAM_SUSPICIOUS',
  symbol_fail = 'VSPAM_FAIL',
}

-- Default weights. These deliberately match the DNSBL return-code weights in
-- integrations/mailcow/scores.conf so that moving from the DNS path to this
-- module does not silently reweight anyone's mail. Override in
-- local.d/groups.conf, which is where Rspamd operators expect to tune.
local default_scores = {
  phishing = 6.0,
  malware = 6.0,
  botnet = 5.0,
  spam = 3.0,
  tor = 0.5,
  threat = 2.0,
}

local descriptions = {
  phishing = 'Listed on vspam.org as phishing',
  malware = 'Listed on vspam.org as malware distribution',
  botnet = 'Listed on vspam.org as botnet command and control',
  spam = 'Listed on vspam.org as a spam source',
  tor = 'Listed on vspam.org as a Tor exit node',
  threat = 'Listed on vspam.org as an aggregated threat indicator',
}

-- Severity order, used only to pick which single result to report when
-- several indicators in one message are listed under different categories.
local severity = {
  phishing = 6,
  malware = 5,
  botnet = 4,
  spam = 3,
  threat = 2,
  tor = 1,
}

-- Report categories are finer-grained than the six DNSBL return codes, so the
-- same folding is applied here that the zone assignment applies server-side.
-- Anything unrecognised lands on 'threat' rather than being dropped: a listing
-- we cannot classify is still a listing.
local category_kind = {
  phishing = 'phishing',
  phishing_url = 'phishing',
  phishing_domain = 'phishing',
  credential_harvest = 'phishing',
  brand_impersonation = 'phishing',
  scam = 'phishing',

  malware = 'malware',
  malware_url = 'malware',
  malware_domain = 'malware',
  spyware_domain = 'malware',

  botnet = 'botnet',
  botnet_c2 = 'botnet',

  spam = 'spam',
  spam_source = 'spam',
  blacklist_ip = 'spam',

  tor = 'tor',
  tor_exit_node = 'tor',
}

-- Set when the agent refuses a connection, so the next messages skip straight
-- to the API instead of each paying a connect timeout. Per worker process.
local agent_down_until = 0

-- Filled in at the end of the file from check_local/check_authed.
local local_authed_conf

local function kind_for_category(category)
  if not category or category == '' then
    return 'threat'
  end
  return category_kind[string.lower(category)] or 'threat'
end

-- rspamd_ip.from_string logs at error level for anything that is not an
-- address, so a domain must never reach it. Only strings that could plausibly
-- be one are handed over.
local function looks_like_ip(s)
  if s:match('^%d+%.%d+%.%d+%.%d+$') then
    return true
  end
  return s:find(':', 1, true) ~= nil and s:match('^[%x:%.]+$') ~= nil
end

-- Mirrors the agent's hashIOC: lowercase, trim, strip trailing dots, then
-- canonicalise IPs so 2001:0db8::0001 and 2001:db8::1 hash identically.
local function normalize_ioc(value)
  local s = string.lower(value:match('^%s*(.-)%s*$') or '')
  -- A URL host may arrive bracketed, as in http://[2001:db8::1]/path.
  s = s:match('^%[(.+)%]$') or s
  s = s:gsub('%.+$', '')
  if s == '' or not looks_like_ip(s) then
    return s
  end
  local ip = rspamd_ip.from_string(s)
  if ip and ip:is_valid() then
    s = tostring(ip)
  end
  return s
end

local function hash_ioc(value)
  return rspamd_hash.create_specific('sha256', normalize_ioc(value)):hex()
end

-- Collects the indicators to look up, deduplicated by the value that will be
-- hashed. Order matters for the agent, which returns the first hit it finds.
local function collect_iocs(task)
  local seen, out = {}, {}

  local function add(kind, value)
    if not value or value == '' then
      return
    end
    local key = normalize_ioc(value)
    if key == '' or seen[key] then
      return
    end
    seen[key] = true
    out[#out + 1] = { kind = kind, value = value, lookup = key }
  end

  if settings.check_sender_domain then
    local from = task:get_from('smtp') or task:get_from('mime')
    if from and from[1] and from[1].domain then
      add('domain', from[1].domain)
    end
  end

  if settings.check_client_ip then
    local ip = task:get_from_ip()
    if ip and ip:is_valid() then
      add('ip', tostring(ip))
    end
  end

  if settings.check_urls then
    local urls = task:get_urls() or {}
    local added = 0
    for _, u in ipairs(urls) do
      if added >= settings.max_urls then
        break
      end
      local host = u:get_host()
      if host and host ~= '' then
        local before = #out
        add('url', host)
        if #out > before then
          added = added + 1
        end
      end
    end
  end

  return out
end

-- A finding is what either transport reduces to before it reaches
-- task:insert_result. kind is nil for a scored-but-not-listed indicator.
local function insert_finding(task, finding)
  if finding.kind then
    local symbol = settings.symbols[finding.kind]
    if not symbol then
      return
    end
    local opts = { finding.lookup }
    if finding.category and finding.category ~= '' then
      opts[#opts + 1] = finding.category
    end
    if finding.source and finding.source ~= '' then
      opts[#opts + 1] = finding.source
    end
    task:insert_result(symbol, 1.0, opts)
    lua_util.debugm(N, task, 'listed %s as %s (%s)', finding.lookup, finding.kind, finding.source)
  else
    local opts = { finding.lookup }
    if finding.reason and finding.reason ~= '' then
      opts[#opts + 1] = finding.reason
    end
    task:insert_result(settings.symbol_suspicious, 1.0, opts)
    lua_util.debugm(N, task, 'suspicious %s', finding.lookup)
  end
end

local function fail(task, why)
  task:insert_result(settings.symbol_fail, 1.0, why)
  lua_util.debugm(N, task, 'lookup failed: %s', why)
end

local function parse_json(body)
  if not body or body == '' then
    return nil, 'empty body'
  end
  local parser = ucl.parser()
  local ok, err = parser:parse_string(body)
  if not ok then
    return nil, err or 'invalid JSON'
  end
  return parser:get_object(), nil
end

-- Reduce an agent /check response to at most one finding.
local function finding_from_agent(obj, fallback_lookup)
  local lookup = obj.lookup_value or obj.ioc_value or fallback_lookup or ''

  if obj.malicious then
    local source = 'agent'
    if obj.effective_decision and obj.effective_decision.source then
      source = obj.effective_decision.source
    end
    return {
      kind = kind_for_category(obj.category),
      lookup = lookup,
      category = obj.category,
      source = source,
    }
  end

  -- Not listed, but the platform has an opinion. This is the signal a DNSBL
  -- return code cannot carry, and the reason to run the module at all.
  local decision = obj.effective_decision
  local scoring = obj.scoring
  local suspicious = (decision and decision.verdict == 'suspicious')
      or (scoring and scoring.needs_manual_review)
  if suspicious then
    return {
      kind = nil,
      lookup = lookup,
      reason = (scoring and scoring.reason_summary) or (decision and decision.rationale) or nil,
    }
  end

  return nil
end

-- Reduce a public API lookup response to at most one finding. The envelope is
-- {"data": {...}}; an unlisted indicator is a 404, handled by the caller.
local function finding_from_api(obj, entry)
  local data = obj.data
  if not data then
    return nil
  end

  local decision = data.effective_decision
  local scoring = data.scoring

  local listed = false
  local source = 'api'
  if decision then
    listed = decision.listed and true or false
    if decision.source and decision.source ~= '' then
      source = decision.source
    end
  elseif data.status == 'confirmed' then
    -- No explicit decision recorded; fall back to the legacy status field,
    -- the same precedence the agent applies.
    listed = true
    source = 'legacy_status'
  end

  if listed then
    return {
      kind = kind_for_category(data.category),
      lookup = entry.lookup,
      category = data.category,
      source = source,
    }
  end

  local suspicious = (decision and decision.verdict == 'suspicious')
      or (scoring and scoring.needs_manual_review)
  if suspicious then
    return {
      kind = nil,
      lookup = entry.lookup,
      reason = (scoring and scoring.reason_summary) or (decision and decision.rationale) or nil,
    }
  end

  return nil
end

local function api_headers()
  if settings.api_key ~= '' then
    return { ['X-API-Key'] = settings.api_key }
  end
  return nil
end

-- Public API path: one request per indicator, fired together. Results are
-- collected and only the strongest is reported, so a message whose sender is
-- listed as spam and whose link is listed as phishing scores as phishing
-- once rather than as both.
local function check_via_api(task, iocs)
  local pending = #iocs
  if pending == 0 then
    return
  end

  local path = '/api/v1/public/lookup/'
  if settings.api_key ~= '' then
    path = '/api/v1/lookup/'
  end

  local best, best_rank, errors = nil, -1, 0

  local function finish()
    if best then
      insert_finding(task, best)
    elseif errors >= #iocs then
      fail(task, 'api unreachable')
    end
  end

  local function consider(finding)
    if not finding then
      return
    end
    local rank = finding.kind and severity[finding.kind] or 0
    if rank > best_rank then
      best, best_rank = finding, rank
    end
  end

  for _, entry in ipairs(iocs) do
    local url = settings.api_url .. path .. hash_ioc(entry.lookup)

    rspamd_http.request({
      task = task,
      url = url,
      method = 'GET',
      headers = api_headers(),
      timeout = settings.timeout,
      no_ssl_verify = settings.no_ssl_verify,
      callback = function(err, code, body, _)
        pending = pending - 1

        if err then
          errors = errors + 1
          lua_util.debugm(N, task, 'api error for %s: %s', entry.lookup, err)
        elseif code == 404 then
          -- Not listed. The common case, and not an error.
          lua_util.debugm(N, task, 'api: %s not listed', entry.lookup)
        elseif code ~= 200 then
          errors = errors + 1
          rspamd_logger.infox(task, 'vspam api returned %s for %s', code, entry.lookup)
        else
          local obj, perr = parse_json(body)
          if not obj then
            errors = errors + 1
            rspamd_logger.infox(task, 'vspam api: cannot parse response: %s', perr)
          else
            consider(finding_from_api(obj, entry))
          end
        end

        if pending == 0 then
          finish()
        end
      end,
    })
  end
end

-- Agent path: a single POST covering everything. The agent walks the same
-- indicators in the same order and answers with the first hit.
local function check_via_agent(task, iocs)
  local body = { urls = {} }
  for _, entry in ipairs(iocs) do
    if entry.kind == 'domain' and not body.sender_domain then
      body.sender_domain = entry.value
    elseif entry.kind == 'ip' and not body.client_ip then
      body.client_ip = entry.value
    elseif entry.kind == 'url' then
      body.urls[#body.urls + 1] = entry.value
    end
  end

  -- The agent rejects a request with neither a sender domain nor any URL.
  if not body.sender_domain and #body.urls == 0 then
    if settings.fallback_to_api then
      check_via_api(task, iocs)
    end
    return
  end

  local function on_agent_failure(why)
    if settings.agent_cooldown > 0 then
      agent_down_until = os.time() + settings.agent_cooldown
    end
    if settings.fallback_to_api then
      lua_util.debugm(N, task, 'agent unavailable (%s), using public API', why)
      check_via_api(task, iocs)
    else
      fail(task, why)
    end
  end

  rspamd_http.request({
    task = task,
    url = settings.agent_url .. '/check',
    method = 'POST',
    body = ucl.to_format(body, 'json-compact'),
    headers = { ['Content-Type'] = 'application/json' },
    timeout = settings.timeout,
    callback = function(err, code, resp, _)
      if err then
        on_agent_failure(err)
        return
      end
      if code ~= 200 then
        on_agent_failure(string.format('agent returned %s', code))
        return
      end

      local obj, perr = parse_json(resp)
      if not obj then
        rspamd_logger.infox(task, 'vspam agent: cannot parse response: %s', perr)
        fail(task, 'bad agent response')
        return
      end

      -- A reachable agent that answers "clean" is authoritative; do not
      -- second-guess it by also asking the API.
      agent_down_until = 0
      local finding = finding_from_agent(obj, iocs[1] and iocs[1].lookup)
      if finding then
        insert_finding(task, finding)
      end
    end,
  })
end

local function vspam_check(task)
  if lua_util.is_skip_local_or_authed(task, local_authed_conf) then
    lua_util.debugm(N, task, 'skipping local or authenticated message')
    return
  end

  local iocs = collect_iocs(task)
  if #iocs == 0 then
    return
  end

  if settings.use_agent and os.time() >= agent_down_until then
    check_via_agent(task, iocs)
  elseif settings.fallback_to_api then
    check_via_api(task, iocs)
  end
end

local opts = rspamd_config:get_all_opt(N)
if not opts then
  lua_util.disable_module(N, 'config')
  return
end

settings = lua_util.override_defaults(settings, opts)
local_authed_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
  settings.check_local, settings.check_authed)

if not settings.use_agent and not settings.fallback_to_api then
  rspamd_logger.errx(rspamd_config, 'vspam: both use_agent and fallback_to_api are off, nothing to query')
  lua_util.disable_module(N, 'config')
  return
end

local id = rspamd_config:register_symbol({
  name = 'VSPAM_CHECK',
  type = 'callback',
  callback = vspam_check,
  group = N,
  augmentations = { string.format('timeout=%f', settings.timeout) },
})

for kind, symbol in pairs(settings.symbols) do
  rspamd_config:register_symbol({
    name = symbol,
    type = 'virtual',
    parent = id,
    group = N,
    -- Several listed indicators in one message must not multiply the weight.
    one_shot = true,
    score = default_scores[kind] or 1.0,
    description = descriptions[kind] or 'Listed on vspam.org',
  })
end

rspamd_config:register_symbol({
  name = settings.symbol_suspicious,
  type = 'virtual',
  parent = id,
  group = N,
  one_shot = true,
  score = 1.5,
  description = 'Scored suspicious by vspam.org but not published to the blocklist',
})

rspamd_config:register_symbol({
  name = settings.symbol_fail,
  type = 'virtual',
  parent = id,
  group = N,
  one_shot = true,
  score = 0.0,
  description = 'vspam.org lookup failed; message was not checked',
})
