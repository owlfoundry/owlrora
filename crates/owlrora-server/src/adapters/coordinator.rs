use std::time::Duration;

use deadpool_redis::{Config, Pool, Runtime};
use redis::Script;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{OrganizationId, PolicyKind};

const STAGE_SCRIPT: &str = r#"
local state = redis.call('HMGET', KEYS[1],
  'desired_epoch', 'desired_generation', 'desired_version', 'desired_config',
  'staged_fence', 'state', 'desired_recovery_generation')
if state[5] and state[5] ~= false then
  if state[5] ~= ARGV[4]
     or state[1] ~= ARGV[1]
     or state[2] ~= ARGV[2]
     or state[3] ~= ARGV[3]
     or state[4] ~= ARGV[5]
     or (state[7] or '0') ~= ARGV[9] then
    return {'conflict'}
  end
  if state[6] ~= 'staged' and state[6] ~= 'armed' then
    return {'conflict'}
  end
  return {'staged', redis.call('HGET', KEYS[1], 'active_epoch') or '',
    redis.call('HGET', KEYS[1], 'active_generation') or ''}
end
local ledger = redis.call('HMGET', KEYS[2], 'policy_kind', 'policy_id', 'epoch')
if ledger[1] and ledger[1] ~= false then
  if ledger[1] ~= ARGV[6] or ledger[2] ~= ARGV[7] or ledger[3] ~= ARGV[1] then
    return {'conflict'}
  end
else
  redis.call('HSET', KEYS[2], 'policy_kind', ARGV[6], 'policy_id', ARGV[7],
    'epoch', ARGV[1], 'charged_nanos', '0', 'returned_nanos', '0',
    'recovery_generation', ARGV[9],
    'rate_request_tokens', '', 'rate_input_tokens', '', 'rate_refill_ms', '')
end
redis.call('HSET', KEYS[1],
  'desired_epoch', ARGV[1],
  'desired_generation', ARGV[2],
  'desired_version', ARGV[3],
  'staged_fence', ARGV[4],
  'desired_config', ARGV[5],
  'desired_recovery_generation', ARGV[9],
  'state', 'staged')
redis.call('PEXPIRE', KEYS[1], ARGV[8])
redis.call('PEXPIRE', KEYS[2], ARGV[8])
return {'staged', redis.call('HGET', KEYS[1], 'active_epoch') or '',
  redis.call('HGET', KEYS[1], 'active_generation') or ''}
"#;

const ARM_SCRIPT: &str = r#"
local values = redis.call('HMGET', KEYS[1], 'desired_epoch', 'desired_generation',
  'desired_version', 'staged_fence', 'state')
if values[1] ~= ARGV[1] or values[2] ~= ARGV[2] or values[3] ~= ARGV[3]
   or values[4] ~= ARGV[4] then
  return {'conflict'}
end
if values[5] ~= 'staged' and values[5] ~= 'armed' then
  return {'conflict'}
end
redis.call('HSET', KEYS[1], 'state', 'armed')
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return {'armed'}
"#;

const ACTIVATE_SCRIPT: &str = r#"
local values = redis.call('HMGET', KEYS[1], 'desired_epoch', 'desired_generation',
  'desired_version', 'desired_config', 'staged_fence', 'state',
  'active_epoch', 'active_generation', 'active_version',
  'desired_recovery_generation')
if values[1] ~= ARGV[1] or values[2] ~= ARGV[2] or values[3] ~= ARGV[3]
   or values[5] ~= ARGV[4] or (values[10] or '0') ~= ARGV[6] then
  return {'conflict'}
end
if values[6] == 'active' and values[7] == ARGV[1]
   and values[8] == ARGV[2] and values[9] == ARGV[3]
   and (redis.call('HGET', KEYS[1], 'active_recovery_generation') or '0') == ARGV[6] then
  return {'active', redis.call('HGET', KEYS[1], 'prior_epoch') or '',
    redis.call('HGET', KEYS[1], 'prior_generation') or ''}
end
if values[6] ~= 'armed' then
  return {'conflict'}
end
local prior_epoch = values[7] or ''
local prior_generation = values[8] or ''
local prior_version = values[9] or ''
local prior_config = redis.call('HGET', KEYS[1], 'active_config') or ''
local prior_recovery = redis.call('HGET', KEYS[1], 'active_recovery_generation') or '0'
redis.call('HSET', KEYS[1],
  'prior_epoch', prior_epoch,
  'prior_generation', prior_generation,
  'prior_version', prior_version,
  'prior_config', prior_config,
  'prior_recovery_generation', prior_recovery,
  'prior_cutoff_ms', '',
  'active_epoch', values[1],
  'active_generation', values[2],
  'active_version', values[3],
  'active_config', values[4],
  'active_recovery_generation', ARGV[6],
  'state', 'active')
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return {'active', prior_epoch, prior_generation}
"#;

const RETIRE_SCRIPT: &str = r#"
local values = redis.call('HMGET', KEYS[1], 'active_epoch', 'active_generation',
  'active_version', 'staged_fence', 'state', 'prior_cutoff_ms')
if values[1] ~= ARGV[1] or values[2] ~= ARGV[2] or values[3] ~= ARGV[3]
   or values[4] ~= ARGV[4] or values[5] ~= 'active' then
  return {'conflict'}
end
if values[6] and values[6] ~= false and values[6] ~= '' and values[6] ~= ARGV[5] then
  return {'conflict'}
end
redis.call('HSET', KEYS[1], 'prior_cutoff_ms', ARGV[5])
redis.call('PEXPIRE', KEYS[1], ARGV[6])
return {'retiring'}
"#;

const FINALIZE_SCRIPT: &str = r#"
local values = redis.call('HMGET', KEYS[1], 'active_epoch', 'active_generation',
  'active_version', 'staged_fence', 'state')
if values[1] ~= ARGV[1] or values[2] ~= ARGV[2] or values[3] ~= ARGV[3]
   or values[4] ~= ARGV[4] then
  return {'conflict'}
end
if values[5] ~= 'active' and values[5] ~= 'finalized' then
  return {'conflict'}
end
redis.call('HSET', KEYS[1], 'state', 'finalized')
redis.call('HDEL', KEYS[1], 'staged_fence', 'desired_epoch', 'desired_generation',
  'desired_version', 'desired_config', 'desired_recovery_generation',
  'prior_epoch', 'prior_generation', 'prior_version', 'prior_config',
  'prior_recovery_generation', 'prior_cutoff_ms')
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return {'finalized'}
"#;

const RECOVERY_INSTALL_BODY: &str = r#"
local policy = redis.call('HMGET', KEYS[1],
  'active_epoch', 'active_generation', 'active_version', 'active_config',
  'active_recovery_generation', 'active_recovery_fingerprint')
local initialized = policy[1] and policy[1] ~= false
if initialized then
  if policy[1] ~= ARGV[1] or policy[2] ~= ARGV[2] or policy[3] ~= ARGV[3]
     or policy[4] ~= ARGV[4] then
    return {'conflict'}
  end
  local current = policy[5] or '0'
  if current == ARGV[5] then
    if policy[6] ~= ARGV[9] then return {'conflict'} end
    return {'installed'}
  end
  if add(current, '1') ~= ARGV[5] then return {'conflict'} end
end
local config = cjson.decode(ARGV[4])
if config.kind ~= 'budget' or config.mode ~= 'enforce'
   or config.limit_cost_nanos ~= ARGV[7] then
  return {'conflict'}
end
if cmp(ARGV[6], ARGV[7]) > 0 then return {'conflict'} end
local ledger = redis.call('HMGET', KEYS[2], 'policy_kind', 'policy_id', 'epoch')
if ledger[1] and ledger[1] ~= false then
  if ledger[1] ~= ARGV[10] or ledger[2] ~= ARGV[11] or ledger[3] ~= ARGV[1] then
    return {'conflict'}
  end
else
  redis.call('HSET', KEYS[2], 'policy_kind', ARGV[10], 'policy_id', ARGV[11],
    'epoch', ARGV[1], 'rate_request_tokens', '', 'rate_input_tokens', '',
    'rate_refill_ms', '')
end
redis.call('HSET', KEYS[2],
  'charged_nanos', sub(ARGV[7], ARGV[6]),
  'returned_nanos', '0',
  'recovery_generation', ARGV[5],
  'recovery_id', ARGV[8])
redis.call('HSET', KEYS[1],
  'active_epoch', ARGV[1],
  'active_generation', ARGV[2],
  'active_version', ARGV[3],
  'active_config', ARGV[4],
  'active_recovery_generation', ARGV[5],
  'active_recovery_id', ARGV[8],
  'active_recovery_fingerprint', ARGV[9],
  'state', 'finalized')
redis.call('PEXPIRE', KEYS[1], ARGV[12])
redis.call('PEXPIRE', KEYS[2], ARGV[12])
return {'installed'}
"#;

const DECIMAL_FUNCTIONS: &str = r#"
local function norm(value)
  value = string.gsub(value, '^0+', '')
  if value == '' then return '0' end
  return value
end
local function cmp(left, right)
  left = norm(left); right = norm(right)
  if string.len(left) < string.len(right) then return -1 end
  if string.len(left) > string.len(right) then return 1 end
  if left < right then return -1 end
  if left > right then return 1 end
  return 0
end
local function add(left, right)
  local carry = 0; local out = {}
  local i = string.len(left); local j = string.len(right)
  while i > 0 or j > 0 or carry > 0 do
    local a = 0; local b = 0
    if i > 0 then a = string.byte(left, i) - 48; i = i - 1 end
    if j > 0 then b = string.byte(right, j) - 48; j = j - 1 end
    local sum = a + b + carry
    table.insert(out, 1, tostring(sum % 10)); carry = math.floor(sum / 10)
  end
  return norm(table.concat(out))
end
local function sub(left, right)
  local borrow = 0; local out = {}; local j = string.len(right)
  for i = string.len(left), 1, -1 do
    local a = string.byte(left, i) - 48 - borrow
    local b = 0
    if j > 0 then b = string.byte(right, j) - 48; j = j - 1 end
    if a < b then a = a + 10; borrow = 1 else borrow = 0 end
    table.insert(out, 1, tostring(a - b))
  end
  return norm(table.concat(out))
end
"#;

const BUDGET_GRANT_BODY: &str = r#"
local function select_config(policy_key, epoch, generation, version, recovery_generation)
  local values = redis.call('HMGET', policy_key, 'active_epoch', 'active_generation',
    'active_version', 'active_config', 'active_recovery_generation',
    'prior_epoch', 'prior_generation', 'prior_version', 'prior_config',
    'prior_cutoff_ms', 'prior_recovery_generation', 'state')
  if values[1] == epoch and values[2] == generation and values[3] == version
     and (values[5] or '0') == recovery_generation then
    return values[4]
  end
  if values[12] == 'active' and values[6] == epoch and values[7] == generation
     and values[8] == version and (values[11] or '0') == recovery_generation then
    if values[10] and values[10] ~= '' then
      local now = redis.call('TIME')
      local now_ms = tostring(now[1] * 1000 + math.floor(now[2] / 1000))
      if cmp(now_ms, values[10]) > 0 then return nil end
    end
    return values[9]
  end
  return nil
end
local function validate_side(policy_key, ledger_key, present, epoch, generation,
  version, recovery_generation, amount, one_shot)
  if present ~= '1' then return nil end
  local encoded = select_config(policy_key, epoch, generation, version, recovery_generation)
  if not encoded then return false end
  local config = cjson.decode(encoded)
  if config.kind ~= 'budget' or config.mode ~= 'enforce' then return false end
  if one_shot ~= '1' and cmp(amount, config.max_slice_nanos) > 0 then return false end
  local ledger = redis.call('HMGET', ledger_key, 'epoch', 'charged_nanos',
    'recovery_generation')
  if ledger[1] ~= epoch or (ledger[3] or '0') ~= recovery_generation then return false end
  local next = add(ledger[2] or '0', amount)
  if cmp(next, config.limit_cost_nanos) > 0 then return false end
  return {next, config.grant_seconds}
end
local existing = redis.call('HMGET', KEYS[5], 'fingerprint', 'expires_ms')
if existing[1] and existing[1] ~= false then
  if existing[1] ~= ARGV[1] then return {'conflict'} end
  return {'granted', existing[2]}
end
local key_side = validate_side(KEYS[1], KEYS[2], ARGV[4], ARGV[5], ARGV[6],
  ARGV[7], ARGV[8], ARGV[9], ARGV[3])
local origin_side = validate_side(KEYS[3], KEYS[4], ARGV[10], ARGV[11], ARGV[12],
  ARGV[13], ARGV[14], ARGV[15], ARGV[3])
if key_side == false or origin_side == false or (not key_side and not origin_side) then
  return {'denied'}
end
local ttl_seconds = tonumber(ARGV[2])
if key_side then ttl_seconds = math.min(ttl_seconds, tonumber(key_side[2])) end
if origin_side then ttl_seconds = math.min(ttl_seconds, tonumber(origin_side[2])) end
if ttl_seconds < 1 then return {'denied'} end
local now = redis.call('TIME')
local expires_ms = tostring(now[1] * 1000 + math.floor(now[2] / 1000) + ttl_seconds * 1000)
if key_side then redis.call('HSET', KEYS[2], 'charged_nanos', key_side[1]) end
if origin_side then redis.call('HSET', KEYS[4], 'charged_nanos', origin_side[1]) end
redis.call('HSET', KEYS[5], 'fingerprint', ARGV[1], 'expires_ms', expires_ms,
  'key_present', ARGV[4], 'key_amount', ARGV[9], 'key_returned', '',
  'origin_present', ARGV[10], 'origin_amount', ARGV[15], 'origin_returned', '')
redis.call('PEXPIRE', KEYS[5], ARGV[16])
return {'granted', expires_ms}
"#;

const BUDGET_RETURN_BODY: &str = r#"
local values = redis.call('HMGET', KEYS[3], 'fingerprint', 'key_present', 'key_amount',
  'key_returned', 'origin_present', 'origin_amount', 'origin_returned')
if not values[1] or values[1] == false then return {'not_found'} end
if values[1] ~= ARGV[1] then return {'conflict'} end
if values[4] ~= '' or values[7] ~= '' then
  if values[4] == ARGV[2] and values[7] == ARGV[3] then return {'returned'} end
  return {'conflict'}
end
if values[2] == '1' and cmp(ARGV[2], values[3]) > 0 then return {'conflict'} end
if values[5] == '1' and cmp(ARGV[3], values[6]) > 0 then return {'conflict'} end
if values[2] ~= '1' and ARGV[2] ~= '0' then return {'conflict'} end
if values[5] ~= '1' and ARGV[3] ~= '0' then return {'conflict'} end
if values[2] == '1' then
  local charged = redis.call('HGET', KEYS[1], 'charged_nanos') or '0'
  if cmp(charged, ARGV[2]) < 0 then return {'conflict'} end
  redis.call('HSET', KEYS[1], 'charged_nanos', sub(charged, ARGV[2]),
    'returned_nanos', add(redis.call('HGET', KEYS[1], 'returned_nanos') or '0', ARGV[2]))
end
if values[5] == '1' then
  local charged = redis.call('HGET', KEYS[2], 'charged_nanos') or '0'
  if cmp(charged, ARGV[3]) < 0 then return {'conflict'} end
  redis.call('HSET', KEYS[2], 'charged_nanos', sub(charged, ARGV[3]),
    'returned_nanos', add(redis.call('HGET', KEYS[2], 'returned_nanos') or '0', ARGV[3]))
end
redis.call('HSET', KEYS[3], 'key_returned', ARGV[2], 'origin_returned', ARGV[3])
redis.call('PEXPIRE', KEYS[3], ARGV[4])
return {'returned'}
"#;

const RATE_GRANT_SCRIPT: &str = r#"
local function select_config(policy_key, epoch, generation, version)
  local values = redis.call('HMGET', policy_key, 'active_epoch', 'active_generation',
    'active_version', 'active_config', 'prior_epoch', 'prior_generation',
    'prior_version', 'prior_config', 'prior_cutoff_ms', 'state')
  if values[1] == epoch and values[2] == generation and values[3] == version then
    return values[4]
  end
  if values[10] == 'active' and values[5] == epoch and values[6] == generation
     and values[7] == version then
    if values[9] and values[9] ~= '' then
      local now = redis.call('TIME')
      local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
      if now_ms > tonumber(values[9]) then return nil end
    end
    return values[8]
  end
  return nil
end
local existing = redis.call('HMGET', KEYS[3], 'fingerprint', 'expires_ms',
  'request_tokens', 'input_tokens')
if existing[1] and existing[1] ~= false then
  if existing[1] ~= ARGV[1] then return {'conflict'} end
  return {'granted', existing[2], existing[3], existing[4]}
end
local encoded = select_config(KEYS[1], ARGV[2], ARGV[3], ARGV[4])
if not encoded then return {'conflict'} end
local config = cjson.decode(encoded)
if config.kind ~= 'request_limits' then return {'conflict'} end
local requested_requests = tonumber(ARGV[5])
local requested_input = tonumber(ARGV[6])
local strict = ARGV[7] == '1'
if strict then
  if config.grant_mode ~= 'strict' or requested_requests ~= 1 then return {'conflict'} end
else
  if config.grant_mode ~= 'local_grants'
     or requested_requests < 1
     or requested_requests > tonumber(config.max_request_tokens) then return {'conflict'} end
end
local now = redis.call('TIME')
local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
local ledger = redis.call('HMGET', KEYS[2], 'epoch', 'rate_request_tokens',
  'rate_input_tokens', 'rate_refill_ms')
if ledger[1] ~= ARGV[2] then return {'conflict'} end
local request_capacity = tonumber(config.requests_per_minute)
local request_tokens = tonumber(ledger[2])
local input_capacity = nil
if config.input_units_per_minute ~= nil and config.input_units_per_minute ~= cjson.null then
  input_capacity = tonumber(config.input_units_per_minute)
end
local input_tokens = tonumber(ledger[3])
local last_ms = tonumber(ledger[4])
if not last_ms then
  request_tokens = request_capacity
  input_tokens = input_capacity or 0
  last_ms = now_ms
else
  local elapsed = math.max(0, math.min(60000, now_ms - last_ms))
  request_tokens = math.min(request_capacity,
    (request_tokens or 0) + elapsed * request_capacity / 60000)
  if input_capacity then
    input_tokens = math.min(input_capacity,
      (input_tokens or 0) + elapsed * input_capacity / 60000)
  else
    input_tokens = 0
  end
end
if request_tokens + 0.0000001 < requested_requests then return {'denied'} end
if input_capacity and input_tokens + 0.0000001 < requested_input then return {'denied'} end
request_tokens = request_tokens - requested_requests
if input_capacity then input_tokens = input_tokens - requested_input end
redis.call('HSET', KEYS[2], 'rate_request_tokens', tostring(request_tokens),
  'rate_input_tokens', tostring(input_tokens), 'rate_refill_ms', tostring(now_ms))
local ttl_seconds = tonumber(config.grant_seconds)
local expires_ms = now_ms + ttl_seconds * 1000
redis.call('HSET', KEYS[3], 'fingerprint', ARGV[1], 'expires_ms', tostring(expires_ms),
  'request_tokens', ARGV[5], 'input_tokens', ARGV[6])
redis.call('PEXPIRE', KEYS[3], ARGV[8])
redis.call('PEXPIRE', KEYS[2], ARGV[8])
return {'granted', tostring(expires_ms), ARGV[5], ARGV[6]}
"#;

const APPROXIMATE_CONCURRENCY_SCRIPT: &str = r#"
local function select_config(policy_key, epoch, generation, version)
  local values = redis.call('HMGET', policy_key, 'active_epoch', 'active_generation',
    'active_version', 'active_config', 'prior_epoch', 'prior_generation',
    'prior_version', 'prior_config', 'prior_cutoff_ms', 'state')
  if values[1] == epoch and values[2] == generation and values[3] == version then
    return values[4]
  end
  if values[10] == 'active' and values[5] == epoch and values[6] == generation
     and values[7] == version then
    if values[9] and values[9] ~= '' then
      local now = redis.call('TIME')
      local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
      if now_ms > tonumber(values[9]) then return nil end
    end
    return values[8]
  end
  return nil
end
local encoded = select_config(KEYS[1], ARGV[1], ARGV[2], ARGV[3])
if not encoded then return {'conflict'} end
local config = cjson.decode(encoded)
if config.kind ~= 'request_limits' or config.concurrency_mode ~= 'approximate' then
  return {'conflict'}
end
local now = redis.call('TIME')
local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now_ms)
local allocated = tonumber(redis.call('HGET', KEYS[3], 'allocated') or '0')
for _, grant_id in ipairs(expired) do
  local slots = tonumber(redis.call('HGET', KEYS[3], grant_id) or '0')
  allocated = math.max(0, allocated - slots)
  redis.call('HDEL', KEYS[3], grant_id)
end
if #expired > 0 then redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms) end
local existing = redis.call('HGET', KEYS[3], ARGV[4])
if existing then
  local expiry = redis.call('ZSCORE', KEYS[2], ARGV[4])
  return {'granted', existing, tostring(math.floor(tonumber(expiry)))}
end
local limit = tonumber(config.concurrency_limit)
local requested = tonumber(ARGV[5])
local granted = math.min(requested, math.max(0, limit - allocated))
if granted < 1 then return {'denied'} end
local expires_ms = now_ms + (tonumber(config.max_stream_seconds) + 30) * 1000
redis.call('HSET', KEYS[3], 'allocated', tostring(allocated + granted),
  ARGV[4], tostring(granted))
redis.call('ZADD', KEYS[2], expires_ms, ARGV[4])
redis.call('PEXPIRE', KEYS[2], ARGV[6])
redis.call('PEXPIRE', KEYS[3], ARGV[6])
return {'granted', tostring(granted), tostring(expires_ms)}
"#;

const STRICT_CONCURRENCY_SCRIPT: &str = r#"
local values = redis.call('HMGET', KEYS[1], 'active_epoch', 'active_generation',
  'active_version', 'active_config', 'prior_epoch', 'prior_generation',
  'prior_version', 'prior_config', 'prior_cutoff_ms', 'state')
local encoded = nil
if values[1] == ARGV[1] and values[2] == ARGV[2] and values[3] == ARGV[3] then
  encoded = values[4]
elseif values[10] == 'active' and values[5] == ARGV[1] and values[6] == ARGV[2]
   and values[7] == ARGV[3] then
  if values[9] and values[9] ~= '' then
    local prior_now = redis.call('TIME')
    local prior_now_ms = prior_now[1] * 1000 + math.floor(prior_now[2] / 1000)
    if prior_now_ms <= tonumber(values[9]) then encoded = values[8] end
  else
    encoded = values[8]
  end
end
if not encoded then return {'conflict'} end
local config = cjson.decode(encoded)
if config.kind ~= 'request_limits' or config.concurrency_mode ~= 'strict'
   or tonumber(config.lease_seconds) ~= tonumber(ARGV[5]) then return {'conflict'} end
local now = redis.call('TIME')
local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
local existing = redis.call('ZSCORE', KEYS[2], ARGV[4])
if existing then return {'acquired', tostring(math.floor(existing))} end
if redis.call('ZCARD', KEYS[2]) >= tonumber(config.concurrency_limit) then return {'denied'} end
local expires = now_ms + tonumber(ARGV[5]) * 1000
redis.call('ZADD', KEYS[2], expires, ARGV[4])
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[5]) * 1000 + tonumber(ARGV[6]))
return {'acquired', tostring(expires)}
"#;

const STATE_ORIGIN_PUT_SCRIPT: &str = r#"
local existing = redis.call('GET', KEYS[1])
if existing then
  if existing == ARGV[1] then return {'stored'} end
  return {'conflict'}
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return {'stored'}
"#;

const TARGET_HEALTH_PUT_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'not_owner'} end
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
return {'stored'}
"#;

#[derive(Clone)]
pub struct RedisCoordinator {
    pool: Pool,
    command_timeout: Duration,
    metadata_ttl: Duration,
}

impl std::fmt::Debug for RedisCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisCoordinator")
            .field("command_timeout", &self.command_timeout)
            .field("metadata_ttl", &self.metadata_ttl)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("coordinator pool configuration failed")]
    PoolConfiguration,
    #[error("coordinator pool is unavailable")]
    PoolUnavailable,
    #[error("coordinator command timed out")]
    Timeout,
    #[error("coordinator command failed")]
    Command,
    #[error("coordinator candidate fence or generation did not match")]
    Conflict,
    #[error("coordinator allowance or capacity was denied")]
    Denied,
    #[error("coordinator state was not found")]
    NotFound,
    #[error("coordinator returned an invalid response")]
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyCoordinatorConfig {
    Budget {
        version_id: Uuid,
        mode: String,
        limit_cost_nanos: String,
        max_slice_nanos: String,
        grant_seconds: u32,
    },
    RequestLimits {
        version_id: Uuid,
        requests_per_minute: u32,
        input_units_per_minute: Option<u64>,
        grant_mode: String,
        max_request_tokens: u32,
        grant_seconds: u32,
        concurrency_mode: Option<String>,
        concurrency_limit: Option<u32>,
        lease_seconds: Option<u32>,
        max_stream_seconds: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCandidate {
    pub organization_id: OrganizationId,
    pub kind: PolicyKind,
    pub policy_id: Uuid,
    pub desired_epoch: String,
    pub desired_version_id: Uuid,
    pub desired_generation: u64,
    pub desired_recovery_generation: u64,
    pub fence: Uuid,
    pub config: PolicyCoordinatorConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorGeneration {
    pub epoch: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PolicyReference {
    pub organization_id: OrganizationId,
    pub kind: PolicyKind,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub epoch: String,
    pub generation: u64,
    pub recovery_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorRecoveryInstall {
    pub recovery_id: Uuid,
    pub organization_id: OrganizationId,
    pub kind: PolicyKind,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub epoch: String,
    pub policy_generation: u64,
    pub recovery_generation: u64,
    pub authorized_allowance_nanos: u128,
    pub limit_cost_nanos: u128,
    pub config: PolicyCoordinatorConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetGrantSide {
    pub policy: PolicyReference,
    pub amount_nanos: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedBudgetGrantRequest {
    pub organization_id: OrganizationId,
    pub grant_id: Uuid,
    pub key: Option<BudgetGrantSide>,
    pub origin: Option<BudgetGrantSide>,
    pub requested_ttl: Duration,
    pub one_shot: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowanceGrant {
    pub id: Uuid,
    pub expires_at_unix_ms: u64,
    pub key_amount_nanos: Option<u128>,
    pub origin_amount_nanos: Option<u128>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateTokenGrant {
    pub id: Uuid,
    pub expires_at_unix_ms: u64,
    pub request_tokens: u32,
    pub input_tokens: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrencySlotGrant {
    pub id: Uuid,
    pub slots: u32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateOrigin {
    pub organization_id: Uuid,
    pub principal_kind: String,
    pub principal_affinity_id: Uuid,
    pub route_id: Uuid,
    pub protocol_family: String,
    pub target_id: Uuid,
    pub deployment_id: Uuid,
    pub deployment_config_version: u64,
    pub endpoint_id: Uuid,
    pub endpoint_config_version: i64,
    pub credential_id: Uuid,
    pub credential_state_identity_version: u64,
    pub origin: String,
    pub transport_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateOriginCleanupPage {
    pub deleted: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHealthCategory {
    Healthy,
    Degraded,
    Open,
    Recovering,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetHealthSummary {
    pub target_id: Uuid,
    pub deployment_id: Uuid,
    pub endpoint_id: Uuid,
    pub credential_id: Uuid,
    pub runtime_revision: i64,
    pub binding_fingerprint: [u8; 32],
    pub health_epoch: Uuid,
    pub category: TargetHealthCategory,
    pub cooldown_until_unix_ms: Option<u64>,
    #[serde(default)]
    pub recovery_started_at_unix_ms: Option<u64>,
    pub observed_at_unix_ms: u64,
}

impl RedisCoordinator {
    pub async fn connect(
        url: &url::Url,
        pool_size: u32,
        connect_timeout: Duration,
        command_timeout: Duration,
    ) -> Result<Self, CoordinatorError> {
        let mut config = Config::from_url(url.as_str());
        let mut pool = deadpool_redis::PoolConfig::new(
            usize::try_from(pool_size).map_err(|_| CoordinatorError::PoolConfiguration)?,
        );
        pool.timeouts.wait = Some(connect_timeout);
        pool.timeouts.create = Some(connect_timeout);
        pool.timeouts.recycle = Some(connect_timeout);
        config.pool = Some(pool);
        let coordinator = Self {
            pool: config
                .create_pool(Some(Runtime::Tokio1))
                .map_err(|_| CoordinatorError::PoolConfiguration)?,
            command_timeout,
            metadata_ttl: Duration::from_secs(7 * 24 * 60 * 60),
        };
        coordinator.ping().await?;
        Ok(coordinator)
    }

    pub async fn ping(&self) -> Result<(), CoordinatorError> {
        let mut connection = self.connection().await?;
        let pong: String = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("PING").query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        (pong == "PONG")
            .then_some(())
            .ok_or(CoordinatorError::InvalidResponse)
    }

    pub async fn cleanup_state_origins(
        &self,
        organization_id: OrganizationId,
        cursor: u64,
        limit: u32,
    ) -> Result<StateOriginCleanupPage, CoordinatorError> {
        let mut connection = self.connection().await?;
        let pattern = format!("owlrora:{{{organization_id}}}:state-origin:v2:*");
        let (next_cursor, keys): (u64, Vec<String>) = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(limit.clamp(1, 500))
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        let deleted = if keys.is_empty() {
            0
        } else {
            let deleted: i64 = tokio::time::timeout(
                self.command_timeout,
                redis::cmd("UNLINK").arg(keys).query_async(&mut connection),
            )
            .await
            .map_err(|_| CoordinatorError::Timeout)?
            .map_err(|_| CoordinatorError::Command)?;
            u64::try_from(deleted).map_err(|_| CoordinatorError::InvalidResponse)?
        };
        Ok(StateOriginCleanupPage {
            deleted,
            next_cursor: (next_cursor != 0).then(|| next_cursor.to_string()),
        })
    }

    pub async fn stage_policy(
        &self,
        candidate: &PolicyCandidate,
    ) -> Result<Option<PriorGeneration>, CoordinatorError> {
        validate_candidate(candidate)?;
        let config = serde_json::to_string(&candidate.config)
            .map_err(|_| CoordinatorError::InvalidResponse)?;
        let ttl = self.metadata_ttl_millis()?;
        let values = self
            .invoke(
                Script::new(STAGE_SCRIPT)
                    .key(policy_key_ref(
                        candidate.organization_id,
                        candidate.kind,
                        candidate.policy_id,
                    ))
                    .key(ledger_key(
                        candidate.organization_id,
                        candidate.kind,
                        candidate.policy_id,
                        &candidate.desired_epoch,
                    ))
                    .arg(&candidate.desired_epoch)
                    .arg(candidate.desired_generation)
                    .arg(candidate.desired_version_id.to_string())
                    .arg(candidate.fence.to_string())
                    .arg(config)
                    .arg(candidate.kind.as_str())
                    .arg(candidate.policy_id.to_string())
                    .arg(ttl)
                    .arg(candidate.desired_recovery_generation),
            )
            .await?;
        match values.as_slice() {
            [state, prior_epoch, prior_generation] if state == "staged" => {
                parse_prior(prior_epoch, prior_generation)
            }
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn arm_policy(&self, candidate: &PolicyCandidate) -> Result<(), CoordinatorError> {
        let values = self
            .invoke(
                Script::new(ARM_SCRIPT)
                    .key(policy_key(candidate))
                    .arg(&candidate.desired_epoch)
                    .arg(candidate.desired_generation)
                    .arg(candidate.desired_version_id.to_string())
                    .arg(candidate.fence.to_string())
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        expect_state(values, "armed")
    }

    pub async fn activate_policy(
        &self,
        candidate: &PolicyCandidate,
    ) -> Result<Option<PriorGeneration>, CoordinatorError> {
        let values = self
            .invoke(
                Script::new(ACTIVATE_SCRIPT)
                    .key(policy_key(candidate))
                    .arg(&candidate.desired_epoch)
                    .arg(candidate.desired_generation)
                    .arg(candidate.desired_version_id.to_string())
                    .arg(candidate.fence.to_string())
                    .arg(self.metadata_ttl_millis()?)
                    .arg(candidate.desired_recovery_generation),
            )
            .await?;
        match values.as_slice() {
            [state, prior_epoch, prior_generation] if state == "active" => {
                parse_prior(prior_epoch, prior_generation)
            }
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn begin_policy_retirement(
        &self,
        candidate: &PolicyCandidate,
        cutoff_unix_ms: u64,
    ) -> Result<(), CoordinatorError> {
        let values = self
            .invoke(
                Script::new(RETIRE_SCRIPT)
                    .key(policy_key(candidate))
                    .arg(&candidate.desired_epoch)
                    .arg(candidate.desired_generation)
                    .arg(candidate.desired_version_id.to_string())
                    .arg(candidate.fence.to_string())
                    .arg(cutoff_unix_ms)
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        expect_state(values, "retiring")
    }

    pub async fn finalize_policy(
        &self,
        candidate: &PolicyCandidate,
    ) -> Result<(), CoordinatorError> {
        let values = self
            .invoke(
                Script::new(FINALIZE_SCRIPT)
                    .key(policy_key(candidate))
                    .arg(&candidate.desired_epoch)
                    .arg(candidate.desired_generation)
                    .arg(candidate.desired_version_id.to_string())
                    .arg(candidate.fence.to_string())
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        expect_state(values, "finalized")
    }

    pub async fn install_coordinator_recovery(
        &self,
        recovery: &CoordinatorRecoveryInstall,
    ) -> Result<(), CoordinatorError> {
        if !matches!(
            recovery.kind,
            PolicyKind::GatewayKeyBudget | PolicyKind::OrganizationOriginBudget
        ) || recovery.epoch.is_empty()
            || recovery.policy_generation == 0
            || recovery.recovery_generation == 0
            || recovery.authorized_allowance_nanos > recovery.limit_cost_nanos
        {
            return Err(CoordinatorError::InvalidResponse);
        }
        let config = serde_json::to_string(&recovery.config)
            .map_err(|_| CoordinatorError::InvalidResponse)?;
        let fingerprint = recovery_fingerprint(recovery, &config);
        let script = format!("{DECIMAL_FUNCTIONS}{RECOVERY_INSTALL_BODY}");
        let values = self
            .invoke(
                Script::new(&script)
                    .key(policy_key_ref(
                        recovery.organization_id,
                        recovery.kind,
                        recovery.policy_id,
                    ))
                    .key(ledger_key(
                        recovery.organization_id,
                        recovery.kind,
                        recovery.policy_id,
                        &recovery.epoch,
                    ))
                    .arg(&recovery.epoch)
                    .arg(recovery.policy_generation)
                    .arg(recovery.version_id.to_string())
                    .arg(config)
                    .arg(recovery.recovery_generation)
                    .arg(recovery.authorized_allowance_nanos.to_string())
                    .arg(recovery.limit_cost_nanos.to_string())
                    .arg(recovery.recovery_id.to_string())
                    .arg(fingerprint)
                    .arg(recovery.kind.as_str())
                    .arg(recovery.policy_id.to_string())
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        expect_state(values, "installed")
    }

    pub async fn grant_budget_allowance(
        &self,
        request: &PairedBudgetGrantRequest,
    ) -> Result<AllowanceGrant, CoordinatorError> {
        validate_grant_request(request)?;
        let key = request.key.as_ref();
        let origin = request.origin.as_ref();
        let fingerprint = grant_fingerprint(request);
        let script = format!("{DECIMAL_FUNCTIONS}{BUDGET_GRANT_BODY}");
        let values = self
            .invoke(
                Script::new(&script)
                    .key(side_policy_key(request.organization_id, key))
                    .key(side_ledger_key(request.organization_id, key))
                    .key(side_policy_key(request.organization_id, origin))
                    .key(side_ledger_key(request.organization_id, origin))
                    .key(grant_key(request.organization_id, request.grant_id))
                    .arg(fingerprint)
                    .arg(request.requested_ttl.as_secs())
                    .arg(if request.one_shot { "1" } else { "0" })
                    .arg(side_present(key))
                    .arg(side_epoch(key))
                    .arg(side_generation(key))
                    .arg(side_version(key))
                    .arg(side_recovery_generation(key))
                    .arg(side_amount(key))
                    .arg(side_present(origin))
                    .arg(side_epoch(origin))
                    .arg(side_generation(origin))
                    .arg(side_version(origin))
                    .arg(side_recovery_generation(origin))
                    .arg(side_amount(origin))
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        match values.as_slice() {
            [state, expires] if state == "granted" => Ok(AllowanceGrant {
                id: request.grant_id,
                expires_at_unix_ms: expires
                    .parse()
                    .map_err(|_| CoordinatorError::InvalidResponse)?,
                key_amount_nanos: key.map(|side| side.amount_nanos),
                origin_amount_nanos: origin.map(|side| side.amount_nanos),
            }),
            [state] if state == "denied" => Err(CoordinatorError::Denied),
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn return_budget_allowance(
        &self,
        request: &PairedBudgetGrantRequest,
        key_unused_nanos: u128,
        origin_unused_nanos: u128,
    ) -> Result<(), CoordinatorError> {
        let script = format!("{DECIMAL_FUNCTIONS}{BUDGET_RETURN_BODY}");
        let values = self
            .invoke(
                Script::new(&script)
                    .key(side_ledger_key(
                        request.organization_id,
                        request.key.as_ref(),
                    ))
                    .key(side_ledger_key(
                        request.organization_id,
                        request.origin.as_ref(),
                    ))
                    .key(grant_key(request.organization_id, request.grant_id))
                    .arg(grant_fingerprint(request))
                    .arg(key_unused_nanos.to_string())
                    .arg(origin_unused_nanos.to_string())
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        match values.as_slice() {
            [state] if state == "returned" => Ok(()),
            [state] if state == "not_found" => Err(CoordinatorError::NotFound),
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn grant_rate_tokens(
        &self,
        policy: &PolicyReference,
        grant_id: Uuid,
        request_tokens: u32,
        input_tokens: u64,
        strict: bool,
    ) -> Result<RateTokenGrant, CoordinatorError> {
        if policy.kind != PolicyKind::GatewayKeyRequestLimits || request_tokens == 0 {
            return Err(CoordinatorError::Conflict);
        }
        let fingerprint = digest_component(&format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            policy.organization_id,
            policy.policy_id,
            policy.version_id,
            policy.epoch,
            policy.generation,
            grant_id,
            request_tokens,
            input_tokens
        ));
        let values = self
            .invoke(
                Script::new(RATE_GRANT_SCRIPT)
                    .key(policy_key_ref(
                        policy.organization_id,
                        policy.kind,
                        policy.policy_id,
                    ))
                    .key(ledger_key(
                        policy.organization_id,
                        policy.kind,
                        policy.policy_id,
                        &policy.epoch,
                    ))
                    .key(rate_grant_key(policy.organization_id, grant_id))
                    .arg(fingerprint)
                    .arg(&policy.epoch)
                    .arg(policy.generation)
                    .arg(policy.version_id.to_string())
                    .arg(request_tokens)
                    .arg(input_tokens)
                    .arg(if strict { "1" } else { "0" })
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        match values.as_slice() {
            [state, expires, requests, input] if state == "granted" => Ok(RateTokenGrant {
                id: grant_id,
                expires_at_unix_ms: expires
                    .parse()
                    .map_err(|_| CoordinatorError::InvalidResponse)?,
                request_tokens: requests
                    .parse()
                    .map_err(|_| CoordinatorError::InvalidResponse)?,
                input_tokens: input
                    .parse()
                    .map_err(|_| CoordinatorError::InvalidResponse)?,
            }),
            [state] if state == "denied" => Err(CoordinatorError::Denied),
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn grant_approximate_concurrency_slots(
        &self,
        policy: &PolicyReference,
        grant_id: Uuid,
        requested_slots: u32,
    ) -> Result<ConcurrencySlotGrant, CoordinatorError> {
        if policy.kind != PolicyKind::GatewayKeyRequestLimits || requested_slots == 0 {
            return Err(CoordinatorError::Conflict);
        }
        let values = self
            .invoke(
                Script::new(APPROXIMATE_CONCURRENCY_SCRIPT)
                    .key(policy_key_ref(
                        policy.organization_id,
                        policy.kind,
                        policy.policy_id,
                    ))
                    .key(approximate_concurrency_expiry_key(policy))
                    .key(approximate_concurrency_grants_key(policy))
                    .arg(&policy.epoch)
                    .arg(policy.generation)
                    .arg(policy.version_id.to_string())
                    .arg(grant_id.to_string())
                    .arg(requested_slots)
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        match values.as_slice() {
            [state, slots, expires] if state == "granted" => Ok(ConcurrencySlotGrant {
                id: grant_id,
                slots: slots
                    .parse()
                    .map_err(|_| CoordinatorError::InvalidResponse)?,
                expires_at_unix_ms: expires
                    .parse()
                    .map_err(|_| CoordinatorError::InvalidResponse)?,
            }),
            [state] if state == "denied" => Err(CoordinatorError::Denied),
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn acquire_strict_concurrency(
        &self,
        policy: &PolicyReference,
        lease_id: Uuid,
        lease_seconds: u32,
    ) -> Result<u64, CoordinatorError> {
        let values = self
            .invoke(
                Script::new(STRICT_CONCURRENCY_SCRIPT)
                    .key(policy_key_ref(
                        policy.organization_id,
                        policy.kind,
                        policy.policy_id,
                    ))
                    .key(concurrency_key(policy))
                    .arg(&policy.epoch)
                    .arg(policy.generation)
                    .arg(policy.version_id.to_string())
                    .arg(lease_id.to_string())
                    .arg(lease_seconds)
                    .arg(self.metadata_ttl_millis()?),
            )
            .await?;
        match values.as_slice() {
            [state, expiry] if state == "acquired" => expiry
                .parse()
                .map_err(|_| CoordinatorError::InvalidResponse),
            [state] if state == "denied" => Err(CoordinatorError::Denied),
            [state] if state == "conflict" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn release_strict_concurrency(
        &self,
        policy: &PolicyReference,
        lease_id: Uuid,
    ) -> Result<(), CoordinatorError> {
        let mut connection = self.connection().await?;
        let removed: i64 = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("ZREM")
                .arg(concurrency_key(policy))
                .arg(lease_id.to_string())
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        if matches!(removed, 0 | 1) {
            Ok(())
        } else {
            Err(CoordinatorError::InvalidResponse)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_state_origin(
        &self,
        organization_id: OrganizationId,
        principal_kind: &str,
        principal_affinity_id: Uuid,
        route_id: Uuid,
        protocol_family: &str,
        state_reference: &str,
        origin: &StateOrigin,
        ttl: Duration,
    ) -> Result<(), CoordinatorError> {
        let payload =
            serde_json::to_string(origin).map_err(|_| CoordinatorError::InvalidResponse)?;
        let values = self
            .invoke(
                Script::new(STATE_ORIGIN_PUT_SCRIPT)
                    .key(state_origin_key(
                        organization_id,
                        principal_kind,
                        principal_affinity_id,
                        route_id,
                        protocol_family,
                        state_reference,
                    ))
                    .arg(payload)
                    .arg(duration_millis(ttl)?),
            )
            .await?;
        expect_state(values, "stored")
    }

    pub async fn get_state_origin(
        &self,
        organization_id: OrganizationId,
        principal_kind: &str,
        principal_affinity_id: Uuid,
        route_id: Uuid,
        protocol_family: &str,
        state_reference: &str,
    ) -> Result<StateOrigin, CoordinatorError> {
        let mut connection = self.connection().await?;
        let payload: Option<String> = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("GET")
                .arg(state_origin_key(
                    organization_id,
                    principal_kind,
                    principal_affinity_id,
                    route_id,
                    protocol_family,
                    state_reference,
                ))
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        serde_json::from_str(&payload.ok_or(CoordinatorError::NotFound)?)
            .map_err(|_| CoordinatorError::InvalidResponse)
    }

    pub async fn try_acquire_target_probe_lease(
        &self,
        target_id: Uuid,
        binding_fingerprint: &[u8; 32],
        owner: &str,
        ttl: Duration,
    ) -> Result<bool, CoordinatorError> {
        if owner.is_empty() || owner.len() > 128 || owner.chars().any(char::is_control) {
            return Err(CoordinatorError::Conflict);
        }
        let mut connection = self.connection().await?;
        let acquired: Option<String> = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("SET")
                .arg(target_probe_lease_key(target_id, binding_fingerprint))
                .arg(owner)
                .arg("NX")
                .arg("PX")
                .arg(duration_millis(ttl)?)
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        match acquired.as_deref() {
            Some("OK") => Ok(true),
            None => Ok(false),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn put_target_health_summary(
        &self,
        summary: &TargetHealthSummary,
        lease_token: &str,
        ttl: Duration,
    ) -> Result<(), CoordinatorError> {
        if lease_token.is_empty()
            || lease_token.len() > 128
            || lease_token.chars().any(char::is_control)
        {
            return Err(CoordinatorError::Conflict);
        }
        let payload =
            serde_json::to_string(summary).map_err(|_| CoordinatorError::InvalidResponse)?;
        let values = self
            .invoke(
                Script::new(TARGET_HEALTH_PUT_SCRIPT)
                    .key(target_probe_lease_key(
                        summary.target_id,
                        &summary.binding_fingerprint,
                    ))
                    .key(target_health_key(
                        summary.target_id,
                        &summary.binding_fingerprint,
                    ))
                    .arg(lease_token)
                    .arg(payload)
                    .arg(duration_millis(ttl)?),
            )
            .await?;
        match values.as_slice() {
            [state] if state == "stored" => Ok(()),
            [state] if state == "not_owner" => Err(CoordinatorError::Conflict),
            _ => Err(CoordinatorError::InvalidResponse),
        }
    }

    pub async fn get_target_health_summary(
        &self,
        target_id: Uuid,
        binding_fingerprint: &[u8; 32],
    ) -> Result<(TargetHealthSummary, Duration), CoordinatorError> {
        let mut connection = self.connection().await?;
        let key = target_health_key(target_id, binding_fingerprint);
        let (payload, ttl_millis): (Option<String>, i64) = tokio::time::timeout(
            self.command_timeout,
            redis::pipe()
                .cmd("GET")
                .arg(&key)
                .cmd("PTTL")
                .arg(&key)
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        let summary: TargetHealthSummary =
            serde_json::from_str(&payload.ok_or(CoordinatorError::NotFound)?)
                .map_err(|_| CoordinatorError::InvalidResponse)?;
        let ttl_millis = u64::try_from(ttl_millis).map_err(|_| CoordinatorError::NotFound)?;
        (summary.target_id == target_id && ttl_millis > 0)
            .then_some((summary, Duration::from_millis(ttl_millis)))
            .ok_or(CoordinatorError::InvalidResponse)
    }

    async fn invoke(
        &self,
        invocation: &mut redis::ScriptInvocation<'_>,
    ) -> Result<Vec<String>, CoordinatorError> {
        let mut connection = self.connection().await?;
        tokio::time::timeout(
            self.command_timeout,
            invocation.invoke_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)
    }

    #[cfg(test)]
    pub(crate) async fn budget_ledger_totals(
        &self,
        candidate: &PolicyCandidate,
    ) -> Result<(u128, u128), CoordinatorError> {
        if !matches!(
            candidate.kind,
            PolicyKind::GatewayKeyBudget | PolicyKind::OrganizationOriginBudget
        ) {
            return Err(CoordinatorError::Conflict);
        }
        let mut connection = self.connection().await?;
        let values: (Option<String>, Option<String>) = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("HMGET")
                .arg(ledger_key(
                    candidate.organization_id,
                    candidate.kind,
                    candidate.policy_id,
                    &candidate.desired_epoch,
                ))
                .arg("charged_nanos")
                .arg("returned_nanos")
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| CoordinatorError::Timeout)?
        .map_err(|_| CoordinatorError::Command)?;
        let parse = |value: Option<String>| {
            value
                .ok_or(CoordinatorError::NotFound)?
                .parse::<u128>()
                .map_err(|_| CoordinatorError::InvalidResponse)
        };
        Ok((parse(values.0)?, parse(values.1)?))
    }

    async fn connection(&self) -> Result<deadpool_redis::Connection, CoordinatorError> {
        tokio::time::timeout(self.command_timeout, self.pool.get())
            .await
            .map_err(|_| CoordinatorError::Timeout)?
            .map(Into::into)
            .map_err(|_| CoordinatorError::PoolUnavailable)
    }

    fn metadata_ttl_millis(&self) -> Result<u64, CoordinatorError> {
        duration_millis(self.metadata_ttl)
    }
}

fn validate_candidate(candidate: &PolicyCandidate) -> Result<(), CoordinatorError> {
    let matches = matches!(
        (&candidate.kind, &candidate.config),
        (
            PolicyKind::GatewayKeyBudget | PolicyKind::OrganizationOriginBudget,
            PolicyCoordinatorConfig::Budget { version_id, .. }
        ) if *version_id == candidate.desired_version_id
    ) || matches!(
        (&candidate.kind, &candidate.config),
        (
            PolicyKind::GatewayKeyRequestLimits,
            PolicyCoordinatorConfig::RequestLimits { version_id, .. }
        ) if *version_id == candidate.desired_version_id
    );
    matches.then_some(()).ok_or(CoordinatorError::Conflict)
}

fn validate_grant_request(request: &PairedBudgetGrantRequest) -> Result<(), CoordinatorError> {
    if request.key.is_none() && request.origin.is_none()
        || request.requested_ttl.is_zero()
        || request.key.iter().chain(request.origin.iter()).any(|side| {
            side.policy.organization_id != request.organization_id
                || !matches!(
                    side.policy.kind,
                    PolicyKind::GatewayKeyBudget | PolicyKind::OrganizationOriginBudget
                )
                || side.amount_nanos == 0
        })
    {
        return Err(CoordinatorError::Conflict);
    }
    Ok(())
}

fn policy_key(candidate: &PolicyCandidate) -> String {
    policy_key_ref(
        candidate.organization_id,
        candidate.kind,
        candidate.policy_id,
    )
}

fn policy_key_ref(organization_id: OrganizationId, kind: PolicyKind, policy_id: Uuid) -> String {
    format!(
        "owlrora:{{{organization_id}}}:policy:{}:{policy_id}",
        kind.as_str()
    )
}

fn ledger_key(
    organization_id: OrganizationId,
    kind: PolicyKind,
    policy_id: Uuid,
    epoch: &str,
) -> String {
    format!(
        "owlrora:{{{organization_id}}}:ledger:{}:{policy_id}:{}",
        kind.as_str(),
        digest_component(epoch)
    )
}

fn side_policy_key(organization_id: OrganizationId, side: Option<&BudgetGrantSide>) -> String {
    side.map_or_else(
        || format!("owlrora:{{{organization_id}}}:unused:policy"),
        |side| policy_key_ref(organization_id, side.policy.kind, side.policy.policy_id),
    )
}

fn side_ledger_key(organization_id: OrganizationId, side: Option<&BudgetGrantSide>) -> String {
    side.map_or_else(
        || format!("owlrora:{{{organization_id}}}:unused:ledger"),
        |side| {
            ledger_key(
                organization_id,
                side.policy.kind,
                side.policy.policy_id,
                &side.policy.epoch,
            )
        },
    )
}

fn grant_key(organization_id: OrganizationId, grant_id: Uuid) -> String {
    format!("owlrora:{{{organization_id}}}:allowance-grant:{grant_id}")
}

fn rate_grant_key(organization_id: OrganizationId, grant_id: Uuid) -> String {
    format!("owlrora:{{{organization_id}}}:rate-grant:{grant_id}")
}

fn approximate_concurrency_expiry_key(policy: &PolicyReference) -> String {
    format!(
        "owlrora:{{{}}}:concurrency-approx-expiry:{}:{}",
        policy.organization_id,
        policy.policy_id,
        digest_component(&policy.epoch)
    )
}

fn approximate_concurrency_grants_key(policy: &PolicyReference) -> String {
    format!(
        "owlrora:{{{}}}:concurrency-approx-grants:{}:{}",
        policy.organization_id,
        policy.policy_id,
        digest_component(&policy.epoch)
    )
}

fn concurrency_key(policy: &PolicyReference) -> String {
    format!(
        "owlrora:{{{}}}:concurrency:{}:{}:{}",
        policy.organization_id,
        policy.policy_id,
        digest_component(&policy.epoch),
        policy.kind.as_str()
    )
}

fn target_probe_lease_key(target_id: Uuid, binding_fingerprint: &[u8; 32]) -> String {
    format!(
        "owlrora:{{{target_id}}}:target-probe-lease:v2:{}",
        hex_digest(binding_fingerprint)
    )
}

fn target_health_key(target_id: Uuid, binding_fingerprint: &[u8; 32]) -> String {
    format!(
        "owlrora:{{{target_id}}}:target-health:v2:{}",
        hex_digest(binding_fingerprint)
    )
}

fn state_origin_key(
    organization_id: OrganizationId,
    principal_kind: &str,
    principal_affinity_id: Uuid,
    route_id: Uuid,
    protocol_family: &str,
    reference: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/state-origin/v2\0");
    digest.update(organization_id.as_uuid().as_bytes());
    digest.update(principal_affinity_id.as_bytes());
    digest.update(route_id.as_bytes());
    for value in [principal_kind, protocol_family, reference] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    format!(
        "owlrora:{{{organization_id}}}:state-origin:v2:{}",
        hex_digest(&digest)
    )
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_component(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn grant_fingerprint(request: &PairedBudgetGrantRequest) -> String {
    let mut value = format!(
        "{}\0{}\0{}\0{}\0",
        request.organization_id,
        request.grant_id,
        request.one_shot,
        request.requested_ttl.as_secs()
    );
    for side in [request.key.as_ref(), request.origin.as_ref()] {
        if let Some(side) = side {
            value.push_str(&format!(
                "{}\0{}\0{}\0{}\0{}\0{}\0",
                side.policy.kind.as_str(),
                side.policy.policy_id,
                side.policy.version_id,
                side.policy.epoch,
                side.policy.generation,
                side.policy.recovery_generation
            ));
            value.push_str(&side.amount_nanos.to_string());
        }
        value.push('\0');
    }
    digest_component(&value)
}

fn side_present(side: Option<&BudgetGrantSide>) -> &'static str {
    if side.is_some() { "1" } else { "0" }
}

fn side_epoch(side: Option<&BudgetGrantSide>) -> &str {
    side.map_or("", |side| side.policy.epoch.as_str())
}

fn side_generation(side: Option<&BudgetGrantSide>) -> u64 {
    side.map_or(0, |side| side.policy.generation)
}

fn side_recovery_generation(side: Option<&BudgetGrantSide>) -> u64 {
    side.map_or(0, |side| side.policy.recovery_generation)
}

fn side_version(side: Option<&BudgetGrantSide>) -> String {
    side.map_or_else(String::new, |side| side.policy.version_id.to_string())
}

fn side_amount(side: Option<&BudgetGrantSide>) -> String {
    side.map_or_else(|| "0".to_owned(), |side| side.amount_nanos.to_string())
}

fn recovery_fingerprint(recovery: &CoordinatorRecoveryInstall, config: &str) -> String {
    digest_component(&format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        recovery.recovery_id,
        recovery.organization_id,
        recovery.kind.as_str(),
        recovery.policy_id,
        recovery.version_id,
        recovery.epoch,
        recovery.policy_generation,
        recovery.recovery_generation,
        recovery.authorized_allowance_nanos,
        recovery.limit_cost_nanos,
        config,
    ))
}

fn duration_millis(duration: Duration) -> Result<u64, CoordinatorError> {
    u64::try_from(duration.as_millis()).map_err(|_| CoordinatorError::PoolConfiguration)
}

fn expect_state(values: Vec<String>, expected: &str) -> Result<(), CoordinatorError> {
    match values.as_slice() {
        [state] if state == expected => Ok(()),
        [state] if state == "conflict" => Err(CoordinatorError::Conflict),
        _ => Err(CoordinatorError::InvalidResponse),
    }
}

fn parse_prior(epoch: &str, generation: &str) -> Result<Option<PriorGeneration>, CoordinatorError> {
    if epoch.is_empty() && generation.is_empty() {
        return Ok(None);
    }
    if epoch.is_empty() || generation.is_empty() {
        return Err(CoordinatorError::InvalidResponse);
    }
    Ok(Some(PriorGeneration {
        epoch: epoch.to_owned(),
        generation: generation
            .parse()
            .map_err(|_| CoordinatorError::InvalidResponse)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_candidate() -> PolicyCandidate {
        let version_id = Uuid::now_v7();
        PolicyCandidate {
            organization_id: OrganizationId::new(),
            kind: PolicyKind::GatewayKeyBudget,
            policy_id: Uuid::now_v7(),
            desired_epoch: "epoch-a".to_owned(),
            desired_version_id: version_id,
            desired_generation: 1,
            desired_recovery_generation: 0,
            fence: Uuid::now_v7(),
            config: PolicyCoordinatorConfig::Budget {
                version_id,
                mode: "enforce".to_owned(),
                limit_cost_nanos: "1000".to_owned(),
                max_slice_nanos: "100".to_owned(),
                grant_seconds: 30,
            },
        }
    }

    #[test]
    fn organization_hash_tag_colocates_policy_and_ledger_state() {
        let first = budget_candidate();
        let mut second = first.clone();
        second.kind = PolicyKind::OrganizationOriginBudget;
        second.policy_id = Uuid::now_v7();
        assert_eq!(
            policy_key(&first).split('}').next(),
            ledger_key(
                second.organization_id,
                second.kind,
                second.policy_id,
                &second.desired_epoch
            )
            .split('}')
            .next()
        );
    }

    #[test]
    fn candidate_configuration_is_bound_to_version_and_kind() {
        let mut candidate = budget_candidate();
        assert!(validate_candidate(&candidate).is_ok());
        candidate.desired_version_id = Uuid::now_v7();
        assert!(validate_candidate(&candidate).is_err());
    }

    #[test]
    fn epoch_state_and_health_keys_are_bounded() {
        let candidate = budget_candidate();
        let key = ledger_key(
            candidate.organization_id,
            candidate.kind,
            candidate.policy_id,
            "epoch:{unsafe}",
        );
        assert!(!key.contains("unsafe"));
        assert_eq!(digest_component("same"), digest_component("same"));
        assert_ne!(digest_component("same"), digest_component("other"));

        let principal_id = Uuid::now_v7();
        let route_id = Uuid::now_v7();
        let state_key = state_origin_key(
            candidate.organization_id,
            "gateway_key",
            principal_id,
            route_id,
            "openai_responses",
            "same",
        );
        assert!(state_key.contains(":state-origin:v2:"));
        assert!(!state_key.contains("same"));
        assert_ne!(
            state_key,
            state_origin_key(
                candidate.organization_id,
                "gateway_key",
                principal_id,
                Uuid::now_v7(),
                "openai_responses",
                "same",
            )
        );
        let target_id = Uuid::now_v7();
        assert_eq!(
            target_probe_lease_key(target_id, &[7; 32]),
            format!(
                "owlrora:{{{target_id}}}:target-probe-lease:v2:{}",
                "07".repeat(32)
            )
        );
        assert_eq!(
            target_health_key(target_id, &[7; 32]),
            format!(
                "owlrora:{{{target_id}}}:target-health:v2:{}",
                "07".repeat(32)
            )
        );
    }

    #[test]
    fn allowance_grant_fingerprint_binds_identity_policy_amount_and_ttl() {
        let candidate = budget_candidate();
        let policy = PolicyReference {
            organization_id: candidate.organization_id,
            kind: candidate.kind,
            policy_id: candidate.policy_id,
            version_id: candidate.desired_version_id,
            epoch: candidate.desired_epoch,
            generation: candidate.desired_generation,
            recovery_generation: 0,
        };
        let request = PairedBudgetGrantRequest {
            organization_id: candidate.organization_id,
            grant_id: Uuid::now_v7(),
            key: Some(BudgetGrantSide {
                policy,
                amount_nanos: 100,
            }),
            origin: None,
            requested_ttl: Duration::from_secs(30),
            one_shot: false,
        };
        let fingerprint = grant_fingerprint(&request);
        let mut changed = request.clone();
        changed.requested_ttl = Duration::from_secs(31);
        assert_ne!(fingerprint, grant_fingerprint(&changed));
        changed = request.clone();
        changed.grant_id = Uuid::now_v7();
        assert_ne!(fingerprint, grant_fingerprint(&changed));
        changed = request.clone();
        changed.key.as_mut().unwrap().amount_nanos = 101;
        assert_ne!(fingerprint, grant_fingerprint(&changed));
    }

    #[test]
    fn prior_generation_requires_exact_epoch_and_generation() {
        assert_eq!(parse_prior("", "").unwrap(), None);
        assert!(parse_prior("epoch", "").is_err());
        assert!(parse_prior("", "1").is_err());
        assert_eq!(
            parse_prior("epoch", "7").unwrap(),
            Some(PriorGeneration {
                epoch: "epoch".to_owned(),
                generation: 7,
            })
        );
    }
}
