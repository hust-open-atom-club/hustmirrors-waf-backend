package redis

import "github.com/redis/go-redis/v9"

// consumeUsage atomically increments uses if below max_uses, and returns
// {allowed, uses} as an int64 reply slice.
//
// KEYS[1] is pow:usage:<sign_id>. ARGV is, in order: max_uses,
// ttl_seconds, now_unix, ip, user_agent, mode, path, sign, token_hash,
// expires_at.
//
// The script runs atomically in Redis so concurrent Consume calls against
// the same sign id can never exceed max_uses. On first use the hash is
// populated with all fields and an EXPIRE is set; on subsequent uses only
// uses, last_ip and updated_at are updated and the TTL is not refreshed.
var consumeUsage = redis.NewScript(`
local key = KEYS[1]
local max_uses = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local now = ARGV[3]
local ip = ARGV[4]
local ua = ARGV[5]
local mode = ARGV[6]
local path = ARGV[7]
local sign = ARGV[8]
local token_hash = ARGV[9]
local expires_at = ARGV[10]

local uses = tonumber(redis.call('HGET', key, 'uses') or '0')

if uses >= max_uses then
  return {0, uses}
end

uses = uses + 1

if uses == 1 then
  redis.call('HSET', key,
    'uses', uses,
    'mode', mode,
    'path', path,
    'sign', sign,
    'token_hash', token_hash,
    'max_uses', max_uses,
    'first_ip', ip,
    'last_ip', ip,
    'user_agent', ua,
    'expires_at', expires_at,
    'created_at', now,
    'updated_at', now
  )
  redis.call('EXPIRE', key, ttl)
else
  redis.call('HSET', key,
    'uses', uses,
    'last_ip', ip,
    'updated_at', now
  )
end

return {1, uses}
`)
