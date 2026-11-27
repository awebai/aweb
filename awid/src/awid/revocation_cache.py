"""Derived membership indexes of the existing complete cached CRL.

The full list remains evidence. No index can answer without that exact list
version, and an old writer's ordinary JSON entry makes the index unusable.
"""

from __future__ import annotations

import json
from uuid import uuid4

from redis.exceptions import RedisError

_VERSION = "_crl_index_version"


def is_revocation_key(key: str, *, prefix: str) -> bool:
    return key.startswith(prefix) and not key.endswith(
        (":membership", ":membership-meta")
    )


def index_keys(key: str) -> tuple[str, str]:
    return key + ":membership", key + ":membership-meta"


# TIME precedes PTTL in the CAS/backfill case. Thus the computed absolute
# expiry cannot exceed the old list's expiry, even if the clock advances
# between commands. All three keys receive the SAME absolute expiry.
_PUBLISH = """
local clock = redis.call('TIME')
local now = clock[1] * 1000 + math.floor(clock[2] / 1000)
local remaining = tonumber(ARGV[3])
if ARGV[4] ~= '' then
    remaining = redis.call('PTTL', KEYS[1])
    if remaining <= 0 or redis.call('GET', KEYS[1]) ~= ARGV[4] then return 0 end
end
local expires = now + remaining
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PEXPIREAT', KEYS[1], expires)
redis.call('DEL', KEYS[2], KEYS[3])
redis.call('SADD', KEYS[2], ARGV[5])
for first = 6, #ARGV, 1000 do
    local members = {}
    for i = first, math.min(first + 999, #ARGV) do
        members[#members + 1] = 'id:' .. ARGV[i]
    end
    redis.call('SADD', KEYS[2], unpack(members))
end
redis.call('PEXPIREAT', KEYS[2], expires)
-- Metadata is published LAST: a failed build can never expose a partial set.
redis.call('SET', KEYS[3], ARGV[2])
redis.call('PEXPIREAT', KEYS[3], expires)
return ARGV[5]
"""

_READ = """
local raw = redis.call('GET', KEYS[3])
if not raw or #raw > 1024 then return {0} end
local ok, meta = pcall(cjson.decode, raw)
if not ok or type(meta) ~= 'table' or type(meta.prefix) ~= 'string'
   or #meta.prefix < 32 or #meta.prefix > 128 or type(meta.marker) ~= 'string'
   or #meta.marker ~= 40 or string.sub(meta.marker, 1, 8) ~= 'present:' then return {0} end
local token = string.sub(meta.marker, 9)
if not string.match(token, '^[0-9a-f]+$')
   or meta.prefix ~= '{"_crl_index_version":"' .. token .. '",' then return {0} end
if redis.call('GETRANGE', KEYS[1], 0, #meta.prefix - 1) ~= meta.prefix then return {0} end
if redis.call('SISMEMBER', KEYS[2], meta.marker) ~= 1 then return {0} end
local result = {1, raw}
for i = 1, #ARGV do
    result[#result + 1] = redis.call('SISMEMBER', KEYS[2], 'id:' .. ARGV[i])
end
return result
"""


async def publish(
    redis, key: str, entry: dict, *, retention_seconds: int, expected: str | None = None
) -> bool:
    """Publish a complete entry/index atomically, or CAS-backfill its old age.

    No EVAL support or an unavailable index is an optimization miss. The
    caller retains its ordinary complete-list cache path in that case.
    """
    if not callable(getattr(redis, "eval", None)):
        return False
    values = entry.get("value")
    fetched_at, fresh_until = entry.get("fetched_at"), entry.get("fresh_until")
    if (
        not isinstance(values, list)
        or not all(isinstance(value, str) for value in values)
        or type(fetched_at) is not int
        or type(fresh_until) is not int
    ):
        return False
    token = uuid4().hex
    marker = "present:" + token
    versioned = {**entry, _VERSION: token}
    prefix = '{"' + _VERSION + '":"' + token + '",'
    meta = {
        "prefix": prefix,
        "marker": marker,
        "fetched_at": fetched_at,
        "fresh_until": fresh_until,
    }
    try:
        answer = await redis.eval(
            _PUBLISH,
            3,
            key,
            *index_keys(key),
            json.dumps(versioned, separators=(",", ":"), sort_keys=True),
            json.dumps(meta, separators=(",", ":"), sort_keys=True),
            retention_seconds * 1000,
            expected or "",
            marker,
            *values,
        )
    except (RedisError, OSError, TypeError, AttributeError):
        return False
    if isinstance(answer, bytes):
        answer = answer.decode("ascii")
    return answer == marker


async def read(redis, key: str, certificate_ids: list[str], *, now: int) -> dict | None:
    """Read original stamps and selected memberships in ONE atomic statement."""
    if not callable(getattr(redis, "eval", None)):
        return None
    try:
        answer = await redis.eval(_READ, 3, key, *index_keys(key), *certificate_ids)
        if (
            not isinstance(answer, (tuple, list))
            or len(answer) != len(certificate_ids) + 2
            or answer[0] != 1
        ):
            return None
        if any(value not in (0, 1) for value in answer[2:]):
            return None
        meta = json.loads(answer[1])
        if type(meta["fetched_at"]) is not int or type(meta["fresh_until"]) is not int:
            return None
        return {
            "fetched_at": meta["fetched_at"],
            "fresh_until": meta["fresh_until"],
            "fresh": meta["fresh_until"] > now,
            "value": {
                cid
                for cid, revoked in zip(certificate_ids, answer[2:], strict=True)
                if revoked
            },
        }
    except (RedisError, OSError, TypeError, AttributeError, ValueError, KeyError):
        return None
