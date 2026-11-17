import redis
from fastapi import HTTPException

from app.core.config import settings

_r = redis.Redis.from_url(settings.redis_url, decode_responses=True)


def redis_client() -> redis.Redis:
    return _r


def rate_limit(bucket: str, ident: str, limit: int, window_s: int) -> None:
    key = f"rl:{bucket}:{ident}"
    n = _r.incr(key)
    if n == 1:
        _r.expire(key, window_s)
    if n > limit:
        raise HTTPException(429, "Demasiados intentos. Inténtalo más tarde.",
                            headers={"Retry-After": str(window_s)})
