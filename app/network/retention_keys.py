"""去关联统计键派生。

统计键不可逆且按到期批次隔离：
- 同一原始标识在同一到期批次内、跨样本/会话/权益表得到同一个键，保留行之间的同人关联与审计链；
- 不同到期批次得到不同键，无法跨期还原出同一旅客；
- HMAC 使用服务端 pepper，库内只存键本身；原始标识删除后，仅凭库内数据无法反查，
  批量拿到候选标识也无法在不知道 pepper 的情况下对照。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

STAT_KEY_VERSION = "v1"
STAT_KEY_PREFIX = "stat"
KEY_BYTES = 32
NAMESPACE = "network-experience-retention"


def generate_pepper() -> str:
    """生成新的服务端 pepper（base64url，无填充）。"""
    return secrets.token_urlsafe(KEY_BYTES)


def normalize_pepper(pepper: str | bytes) -> bytes:
    if isinstance(pepper, str):
        if not pepper:
            raise ValueError("去关联 pepper 不能为空")
        return pepper.encode("utf-8")
    return pepper


def pepper_identifier(pepper: str | bytes) -> str:
    """返回 pepper 的短指纹，用于报告标识所用 pepper，且不泄露 pepper 本身。"""
    return hashlib.sha256(normalize_pepper(pepper)).hexdigest()[:16]


def derive_stat_key(pepper: str | bytes, *, batch_key: str, subscriber_hash: str) -> str:
    """为单条记录派生不可逆、批次隔离的统计键。"""
    message = "|".join((STAT_KEY_VERSION, NAMESPACE, batch_key, subscriber_hash)).encode("utf-8")
    digest = hmac.new(normalize_pepper(pepper), message, hashlib.sha256).hexdigest()
    return f"{STAT_KEY_PREFIX}:{STAT_KEY_VERSION}:{batch_key}:{digest[:32]}"


def key_batch(stat_key: str) -> str | None:
    """从统计键中解析批次；非统计键返回 None。"""
    parts = stat_key.split(":", 3)
    if len(parts) >= 3 and parts[0] == STAT_KEY_PREFIX and parts[1] == STAT_KEY_VERSION:
        return parts[2]
    return None


def is_stat_key(value: str | None) -> bool:
    return bool(value) and key_batch(value or "") is not None
