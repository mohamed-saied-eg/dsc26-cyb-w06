"""Building the model's input. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

ALLOWED_FIELDS = ("rule_id", "rule_description", "level", "agent_name", "timestamp",
                  "full_log", "src_ip", "dst_ip", "user")
MAX_LOG_CHARS = 4000


def build_messages(alert: dict, tenant_id: str, nonce: str) -> list[dict]:
    """Return [system_message, user_message] (each {"role": ..., "content": ...}).

    - `nonce` must be 16-64 lowercase hex characters and `tenant_id` must match `TEN-` + 3 digits,
      else raise ValueError.
    - Keep only ALLOWED_FIELDS that are present and not None; cut `full_log` to MAX_LOG_CHARS.
    - The system message names the tenant id and the nonce, says the tagged content is data, and
      carries no alert data.
    - The user message is exactly f"<alert-{nonce}>\\n{body}\\n</alert-{nonce}>", where `body` is
      json.dumps(data, ensure_ascii=False, sort_keys=True) with every "<" replaced by "\\u003c" and
      every ">" replaced by "\\u003e".
    """
    raise NotImplementedError
