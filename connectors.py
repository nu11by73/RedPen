"""Target chatbot connectors. Supports Anthropic, OpenAI-compatible, and custom HTTP."""
from __future__ import annotations
import json
import requests
from dataclasses import dataclass, field
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class TargetConfig:
    kind: str                       # "anthropic" | "openai" | "custom_http"
    endpoint: str = ""
    api_key: str = ""
    model: str = ""
    system_prompt: str = ""
    extra_headers: dict = field(default_factory=dict)
    body_template: str = ""
    response_path: str = ""
    timeout: int = 60


class TargetError(Exception):
    pass


def _dig(obj, path: str):
    cur = obj
    for part in path.split("."):
        if part.isdigit():
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def send_prompt(cfg: TargetConfig, prompt: str,
                history: Optional[list[dict]] = None) -> str:
    history = history or []

    if cfg.kind == "anthropic":
        headers = {
            "x-api-key": cfg.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            **cfg.extra_headers,
        }
        messages = history + [{"role": "user", "content": prompt}]
        body = {
            "model": cfg.model or "claude-3-5-sonnet-latest",
            "max_tokens": 1024,
            "messages": messages,
        }
        if cfg.system_prompt:
            body["system"] = cfg.system_prompt
        url = cfg.endpoint or "https://api.anthropic.com/v1/messages"
        r = requests.post(url, headers=headers, json=body, timeout=cfg.timeout)
        if r.status_code >= 400:
            raise TargetError(f"{r.status_code}: {r.text[:500]}")
        data = r.json()
        return "".join(block.get("text", "") for block in data.get("content", []))

    if cfg.kind == "openai":
        headers = {
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
            **cfg.extra_headers,
        }
        msgs = []
        if cfg.system_prompt:
            msgs.append({"role": "system", "content": cfg.system_prompt})
        msgs.extend(history)
        msgs.append({"role": "user", "content": prompt})
        body = {"model": cfg.model or "gpt-4o-mini", "messages": msgs}
        url = cfg.endpoint or "https://api.openai.com/v1/chat/completions"
        r = requests.post(url, headers=headers, json=body, timeout=cfg.timeout)
        if r.status_code >= 400:
            raise TargetError(f"{r.status_code}: {r.text[:500]}")
        return r.json()["choices"][0]["message"]["content"]

    if cfg.kind == "custom_http":
        if not cfg.body_template:
            raise TargetError("custom_http requires body_template containing {{PROMPT}}")
        body_str = cfg.body_template.replace("{{PROMPT}}", json.dumps(prompt)[1:-1])
        body = json.loads(body_str)
        headers = {"Content-Type": "application/json", **cfg.extra_headers}
        if cfg.api_key:
            headers.setdefault("Authorization", f"Bearer {cfg.api_key}")
        r = requests.post(cfg.endpoint, headers=headers, json=body, timeout=cfg.timeout)
        if r.status_code >= 400:
            raise TargetError(f"{r.status_code}: {r.text[:500]}")
        data = r.json()
        if cfg.response_path:
            return str(_dig(data, cfg.response_path))
        return json.dumps(data)[:4000]

    raise TargetError(f"Unknown connector kind: {cfg.kind}")