import json
import os
from typing import Callable, Optional

import yaml
from fastapi import Request, Response
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

cwd = os.path.abspath(os.path.dirname(__file__))
translations_file = os.path.join(cwd, "translations.yml")


class Translation(BaseModel):
    en: Optional[str]
    sk: Optional[str]


def flatten_dict(d, parent_key="", sep="."):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


with open(translations_file, "r", encoding="utf-8") as f:
    translations = yaml.safe_load(f)
    translations = flatten_dict(translations)


def translate(s, lang: str):
    if isinstance(s, list):
        return [translate(i, lang) for i in s]
    elif isinstance(s, dict):
        if lang in s.keys():
            return s[lang]
        return {k: translate(v, lang) for k, v in s.items()}
    elif isinstance(s, str):
        return translations.get(f"{s}.{lang}", s)
    else:
        return s


def translate_response(response_body: bytes, lang: str) -> bytes:
    try:
        response = json.loads(response_body.decode())
    except json.decoder.JSONDecodeError:
        return response_body
    if response and isinstance(response, dict) or (isinstance(response, list) and isinstance(response[0], dict)):
        return json.dumps(translate(response, lang)).encode("utf-8")
    else:
        return response_body


def parse_language(lang_header: str) -> str:
    return lang_header.split(",")[0].split("-")[0]


class I18nMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk
        language = parse_language(request.headers.get("accept-language", "en"))
        response_body = translate_response(response_body, language)
        response.headers["Content-Length"] = str(len(response_body))
        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
