"""Outbound audit notifications to server-configured endpoints."""
from collections import Counter
import http.client
import ipaddress
import json
import os
import re
import socket
from time import monotonic, sleep
from urllib.parse import urlsplit

from ai_assistant import SECRET_TEXT

REFERENCE = re.compile(r"[a-zA-Z0-9_-]{1,64}")
TOKEN_ENV = re.compile(r"CYBERGARDEN_WEBHOOK_TOKEN_[A-Z0-9_]+")
HTTP_RETRY = {408, 425, 429}
MAX_RESPONSE = 8192
DEMO_PORT = 8767
CATEGORIES = ("SECRET", "SAST", "SCA")
RECOMMENDATIONS = {
    "SECRET": "Перенесите секреты в защищённое хранилище и замените опубликованные значения.",
    "SAST": "Проверьте затронутые участки и примените рекомендации анализатора.",
    "SCA": "Обновите уязвимые зависимости до проверенных исправленных версий.",
}


class WebhookError(ValueError):
    def __init__(self, message, delivery=None):
        super().__init__(message)
        self.delivery = delivery


def public_address(address):
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        # Avoid mapped or transition addresses that can conceal private IPv4 targets.
        if (ip.ipv4_mapped or ip.sixtofour or ip.teredo or ip.is_site_local
                or ip in ipaddress.ip_network("64:ff9b::/96")
                or ip in ipaddress.ip_network("64:ff9b:1::/48")):
            return False
    return ip.is_global and not any((ip.is_multicast, ip.is_reserved, ip.is_loopback, ip.is_unspecified))


def endpoint(profile):
    try:
        profiles = json.loads(os.environ.get("CYBERGARDEN_WEBHOOK_PROFILES", "{}"))
        record = profiles.get(profile) if isinstance(profiles, dict) else None
        if not isinstance(profile, str) or not REFERENCE.fullmatch(profile) or not isinstance(record, dict):
            raise WebhookError("Настройте профиль webhook в CYBERGARDEN_WEBHOOK_PROFILES.")
        if record.keys() - {"url", "tokenEnv"} or not isinstance(record.get("url"), str):
            raise WebhookError("Некорректная конфигурация профиля webhook.")
        text = record["url"]
        url = urlsplit(text)
        host, port = url.hostname, url.port
        token_env = record.get("tokenEnv")
        demo_port = int(os.environ.get("CYBERGARDEN_WEBHOOK_DEMO_PORT", DEMO_PORT))
    except WebhookError:
        raise
    except (TypeError, ValueError):
        raise WebhookError("Некорректная конфигурация профиля webhook.") from None
    if not host or url.username is not None or url.password is not None or url.query or url.fragment or (
        any(ord(char) <= 32 for char in text) or "\\" in text
    ):
        raise WebhookError("URL webhook должен быть без учётных данных, query и fragment.")
    explicit_demo = (
        profile == "demo" and os.environ.get("CYBERGARDEN_WEBHOOK_ALLOW_LOOPBACK_DEMO") == "1"
        and url.scheme == "http" and host == "127.0.0.1" and port == demo_port
        and url.netloc == f"127.0.0.1:{demo_port}" and url.path == "/webhook"
    )
    if not explicit_demo and (url.scheme != "https" or port not in {None, 443}):
        raise WebhookError("Внешний webhook требует HTTPS на порту 443. Loopback разрешён только профилю demo.")
    token = ""
    if token_env is not None:
        if not isinstance(token_env, str) or not TOKEN_ENV.fullmatch(token_env):
            raise WebhookError("Укажите имя CYBERGARDEN_WEBHOOK_TOKEN_* в параметре tokenEnv.")
        token = os.environ.get(token_env, "")
        if not token or any(not 33 <= ord(char) < 127 for char in token):
            raise WebhookError("В окружении отсутствует корректный токен webhook.")
    return host, port or 443, url.path or "/", explicit_demo, token


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self._create_connection = lambda address_pair, seconds, source_address: socket.create_connection(
            (address, address_pair[1]), seconds, source_address,
        )


def public_ip(host, port):
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or not all(public_address(address) for address in addresses):
        raise WebhookError("Webhook отклонён: адрес получателя должен быть публичным.")
    return addresses[0]


def notification(run_id, status, findings, reviews):
    counts = Counter(row["category"] for row in findings)
    summaries = [
        {"summary": item["summary"], "analyzedCount": item["analyzedCount"]}
        for item in reviews[:8] if not SECRET_TEXT.search(item["summary"])
    ]
    return {
        "runId": run_id, "status": status, "phase": "notification",
        "findingCount": len(findings), "counts": {label: counts[label] for label in CATEGORIES},
        "criticalCount": sum(row["severity"] == "CRITICAL" for row in findings),
        "recommendations": [RECOMMENDATIONS[label] for label in CATEGORIES if counts[label]],
        **({"ai": summaries} if summaries else {}),
    }


def confirmation(response_body, run_id):
    try:
        body = json.loads(response_body)
    except (ValueError, RecursionError):
        return {}
    if isinstance(body, dict) and body.get("accepted") is True and body.get("runId") == run_id:
        return {"accepted": True, "runId": run_id}
    return {}


def deliver(profile, payload, timeout, node_id=None):
    host, port, path, demo, token = endpoint(profile)
    body = json.dumps(payload, ensure_ascii=False).encode()
    key = payload["runId"] + ("." + node_id if node_id else "")
    headers = {"Content-Type": "application/json", "Idempotency-Key": key}
    if token:
        headers["Authorization"] = "Bearer " + token
        if token.encode() in body:
            raise WebhookError("В уведомлении найдено потенциально чувствительное значение.")
    deadline = monotonic() + timeout
    http_status = None
    attempts = 0
    failure = "Webhook не ответил за отведённое время."
    for attempt in range(1, 4):
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        attempts = attempt
        http_status = None
        connection = None
        try:
            seconds = min(4, remaining)
            if demo:
                connection = http.client.HTTPConnection(host, port, timeout=seconds)
            else:
                connection = PinnedHTTPS(host, port, public_ip(host, port), seconds)
            connection.request("POST", path, body, headers)
            with connection.getresponse() as response:
                http_status = response.status
                if 200 <= http_status < 300:
                    # A successful HTTP status is sufficient even if the optional body is missing.
                    try:
                        received = response.read(MAX_RESPONSE + 1)
                    except (OSError, http.client.HTTPException):
                        received = b""
                    reply = confirmation(received, payload["runId"]) if len(received) <= MAX_RESPONSE else {}
                    return {"status": "delivered", "httpStatus": http_status, "attempts": attempt,
                            "receiver": reply}
            failure = f"Webhook вернул HTTP {http_status}."
            if http_status not in HTTP_RETRY and not 500 <= http_status < 600:
                break
        except TimeoutError:
            failure = "Webhook не ответил за отведённое время."
        except (OSError, http.client.HTTPException):
            failure = "Не удалось связаться с получателем webhook."
        finally:
            if connection is not None:
                connection.close()
        if attempt < 3:
            sleep(max(0, min(0.15 * attempt, deadline - monotonic())))
    raise WebhookError(failure, {"status": "failed", "httpStatus": http_status,
                                "attempts": attempts, "receiver": {}})
