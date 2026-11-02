import hmac
import ipaddress
import logging
import re
import sys
from typing import Optional
from urllib.parse import urlsplit

from flask import Flask, jsonify, request

from config import Settings
from mailer import (
    GmailMailer,
    MailConfigError,
    MailSendError,
    build_password_reset_message,
    build_two_factor_message,
    load_logo,
)
from ratelimit import RateLimiter

EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+"
)
CODE_PATTERN = re.compile(r"\d{6}")
MAX_EMAIL_LENGTH = 254
TWO_FACTOR_FIELDS = {"email", "code", "expires_minutes"}
PASSWORD_RESET_FIELDS = {"email", "reset_url", "expires_minutes"}


def _valid_reset_url(value: str) -> bool:
    if not value or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    if parsed.scheme == "https" or hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _masked_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:2]}***@{domain}"


def create_app(settings: Optional[Settings] = None, mailer=None) -> Flask:
    settings = settings or Settings.from_env()
    mailer = mailer or GmailMailer(settings.credentials_dir)
    limiter = RateLimiter()
    logo = load_logo()
    app = Flask(__name__)
    app.logger.setLevel(logging.INFO)

    def error(message: str, status: int):
        return jsonify(error=message), status

    def authorized() -> bool:
        provided = request.headers.get("X-Service-Key", "").encode("utf-8")
        expected = settings.api_key.encode("utf-8")
        return bool(settings.api_key) and hmac.compare_digest(provided, expected)

    def common_checks():
        if not settings.api_key or not settings.sender:
            app.logger.error("EMAIL_SERVICE_API_KEY o GMAIL_SENDER no configurados")
            return error("El servicio de correo no está configurado.", 500)
        if not limiter.allow(
            f"ip:{request.remote_addr or 'desconocida'}",
            settings.rate_per_ip,
            settings.rate_window_seconds,
        ):
            return error("Demasiadas solicitudes.", 429)
        if not authorized():
            app.logger.warning("Solicitud rechazada: clave de servicio inválida")
            return error("No autorizado.", 401)
        return None

    @app.post("/api/2fa/send")
    def send_2fa_code():
        rejected = common_checks()
        if rejected:
            return rejected
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != TWO_FACTOR_FIELDS:
            return error("Cuerpo inválido.", 400)
        recipient, code, minutes = (
            payload["email"],
            payload["code"],
            payload["expires_minutes"],
        )
        if (
            not isinstance(recipient, str)
            or len(recipient) > MAX_EMAIL_LENGTH
            or not EMAIL_PATTERN.fullmatch(recipient)
            or not isinstance(code, str)
            or not CODE_PATTERN.fullmatch(code)
            or not isinstance(minutes, int)
            or isinstance(minutes, bool)
            or not 1 <= minutes <= 30
        ):
            return error("Datos inválidos.", 400)
        if not limiter.allow(f"to:{recipient.lower()}", settings.rate_per_recipient, settings.rate_window_seconds):
            return error("Demasiadas solicitudes.", 429)
        try:
            mailer.send(build_two_factor_message(
                recipient, settings.sender, code, minutes, logo_bytes=logo
            ))
        except MailConfigError as exc:
            app.logger.error("Gmail no configurado: %s", exc)
            return error("El servicio de correo no está configurado.", 500)
        except MailSendError as exc:
            app.logger.error("Gmail no pudo enviar el correo (%s)", exc)
            return error("No fue posible enviar el correo.", 502)
        app.logger.info("Correo 2FA enviado a %s", _masked_email(recipient))
        return jsonify(message="Correo enviado."), 200

    @app.post("/api/password-reset/send")
    def send_password_reset():
        rejected = common_checks()
        if rejected:
            return rejected
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != PASSWORD_RESET_FIELDS:
            return error("Cuerpo inválido.", 400)
        recipient, reset_url, minutes = (
            payload["email"],
            payload["reset_url"],
            payload["expires_minutes"],
        )
        if (
            not isinstance(recipient, str)
            or len(recipient) > MAX_EMAIL_LENGTH
            or not EMAIL_PATTERN.fullmatch(recipient)
            or not isinstance(reset_url, str)
            or not _valid_reset_url(reset_url)
            or not isinstance(minutes, int)
            or isinstance(minutes, bool)
            or not 1 <= minutes <= 30
        ):
            return error("Datos inválidos.", 400)
        if not limiter.allow(f"to:{recipient.lower()}", settings.rate_per_recipient, settings.rate_window_seconds):
            return error("Demasiadas solicitudes.", 429)
        try:
            mailer.send(build_password_reset_message(
                recipient, settings.sender, reset_url, minutes, logo_bytes=logo
            ))
        except MailConfigError as exc:
            app.logger.error("Gmail no configurado: %s", exc)
            return error("El servicio de correo no está configurado.", 500)
        except MailSendError as exc:
            app.logger.error("Gmail no pudo enviar el correo (%s)", exc)
            return error("No fue posible enviar el correo.", 502)
        app.logger.info("Correo de recuperación enviado a %s", _masked_email(recipient))
        return jsonify(message="Correo enviado."), 200

    return app


def main(argv: list[str]) -> None:
    settings = Settings.from_env()
    if "--authorize" in argv:
        GmailMailer(settings.credentials_dir).authorize_interactively()
        print("Gmail autorizado. Se guardó token.pickle.")
        return
    create_app(settings).run(host=settings.host, port=settings.port, debug=False, threaded=True)


if __name__ == "__main__":
    main(sys.argv[1:])
