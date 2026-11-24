import base64
import os
import pickle
import re
import threading
from html.parser import HTMLParser
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Callable, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import BASE_DIR

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
LOGO_FILE = os.path.join(BASE_DIR, "assets", "logo.png")
BOGOTA = timezone(timedelta(hours=-5))
MONTHS = ["enero", "febrero", "marzo", "abril", "mayo", "junio",
          "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"]
_html = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape(["html"]))
_text = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=False)


class MailConfigError(Exception):
    pass


class MailSendError(Exception):
    pass


def format_request_time(moment: Optional[datetime] = None) -> str:
    local = (moment or datetime.now(timezone.utc)).astimezone(BOGOTA)
    return f"{local.day} de {MONTHS[local.month - 1]} de {local.year}, {local:%H:%M} (hora de Colombia)"


def _message(to: str, sender: str, subject: str, template: str, context: dict[str, Any],
             logo_bytes: Optional[bytes]) -> EmailMessage:
    message = EmailMessage()
    message["To"], message["From"], message["Subject"] = to, sender, subject
    message.set_content(_text.get_template(f"{template}.txt").render(**context))
    message.add_alternative(_html.get_template(f"{template}.html").render(**context), subtype="html")
    if logo_bytes is not None:
        message.get_payload()[1].add_related(logo_bytes, "image", "png", cid="<logo>")
    return message


def build_two_factor_message(to, sender, code, expires_minutes, requested_at=None, logo_bytes=None):
    return _message(to, sender, "Tu código de verificación de LigaHub", "two_factor", {
        "code": code, "expires_minutes": expires_minutes,
        "requested_at": format_request_time(requested_at), "has_logo": logo_bytes is not None,
    }, logo_bytes)


def build_password_reset_message(to, sender, reset_url, expires_minutes, logo_bytes=None):
    return _message(to, sender, "Restablece tu contraseña de LigaHub", "password_reset", {
        "reset_url": reset_url, "expires_minutes": expires_minutes,
        "has_logo": logo_bytes is not None,
    }, logo_bytes)


class _TextExtractor(HTMLParser):
    """Extrae el texto visible de un HTML para el respaldo en texto plano."""

    def __init__(self):
        super().__init__()
        self._parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._skip += 1
        elif tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3"}:
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self._parts.append(data)

    def text(self) -> str:
        return re.sub(r"\n\s*\n+", "\n\n", "".join(self._parts)).strip()


def build_notification_message(to: list[str], sender: str, subject: str, html: str) -> EmailMessage:
    extractor = _TextExtractor()
    extractor.feed(html)
    message = EmailMessage()
    message["To"], message["From"], message["Subject"] = ", ".join(to), sender, subject
    message.set_content(extractor.text() or subject)
    message.add_alternative(html, subtype="html")
    return message


def load_logo() -> Optional[bytes]:
    try:
        with open(LOGO_FILE, "rb") as handle:
            return handle.read()
    except OSError:
        return None


class GmailMailer:
    def __init__(self, credentials_dir: str, service_factory: Optional[Callable[[], Any]] = None):
        self._credentials_dir = credentials_dir
        self._client_secret = os.path.join(credentials_dir, "credentials.json")
        self._token_file = os.path.join(credentials_dir, "token.pickle")
        self._service_factory = service_factory or self._default_service
        self._service = None
        self._lock = threading.Lock()

    def send(self, message: EmailMessage) -> None:
        with self._lock:
            try:
                if self._service is None:
                    self._service = self._service_factory()
                raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
                self._service.users().messages().send(userId="me", body={"raw": raw}).execute()
            except MailConfigError:
                raise
            except Exception as exc:
                self._service = None
                raise MailSendError(type(exc).__name__) from None

    def _default_service(self):
        from googleapiclient.discovery import build
        return build("gmail", "v1", credentials=self._load_credentials(), cache_discovery=False)

    def _load_credentials(self):
        from google.auth.transport.requests import Request
        if not os.path.exists(self._token_file):
            raise MailConfigError("Falta token.pickle. Ejecuta python app.py --authorize")
        with open(self._token_file, "rb") as handle:
            credentials = pickle.load(handle)
        if not credentials.valid:
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                self._save_token(credentials)
            else:
                raise MailConfigError("Las credenciales de Gmail no son válidas")
        return credentials

    def _save_token(self, credentials):
        os.makedirs(self._credentials_dir, exist_ok=True)
        with open(self._token_file, "wb") as handle:
            pickle.dump(credentials, handle)

    def authorize_interactively(self):
        from google_auth_oauthlib.flow import InstalledAppFlow
        if not os.path.exists(self._client_secret):
            raise MailConfigError(f"No se encontró {self._client_secret}")
        flow = InstalledAppFlow.from_client_secrets_file(self._client_secret, SCOPES)
        self._save_token(flow.run_local_server(port=0))
